package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var (
	ErrOverflow = errors.New("ring: overflow")
	ErrClosed   = errors.New("ring: closed")
)

const (
	// DefaultL1Cap is the default in-memory RAM limit before spilling to L2 disk (8 MiB).
	DefaultL1Cap = 8 * 1024 * 1024
)

// RingConfig configures a tiered ring buffer.
type RingConfig struct {
	CapMax   int
	L1Cap    int
	Budget   *Budget
	SpillDir string
	NoSpill  bool
}

// Ring is a growable tiered circular byte buffer addressed by absolute stream offsets.
// L1 data resides in RAM; when L1 or the global memory budget is exceeded, overflow
// blocks spill to an encrypted L2 disk temporary file.
type Ring struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	start    int
	length   int // total unacknowledged bytes (spillLen + ramLen)
	ramLen   int // unacknowledged bytes currently in RAM buf
	capMax   int
	soft     int // 0 = no soft cap (use capMax)
	base     uint64
	closed   atomic.Bool
	budget   *Budget
	budgeted int
	notify   chan struct{}

	spill           *spillFile
	l1Cap           int    // L1 RAM capacity threshold
	spillDir        string // directory for spill files
	noSpill         bool   // disable L2 disk spilling
	spillLen        int    // unacknowledged bytes stored on disk
	spillBaseOffset uint64 // logical stream offset of block 0 in spill file
	spillBlocksWritten uint64
}

// NewRing creates a Ring buffer with default L1 RAM capacity (8 MiB).
func NewRing(cap int, budget *Budget) *Ring {
	return NewTieredRing(RingConfig{
		CapMax: cap,
		Budget: budget,
	})
}

// NewTieredRing creates a Ring buffer with custom tiered storage configuration.
func NewTieredRing(cfg RingConfig) *Ring {
	cap := cfg.CapMax
	if cap <= 0 {
		cap = 1
	}
	l1 := cfg.L1Cap
	if l1 <= 0 {
		l1 = DefaultL1Cap
	}
	if l1 < spillBlockSize {
		l1 = spillBlockSize
	}
	if l1 > cap {
		l1 = cap
	}
	r := &Ring{
		capMax:   cap,
		l1Cap:    l1,
		budget:   cfg.Budget,
		spillDir: cfg.SpillDir,
		noSpill:  cfg.NoSpill,
		notify:   make(chan struct{}, 1),
	}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *Ring) Cap() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.capMax
}

func (r *Ring) SetCap(n int) {
	if n <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.capMax = n
	if !r.noSpill && r.l1Cap > r.capMax {
		r.l1Cap = r.capMax
	}
	r.cond.Broadcast()
	r.pokeLocked()
}

func (r *Ring) SetL1Cap(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n >= spillBlockSize {
		r.l1Cap = n
	}
}

func (r *Ring) SetNoSpill(noSpill bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.noSpill = noSpill
}

func (r *Ring) SetSoftLimit(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.soft = n
	r.cond.Broadcast()
	r.pokeLocked()
}

// Len returns the total number of unacknowledged bytes (both in RAM and on disk).
func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.length
}

// RAMLen returns the number of unacknowledged bytes currently resident in RAM.
func (r *Ring) RAMLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ramLen
}

// SpillLen returns the number of unacknowledged bytes currently resident on disk.
func (r *Ring) SpillLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.spillLen
}

func (r *Ring) Base() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.base
}

func (r *Ring) End() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.base + uint64(r.length)
}

func (r *Ring) Notify() <-chan struct{} {
	return r.notify
}

func (r *Ring) Close() {
	r.mu.Lock()
	r.closed.Store(true)
	r.cond.Broadcast()
	r.pokeLocked()
	r.mu.Unlock()
	if r.budget != nil {
		r.budget.wake()
	}
}

func (r *Ring) Release() {
	r.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.spill != nil {
		_ = r.spill.Close()
		r.spill = nil
	}
	if r.budget != nil && r.budgeted > 0 {
		r.budget.Release(int64(r.budgeted))
		r.budgeted = 0
	}
	r.buf = nil
	r.length = 0
	r.ramLen = 0
	r.spillLen = 0
	r.start = 0
}

func (r *Ring) limitLocked() int {
	lim := r.capMax
	if r.soft > 0 && r.soft < lim {
		lim = r.soft
	}
	return lim
}

func (r *Ring) pokeLocked() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

func (r *Ring) Append(ctx context.Context, p []byte) error {
	for len(p) > 0 {
		n, err := r.appendSome(ctx, p, true)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func (r *Ring) TryAppend(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	_, err := r.appendSome(context.Background(), p, false)
	return err
}

func (r *Ring) ensureSpillFileLocked() error {
	if r.spill != nil {
		return nil
	}
	sf, err := newSpillFile(r.spillDir)
	if err != nil {
		return err
	}
	r.spill = sf
	r.spillBaseOffset = r.base + uint64(r.spillLen)
	r.spillBlocksWritten = 0
	return nil
}

// spillOneBlockLocked extracts 64 KiB from the front of the in-memory RAM buffer,
// encrypts it, writes it to the L2 spill file, and releases its RAM budget.
func (r *Ring) spillOneBlockLocked() error {
	if r.ramLen < spillBlockSize {
		return nil
	}
	toSpill := spillBlockSize
	if err := r.ensureSpillFileLocked(); err != nil {
		return err
	}

	blockIndex := r.spillBlocksWritten

	var blockBuf [spillBlockSize]byte
	copyOut(blockBuf[:toSpill], r.buf, r.start, toSpill)

	if err := r.spill.WriteBlock(blockIndex, blockBuf[:toSpill]); err != nil {
		return err
	}

	r.spillBlocksWritten++
	r.start = (r.start + toSpill) % len(r.buf)
	r.ramLen -= toSpill
	r.spillLen += toSpill

	if r.budget != nil {
		r.budget.Release(int64(toSpill))
		r.budgeted -= toSpill
		if r.budgeted < 0 {
			r.budgeted = 0
		}
	}
	return nil
}

func (r *Ring) appendSome(ctx context.Context, p []byte, wait bool) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	stop := context.AfterFunc(ctx, func() {
		r.mu.Lock()
		r.cond.Broadcast()
		r.mu.Unlock()
	})
	defer stop()

	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if r.closed.Load() {
			return 0, ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		lim := r.limitLocked()
		space := lim - r.length
		if space <= 0 {
			if !wait {
				return 0, ErrOverflow
			}
			r.cond.Wait()
			continue
		}
		if !wait && len(p) > space {
			return 0, ErrOverflow
		}
		n := len(p)
		if n > space {
			n = space
		}

		maxRAM := r.l1Cap + spillBlockSize
		if r.noSpill || r.capMax <= r.l1Cap {
			maxRAM = r.capMax
		}

		// If spilling is enabled, spill oldest RAM blocks to disk when RAM is full or over L1 threshold
		if !r.noSpill && r.capMax > r.l1Cap {
			for (r.ramLen+n > maxRAM || r.ramLen >= r.l1Cap) && r.ramLen >= spillBlockSize {
				if err := r.spillOneBlockLocked(); err != nil {
					return 0, err
				}
			}
		}

		neededRAM := r.ramLen + n
		if neededRAM > maxRAM {
			neededRAM = maxRAM
		}
		_ = r.ensureRAMLocked(neededRAM, maxRAM)

		room := len(r.buf) - r.ramLen
		if room <= 0 {
			if !r.noSpill && r.ramLen >= spillBlockSize {
				if err := r.spillOneBlockLocked(); err != nil {
					return 0, err
				}
				continue
			}
			if !wait {
				return 0, ErrOverflow
			}
			r.cond.Wait()
			continue
		}
		if n > room {
			n = room
		}

		if r.budget != nil {
			got := r.budget.TryAcquire(int64(n))
			if got <= 0 {
				// Budget exhausted: spill from RAM to free budget if possible
				if !r.noSpill && r.ramLen >= spillBlockSize {
					if err := r.spillOneBlockLocked(); err != nil {
						return 0, err
					}
					continue
				}
				if !wait {
					return 0, ErrOverflow
				}
				r.mu.Unlock()
				err := r.budget.Wait(ctx, r.closed.Load)
				r.mu.Lock()
				if r.closed.Load() {
					return 0, ErrClosed
				}
				if err != nil {
					return 0, err
				}
				continue
			}
			n = int(got)
		}

		copyIn(r.buf, r.start, r.ramLen, p[:n])
		r.ramLen += n
		r.length += n
		r.budgeted += n
		r.cond.Broadcast()
		r.pokeLocked()
		return n, nil
	}
}

func (r *Ring) ensureRAMLocked(need, maxRAM int) bool {
	if need <= len(r.buf) {
		return true
	}
	if need > maxRAM {
		need = maxRAM
	}
	newSize := nextSize(len(r.buf), need, maxRAM)
	if newSize <= len(r.buf) {
		return false
	}
	nb := make([]byte, newSize)
	if r.ramLen > 0 && len(r.buf) > 0 {
		copyOut(nb[:r.ramLen], r.buf, r.start, r.ramLen)
	}
	r.buf = nb
	r.start = 0
	return len(r.buf) >= need
}

func (r *Ring) AdvanceTo(ack uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ack <= r.base {
		return
	}
	end := r.base + uint64(r.length)
	if ack > end {
		ack = end
	}
	totalDrop := int(ack - r.base)
	if totalDrop <= 0 {
		return
	}

	if r.spillLen > 0 {
		spillEnd := r.base + uint64(r.spillLen)
		if ack <= spillEnd {
			// Acknowledgment is within disk spill
			r.spillLen -= totalDrop
			r.length -= totalDrop
			r.base = ack
			if r.spill != nil {
				r.spill.PunchHole(ack - r.spillBaseOffset)
				if r.spillLen == 0 {
					r.spill.Reset()
					r.spillBlocksWritten = 0
					r.spillBaseOffset = r.base
				}
			}
			r.cond.Broadcast()
			r.pokeLocked()
			return
		}

		// Acknowledgment covers entire disk spill plus part of RAM
		diskDrop := r.spillLen
		ramDrop := totalDrop - diskDrop
		r.spillLen = 0
		if r.spill != nil {
			r.spill.Reset()
			r.spillBlocksWritten = 0
			r.spillBaseOffset = ack
		}
		if len(r.buf) > 0 {
			r.start = (r.start + ramDrop) % len(r.buf)
		}
		r.ramLen -= ramDrop
		r.length -= totalDrop
		r.base = ack
		if r.budget != nil && ramDrop > 0 {
			r.budget.Release(int64(ramDrop))
			r.budgeted -= ramDrop
			if r.budgeted < 0 {
				r.budgeted = 0
			}
		}
		r.cond.Broadcast()
		r.pokeLocked()
		return
	}

	// Pure RAM
	if len(r.buf) > 0 {
		r.start = (r.start + totalDrop) % len(r.buf)
	}
	r.ramLen -= totalDrop
	r.length -= totalDrop
	r.base = ack
	if r.spill != nil {
		r.spillBaseOffset = ack
		r.spillBlocksWritten = 0
	}
	if r.budget != nil && totalDrop > 0 {
		r.budget.Release(int64(totalDrop))
		r.budgeted -= totalDrop
		if r.budgeted < 0 {
			r.budgeted = 0
		}
	}
	r.cond.Broadcast()
	r.pokeLocked()
}

func (r *Ring) Slice(from uint64, max int) (uint64, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if max <= 0 || r.length == 0 {
		if from < r.base {
			from = r.base
		}
		return from, nil
	}
	if from < r.base {
		from = r.base
	}
	end := r.base + uint64(r.length)
	if from >= end {
		return from, nil
	}
	avail := int(end - from)
	if max > avail {
		max = avail
	}
	out := make([]byte, max)

	spillEnd := r.base + uint64(r.spillLen)

	if from < spillEnd {
		// Read from disk spill
		diskAvail := int(spillEnd - from)
		if diskAvail > max {
			diskAvail = max
		}
		relOffset := from - r.spillBaseOffset
		n, err := r.spill.ReadAt(relOffset, out[:diskAvail])
		if err != nil && n < diskAvail {
			return from, out[:n]
		}
		if max > diskAvail {
			// Read remainder from RAM
			ramNeeded := max - diskAvail
			copyOut(out[diskAvail:], r.buf, r.start, ramNeeded)
		}
		return from, out
	}

	// Entirely in RAM
	ramOffset := int(from - spillEnd)
	start := r.start
	if len(r.buf) > 0 {
		start = (r.start + ramOffset) % len(r.buf)
	}
	copyOut(out, r.buf, start, max)
	return from, out
}

// Snapshot returns the current base offset, a copy of all unacknowledged bytes,
// and the ring's maximum capacity.
func (r *Ring) Snapshot() (base uint64, data []byte, capMax int) {
	if r == nil {
		return 0, nil, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	base = r.base
	capMax = r.capMax
	if r.length > 0 {
		data = make([]byte, r.length)
		if r.spillLen > 0 && r.spill != nil {
			_, _ = r.spill.ReadAt(r.base-r.spillBaseOffset, data[:r.spillLen])
			if r.ramLen > 0 && len(r.buf) > 0 {
				copyOut(data[r.spillLen:], r.buf, r.start, r.ramLen)
			}
		} else if len(r.buf) > 0 {
			copyOut(data, r.buf, r.start, r.length)
		}
	}
	return base, data, capMax
}

// RestoreRing reconstructs a Ring buffer from a previously snapshotted state.
func RestoreRing(base uint64, data []byte, capMax int, budget *Budget) *Ring {
	return RestoreTieredRing(base, data, capMax, budget, RingConfig{})
}

// RestoreTieredRing reconstructs a Ring buffer with custom tiered storage configuration.
func RestoreTieredRing(base uint64, data []byte, capMax int, budget *Budget, cfg RingConfig) *Ring {
	cfg.CapMax = capMax
	cfg.Budget = budget
	r := NewTieredRing(cfg)
	r.base = base
	if len(data) > 0 {
		if !r.noSpill && len(data) > r.l1Cap {
			_ = r.Append(context.Background(), data)
		} else {
			r.buf = make([]byte, len(data))
			copy(r.buf, data)
			r.length = len(data)
			r.ramLen = len(data)
			r.start = 0
			if budget != nil {
				budget.AcquireDirect(int64(len(data)))
				r.budgeted = len(data)
			}
		}
	}
	return r
}

func nextSize(cur, need, capMax int) int {
	if capMax <= 0 {
		capMax = need
	}
	n := cur
	if n == 0 {
		n = 64
		if n > capMax {
			n = capMax
		}
	}
	for n < need && n < capMax {
		n2 := n * 2
		if n2 <= n || n2 > capMax {
			n = capMax
			break
		}
		n = n2
	}
	if n > capMax {
		n = capMax
	}
	if n < need && need <= capMax {
		n = need
	}
	return n
}

func copyIn(buf []byte, start, length int, src []byte) {
	if len(buf) == 0 || len(src) == 0 {
		return
	}
	pos := (start + length) % len(buf)
	n := len(src)
	right := len(buf) - pos
	if n <= right {
		copy(buf[pos:pos+n], src)
		return
	}
	copy(buf[pos:], src[:right])
	copy(buf[:n-right], src[right:])
}

func copyOut(dst, buf []byte, start, n int) {
	if n == 0 || len(buf) == 0 {
		return
	}
	right := len(buf) - start
	if n <= right {
		copy(dst, buf[start:start+n])
		return
	}
	copy(dst, buf[start:])
	copy(dst[right:], buf[:n-right])
}
