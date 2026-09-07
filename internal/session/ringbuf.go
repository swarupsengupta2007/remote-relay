package session

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrOverflow = errors.New("ring: overflow")
	ErrClosed   = errors.New("ring: closed")
)

// Ring is a growable circular byte buffer addressed by absolute stream offsets.
// One goroutine appends; another calls AdvanceTo. The mutex/cond serialise both.
type Ring struct {
	mu        sync.Mutex
	cond      *sync.Cond
	buf       []byte
	start     int
	length    int
	capMax    int
	soft      int // 0 = no soft cap (use capMax)
	base      uint64
	closed    bool
	budget    *Budget
	allocated int
	notify    chan struct{}
}

func NewRing(cap int, budget *Budget) *Ring {
	if cap <= 0 {
		cap = 1
	}
	r := &Ring{
		capMax: cap,
		budget: budget,
		notify: make(chan struct{}, 1),
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
	r.cond.Broadcast()
	r.pokeLocked()
}

func (r *Ring) SetSoftLimit(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.soft = n
	r.cond.Broadcast()
	r.pokeLocked()
}

func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.length
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
	defer r.mu.Unlock()
	r.closed = true
	r.cond.Broadcast()
	r.pokeLocked()
}

func (r *Ring) Release() {
	r.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.budget != nil && r.allocated > 0 {
		r.budget.Release(int64(r.allocated))
		r.allocated = 0
	}
	r.buf = nil
	r.length = 0
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
		if r.closed {
			return 0, ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		lim := r.limitLocked()
		space := lim - r.length
		if space > 0 {
			if !wait && len(p) > space {
				return 0, ErrOverflow
			}
			n := len(p)
			if n > space {
				n = space
			}
			if !r.ensureLocked(r.length + n) {
				if !wait {
					return 0, ErrOverflow
				}
				if r.length >= len(r.buf) && len(r.buf) > 0 {
					r.cond.Wait()
					continue
				}
				room := len(r.buf) - r.length
				if room <= 0 {
					r.cond.Wait()
					continue
				}
				if n > room {
					n = room
				}
			}
			copyIn(r.buf, r.start, r.length, p[:n])
			r.length += n
			r.cond.Broadcast()
			r.pokeLocked()
			return n, nil
		}
		if !wait {
			return 0, ErrOverflow
		}
		r.cond.Wait()
	}
}

func (r *Ring) ensureLocked(need int) bool {
	if need <= len(r.buf) {
		return true
	}
	if need > r.capMax {
		need = r.capMax
	}
	newSize := nextSize(len(r.buf), need, r.capMax)
	if newSize <= len(r.buf) {
		return false
	}
	delta := newSize - len(r.buf)
	if r.budget != nil {
		got := r.budget.TryAcquire(int64(delta))
		if got <= 0 {
			return false
		}
		if int(got) < delta {
			newSize = len(r.buf) + int(got)
			if newSize <= len(r.buf) {
				r.budget.Release(got)
				return false
			}
		}
	}
	nb := make([]byte, newSize)
	if r.length > 0 && len(r.buf) > 0 {
		copyOut(nb[:r.length], r.buf, r.start, r.length)
	}
	r.buf = nb
	r.start = 0
	r.allocated = newSize
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
	drop := int(ack - r.base)
	if drop <= 0 {
		return
	}
	if len(r.buf) > 0 {
		r.start = (r.start + drop) % len(r.buf)
	}
	r.length -= drop
	r.base = ack
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
	off := int(from - r.base)
	start := r.start
	if len(r.buf) > 0 {
		start = (r.start + off) % len(r.buf)
	}
	copyOut(out, r.buf, start, max)
	return from, out
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
