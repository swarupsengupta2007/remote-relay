package session

import "sync"

// Budget is a process-wide ceiling on live sendLog occupancy.
type Budget struct {
	mu   sync.Mutex
	cap  int64
	used int64
}

func NewBudget(cap int64) *Budget {
	if cap < 0 {
		cap = 0
	}
	return &Budget{cap: cap}
}

func (b *Budget) Cap() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cap
}

func (b *Budget) Used() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

func (b *Budget) Remaining() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	rem := b.cap - b.used
	if rem < 0 {
		return 0
	}
	return rem
}

func (b *Budget) Exhausted() bool {
	return b.Remaining() <= 0
}

func (b *Budget) TryAcquire(n int64) int64 {
	if b == nil || n <= 0 {
		return n
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	rem := b.cap - b.used
	if rem <= 0 {
		return 0
	}
	if n > rem {
		n = rem
	}
	b.used += n
	return n
}

func (b *Budget) Release(n int64) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
}
