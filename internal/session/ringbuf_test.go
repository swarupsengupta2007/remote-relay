package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRingAppendSliceAdvance(t *testing.T) {
	r := NewRing(64, nil)
	if err := r.TryAppend([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 5 || r.Base() != 0 || r.End() != 5 {
		t.Fatalf("len=%d base=%d end=%d", r.Len(), r.Base(), r.End())
	}
	off, data := r.Slice(0, 64)
	if off != 0 || string(data) != "hello" {
		t.Fatalf("slice %d %q", off, data)
	}
	r.AdvanceTo(2)
	if r.Base() != 2 || r.Len() != 3 {
		t.Fatalf("after advance base=%d len=%d", r.Base(), r.Len())
	}
	off, data = r.Slice(0, 64)
	if off != 2 || string(data) != "llo" {
		t.Fatalf("slice after advance %d %q", off, data)
	}
	off, data = r.Slice(5, 8)
	if off != 5 || len(data) != 0 {
		t.Fatalf("slice at end %d %q", off, data)
	}
}

func TestRingGrowthToCapAndOverflow(t *testing.T) {
	r := NewRing(16, nil)
	if err := r.TryAppend([]byte("abcdefghijklmnop")); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 16 {
		t.Fatalf("len=%d", r.Len())
	}
	if err := r.TryAppend([]byte("x")); !errors.Is(err, ErrOverflow) {
		t.Fatalf("got %v want overflow", err)
	}
	r.AdvanceTo(4)
	if err := r.TryAppend([]byte("wxyz")); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 16 {
		t.Fatalf("len after refill %d", r.Len())
	}
	if err := r.TryAppend([]byte("!")); !errors.Is(err, ErrOverflow) {
		t.Fatalf("got %v want overflow", err)
	}
}

func TestRingWraparoundOffsets(t *testing.T) {
	r := NewRing(8, nil)
	if err := r.TryAppend([]byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	r.AdvanceTo(5) // leftover "fgh"
	if err := r.TryAppend([]byte("ijklm")); err != nil {
		t.Fatal(err)
	}
	if r.Base() != 5 || r.End() != 13 || r.Len() != 8 {
		t.Fatalf("base=%d end=%d len=%d", r.Base(), r.End(), r.Len())
	}
	off, data := r.Slice(5, 64)
	if off != 5 || string(data) != "fghijklm" {
		t.Fatalf("wrapped slice %d %q", off, data)
	}
	off, data = r.Slice(8, 3)
	if off != 8 || string(data) != "ijk" {
		t.Fatalf("mid wrap %d %q", off, data)
	}
	r.AdvanceTo(13)
	if r.Len() != 0 || r.Base() != 13 {
		t.Fatalf("drained base=%d len=%d", r.Base(), r.Len())
	}
}

func TestRingAppendWaitAndClose(t *testing.T) {
	r := NewRing(4, nil)
	if err := r.TryAppend([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- r.Append(ctx, []byte("ef"))
	}()
	time.Sleep(20 * time.Millisecond)
	r.AdvanceTo(2)
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("append did not unblock")
	}
	off, data := r.Slice(2, 64)
	if off != 2 || string(data) != "cdef" {
		t.Fatalf("got %d %q", off, data)
	}

	r.Close()
	if err := r.Append(context.Background(), []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v want closed", err)
	}
}

func TestRingBudgetCapsGrowth(t *testing.T) {
	b := NewBudget(8)
	r := NewRing(64, b)
	if err := r.TryAppend([]byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	if b.Remaining() != 0 {
		t.Fatalf("remaining=%d", b.Remaining())
	}
	if err := r.TryAppend([]byte("i")); !errors.Is(err, ErrOverflow) {
		t.Fatalf("got %v", err)
	}
	r.AdvanceTo(8)
	if b.Used() != 0 {
		t.Fatalf("used after advance %d", b.Used())
	}
	if err := r.TryAppend([]byte("ijkl")); err != nil {
		t.Fatal(err)
	}
	if b.Used() != 4 {
		t.Fatalf("used=%d", b.Used())
	}
	r.Release()
	if b.Used() != 0 {
		t.Fatalf("used after release %d", b.Used())
	}
}

func TestRingConcurrentAppendAdvance(t *testing.T) {
	r := NewRing(1024, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const n = 10_000
	payload := bytes.Repeat([]byte("x"), n)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := r.Append(ctx, payload); err != nil {
			t.Errorf("append: %v", err)
		}
		r.Close()
	}()
	go func() {
		defer wg.Done()
		var got int
		for got < n {
			_, data := r.Slice(uint64(got), 100)
			if len(data) == 0 {
				time.Sleep(time.Millisecond)
				continue
			}
			r.AdvanceTo(uint64(got + len(data)))
			got += len(data)
		}
	}()
	wg.Wait()
	if r.Base() != uint64(n) {
		t.Fatalf("base=%d", r.Base())
	}
}
