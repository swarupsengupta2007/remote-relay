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

func TestBudgetReleaseWakesOtherRing(t *testing.T) {
	b := NewBudget(8)
	a := NewRing(8, b)
	c := NewRing(8, b)
	if err := a.TryAppend([]byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- c.Append(ctx, []byte("xyz"))
	}()
	time.Sleep(30 * time.Millisecond)
	select {
	case err := <-errc:
		t.Fatalf("append should block on budget, got %v", err)
	default:
	}
	if c.Len() != 0 {
		t.Fatalf("blocked ring grew to %d", c.Len())
	}
	a.AdvanceTo(8)
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("budget release did not wake the other ring")
	}
	if c.Len() != 3 {
		t.Fatalf("len=%d", c.Len())
	}
}

func TestBudgetWaitUnblocksOnClose(t *testing.T) {
	b := NewBudget(4)
	a := NewRing(4, b)
	c := NewRing(4, b)
	if err := a.TryAppend([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- c.Append(ctx, []byte("x"))
	}()
	time.Sleep(20 * time.Millisecond)
	c.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("got %v want closed", err)
		}
	case <-ctx.Done():
		t.Fatal("close did not wake budget waiter")
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

func TestRingSnapshotRestore(t *testing.T) {
	budget := NewBudget(1024)
	r := NewRing(512, budget)
	ctx := context.Background()

	// Append initial data
	if err := r.Append(ctx, []byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	// Advance past first 4 bytes
	r.AdvanceTo(4)

	// Append more data
	if err := r.Append(ctx, []byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}

	// Snapshot
	base, data, capMax := r.Snapshot()
	if base != 4 {
		t.Fatalf("expected base 4, got %d", base)
	}
	expectedData := []byte("456789abcdefghij")
	if !bytes.Equal(data, expectedData) {
		t.Fatalf("expected %q, got %q", expectedData, data)
	}
	if capMax != 512 {
		t.Fatalf("expected capMax 512, got %d", capMax)
	}

	// Restore into a new ring
	restoredBudget := NewBudget(1024)
	r2 := RestoreRing(base, data, capMax, restoredBudget)

	if r2.Base() != 4 {
		t.Fatalf("r2 base: got %d want 4", r2.Base())
	}
	if r2.End() != 4+uint64(len(expectedData)) {
		t.Fatalf("r2 end: got %d want %d", r2.End(), 4+len(expectedData))
	}
	if r2.Len() != len(expectedData) {
		t.Fatalf("r2 len: got %d want %d", r2.Len(), len(expectedData))
	}
	if restoredBudget.Used() != int64(len(expectedData)) {
		t.Fatalf("restored budget used: got %d want %d", restoredBudget.Used(), len(expectedData))
	}

	// Verify slicing from restored ring
	_, sliced := r2.Slice(4, len(expectedData))
	if !bytes.Equal(sliced, expectedData) {
		t.Fatalf("r2 slice: got %q want %q", sliced, expectedData)
	}

	// Verify advancing on restored ring releases budget
	r2.AdvanceTo(10)
	if r2.Base() != 10 {
		t.Fatalf("r2 base after advance: got %d want 10", r2.Base())
	}
	if restoredBudget.Used() != int64(len(expectedData)-6) {
		t.Fatalf("budget after advance: got %d want %d", restoredBudget.Used(), len(expectedData)-6)
	}
}
