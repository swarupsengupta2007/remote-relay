package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"testing"
)

func TestSpillFile_WriteRead(t *testing.T) {
	dir := t.TempDir()
	sf, err := newSpillFile(dir)
	if err != nil {
		t.Fatalf("newSpillFile: %v", err)
	}
	defer sf.Close()

	// Verify file is unlinked from filesystem
	if _, err := os.Stat(sf.file.Name()); !os.IsNotExist(err) {
		t.Fatalf("expected spill file %s to be unlinked, got err: %v", sf.file.Name(), err)
	}

	// Generate 3 blocks of data (2 full 64 KiB blocks + 1 partial 10 KiB block)
	data1 := make([]byte, spillBlockSize)
	_, _ = rand.Read(data1)
	data2 := make([]byte, spillBlockSize)
	_, _ = rand.Read(data2)
	data3 := make([]byte, 10*1024)
	_, _ = rand.Read(data3)

	if err := sf.WriteBlock(0, data1); err != nil {
		t.Fatalf("WriteBlock 0: %v", err)
	}
	if err := sf.WriteBlock(1, data2); err != nil {
		t.Fatalf("WriteBlock 1: %v", err)
	}
	if err := sf.WriteBlock(2, data3); err != nil {
		t.Fatalf("WriteBlock 2: %v", err)
	}

	all := append(append(append([]byte{}, data1...), data2...), data3...)

	// Read in chunks of 15 KiB spanning across block boundaries
	buf := make([]byte, 15*1024)
	offset := uint64(0)
	var recovered []byte

	for offset < uint64(len(all)) {
		needed := len(buf)
		if offset+uint64(needed) > uint64(len(all)) {
			needed = int(uint64(len(all)) - offset)
		}
		n, err := sf.ReadAt(offset, buf[:needed])
		if err != nil {
			t.Fatalf("ReadAt offset %d: %v", offset, err)
		}
		if n != needed {
			t.Fatalf("ReadAt returned %d bytes, want %d", n, needed)
		}
		recovered = append(recovered, buf[:n]...)
		offset += uint64(n)
	}

	if !bytes.Equal(recovered, all) {
		t.Fatalf("recovered data mismatch: got %d bytes, want %d", len(recovered), len(all))
	}
}

func TestSpillFile_HolePunchAndReset(t *testing.T) {
	dir := t.TempDir()
	sf, err := newSpillFile(dir)
	if err != nil {
		t.Fatalf("newSpillFile: %v", err)
	}
	defer sf.Close()

	// Write 4 blocks
	for b := uint64(0); b < 4; b++ {
		blk := make([]byte, spillBlockSize)
		_, _ = rand.Read(blk)
		if err := sf.WriteBlock(b, blk); err != nil {
			t.Fatalf("WriteBlock %d: %v", b, err)
		}
	}

	// Punch hole for blocks 0 and 1
	sf.PunchHole(2 * spillBlockSize)
	if sf.punchedBlock != 2 {
		t.Fatalf("punchedBlock = %d, want 2", sf.punchedBlock)
	}

	// Reset truncates file
	sf.Reset()
	if sf.nextBlock != 0 || sf.punchedBlock != 0 {
		t.Fatalf("after Reset: nextBlock=%d, punchedBlock=%d", sf.nextBlock, sf.punchedBlock)
	}
}

func TestTieredRing_BasicSpillAndResume(t *testing.T) {
	// 5 MiB cap, 128 KiB L1 RAM limit
	r := NewTieredRing(RingConfig{
		CapMax: 5 * 1024 * 1024,
		L1Cap:  128 * 1024,
	})
	defer r.Release()

	totalBytes := 1024 * 1024 // 1 MiB
	payload := make([]byte, totalBytes)
	_, _ = rand.Read(payload)

	ctx := context.Background()
	if err := r.Append(ctx, payload); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if r.Len() != totalBytes {
		t.Fatalf("r.Len() = %d, want %d", r.Len(), totalBytes)
	}

	// RAM occupancy must be capped at L1 limit + 1 block
	if r.RAMLen() > 128*1024+spillBlockSize {
		t.Fatalf("r.RAMLen() = %d exceeds L1Cap + block (%d)", r.RAMLen(), 128*1024+spillBlockSize)
	}

	// Most data must have spilled to L2 disk
	if r.SpillLen() < 700*1024 {
		t.Fatalf("expected r.SpillLen() >= 700 KiB, got %d", r.SpillLen())
	}

	// Simulate resumption: sequential reads of 32 KiB
	chunkSize := 32 * 1024
	from := r.Base()
	var recovered []byte

	for from < r.End() {
		_, chunk := r.Slice(from, chunkSize)
		if len(chunk) == 0 {
			t.Fatalf("empty slice at offset %d", from)
		}
		recovered = append(recovered, chunk...)
		from += uint64(len(chunk))
	}

	if !bytes.Equal(recovered, payload) {
		t.Fatalf("payload mismatch after tiered slice: got %d bytes, want %d", len(recovered), len(payload))
	}

	// Advance to end
	r.AdvanceTo(r.End())
	if r.Len() != 0 || r.SpillLen() != 0 || r.RAMLen() != 0 {
		t.Fatalf("after AdvanceTo end: len=%d, spillLen=%d, ramLen=%d", r.Len(), r.SpillLen(), r.RAMLen())
	}
}

func TestTieredRing_BudgetRelief(t *testing.T) {
	// Tight global budget: only 256 KiB
	budget := NewBudget(256 * 1024)

	// Ring with 4 MiB capacity, 128 KiB L1 cap
	r := NewTieredRing(RingConfig{
		CapMax: 4 * 1024 * 1024,
		L1Cap:  128 * 1024,
		Budget: budget,
	})
	defer r.Release()

	// Append 2 MiB through the ring (8x the global RAM budget!)
	payload := make([]byte, 2*1024*1024)
	_, _ = rand.Read(payload)

	ctx := context.Background()
	if err := r.Append(ctx, payload); err != nil {
		t.Fatalf("Append 2 MiB through 256 KiB budget: %v", err)
	}

	// Budget used in RAM must never exceed the 256 KiB ceiling
	used := budget.Used()
	if used > 256*1024 {
		t.Fatalf("budget.Used() = %d exceeded cap 256 KiB", used)
	}

	// Slice and verify all 2 MiB
	_, all := r.Slice(r.Base(), len(payload))
	if !bytes.Equal(all, payload) {
		t.Fatalf("data mismatch on budget-relieved ring")
	}

	// AdvanceTo should free all budget
	r.AdvanceTo(r.End())
	if budget.Used() != 0 {
		t.Fatalf("after AdvanceTo end: budget.Used() = %d, want 0", budget.Used())
	}
}

func TestTieredRing_SliceStraddle(t *testing.T) {
	// Ring with 64 KiB L1 cap
	r := NewTieredRing(RingConfig{
		CapMax: 1024 * 1024,
		L1Cap:  64 * 1024,
	})
	defer r.Release()

	payload := make([]byte, 256*1024)
	_, _ = rand.Read(payload)

	ctx := context.Background()
	if err := r.Append(ctx, payload); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if r.SpillLen() == 0 {
		t.Fatal("expected data to have spilled to disk")
	}

	// Request slice spanning across the exact L2 disk / L1 RAM boundary
	spillEnd := r.Base() + uint64(r.SpillLen())
	straddleFrom := spillEnd - 1024
	straddleLen := 2048 // 1024 bytes from disk + 1024 bytes from RAM

	_, slice := r.Slice(straddleFrom, straddleLen)
	if len(slice) != straddleLen {
		t.Fatalf("Slice len = %d, want %d", len(slice), straddleLen)
	}

	relOffset := int(straddleFrom - r.Base())
	expected := payload[relOffset : relOffset+straddleLen]
	if !bytes.Equal(slice, expected) {
		t.Fatal("straddle slice content mismatch")
	}
}

func TestTieredRing_SnapshotRestoreWithSpill(t *testing.T) {
	r := NewTieredRing(RingConfig{
		CapMax: 2 * 1024 * 1024,
		L1Cap:  128 * 1024,
	})
	defer r.Release()

	payload := make([]byte, 512*1024)
	_, _ = rand.Read(payload)

	ctx := context.Background()
	if err := r.Append(ctx, payload); err != nil {
		t.Fatalf("Append: %v", err)
	}

	base, snapData, capMax := r.Snapshot()
	if !bytes.Equal(snapData, payload) {
		t.Fatal("Snapshot data mismatch with original payload")
	}

	restored := RestoreTieredRing(base, snapData, capMax, nil, RingConfig{
		L1Cap: 128 * 1024,
	})
	defer restored.Release()

	if restored.Len() != len(payload) {
		t.Fatalf("restored.Len() = %d, want %d", restored.Len(), len(payload))
	}

	_, readAll := restored.Slice(restored.Base(), len(payload))
	if !bytes.Equal(readAll, payload) {
		t.Fatal("restored ring Slice data mismatch")
	}
}
