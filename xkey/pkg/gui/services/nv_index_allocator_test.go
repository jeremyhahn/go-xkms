// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestNVIndexAllocator_NewWithEmptyDir(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alloc.CurrentIndex() != NVIndexStart {
		t.Errorf("expected %#x, got %#x", NVIndexStart, alloc.CurrentIndex())
	}
}

func TestNVIndexAllocator_NewWithNonExistentDir(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "nonexistent-subdir")
	alloc, err := NewNVIndexAllocator(subDir)
	if err != nil {
		t.Fatalf("unexpected error for missing dir: %v", err)
	}
	if alloc.CurrentIndex() != NVIndexStart {
		t.Errorf("expected %#x, got %#x", NVIndexStart, alloc.CurrentIndex())
	}
}

func TestNVIndexAllocator_NextIndex(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	idx1, err := alloc.NextIndex()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx1 != NVIndexStart {
		t.Errorf("first index: expected %#x, got %#x", NVIndexStart, idx1)
	}

	idx2, err := alloc.NextIndex()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx2 != NVIndexStart+1 {
		t.Errorf("second index: expected %#x, got %#x", NVIndexStart+1, idx2)
	}
}

func TestNVIndexAllocator_NextIndex_Sequential(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := uint32(0); i < 100; i++ {
		idx, err := alloc.NextIndex()
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		expected := NVIndexStart + i
		if idx != expected {
			t.Fatalf("allocation %d: expected %#x, got %#x", i, expected, idx)
		}
	}
}

func TestNVIndexAllocator_NextIndex_Exhausted(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Set counter past end of range.
	alloc.counter.Store(NVIndexEnd + 1)

	_, err = alloc.NextIndex()
	if err != ErrNVIndexRangeExhausted {
		t.Errorf("expected ErrNVIndexRangeExhausted, got %v", err)
	}
}

func TestNVIndexAllocator_NextIndex_LastValid(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Set counter to the last valid index.
	alloc.counter.Store(NVIndexEnd)

	idx, err := alloc.NextIndex()
	if err != nil {
		t.Fatalf("unexpected error allocating last index: %v", err)
	}
	if idx != NVIndexEnd {
		t.Errorf("expected %#x, got %#x", NVIndexEnd, idx)
	}

	// Next allocation should fail.
	_, err = alloc.NextIndex()
	if err != ErrNVIndexRangeExhausted {
		t.Errorf("expected ErrNVIndexRangeExhausted after last index, got %v", err)
	}
}

func TestNVIndexAllocator_CurrentIndex(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CurrentIndex should not advance the counter.
	before := alloc.CurrentIndex()
	after := alloc.CurrentIndex()
	if before != after {
		t.Errorf("CurrentIndex advanced counter: %#x -> %#x", before, after)
	}
	if before != NVIndexStart {
		t.Errorf("expected %#x, got %#x", NVIndexStart, before)
	}
}

func TestNVIndexAllocator_CurrentIndex_AfterAllocation(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = alloc.NextIndex()
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}

	current := alloc.CurrentIndex()
	if current != NVIndexStart+1 {
		t.Errorf("expected %#x after one allocation, got %#x", NVIndexStart+1, current)
	}
}

func TestNVIndexAllocator_SetIndex(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetIndex(NVIndexStart + 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if alloc.CurrentIndex() != NVIndexStart+50 {
		t.Errorf("expected %#x, got %#x", NVIndexStart+50, alloc.CurrentIndex())
	}
}

func TestNVIndexAllocator_SetIndex_AtEnd(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Setting to end+1 is valid (means range is exhausted).
	err = alloc.SetIndex(NVIndexEnd + 1)
	if err != nil {
		t.Fatalf("unexpected error setting to end+1: %v", err)
	}
}

func TestNVIndexAllocator_SetIndex_OutOfRange_Below(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetIndex(0x00000001)
	if err != ErrNVIndexOutOfRange {
		t.Errorf("expected ErrNVIndexOutOfRange, got %v", err)
	}
}

func TestNVIndexAllocator_SetIndex_OutOfRange_Above(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetIndex(NVIndexEnd + 2)
	if err != ErrNVIndexOutOfRange {
		t.Errorf("expected ErrNVIndexOutOfRange for above-range value, got %v", err)
	}
}

func TestNVIndexAllocator_SetIndex_ThenAllocate(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetIndex(NVIndexStart + 100)
	if err != nil {
		t.Fatalf("set index: %v", err)
	}

	idx, err := alloc.NextIndex()
	if err != nil {
		t.Fatalf("next index: %v", err)
	}
	if idx != NVIndexStart+100 {
		t.Errorf("expected %#x, got %#x", NVIndexStart+100, idx)
	}
}

func TestNVIndexAllocator_Persistence(t *testing.T) {
	dir := t.TempDir()

	// Create allocator and allocate indices.
	alloc1, err := NewNVIndexAllocator(dir)
	if err != nil {
		t.Fatalf("create allocator: %v", err)
	}
	if _, err := alloc1.NextIndex(); err != nil {
		t.Fatalf("alloc 1: %v", err)
	}
	if _, err := alloc1.NextIndex(); err != nil {
		t.Fatalf("alloc 2: %v", err)
	}
	if _, err := alloc1.NextIndex(); err != nil {
		t.Fatalf("alloc 3: %v", err)
	}

	// Create new allocator from same dir -- should load persisted state.
	alloc2, err := NewNVIndexAllocator(dir)
	if err != nil {
		t.Fatalf("reload allocator: %v", err)
	}

	current := alloc2.CurrentIndex()
	if current != NVIndexStart+3 {
		t.Errorf("expected %#x after reload, got %#x", NVIndexStart+3, current)
	}
}

func TestNVIndexAllocator_PersistenceFileContent(t *testing.T) {
	dir := t.TempDir()

	alloc, err := NewNVIndexAllocator(dir)
	if err != nil {
		t.Fatalf("create allocator: %v", err)
	}
	if _, err := alloc.NextIndex(); err != nil {
		t.Fatalf("alloc: %v", err)
	}

	// Verify the file exists and contains valid JSON.
	data, err := os.ReadFile(filepath.Join(dir, nvIndexCounterFile))
	if err != nil {
		t.Fatalf("read counter file: %v", err)
	}
	var state nvIndexCounterState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal counter file: %v", err)
	}
	if state.NextIndex != NVIndexStart+1 {
		t.Errorf("persisted index: expected %#x, got %#x", NVIndexStart+1, state.NextIndex)
	}
}

func TestNVIndexAllocator_SetIndex_WithPersistence(t *testing.T) {
	dir := t.TempDir()

	alloc, err := NewNVIndexAllocator(dir)
	if err != nil {
		t.Fatalf("create allocator: %v", err)
	}

	err = alloc.SetIndex(NVIndexStart + 10)
	if err != nil {
		t.Fatalf("set index: %v", err)
	}

	// Reload and verify.
	alloc2, err := NewNVIndexAllocator(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if alloc2.CurrentIndex() != NVIndexStart+10 {
		t.Errorf("expected %#x, got %#x", NVIndexStart+10, alloc2.CurrentIndex())
	}
}

func TestNVIndexAllocator_CorruptedStateFile(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, nvIndexCounterFile), []byte("not json"), 0600)
	if err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, err = NewNVIndexAllocator(dir)
	if err == nil {
		t.Error("expected error for corrupted state file")
	}
}

func TestNVIndexAllocator_LoadCounter_IgnoresLowValues(t *testing.T) {
	dir := t.TempDir()

	// Write a state file with a value below the valid start range.
	state := nvIndexCounterState{
		NextIndex: 0x00000001,
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	err = os.WriteFile(filepath.Join(dir, nvIndexCounterFile), data, 0600)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	alloc, err := NewNVIndexAllocator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Value below start range should be ignored, counter stays at default.
	if alloc.CurrentIndex() != NVIndexStart {
		t.Errorf("expected default %#x, got %#x", NVIndexStart, alloc.CurrentIndex())
	}
}

func TestNVIndexAllocator_SyncFromTPM(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	usedIndices := []uint32{
		NVIndexStart + 5,
		NVIndexStart + 10,
		NVIndexStart + 3,
	}

	err = alloc.SyncFromTPM(usedIndices)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Counter should be set past the highest used index.
	expected := NVIndexStart + 11
	if alloc.CurrentIndex() != expected {
		t.Errorf("expected %#x, got %#x", expected, alloc.CurrentIndex())
	}
}

func TestNVIndexAllocator_SyncFromTPM_Empty(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SyncFromTPM(nil)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// With no used indices, counter stays at start.
	if alloc.CurrentIndex() != NVIndexStart {
		t.Errorf("expected %#x, got %#x", NVIndexStart, alloc.CurrentIndex())
	}
}

func TestNVIndexAllocator_SyncFromTPM_OutOfRangeIgnored(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Include indices outside the valid range; they should be ignored.
	usedIndices := []uint32{
		0x00000001,       // Below range.
		0xFFFFFFFF,       // Above range.
		NVIndexStart - 1, // Just below range.
		NVIndexEnd + 1,   // Just above range.
		NVIndexStart + 5, // Valid.
	}

	err = alloc.SyncFromTPM(usedIndices)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	expected := NVIndexStart + 6
	if alloc.CurrentIndex() != expected {
		t.Errorf("expected %#x, got %#x", expected, alloc.CurrentIndex())
	}
}

func TestNVIndexAllocator_SyncFromTPM_WithPersistence(t *testing.T) {
	dir := t.TempDir()

	alloc, err := NewNVIndexAllocator(dir)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	usedIndices := []uint32{NVIndexStart + 20}
	err = alloc.SyncFromTPM(usedIndices)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Reload and verify.
	alloc2, err := NewNVIndexAllocator(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	expected := NVIndexStart + 21
	if alloc2.CurrentIndex() != expected {
		t.Errorf("expected %#x after reload, got %#x", expected, alloc2.CurrentIndex())
	}
}

func TestNVIndexAllocator_SyncFromTPM_AtEnd(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Sync with the last valid index used.
	usedIndices := []uint32{NVIndexEnd}
	err = alloc.SyncFromTPM(usedIndices)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Counter should be NVIndexEnd + 1, which means exhausted.
	if alloc.CurrentIndex() != NVIndexEnd+1 {
		t.Errorf("expected %#x, got %#x", NVIndexEnd+1, alloc.CurrentIndex())
	}

	// Next allocation should fail.
	_, err = alloc.NextIndex()
	if err != ErrNVIndexRangeExhausted {
		t.Errorf("expected ErrNVIndexRangeExhausted, got %v", err)
	}
}

func TestNVIndexAllocator_Concurrent(t *testing.T) {
	alloc, err := NewNVIndexAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	const goroutines = 100
	results := make(chan uint32, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			idx, err := alloc.NextIndex()
			if err != nil {
				t.Errorf("concurrent alloc: %v", err)
				return
			}
			results <- idx
		}()
	}
	wg.Wait()
	close(results)

	// All indices must be unique.
	seen := make(map[uint32]struct{}, goroutines)
	for idx := range results {
		if _, exists := seen[idx]; exists {
			t.Errorf("duplicate index %#x", idx)
		}
		seen[idx] = struct{}{}
	}
	if len(seen) != goroutines {
		t.Errorf("expected %d unique indices, got %d", goroutines, len(seen))
	}
}

func TestNVIndexAllocator_Constants(t *testing.T) {
	// Verify NV index constants match expected TCG spec values.
	if NVIndexStart != 0x01800100 {
		t.Errorf("NVIndexStart: expected 0x01800100, got %#x", NVIndexStart)
	}
	if NVIndexEnd != 0x01BFFFFF {
		t.Errorf("NVIndexEnd: expected 0x01BFFFFF, got %#x", NVIndexEnd)
	}
	if NVIndexStart >= NVIndexEnd {
		t.Errorf("NVIndexStart (%#x) must be less than NVIndexEnd (%#x)", NVIndexStart, NVIndexEnd)
	}
}
