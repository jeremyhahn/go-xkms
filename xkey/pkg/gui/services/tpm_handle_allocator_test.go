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

func TestTPMHandleAllocator_NewWithEmptyDir(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tc := range []struct {
		hierarchy string
		expected  uint32
	}{
		{HierarchyOwner, OwnerHandleStart},
		{HierarchyEndorsement, EndorsementHandleStart},
		{HierarchyPlatform, PlatformHandleStart},
	} {
		h, err := alloc.CurrentHandle(tc.hierarchy)
		if err != nil {
			t.Fatalf("CurrentHandle(%s): %v", tc.hierarchy, err)
		}
		if h != tc.expected {
			t.Errorf("%s: expected %#x, got %#x", tc.hierarchy, tc.expected, h)
		}
	}
}

func TestTPMHandleAllocator_NewWithNonExistentDir(t *testing.T) {
	// Non-existent directory file is treated as os.ErrNotExist and silently ignored.
	dir := t.TempDir()
	subDir := filepath.Join(dir, "nonexistent-subdir")
	alloc, err := NewTPMHandleAllocator(subDir)
	if err != nil {
		t.Fatalf("unexpected error for missing dir: %v", err)
	}
	h, err := alloc.CurrentHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != OwnerHandleStart {
		t.Errorf("expected %#x, got %#x", OwnerHandleStart, h)
	}
}

func TestTPMHandleAllocator_NextHandle_Owner(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h1, err := alloc.NextHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 != OwnerHandleStart {
		t.Errorf("first handle: expected %#x, got %#x", OwnerHandleStart, h1)
	}

	h2, err := alloc.NextHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h2 != OwnerHandleStart+1 {
		t.Errorf("second handle: expected %#x, got %#x", OwnerHandleStart+1, h2)
	}
}

func TestTPMHandleAllocator_NextHandle_Endorsement(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h, err := alloc.NextHandle(HierarchyEndorsement)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != EndorsementHandleStart {
		t.Errorf("expected %#x, got %#x", EndorsementHandleStart, h)
	}
}

func TestTPMHandleAllocator_NextHandle_Platform(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h, err := alloc.NextHandle(HierarchyPlatform)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != PlatformHandleStart {
		t.Errorf("expected %#x, got %#x", PlatformHandleStart, h)
	}
}

func TestTPMHandleAllocator_NextHandle_InvalidHierarchy(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = alloc.NextHandle("invalid")
	if err != ErrTPMInvalidHierarchy {
		t.Errorf("expected ErrTPMInvalidHierarchy, got %v", err)
	}
}

func TestTPMHandleAllocator_NextHandle_NullHierarchyInvalid(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Null hierarchy has no persistent handle range.
	_, err = alloc.NextHandle(HierarchyNull)
	if err != ErrTPMInvalidHierarchy {
		t.Errorf("expected ErrTPMInvalidHierarchy for null hierarchy, got %v", err)
	}
}

func TestTPMHandleAllocator_NextHandle_RangeExhausted(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Set counter past end of range.
	alloc.counters[HierarchyEndorsement].Store(EndorsementHandleEnd + 1)

	_, err = alloc.NextHandle(HierarchyEndorsement)
	if err != ErrTPMHandleRangeExhausted {
		t.Errorf("expected ErrTPMHandleRangeExhausted, got %v", err)
	}
}

func TestTPMHandleAllocator_NextHandle_LastValidHandle(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Set counter to the last valid handle.
	alloc.counters[HierarchyEndorsement].Store(EndorsementHandleEnd)

	h, err := alloc.NextHandle(HierarchyEndorsement)
	if err != nil {
		t.Fatalf("unexpected error allocating last handle: %v", err)
	}
	if h != EndorsementHandleEnd {
		t.Errorf("expected %#x, got %#x", EndorsementHandleEnd, h)
	}

	// Next allocation should fail.
	_, err = alloc.NextHandle(HierarchyEndorsement)
	if err != ErrTPMHandleRangeExhausted {
		t.Errorf("expected ErrTPMHandleRangeExhausted after last handle, got %v", err)
	}
}

func TestTPMHandleAllocator_Persistence(t *testing.T) {
	dir := t.TempDir()

	// Create allocator and allocate handles.
	alloc1, err := NewTPMHandleAllocator(dir)
	if err != nil {
		t.Fatalf("create allocator: %v", err)
	}
	if _, err := alloc1.NextHandle(HierarchyOwner); err != nil {
		t.Fatalf("owner alloc 1: %v", err)
	}
	if _, err := alloc1.NextHandle(HierarchyOwner); err != nil {
		t.Fatalf("owner alloc 2: %v", err)
	}
	if _, err := alloc1.NextHandle(HierarchyEndorsement); err != nil {
		t.Fatalf("endorsement alloc: %v", err)
	}

	// Create new allocator from same dir -- should load persisted state.
	alloc2, err := NewTPMHandleAllocator(dir)
	if err != nil {
		t.Fatalf("reload allocator: %v", err)
	}

	ownerH, err := alloc2.CurrentHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("current owner: %v", err)
	}
	if ownerH != OwnerHandleStart+2 {
		t.Errorf("owner: expected %#x, got %#x", OwnerHandleStart+2, ownerH)
	}

	endorseH, err := alloc2.CurrentHandle(HierarchyEndorsement)
	if err != nil {
		t.Fatalf("current endorsement: %v", err)
	}
	if endorseH != EndorsementHandleStart+1 {
		t.Errorf("endorsement: expected %#x, got %#x", EndorsementHandleStart+1, endorseH)
	}

	// Platform should still be at start (never allocated).
	platformH, err := alloc2.CurrentHandle(HierarchyPlatform)
	if err != nil {
		t.Fatalf("current platform: %v", err)
	}
	if platformH != PlatformHandleStart {
		t.Errorf("platform: expected %#x, got %#x", PlatformHandleStart, platformH)
	}
}

func TestTPMHandleAllocator_PersistenceFileContent(t *testing.T) {
	dir := t.TempDir()

	alloc, err := NewTPMHandleAllocator(dir)
	if err != nil {
		t.Fatalf("create allocator: %v", err)
	}
	if _, err := alloc.NextHandle(HierarchyOwner); err != nil {
		t.Fatalf("alloc: %v", err)
	}

	// Verify the file exists and contains valid JSON.
	data, err := os.ReadFile(filepath.Join(dir, handleCounterFile))
	if err != nil {
		t.Fatalf("read counter file: %v", err)
	}
	var state handleCounterState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal counter file: %v", err)
	}
	if state.Owner != OwnerHandleStart+1 {
		t.Errorf("persisted owner: expected %#x, got %#x", OwnerHandleStart+1, state.Owner)
	}
}

func TestTPMHandleAllocator_SetHandle(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetHandle(HierarchyOwner, OwnerHandleStart+50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h, err := alloc.CurrentHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != OwnerHandleStart+50 {
		t.Errorf("expected %#x, got %#x", OwnerHandleStart+50, h)
	}
}

func TestTPMHandleAllocator_SetHandle_AtEnd(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Setting to end+1 is valid (means range is exhausted).
	err = alloc.SetHandle(HierarchyEndorsement, EndorsementHandleEnd+1)
	if err != nil {
		t.Fatalf("unexpected error setting to end+1: %v", err)
	}
}

func TestTPMHandleAllocator_SetHandle_OutOfRange_Below(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetHandle(HierarchyOwner, 0x00000001)
	if err != ErrTPMHandleOutOfRange {
		t.Errorf("expected ErrTPMHandleOutOfRange, got %v", err)
	}
}

func TestTPMHandleAllocator_SetHandle_OutOfRange_Above(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetHandle(HierarchyOwner, OwnerHandleEnd+2)
	if err != ErrTPMHandleOutOfRange {
		t.Errorf("expected ErrTPMHandleOutOfRange for above-range value, got %v", err)
	}
}

func TestTPMHandleAllocator_SetHandle_InvalidHierarchy(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetHandle("bogus", 0x81000100)
	if err != ErrTPMInvalidHierarchy {
		t.Errorf("expected ErrTPMInvalidHierarchy, got %v", err)
	}
}

func TestTPMHandleAllocator_SetHandle_WithPersistence(t *testing.T) {
	dir := t.TempDir()

	alloc, err := NewTPMHandleAllocator(dir)
	if err != nil {
		t.Fatalf("create allocator: %v", err)
	}

	err = alloc.SetHandle(HierarchyOwner, OwnerHandleStart+10)
	if err != nil {
		t.Fatalf("set handle: %v", err)
	}

	// Reload and verify.
	alloc2, err := NewTPMHandleAllocator(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	h, err := alloc2.CurrentHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if h != OwnerHandleStart+10 {
		t.Errorf("expected %#x, got %#x", OwnerHandleStart+10, h)
	}
}

func TestTPMHandleAllocator_CurrentHandle_InvalidHierarchy(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = alloc.CurrentHandle("nonexistent")
	if err != ErrTPMInvalidHierarchy {
		t.Errorf("expected ErrTPMInvalidHierarchy, got %v", err)
	}
}

func TestTPMHandleAllocator_CorruptedStateFile(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, handleCounterFile), []byte("not json"), 0600)
	if err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, err = NewTPMHandleAllocator(dir)
	if err == nil {
		t.Error("expected error for corrupted state file")
	}
}

func TestTPMHandleAllocator_SequentialAllocation(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := uint32(0); i < 100; i++ {
		h, err := alloc.NextHandle(HierarchyOwner)
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		expected := OwnerHandleStart + i
		if h != expected {
			t.Fatalf("allocation %d: expected %#x, got %#x", i, expected, h)
		}
	}
}

func TestTPMHandleAllocator_ConcurrentAllocation(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	const goroutines = 50
	results := make(chan uint32, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			h, err := alloc.NextHandle(HierarchyOwner)
			if err != nil {
				t.Errorf("concurrent alloc: %v", err)
				return
			}
			results <- h
		}()
	}
	wg.Wait()
	close(results)

	// All handles must be unique.
	seen := make(map[uint32]struct{}, goroutines)
	for h := range results {
		if _, exists := seen[h]; exists {
			t.Errorf("duplicate handle %#x", h)
		}
		seen[h] = struct{}{}
	}
	if len(seen) != goroutines {
		t.Errorf("expected %d unique handles, got %d", goroutines, len(seen))
	}
}

func TestTPMHandleAllocator_HierarchyConstants(t *testing.T) {
	// Verify constants match expected spec values.
	if HierarchyOwner != "owner" {
		t.Errorf("HierarchyOwner: expected 'owner', got %q", HierarchyOwner)
	}
	if HierarchyEndorsement != "endorsement" {
		t.Errorf("HierarchyEndorsement: expected 'endorsement', got %q", HierarchyEndorsement)
	}
	if HierarchyPlatform != "platform" {
		t.Errorf("HierarchyPlatform: expected 'platform', got %q", HierarchyPlatform)
	}
	if HierarchyNull != "null" {
		t.Errorf("HierarchyNull: expected 'null', got %q", HierarchyNull)
	}
}

func TestTPMHandleAllocator_HandleRanges(t *testing.T) {
	// Verify start < end for all hierarchies.
	for name, hr := range hierarchyRanges {
		if hr.start >= hr.end {
			t.Errorf("%s: start (%#x) must be less than end (%#x)", name, hr.start, hr.end)
		}
	}
}

func TestTPMHandleAllocator_LoadCounters_IgnoresLowValues(t *testing.T) {
	dir := t.TempDir()

	// Write a state file with values below the valid start range.
	state := handleCounterState{
		Owner:       0x00000001,
		Endorsement: 0x00000001,
		Platform:    0x00000001,
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	err = os.WriteFile(filepath.Join(dir, handleCounterFile), data, 0600)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	alloc, err := NewTPMHandleAllocator(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Values below start range should be ignored, counters stay at defaults.
	h, err := alloc.CurrentHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if h != OwnerHandleStart {
		t.Errorf("expected default %#x, got %#x", OwnerHandleStart, h)
	}
}

func TestTPMHandleAllocator_SetHandle_ThenAllocate(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = alloc.SetHandle(HierarchyOwner, OwnerHandleStart+100)
	if err != nil {
		t.Fatalf("set handle: %v", err)
	}

	h, err := alloc.NextHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("next handle: %v", err)
	}
	if h != OwnerHandleStart+100 {
		t.Errorf("expected %#x, got %#x", OwnerHandleStart+100, h)
	}
}

func TestTPMHandleAllocator_IndependentHierarchies(t *testing.T) {
	alloc, err := NewTPMHandleAllocator("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allocate from owner.
	_, err = alloc.NextHandle(HierarchyOwner)
	if err != nil {
		t.Fatalf("owner alloc: %v", err)
	}

	// Endorsement should still be at its start.
	h, err := alloc.CurrentHandle(HierarchyEndorsement)
	if err != nil {
		t.Fatalf("endorsement current: %v", err)
	}
	if h != EndorsementHandleStart {
		t.Errorf("endorsement should be unaffected: expected %#x, got %#x",
			EndorsementHandleStart, h)
	}
}
