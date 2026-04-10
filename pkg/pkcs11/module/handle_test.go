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

package module

import (
	"sync"
	"testing"
)

// testObject is a simple struct for testing handle table with struct values.
type testObject struct {
	ID   int
	Name string
}

// testSession simulates a session for testing.
type testSession struct {
	State  string
	UserID uint64
}

func TestNewHandleTable(t *testing.T) {
	table := NewHandleTable[*testObject]()
	if table == nil {
		t.Fatal("NewHandleTable returned nil")
	}
	if table.handles == nil {
		t.Fatal("handles map not initialized")
	}
	if table.Size() != 0 {
		t.Errorf("expected size 0, got %d", table.Size())
	}
}

func TestHandleTable_Allocate_Success(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 1, Name: "test"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	if handle == InvalidHandle {
		t.Error("Allocate returned InvalidHandle")
	}
	if handle != 1 {
		t.Errorf("expected handle 1, got %d", handle)
	}
	if table.Size() != 1 {
		t.Errorf("expected size 1, got %d", table.Size())
	}
}

func TestHandleTable_Allocate_MultipleHandles(t *testing.T) {
	table := NewHandleTable[*testObject]()

	handles := make([]uint64, 10)
	for i := 0; i < 10; i++ {
		obj := &testObject{ID: i, Name: "test"}
		h, err := table.Allocate(obj)
		if err != nil {
			t.Fatalf("Allocate failed for handle %d: %v", i, err)
		}
		handles[i] = h
	}

	// Verify all handles are unique and sequential
	for i, h := range handles {
		if h != uint64(i+1) {
			t.Errorf("expected handle %d, got %d", i+1, h)
		}
	}

	if table.Size() != 10 {
		t.Errorf("expected size 10, got %d", table.Size())
	}
}

func TestHandleTable_Allocate_NilValue(t *testing.T) {
	table := NewHandleTable[*testObject]()

	handle, err := table.Allocate(nil)
	if err != ErrHandleNilValue {
		t.Errorf("expected ErrHandleNilValue, got %v", err)
	}
	if handle != InvalidHandle {
		t.Errorf("expected InvalidHandle, got %d", handle)
	}
}

func TestHandleTable_Lookup_Success(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 42, Name: "lookup-test"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	found, ok := table.Lookup(handle)
	if !ok {
		t.Fatal("Lookup returned false")
	}
	if found.ID != 42 {
		t.Errorf("expected ID 42, got %d", found.ID)
	}
	if found.Name != "lookup-test" {
		t.Errorf("expected Name 'lookup-test', got %s", found.Name)
	}
}

func TestHandleTable_Lookup_NotFound(t *testing.T) {
	table := NewHandleTable[*testObject]()

	found, ok := table.Lookup(999)
	if ok {
		t.Error("Lookup returned true for non-existent handle")
	}
	if found != nil {
		t.Error("expected nil value for non-existent handle")
	}
}

func TestHandleTable_Lookup_InvalidHandle(t *testing.T) {
	table := NewHandleTable[*testObject]()

	found, ok := table.Lookup(InvalidHandle)
	if ok {
		t.Error("Lookup returned true for InvalidHandle")
	}
	if found != nil {
		t.Error("expected nil value for InvalidHandle")
	}
}

func TestHandleTable_LookupOrError_Success(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 100, Name: "error-lookup-test"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	found, err := table.LookupOrError(handle)
	if err != nil {
		t.Fatalf("LookupOrError failed: %v", err)
	}
	if found.ID != 100 {
		t.Errorf("expected ID 100, got %d", found.ID)
	}
}

func TestHandleTable_LookupOrError_NotFound(t *testing.T) {
	table := NewHandleTable[*testObject]()

	found, err := table.LookupOrError(999)
	if err == nil {
		t.Fatal("expected error for non-existent handle")
	}
	if found != nil {
		t.Error("expected nil value for non-existent handle")
	}

	he, ok := err.(*HandleError)
	if !ok {
		t.Fatalf("expected *HandleError, got %T", err)
	}
	if he.Op != "lookup" {
		t.Errorf("expected Op 'lookup', got %s", he.Op)
	}
	if he.Handle != 999 {
		t.Errorf("expected Handle 999, got %d", he.Handle)
	}
}

func TestHandleTable_LookupOrError_InvalidHandle(t *testing.T) {
	table := NewHandleTable[*testObject]()

	found, err := table.LookupOrError(InvalidHandle)
	if err != ErrHandleInvalid {
		t.Errorf("expected ErrHandleInvalid, got %v", err)
	}
	if found != nil {
		t.Error("expected nil value for InvalidHandle")
	}
}

func TestHandleTable_Release_Success(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 50, Name: "release-test"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	released, ok := table.Release(handle)
	if !ok {
		t.Fatal("Release returned false")
	}
	if released.ID != 50 {
		t.Errorf("expected ID 50, got %d", released.ID)
	}

	if table.Size() != 0 {
		t.Errorf("expected size 0 after release, got %d", table.Size())
	}

	// Verify handle is no longer valid
	_, ok = table.Lookup(handle)
	if ok {
		t.Error("handle still valid after release")
	}
}

func TestHandleTable_Release_NotFound(t *testing.T) {
	table := NewHandleTable[*testObject]()

	released, ok := table.Release(999)
	if ok {
		t.Error("Release returned true for non-existent handle")
	}
	if released != nil {
		t.Error("expected nil value for non-existent handle")
	}
}

func TestHandleTable_Release_InvalidHandle(t *testing.T) {
	table := NewHandleTable[*testObject]()

	released, ok := table.Release(InvalidHandle)
	if ok {
		t.Error("Release returned true for InvalidHandle")
	}
	if released != nil {
		t.Error("expected nil value for InvalidHandle")
	}
}

func TestHandleTable_ReleaseOrError_Success(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 75, Name: "release-error-test"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	released, err := table.ReleaseOrError(handle)
	if err != nil {
		t.Fatalf("ReleaseOrError failed: %v", err)
	}
	if released.ID != 75 {
		t.Errorf("expected ID 75, got %d", released.ID)
	}
}

func TestHandleTable_ReleaseOrError_NotFound(t *testing.T) {
	table := NewHandleTable[*testObject]()

	released, err := table.ReleaseOrError(999)
	if err == nil {
		t.Fatal("expected error for non-existent handle")
	}
	if released != nil {
		t.Error("expected nil value for non-existent handle")
	}

	he, ok := err.(*HandleError)
	if !ok {
		t.Fatalf("expected *HandleError, got %T", err)
	}
	if he.Op != "release" {
		t.Errorf("expected Op 'release', got %s", he.Op)
	}
}

func TestHandleTable_ReleaseOrError_InvalidHandle(t *testing.T) {
	table := NewHandleTable[*testObject]()

	released, err := table.ReleaseOrError(InvalidHandle)
	if err != ErrHandleInvalid {
		t.Errorf("expected ErrHandleInvalid, got %v", err)
	}
	if released != nil {
		t.Error("expected nil value for InvalidHandle")
	}
}

func TestHandleTable_Contains_Exists(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 1, Name: "contains-test"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	if !table.Contains(handle) {
		t.Error("Contains returned false for existing handle")
	}
}

func TestHandleTable_Contains_NotExists(t *testing.T) {
	table := NewHandleTable[*testObject]()

	if table.Contains(999) {
		t.Error("Contains returned true for non-existent handle")
	}
}

func TestHandleTable_Contains_InvalidHandle(t *testing.T) {
	table := NewHandleTable[*testObject]()

	if table.Contains(InvalidHandle) {
		t.Error("Contains returned true for InvalidHandle")
	}
}

func TestHandleTable_Size(t *testing.T) {
	table := NewHandleTable[*testObject]()

	if table.Size() != 0 {
		t.Errorf("expected size 0, got %d", table.Size())
	}

	for i := 0; i < 5; i++ {
		obj := &testObject{ID: i, Name: "size-test"}
		_, err := table.Allocate(obj)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
	}

	if table.Size() != 5 {
		t.Errorf("expected size 5, got %d", table.Size())
	}
}

func TestHandleTable_Clear(t *testing.T) {
	table := NewHandleTable[*testObject]()

	for i := 0; i < 5; i++ {
		obj := &testObject{ID: i, Name: "clear-test"}
		_, err := table.Allocate(obj)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
	}

	table.Clear()

	if table.Size() != 0 {
		t.Errorf("expected size 0 after Clear, got %d", table.Size())
	}

	// Verify counter was not reset - new handle should be 6
	obj := &testObject{ID: 99, Name: "after-clear"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	if handle != 6 {
		t.Errorf("expected handle 6 after Clear, got %d", handle)
	}
}

func TestHandleTable_Handles(t *testing.T) {
	table := NewHandleTable[*testObject]()

	expectedHandles := make(map[uint64]bool)
	for i := 0; i < 5; i++ {
		obj := &testObject{ID: i, Name: "handles-test"}
		h, err := table.Allocate(obj)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
		expectedHandles[h] = true
	}

	handles := table.Handles()
	if len(handles) != 5 {
		t.Errorf("expected 5 handles, got %d", len(handles))
	}

	for _, h := range handles {
		if !expectedHandles[h] {
			t.Errorf("unexpected handle %d", h)
		}
	}
}

func TestHandleTable_ForEach(t *testing.T) {
	table := NewHandleTable[*testObject]()

	for i := 0; i < 5; i++ {
		obj := &testObject{ID: i, Name: "foreach-test"}
		_, err := table.Allocate(obj)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
	}

	count := 0
	table.ForEach(func(handle uint64, value *testObject) bool {
		count++
		if value == nil {
			t.Error("ForEach provided nil value")
		}
		return true
	})

	if count != 5 {
		t.Errorf("expected ForEach to iterate 5 times, got %d", count)
	}
}

func TestHandleTable_ForEach_EarlyExit(t *testing.T) {
	table := NewHandleTable[*testObject]()

	for i := 0; i < 10; i++ {
		obj := &testObject{ID: i, Name: "foreach-early-test"}
		_, err := table.Allocate(obj)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
	}

	count := 0
	table.ForEach(func(handle uint64, value *testObject) bool {
		count++
		return count < 3 // Stop after 3 iterations
	})

	if count != 3 {
		t.Errorf("expected ForEach to stop after 3 iterations, got %d", count)
	}
}

func TestHandleTable_Update_Success(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 1, Name: "original"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	newObj := &testObject{ID: 2, Name: "updated"}
	err = table.Update(handle, newObj)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	found, ok := table.Lookup(handle)
	if !ok {
		t.Fatal("Lookup failed after Update")
	}
	if found.ID != 2 {
		t.Errorf("expected ID 2, got %d", found.ID)
	}
	if found.Name != "updated" {
		t.Errorf("expected Name 'updated', got %s", found.Name)
	}
}

func TestHandleTable_Update_NotFound(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 1, Name: "test"}
	err := table.Update(999, obj)
	if err == nil {
		t.Fatal("expected error for non-existent handle")
	}

	he, ok := err.(*HandleError)
	if !ok {
		t.Fatalf("expected *HandleError, got %T", err)
	}
	if he.Op != "update" {
		t.Errorf("expected Op 'update', got %s", he.Op)
	}
}

func TestHandleTable_Update_InvalidHandle(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 1, Name: "test"}
	err := table.Update(InvalidHandle, obj)
	if err != ErrHandleInvalid {
		t.Errorf("expected ErrHandleInvalid, got %v", err)
	}
}

func TestHandleTable_Update_NilValue(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 1, Name: "original"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	err = table.Update(handle, nil)
	if err != ErrHandleNilValue {
		t.Errorf("expected ErrHandleNilValue, got %v", err)
	}
}

func TestHandleTable_Insert_Success(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 100, Name: "restored"}
	specificHandle := uint64(42)

	err := table.Insert(specificHandle, obj)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Verify object is at the specific handle
	retrieved, ok := table.Lookup(specificHandle)
	if !ok {
		t.Fatalf("Lookup failed for inserted handle")
	}
	if retrieved.ID != obj.ID || retrieved.Name != obj.Name {
		t.Errorf("Retrieved object mismatch: got %+v, want %+v", retrieved, obj)
	}

	// Verify counter was not affected (allocate should give 1, not 43)
	newObj := &testObject{ID: 200, Name: "new"}
	newHandle, err := table.Allocate(newObj)
	if err != nil {
		t.Fatalf("Allocate after insert failed: %v", err)
	}
	if newHandle == specificHandle {
		t.Errorf("Allocate returned same handle as inserted: %d", newHandle)
	}
}

func TestHandleTable_Insert_InvalidHandle(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj := &testObject{ID: 1, Name: "test"}
	err := table.Insert(InvalidHandle, obj)
	if err != ErrHandleInvalid {
		t.Errorf("expected ErrHandleInvalid, got %v", err)
	}
}

func TestHandleTable_Insert_NilValue(t *testing.T) {
	table := NewHandleTable[*testObject]()

	err := table.Insert(42, nil)
	if err != ErrHandleNilValue {
		t.Errorf("expected ErrHandleNilValue, got %v", err)
	}
}

func TestHandleTable_Insert_HandleInUse(t *testing.T) {
	table := NewHandleTable[*testObject]()

	obj1 := &testObject{ID: 1, Name: "first"}
	err := table.Insert(42, obj1)
	if err != nil {
		t.Fatalf("First insert failed: %v", err)
	}

	obj2 := &testObject{ID: 2, Name: "second"}
	err = table.Insert(42, obj2)
	if err != ErrHandleInUse {
		t.Errorf("expected ErrHandleInUse, got %v", err)
	}
}

func TestHandleTable_SetCounter(t *testing.T) {
	table := NewHandleTable[*testObject]()

	// Set counter to 100
	table.SetCounter(100)

	// Allocate should start from 101
	obj := &testObject{ID: 1, Name: "test"}
	handle, err := table.Allocate(obj)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	if handle != 101 {
		t.Errorf("expected handle 101, got %d", handle)
	}
}

func TestHandleTable_SetCounter_AfterInsert(t *testing.T) {
	table := NewHandleTable[*testObject]()

	// Insert objects at specific handles (simulating restored objects)
	obj1 := &testObject{ID: 1, Name: "restored1"}
	if err := table.Insert(5, obj1); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	obj2 := &testObject{ID: 2, Name: "restored2"}
	if err := table.Insert(10, obj2); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Set counter to start after the highest restored handle
	table.SetCounter(11)

	// New allocations should not conflict
	obj3 := &testObject{ID: 3, Name: "new1"}
	handle1, err := table.Allocate(obj3)
	if err != nil {
		t.Fatalf("First Allocate failed: %v", err)
	}
	if handle1 != 12 {
		t.Errorf("expected handle 12, got %d", handle1)
	}

	obj4 := &testObject{ID: 4, Name: "new2"}
	handle2, err := table.Allocate(obj4)
	if err != nil {
		t.Fatalf("Second Allocate failed: %v", err)
	}
	if handle2 != 13 {
		t.Errorf("expected handle 13, got %d", handle2)
	}

	// Verify all objects are accessible
	if _, ok := table.Lookup(5); !ok {
		t.Error("Object at handle 5 not found")
	}
	if _, ok := table.Lookup(10); !ok {
		t.Error("Object at handle 10 not found")
	}
	if _, ok := table.Lookup(12); !ok {
		t.Error("Object at handle 12 not found")
	}
	if _, ok := table.Lookup(13); !ok {
		t.Error("Object at handle 13 not found")
	}
}

func TestHandleTable_ConcurrentAllocate(t *testing.T) {
	table := NewHandleTable[*testObject]()
	numGoroutines := 100
	allocsPerGoroutine := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	handlesChan := make(chan uint64, numGoroutines*allocsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < allocsPerGoroutine; j++ {
				obj := &testObject{ID: id*1000 + j, Name: "concurrent"}
				h, err := table.Allocate(obj)
				if err != nil {
					t.Errorf("Concurrent Allocate failed: %v", err)
					return
				}
				handlesChan <- h
			}
		}(i)
	}

	wg.Wait()
	close(handlesChan)

	// Verify all handles are unique
	seen := make(map[uint64]bool)
	for h := range handlesChan {
		if seen[h] {
			t.Errorf("duplicate handle %d", h)
		}
		seen[h] = true
	}

	if len(seen) != numGoroutines*allocsPerGoroutine {
		t.Errorf("expected %d unique handles, got %d", numGoroutines*allocsPerGoroutine, len(seen))
	}

	if table.Size() != numGoroutines*allocsPerGoroutine {
		t.Errorf("expected size %d, got %d", numGoroutines*allocsPerGoroutine, table.Size())
	}
}

func TestHandleTable_ConcurrentLookup(t *testing.T) {
	table := NewHandleTable[*testObject]()

	// Pre-allocate some handles
	handles := make([]uint64, 100)
	for i := 0; i < 100; i++ {
		obj := &testObject{ID: i, Name: "lookup-concurrent"}
		h, err := table.Allocate(obj)
		if err != nil {
			t.Fatalf("Allocate failed: %v", err)
		}
		handles[i] = h
	}

	var wg sync.WaitGroup
	numGoroutines := 50
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for _, h := range handles {
				found, ok := table.Lookup(h)
				if !ok {
					t.Error("Concurrent Lookup failed")
					return
				}
				if found == nil {
					t.Error("Concurrent Lookup returned nil")
					return
				}
			}
		}()
	}

	wg.Wait()
}

func TestHandleTable_ConcurrentAllocateAndRelease(t *testing.T) {
	table := NewHandleTable[*testObject]()
	numGoroutines := 50
	iterations := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Allocators
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				obj := &testObject{ID: id*1000 + j, Name: "alloc-release"}
				_, err := table.Allocate(obj)
				if err != nil {
					t.Errorf("Concurrent Allocate failed: %v", err)
					return
				}
			}
		}(i)
	}

	// Releasers
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				handles := table.Handles()
				if len(handles) > 0 {
					table.Release(handles[0])
				}
			}
		}()
	}

	wg.Wait()
}

func TestHandleTable_WithSessionType(t *testing.T) {
	table := NewHandleTable[*testSession]()

	session := &testSession{State: "active", UserID: 12345}
	handle, err := table.Allocate(session)
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}

	found, ok := table.Lookup(handle)
	if !ok {
		t.Fatal("Lookup failed")
	}
	if found.State != "active" {
		t.Errorf("expected State 'active', got %s", found.State)
	}
	if found.UserID != 12345 {
		t.Errorf("expected UserID 12345, got %d", found.UserID)
	}
}

func TestHandleTable_WithInterfaceType(t *testing.T) {
	table := NewHandleTable[any]()

	// Store different types
	h1, err := table.Allocate("string value")
	if err != nil {
		t.Fatalf("Allocate string failed: %v", err)
	}

	h2, err := table.Allocate(42)
	if err != nil {
		t.Fatalf("Allocate int failed: %v", err)
	}

	h3, err := table.Allocate(&testObject{ID: 1, Name: "interface"})
	if err != nil {
		t.Fatalf("Allocate struct failed: %v", err)
	}

	// Verify lookups
	v1, ok := table.Lookup(h1)
	if !ok || v1 != "string value" {
		t.Error("string lookup failed")
	}

	v2, ok := table.Lookup(h2)
	if !ok || v2 != 42 {
		t.Error("int lookup failed")
	}

	v3, ok := table.Lookup(h3)
	if !ok {
		t.Error("struct lookup failed")
	}
	obj, ok := v3.(*testObject)
	if !ok || obj.Name != "interface" {
		t.Error("struct type assertion failed")
	}
}

func TestHandleError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *HandleError
		expected string
	}{
		{
			name:     "with handle",
			err:      &HandleError{Op: "lookup", Handle: 123, Msg: "not found"},
			expected: "handle: lookup: handle 123: not found",
		},
		{
			name:     "without handle",
			err:      &HandleError{Op: "allocate", Handle: InvalidHandle, Msg: "overflow"},
			expected: "handle: allocate: overflow",
		},
		{
			name:     "zero as explicit handle",
			err:      &HandleError{Op: "validate", Handle: 0, Msg: "invalid"},
			expected: "handle: validate: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestUitoa(t *testing.T) {
	tests := []struct {
		val      uint64
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{123, "123"},
		{18446744073709551615, "18446744073709551615"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := uitoa(tt.val); got != tt.expected {
				t.Errorf("uitoa(%d) = %q, want %q", tt.val, got, tt.expected)
			}
		})
	}
}

func TestObjectHandle_TypeAlias(t *testing.T) {
	var h ObjectHandle = 42
	if h != 42 {
		t.Errorf("ObjectHandle value mismatch")
	}

	// Verify it can be used as uint64
	u := uint64(h)
	if u != 42 {
		t.Errorf("ObjectHandle to uint64 conversion failed")
	}
}

func TestSessionHandle_TypeAlias(t *testing.T) {
	var h SessionHandle = 99
	if h != 99 {
		t.Errorf("SessionHandle value mismatch")
	}

	// Verify it can be used as uint64
	u := uint64(h)
	if u != 99 {
		t.Errorf("SessionHandle to uint64 conversion failed")
	}
}

func TestInvalidHandle_Constant(t *testing.T) {
	if InvalidHandle != 0 {
		t.Errorf("InvalidHandle should be 0, got %d", InvalidHandle)
	}
}

func TestPredefinedErrors(t *testing.T) {
	// Verify predefined errors are of correct type
	errors := []*HandleError{
		ErrHandleNotFound,
		ErrHandleInvalid,
		ErrHandleOverflow,
		ErrHandleInUse,
		ErrHandleNilValue,
		ErrHandleReleased,
		ErrHandleTypeMismatch,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("predefined error is nil")
		}
		// Verify Error() doesn't panic
		_ = err.Error()
	}
}

func BenchmarkHandleTable_Allocate(b *testing.B) {
	table := NewHandleTable[*testObject]()
	obj := &testObject{ID: 1, Name: "bench"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = table.Allocate(obj)
	}
}

func BenchmarkHandleTable_Lookup(b *testing.B) {
	table := NewHandleTable[*testObject]()

	// Pre-allocate handles
	handles := make([]uint64, 1000)
	for i := 0; i < 1000; i++ {
		obj := &testObject{ID: i, Name: "bench"}
		h, _ := table.Allocate(obj)
		handles[i] = h
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.Lookup(handles[i%1000])
	}
}

func BenchmarkHandleTable_ConcurrentAllocate(b *testing.B) {
	table := NewHandleTable[*testObject]()
	obj := &testObject{ID: 1, Name: "bench"}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = table.Allocate(obj)
		}
	})
}

func BenchmarkHandleTable_ConcurrentLookup(b *testing.B) {
	table := NewHandleTable[*testObject]()

	// Pre-allocate handles
	handles := make([]uint64, 1000)
	for i := 0; i < 1000; i++ {
		obj := &testObject{ID: i, Name: "bench"}
		h, _ := table.Allocate(obj)
		handles[i] = h
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			table.Lookup(handles[i%1000])
			i++
		}
	})
}
