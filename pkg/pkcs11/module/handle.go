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
	"reflect"
	"sync"
	"sync/atomic"
)

// InvalidHandle represents an invalid or unassigned handle value.
const InvalidHandle = 0

// ObjectHandle is a unique identifier for PKCS#11 objects.
type ObjectHandle uint64

// SessionHandle is a unique identifier for PKCS#11 sessions.
type SessionHandle uint64

// HandleError represents errors related to handle operations.
type HandleError struct {
	Op     string
	Handle uint64
	Msg    string
}

// Error implements the error interface.
func (e *HandleError) Error() string {
	if e.Handle == InvalidHandle {
		return "handle: " + e.Op + ": " + e.Msg
	}
	return "handle: " + e.Op + ": handle " + uitoa(e.Handle) + ": " + e.Msg
}

// uitoa converts a uint64 to a string without importing strconv.
func uitoa(val uint64) string {
	if val == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf) - 1
	for val > 0 {
		buf[i] = byte('0' + val%10)
		val /= 10
		i--
	}
	return string(buf[i+1:])
}

// Predefined handle errors.
var (
	ErrHandleNotFound     = &HandleError{Op: "lookup", Msg: "handle not found"}
	ErrHandleInvalid      = &HandleError{Op: "validate", Handle: InvalidHandle, Msg: "invalid handle"}
	ErrHandleOverflow     = &HandleError{Op: "allocate", Msg: "handle counter overflow"}
	ErrHandleInUse        = &HandleError{Op: "allocate", Msg: "handle already in use"}
	ErrHandleNilValue     = &HandleError{Op: "store", Msg: "cannot store nil value"}
	ErrHandleReleased     = &HandleError{Op: "access", Msg: "handle has been released"}
	ErrHandleTypeMismatch = &HandleError{Op: "lookup", Msg: "handle type mismatch"}
)

// HandleTable provides thread-safe handle allocation and storage.
// It uses atomic operations for handle generation and RWMutex for map access.
type HandleTable[T any] struct {
	counter atomic.Uint64
	mu      sync.RWMutex
	handles map[uint64]T
}

// NewHandleTable creates a new handle table for storing values of type T.
func NewHandleTable[T any]() *HandleTable[T] {
	return &HandleTable[T]{
		handles: make(map[uint64]T),
	}
}

// Allocate generates a new unique handle and stores the value.
// Returns the allocated handle or an error if allocation fails.
// Thread-safe: uses atomic increment for handle generation.
func (t *HandleTable[T]) Allocate(value T) (uint64, error) {
	// Check for nil using reflection for proper nil pointer detection
	if isNil(value) {
		return InvalidHandle, ErrHandleNilValue
	}

	// Atomically increment and get the new handle value
	handle := t.counter.Add(1)

	// Check for overflow (wrapped around to 0 or past max safe value)
	if handle == 0 {
		return InvalidHandle, ErrHandleOverflow
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Verify handle is not already in use (defensive check)
	if _, exists := t.handles[handle]; exists {
		return InvalidHandle, ErrHandleInUse
	}

	t.handles[handle] = value
	return handle, nil
}

// Lookup retrieves a value by its handle.
// Returns the value and true if found, or zero value and false if not found.
// Thread-safe: uses read lock for concurrent access.
func (t *HandleTable[T]) Lookup(handle uint64) (T, bool) {
	if handle == InvalidHandle {
		var zero T
		return zero, false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	value, ok := t.handles[handle]
	return value, ok
}

// LookupOrError retrieves a value by its handle or returns an error.
// Thread-safe: uses read lock for concurrent access.
func (t *HandleTable[T]) LookupOrError(handle uint64) (T, error) {
	if handle == InvalidHandle {
		var zero T
		return zero, ErrHandleInvalid
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	value, ok := t.handles[handle]
	if !ok {
		var zero T
		return zero, &HandleError{
			Op:     "lookup",
			Handle: handle,
			Msg:    "handle not found",
		}
	}
	return value, nil
}

// Release invalidates a handle and removes its associated value.
// Returns the removed value and true if successful, or zero value and false if not found.
// Thread-safe: uses write lock for map modification.
func (t *HandleTable[T]) Release(handle uint64) (T, bool) {
	if handle == InvalidHandle {
		var zero T
		return zero, false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	value, ok := t.handles[handle]
	if ok {
		delete(t.handles, handle)
	}
	return value, ok
}

// ReleaseOrError invalidates a handle or returns an error.
// Thread-safe: uses write lock for map modification.
func (t *HandleTable[T]) ReleaseOrError(handle uint64) (T, error) {
	if handle == InvalidHandle {
		var zero T
		return zero, ErrHandleInvalid
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	value, ok := t.handles[handle]
	if !ok {
		var zero T
		return zero, &HandleError{
			Op:     "release",
			Handle: handle,
			Msg:    "handle not found",
		}
	}
	delete(t.handles, handle)
	return value, nil
}

// Contains checks if a handle exists in the table.
// Thread-safe: uses read lock for concurrent access.
func (t *HandleTable[T]) Contains(handle uint64) bool {
	if handle == InvalidHandle {
		return false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	_, ok := t.handles[handle]
	return ok
}

// Size returns the current number of stored handles.
// Thread-safe: uses read lock for concurrent access.
func (t *HandleTable[T]) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.handles)
}

// Clear removes all handles from the table but does not reset the counter.
// Thread-safe: uses write lock for map modification.
func (t *HandleTable[T]) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.handles = make(map[uint64]T)
}

// Handles returns a slice of all currently valid handles.
// Thread-safe: uses read lock for concurrent access.
func (t *HandleTable[T]) Handles() []uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	handles := make([]uint64, 0, len(t.handles))
	for h := range t.handles {
		handles = append(handles, h)
	}
	return handles
}

// ForEach iterates over all handles and their values.
// The callback is invoked with the read lock held, so it should not
// attempt to modify the table or call other table methods.
// Thread-safe: uses read lock for concurrent access.
func (t *HandleTable[T]) ForEach(fn func(handle uint64, value T) bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for h, v := range t.handles {
		if !fn(h, v) {
			break
		}
	}
}

// Update atomically updates the value associated with a handle.
// Returns an error if the handle does not exist.
// Thread-safe: uses write lock for map modification.
func (t *HandleTable[T]) Update(handle uint64, value T) error {
	if handle == InvalidHandle {
		return ErrHandleInvalid
	}

	if isNil(value) {
		return ErrHandleNilValue
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.handles[handle]; !ok {
		return &HandleError{
			Op:     "update",
			Handle: handle,
			Msg:    "handle not found",
		}
	}

	t.handles[handle] = value
	return nil
}

// Insert stores a value at a specific handle without modifying the counter.
// Used for restoring objects from persistent storage with their original handles.
// Returns an error if the handle is invalid, value is nil, or handle already exists.
// Thread-safe: uses write lock for map modification.
func (t *HandleTable[T]) Insert(handle uint64, value T) error {
	if handle == InvalidHandle {
		return ErrHandleInvalid
	}

	if isNil(value) {
		return ErrHandleNilValue
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.handles[handle]; exists {
		return ErrHandleInUse
	}

	t.handles[handle] = value
	return nil
}

// SetCounter sets the internal handle counter to the specified value.
// This is used when restoring objects from persistence to ensure new allocations
// don't conflict with restored handles.
// Thread-safe: uses atomic store operation.
func (t *HandleTable[T]) SetCounter(value uint64) {
	t.counter.Store(value)
}

// isNil checks if the value is nil using reflection.
// Works for pointer types, interfaces, maps, slices, channels, and functions.
func isNil[T any](value T) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Invalid:
		return true
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return v.IsNil()
	default:
		return false
	}
}
