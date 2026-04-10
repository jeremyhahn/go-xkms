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
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
)

// Owner-defined NV index range boundaries per TCG specification.
// The TCG spec defines 0x01800000-0x01BFFFFF as the owner-defined range.
// We skip the first 256 indices for reserved/system use.
const (
	// NVIndexStart is the first allocatable owner-defined NV index.
	NVIndexStart uint32 = 0x01800100

	// NVIndexEnd is the last allocatable owner-defined NV index.
	NVIndexEnd uint32 = 0x01BFFFFF

	// nvIndexCounterFile is the persistence filename for the NV index counter.
	nvIndexCounterFile = "nv_index_counter.json"
)

// NVIndexAllocator tracks and atomically allocates NV RAM indices for
// storing sealed blobs in TPM NV memory. It uses lock-free atomic
// operations for allocation and optionally persists counter state to
// a JSON file on disk.
type NVIndexAllocator struct {
	counter *atomic.Uint32
	dataDir string
}

// nvIndexCounterState is the JSON serialization format for the persisted counter.
type nvIndexCounterState struct {
	NextIndex uint32 `json:"next_index"`
}

// NewNVIndexAllocator creates a new NV index allocator. If dataDir is
// non-empty, persisted counter state is loaded from disk on creation
// and written back after each allocation.
func NewNVIndexAllocator(dataDir string) (*NVIndexAllocator, error) {
	a := &NVIndexAllocator{
		counter: &atomic.Uint32{},
		dataDir: dataDir,
	}
	a.counter.Store(NVIndexStart)

	// Load persisted state if a data directory is configured.
	if dataDir != "" {
		if err := a.loadCounter(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return a, nil
}

// NextIndex atomically allocates the next available NV index. The
// allocation uses a compare-and-swap loop to guarantee correctness
// under concurrent access without locks.
func (a *NVIndexAllocator) NextIndex() (uint32, error) {
	for {
		current := a.counter.Load()
		if current > NVIndexEnd {
			return 0, ErrNVIndexRangeExhausted
		}
		next := current + 1
		if a.counter.CompareAndSwap(current, next) {
			// Best-effort persist after successful allocation.
			if a.dataDir != "" {
				_ = a.persistCounter()
			}
			return current, nil
		}
		// CAS failed due to concurrent update, retry.
	}
}

// CurrentIndex returns the current (next-to-allocate) NV index without
// allocating it.
func (a *NVIndexAllocator) CurrentIndex() uint32 {
	return a.counter.Load()
}

// SetIndex sets the counter to the given value. This is used after
// scanning existing NV indices to avoid collisions with previously
// defined indices. The value must be within the valid allocation range.
func (a *NVIndexAllocator) SetIndex(value uint32) error {
	if value < NVIndexStart || value > NVIndexEnd+1 {
		return ErrNVIndexOutOfRange
	}
	a.counter.Store(value)
	if a.dataDir != "" {
		return a.persistCounter()
	}
	return nil
}

// SyncFromTPM scans the provided list of used NV indices and sets the
// counter past the highest index within the valid owner-defined range.
// This ensures new allocations do not collide with existing NV objects.
func (a *NVIndexAllocator) SyncFromTPM(usedIndices []uint32) error {
	highest := NVIndexStart
	for _, idx := range usedIndices {
		if idx >= NVIndexStart && idx <= NVIndexEnd && idx >= highest {
			highest = idx + 1
		}
	}
	a.counter.Store(highest)
	if a.dataDir != "" {
		return a.persistCounter()
	}
	return nil
}

func (a *NVIndexAllocator) counterFilePath() string {
	return filepath.Join(a.dataDir, nvIndexCounterFile)
}

func (a *NVIndexAllocator) loadCounter() error {
	data, err := os.ReadFile(a.counterFilePath())
	if err != nil {
		return err
	}
	var state nvIndexCounterState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.NextIndex >= NVIndexStart {
		a.counter.Store(state.NextIndex)
	}
	return nil
}

func (a *NVIndexAllocator) persistCounter() error {
	state := nvIndexCounterState{
		NextIndex: a.counter.Load(),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(a.counterFilePath(), data, 0600)
}
