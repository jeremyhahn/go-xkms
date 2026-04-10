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

// TPM hierarchy constants for key generation.
const (
	HierarchyOwner       = "owner"
	HierarchyEndorsement = "endorsement"
	HierarchyPlatform    = "platform"
	HierarchyNull        = "null"
)

// TPM handle range boundaries per hierarchy (from TPM 2.0 specification).
// Start offsets skip reserved handles for SRK/EK.
const (
	OwnerHandleStart       uint32 = 0x81000100
	OwnerHandleEnd         uint32 = 0x810FFFFF
	EndorsementHandleStart uint32 = 0x81010100
	EndorsementHandleEnd   uint32 = 0x8101FFFF
	PlatformHandleStart    uint32 = 0x81800100
	PlatformHandleEnd      uint32 = 0x818FFFFF
)

// hierarchyRange defines the valid handle range for a TPM hierarchy.
type hierarchyRange struct {
	start uint32
	end   uint32
}

// hierarchyRanges maps hierarchy names to their handle ranges.
var hierarchyRanges = map[string]hierarchyRange{
	HierarchyOwner:       {start: OwnerHandleStart, end: OwnerHandleEnd},
	HierarchyEndorsement: {start: EndorsementHandleStart, end: EndorsementHandleEnd},
	HierarchyPlatform:    {start: PlatformHandleStart, end: PlatformHandleEnd},
}

// TPMHandleAllocator tracks and atomically allocates persistent TPM object
// handles per hierarchy. It uses lock-free atomic operations for allocation
// and optionally persists counter state to a JSON file on disk.
type TPMHandleAllocator struct {
	counters map[string]*atomic.Uint32
	dataDir  string
}

// NewTPMHandleAllocator creates a new allocator. If dataDir is non-empty,
// persisted counter state is loaded from disk on creation and written back
// after each allocation.
func NewTPMHandleAllocator(dataDir string) (*TPMHandleAllocator, error) {
	a := &TPMHandleAllocator{
		counters: make(map[string]*atomic.Uint32, len(hierarchyRanges)),
		dataDir:  dataDir,
	}
	// Initialize counters with default start values.
	for hierarchy, hr := range hierarchyRanges {
		counter := &atomic.Uint32{}
		counter.Store(hr.start)
		a.counters[hierarchy] = counter
	}
	// Load persisted state if a data directory is configured.
	if dataDir != "" {
		if err := a.loadCounters(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return a, nil
}

// NextHandle atomically allocates the next available handle for the given
// hierarchy. The allocation uses a compare-and-swap loop to guarantee
// correctness under concurrent access without locks.
func (a *TPMHandleAllocator) NextHandle(hierarchy string) (uint32, error) {
	counter, ok := a.counters[hierarchy]
	if !ok {
		return 0, ErrTPMInvalidHierarchy
	}
	hr := hierarchyRanges[hierarchy]

	for {
		current := counter.Load()
		if current > hr.end {
			return 0, ErrTPMHandleRangeExhausted
		}
		next := current + 1
		if counter.CompareAndSwap(current, next) {
			// Best-effort persist after successful allocation.
			if a.dataDir != "" {
				_ = a.persistCounters()
			}
			return current, nil
		}
		// CAS failed due to concurrent update, retry.
	}
}

// CurrentHandle returns the current (next-to-allocate) handle for the given
// hierarchy without allocating it.
func (a *TPMHandleAllocator) CurrentHandle(hierarchy string) (uint32, error) {
	counter, ok := a.counters[hierarchy]
	if !ok {
		return 0, ErrTPMInvalidHierarchy
	}
	return counter.Load(), nil
}

// SetHandle sets the counter for a hierarchy to the given value. This is
// used after scanning existing TPM handles to avoid collisions with
// previously persisted objects.
func (a *TPMHandleAllocator) SetHandle(hierarchy string, value uint32) error {
	counter, ok := a.counters[hierarchy]
	if !ok {
		return ErrTPMInvalidHierarchy
	}
	hr := hierarchyRanges[hierarchy]
	if value < hr.start || value > hr.end+1 {
		return ErrTPMHandleOutOfRange
	}
	counter.Store(value)
	if a.dataDir != "" {
		return a.persistCounters()
	}
	return nil
}

// handleCounterState is the JSON serialization format for persisted counters.
type handleCounterState struct {
	Owner       uint32 `json:"owner"`
	Endorsement uint32 `json:"endorsement"`
	Platform    uint32 `json:"platform"`
}

const handleCounterFile = "tpm_handle_counters.json"

func (a *TPMHandleAllocator) counterFilePath() string {
	return filepath.Join(a.dataDir, handleCounterFile)
}

func (a *TPMHandleAllocator) loadCounters() error {
	data, err := os.ReadFile(a.counterFilePath())
	if err != nil {
		return err
	}
	var state handleCounterState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.Owner >= OwnerHandleStart {
		a.counters[HierarchyOwner].Store(state.Owner)
	}
	if state.Endorsement >= EndorsementHandleStart {
		a.counters[HierarchyEndorsement].Store(state.Endorsement)
	}
	if state.Platform >= PlatformHandleStart {
		a.counters[HierarchyPlatform].Store(state.Platform)
	}
	return nil
}

func (a *TPMHandleAllocator) persistCounters() error {
	state := handleCounterState{
		Owner:       a.counters[HierarchyOwner].Load(),
		Endorsement: a.counters[HierarchyEndorsement].Load(),
		Platform:    a.counters[HierarchyPlatform].Load(),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(a.counterFilePath(), data, 0600)
}
