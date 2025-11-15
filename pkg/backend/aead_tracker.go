// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package backend

import (
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// NOTE: AEADOptions and AEADSafetyTracker have been moved to pkg/types to resolve import cycles.
// Import "github.com/jeremyhahn/go-keychain/pkg/types" for these types.
//
// This file contains the memory-based implementation of AEADSafetyTracker.

// memoryAEADTracker is an in-memory implementation of types.AEADSafetyTracker.
// This is suitable for testing and short-lived processes.
// Production systems should use persistent storage (file-based or database).
type memoryAEADTracker struct {
	// Map of keyID -> AEAD options
	options map[string]*types.AEADOptions

	// Map of keyID -> set of used nonces (hex-encoded)
	nonces map[string]map[string]bool

	// Map of keyID -> bytes encrypted counter
	bytes map[string]*int64

	mu sync.RWMutex
}

// NewMemoryAEADTracker creates a new in-memory AEAD safety tracker.
// This is suitable for testing and short-lived processes.
//
// For production systems with persistent keys, use a persistent tracker
// that survives process restarts.
func NewMemoryAEADTracker() types.AEADSafetyTracker {
	return &memoryAEADTracker{
		options: make(map[string]*types.AEADOptions),
		nonces:  make(map[string]map[string]bool),
		bytes:   make(map[string]*int64),
	}
}

// CheckNonce verifies nonce uniqueness for the given key.
func (t *memoryAEADTracker) CheckNonce(keyID string, nonce []byte) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Get options for this key
	opts, ok := t.options[keyID]
	if !ok || !opts.NonceTracking {
		// Tracking disabled for this key
		return nil
	}

	// Check if nonce was used before
	nonceHex := hex.EncodeToString(nonce)
	usedNonces, ok := t.nonces[keyID]
	if !ok {
		// No nonces recorded yet - this is the first encryption
		return nil
	}

	if usedNonces[nonceHex] {
		return ErrNonceReused
	}

	return nil
}

// RecordNonce records a nonce as used for the given key.
func (t *memoryAEADTracker) RecordNonce(keyID string, nonce []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Get options for this key
	opts, ok := t.options[keyID]
	if !ok || !opts.NonceTracking {
		// Tracking disabled for this key
		return nil
	}

	// Initialize nonce set if needed
	if t.nonces[keyID] == nil {
		t.nonces[keyID] = make(map[string]bool)
	}

	// Record the nonce
	nonceHex := hex.EncodeToString(nonce)
	t.nonces[keyID][nonceHex] = true

	return nil
}

// IncrementBytes increments the bytes encrypted counter.
func (t *memoryAEADTracker) IncrementBytes(keyID string, numBytes int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Get options for this key
	opts, ok := t.options[keyID]
	if !ok || !opts.BytesTracking {
		// Tracking disabled for this key
		return nil
	}

	// Initialize counter if needed
	if t.bytes[keyID] == nil {
		var zero int64
		t.bytes[keyID] = &zero
	}

	// Check if adding bytes would exceed limit
	current := atomic.LoadInt64(t.bytes[keyID])
	if current+numBytes > opts.BytesTrackingLimit {
		return ErrBytesLimitExceeded
	}

	// Increment counter
	atomic.AddInt64(t.bytes[keyID], numBytes)

	return nil
}

// GetBytesEncrypted returns the total bytes encrypted.
func (t *memoryAEADTracker) GetBytesEncrypted(keyID string) (int64, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	counter, ok := t.bytes[keyID]
	if !ok {
		return 0, nil
	}

	return atomic.LoadInt64(counter), nil
}

// GetAEADOptions returns the AEAD options for a key.
func (t *memoryAEADTracker) GetAEADOptions(keyID string) (*types.AEADOptions, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	opts, ok := t.options[keyID]
	if !ok {
		return nil, nil
	}

	// Return a copy to prevent modification
	return &types.AEADOptions{
		NonceTracking:      opts.NonceTracking,
		BytesTracking:      opts.BytesTracking,
		BytesTrackingLimit: opts.BytesTrackingLimit,
		NonceSize:          opts.NonceSize,
	}, nil
}

// SetAEADOptions sets the AEAD options for a key.
func (t *memoryAEADTracker) SetAEADOptions(keyID string, opts *types.AEADOptions) error {
	if opts == nil {
		return ErrInvalidOptions
	}

	if err := opts.Validate(); err != nil {
		return ErrInvalidOptions
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Store a copy to prevent external modification
	t.options[keyID] = &types.AEADOptions{
		NonceTracking:      opts.NonceTracking,
		BytesTracking:      opts.BytesTracking,
		BytesTrackingLimit: opts.BytesTrackingLimit,
		NonceSize:          opts.NonceSize,
	}

	return nil
}

// ResetTracking resets all tracking state for a key.
func (t *memoryAEADTracker) ResetTracking(keyID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Clear nonces
	delete(t.nonces, keyID)

	// Reset byte counter
	if t.bytes[keyID] != nil {
		atomic.StoreInt64(t.bytes[keyID], 0)
	}

	return nil
}

// Verify interface compliance
var _ types.AEADSafetyTracker = (*memoryAEADTracker)(nil)
