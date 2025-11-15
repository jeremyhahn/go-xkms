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

package aead

import (
	"encoding/hex"
	"sync"
)

// NonceTracker provides thread-safe tracking of used nonces to prevent
// catastrophic nonce reuse in AEAD ciphers (AES-GCM, ChaCha20-Poly1305).
//
// Nonce reuse in AEAD ciphers is catastrophic:
//   - AES-GCM: Reusing a nonce with the same key completely breaks authentication
//     and can reveal the authentication key, allowing attackers to forge messages.
//   - ChaCha20-Poly1305: Reusing a nonce can leak keystream and compromise confidentiality.
//
// This tracker ensures that each nonce is used only once per key, as required by
// NIST SP 800-38D (for GCM) and RFC 8439 (for ChaCha20-Poly1305).
//
// Security considerations:
//   - The tracker uses a map for O(1) lookup performance
//   - All operations are protected by a RWMutex for thread safety
//   - Nonces are stored as hex-encoded strings for efficient comparison
//   - Memory usage grows with each encryption operation
//   - For long-running systems, consider key rotation instead of unbounded tracking
//
// Example usage:
//
//	tracker := aead.NewNonceTracker(true)
//
//	// Before each encryption
//	nonce := make([]byte, 12)
//	rand.Read(nonce)
//	if err := tracker.CheckAndRecordNonce(nonce); err != nil {
//	    return err // Nonce was already used!
//	}
//
//	// Proceed with encryption...
type NonceTracker struct {
	enabled bool
	nonces  map[string]struct{} // Set of used nonces (hex encoded)
	mu      sync.RWMutex
}

// NewNonceTracker creates a new nonce tracker.
//
// Parameters:
//   - enabled: If true, nonce tracking is active. If false, all operations are no-ops.
//
// Returns:
//   - A new NonceTracker instance
//
// Example:
//
//	// Enable nonce tracking (recommended for production)
//	tracker := aead.NewNonceTracker(true)
//
//	// Disable nonce tracking (only for testing or specific use cases)
//	tracker := aead.NewNonceTracker(false)
func NewNonceTracker(enabled bool) *NonceTracker {
	return &NonceTracker{
		enabled: enabled,
		nonces:  make(map[string]struct{}),
	}
}

// CheckAndRecordNonce checks if a nonce has been used before and records it.
//
// This method performs two operations atomically:
//  1. Check if the nonce exists in the tracker
//  2. If not, record it for future checks
//
// If tracking is disabled (enabled=false), this method always returns nil.
//
// Thread safety: This method is safe for concurrent use.
//
// Parameters:
//   - nonce: The nonce bytes to check and record
//
// Returns:
//   - nil if the nonce is unique and has been recorded
//   - error if the nonce was previously used (nonce reuse detected)
//
// Example:
//
//	nonce := make([]byte, 12)
//	rand.Read(nonce)
//
//	if err := tracker.CheckAndRecordNonce(nonce); err != nil {
//	    // Handle nonce reuse - this is a critical security error!
//	    log.Fatal("CRITICAL: Nonce reuse detected!")
//	}
func (nt *NonceTracker) CheckAndRecordNonce(nonce []byte) error {
	if !nt.enabled {
		return nil
	}

	nonceHex := hex.EncodeToString(nonce)

	nt.mu.Lock()
	defer nt.mu.Unlock()

	if _, exists := nt.nonces[nonceHex]; exists {
		return ErrNonceReuse
	}

	nt.nonces[nonceHex] = struct{}{}
	return nil
}

// Contains checks if a nonce has been used before without recording it.
//
// This is a read-only operation that doesn't modify the tracker state.
// Use this when you need to check for nonce existence without side effects.
//
// If tracking is disabled, this always returns false.
//
// Thread safety: This method is safe for concurrent use.
//
// Parameters:
//   - nonce: The nonce bytes to check
//
// Returns:
//   - true if the nonce exists in the tracker
//   - false if the nonce is new or tracking is disabled
//
// Example:
//
//	if tracker.Contains(nonce) {
//	    log.Warn("Nonce was previously used")
//	}
func (nt *NonceTracker) Contains(nonce []byte) bool {
	if !nt.enabled {
		return false
	}

	nonceHex := hex.EncodeToString(nonce)

	nt.mu.RLock()
	defer nt.mu.RUnlock()

	_, exists := nt.nonces[nonceHex]
	return exists
}

// Count returns the number of unique nonces tracked.
//
// This is useful for monitoring memory usage and determining when
// key rotation should occur.
//
// If tracking is disabled, this always returns 0.
//
// Thread safety: This method is safe for concurrent use.
//
// Returns:
//   - The number of nonces currently tracked
//
// Example:
//
//	count := tracker.Count()
//	if count > 1000000 {
//	    log.Warn("Large number of nonces tracked, consider key rotation")
//	}
func (nt *NonceTracker) Count() int {
	if !nt.enabled {
		return 0
	}

	nt.mu.RLock()
	defer nt.mu.RUnlock()

	return len(nt.nonces)
}

// Clear removes all tracked nonces.
//
// Use this with caution - clearing the tracker and reusing nonces
// can compromise security. Only clear when rotating to a new key.
//
// If tracking is disabled, this is a no-op.
//
// Thread safety: This method is safe for concurrent use.
//
// Example:
//
//	// After rotating to a new key
//	tracker.Clear()
//	log.Info("Nonce tracker cleared after key rotation")
func (nt *NonceTracker) Clear() {
	if !nt.enabled {
		return
	}

	nt.mu.Lock()
	defer nt.mu.Unlock()

	nt.nonces = make(map[string]struct{})
}

// IsEnabled returns whether nonce tracking is enabled.
//
// Returns:
//   - true if tracking is active
//   - false if tracking is disabled
//
// Example:
//
//	if tracker.IsEnabled() {
//	    log.Info("Nonce tracking is active")
//	}
func (nt *NonceTracker) IsEnabled() bool {
	return nt.enabled
}

// SetEnabled enables or disables nonce tracking.
//
// Disabling tracking does not clear existing nonces.
// Re-enabling tracking will resume checking against previously tracked nonces.
//
// Thread safety: This method is safe for concurrent use.
//
// Parameters:
//   - enabled: true to enable tracking, false to disable
//
// Example:
//
//	// Temporarily disable for testing
//	tracker.SetEnabled(false)
//	// ... perform test operations ...
//	tracker.SetEnabled(true)
func (nt *NonceTracker) SetEnabled(enabled bool) {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	nt.enabled = enabled
}
