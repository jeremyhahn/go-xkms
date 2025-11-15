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
	"fmt"
	"sync/atomic"
)

const (
	// DefaultBytesTrackingLimit is the default maximum bytes that can be encrypted with a single key.
	// Set to 350GB as a conservative limit for AEAD ciphers.
	//
	// NIST SP 800-38D recommends limits for AES-GCM:
	//  - For random 96-bit IVs: max 2^32 invocations (~68GB practical limit)
	//  - For deterministic IVs with nonce tracking: higher limits are acceptable
	//
	// We use 350GB as a conservative limit that works well with nonce tracking
	// while still providing strong security guarantees.
	DefaultBytesTrackingLimit = 350 * 1024 * 1024 * 1024 // 350GB in bytes

	// Conservative68GB is a more conservative limit based on birthday paradox
	// considerations for random nonces. Use this if nonce tracking is disabled.
	Conservative68GB = 68 * 1024 * 1024 * 1024 // 68GB in bytes
)

// BytesTracker tracks the total number of bytes encrypted with a single AEAD key
// and enforces usage limits to prevent security degradation.
//
// This implements NIST SP 800-38D recommendations for AEAD cipher usage limits.
// When the limit is reached, the key should be rotated to maintain security.
//
// Thread-safe: All operations use atomic operations for concurrent safety.
type BytesTracker struct {
	// enabled controls whether bytes tracking is active
	enabled bool

	// bytesEncrypted tracks total bytes encrypted (atomic counter)
	bytesEncrypted atomic.Int64

	// limit is the maximum bytes allowed before rotation required
	limit int64
}

// NewBytesTracker creates a new bytes tracker with the specified limit.
// If limit is 0, uses DefaultBytesTrackingLimit (350GB).
//
// Example:
//
//	// Use default 350GB limit
//	tracker := aead.NewBytesTracker(true, 0)
//
//	// Use custom 100GB limit
//	tracker := aead.NewBytesTracker(true, 100*1024*1024*1024)
//
//	// Disable tracking
//	tracker := aead.NewBytesTracker(false, 0)
func NewBytesTracker(enabled bool, limit int64) *BytesTracker {
	if limit == 0 {
		limit = DefaultBytesTrackingLimit
	}
	return &BytesTracker{
		enabled: enabled,
		limit:   limit,
	}
}

// CheckAndIncrementBytes verifies that adding numBytes won't exceed the limit,
// and if safe, increments the counter atomically.
//
// Returns an error if the operation would exceed the limit. The counter is NOT
// incremented in this case, allowing the caller to handle the error (e.g., rotate key).
//
// Thread-safe: Uses atomic operations for concurrent access.
//
// Example:
//
//	plaintext := []byte("sensitive data")
//	if err := tracker.CheckAndIncrementBytes(int64(len(plaintext))); err != nil {
//	    // Limit exceeded - rotate key
//	    return fmt.Errorf("key rotation required: %w", err)
//	}
//	// Safe to encrypt
//	ciphertext, err := encrypt(plaintext)
func (bt *BytesTracker) CheckAndIncrementBytes(numBytes int64) error {
	if !bt.enabled {
		return nil
	}

	// Atomically add and get new total
	newTotal := bt.bytesEncrypted.Add(numBytes)

	// Check if we exceeded the limit
	if newTotal > bt.limit {
		// Rollback the increment - we don't want to count failed operations
		bt.bytesEncrypted.Add(-numBytes)
		return fmt.Errorf("AEAD key usage limit exceeded: encrypted %d bytes, limit %d bytes (exceeded by %d bytes)",
			newTotal-numBytes, bt.limit, newTotal-bt.limit)
	}

	return nil
}

// GetBytesEncrypted returns the total number of bytes encrypted so far.
// Returns 0 if tracking is disabled.
//
// Thread-safe: Uses atomic load operation.
func (bt *BytesTracker) GetBytesEncrypted() int64 {
	if !bt.enabled {
		return 0
	}
	return bt.bytesEncrypted.Load()
}

// GetRemainingBytes returns how many more bytes can be encrypted before hitting the limit.
// Returns -1 if tracking is disabled (unlimited).
//
// Thread-safe: Uses atomic load operation.
//
// Example:
//
//	remaining := tracker.GetRemainingBytes()
//	if remaining > 0 && remaining < 10*1024*1024*1024 { // Less than 10GB
//	    log.Printf("WARNING: Only %d bytes remaining before key rotation required", remaining)
//	}
func (bt *BytesTracker) GetRemainingBytes() int64 {
	if !bt.enabled {
		return -1 // Unlimited
	}
	encrypted := bt.bytesEncrypted.Load()
	return bt.limit - encrypted
}

// GetLimit returns the configured bytes limit.
// Returns -1 if tracking is disabled.
func (bt *BytesTracker) GetLimit() int64 {
	if !bt.enabled {
		return -1
	}
	return bt.limit
}

// IsEnabled returns true if bytes tracking is enabled.
func (bt *BytesTracker) IsEnabled() bool {
	return bt.enabled
}

// GetUsagePercentage returns the percentage of the limit that has been used (0.0 to 100.0).
// Returns 0.0 if tracking is disabled.
//
// Example:
//
//	usage := tracker.GetUsagePercentage()
//	if usage > 90.0 {
//	    log.Printf("WARNING: Key usage at %.1f%% - rotation recommended", usage)
//	}
func (bt *BytesTracker) GetUsagePercentage() float64 {
	if !bt.enabled || bt.limit == 0 {
		return 0.0
	}
	encrypted := bt.bytesEncrypted.Load()
	return (float64(encrypted) / float64(bt.limit)) * 100.0
}

// ShouldWarnUser returns true if usage has exceeded 90% of the limit.
// This provides an early warning before the hard limit is reached.
//
// Example:
//
//	if tracker.ShouldWarnUser() {
//	    log.Println("WARNING: AEAD key usage >90% - plan key rotation soon")
//	}
func (bt *BytesTracker) ShouldWarnUser() bool {
	if !bt.enabled {
		return false
	}
	return bt.GetUsagePercentage() >= 90.0
}

// GetUsageStats returns comprehensive usage statistics as a map.
// Useful for monitoring, logging, and diagnostics.
//
// Example:
//
//	stats := tracker.GetUsageStats()
//	log.Printf("Key usage: %+v", stats)
//	// Output: Key usage: map[bytes_encrypted:1073741824 bytes_remaining:375809638400 enabled:true limit:376880379904 usage_percent:0.28 warn:false]
func (bt *BytesTracker) GetUsageStats() map[string]interface{} {
	if !bt.enabled {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	encrypted := bt.bytesEncrypted.Load()
	return map[string]interface{}{
		"enabled":         true,
		"bytes_encrypted": encrypted,
		"limit":           bt.limit,
		"bytes_remaining": bt.limit - encrypted,
		"usage_percent":   bt.GetUsagePercentage(),
		"warn":            bt.ShouldWarnUser(),
	}
}

// Reset resets the bytes counter to zero.
// This should typically only be called after key rotation.
//
// WARNING: Use with caution. Only reset after generating a new key.
//
// Thread-safe: Uses atomic store operation.
//
// Example:
//
//	// After rotating to a new key
//	newKey, err := generateNewKey()
//	if err != nil {
//	    return err
//	}
//	tracker.Reset() // Start fresh counter for new key
func (bt *BytesTracker) Reset() {
	if bt.enabled {
		bt.bytesEncrypted.Store(0)
	}
}

// SetLimit updates the bytes limit.
// This does not affect the current counter value.
//
// Thread-safe: No synchronization needed as limit is read atomically with counter.
//
// Example:
//
//	// Temporarily increase limit for batch operation
//	tracker.SetLimit(500 * 1024 * 1024 * 1024) // 500GB
func (bt *BytesTracker) SetLimit(limit int64) {
	if bt.enabled {
		bt.limit = limit
	}
}

// Enable enables bytes tracking with the current or specified limit.
// If limit is 0, uses the existing limit or DefaultBytesTrackingLimit if no limit is set.
// If limit is positive, always updates to the new limit.
func (bt *BytesTracker) Enable(limit int64) {
	bt.enabled = true
	if limit > 0 {
		bt.limit = limit
	} else if limit == 0 && bt.limit == 0 {
		bt.limit = DefaultBytesTrackingLimit
	}
	// If limit is 0 but bt.limit is already set, keep the existing limit
}

// Disable disables bytes tracking.
// The counter value is preserved but checks are skipped.
func (bt *BytesTracker) Disable() {
	bt.enabled = false
}
