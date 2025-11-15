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

//go:build integration

package crypto_test

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAEAD_AutoSelection(t *testing.T) {
	tests := []struct {
		name             string
		isHardwareBacked bool
		expectAES        bool
		expectChaCha     bool
	}{
		{
			name:             "Hardware-backed key always selects AES",
			isHardwareBacked: true,
			expectAES:        true,
			expectChaCha:     false,
		},
		{
			name:             "Software key selection depends on CPU",
			isHardwareBacked: false,
			expectAES:        aead.HasAESNI(),
			expectChaCha:     !aead.HasAESNI(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo := aead.SelectOptimal(tt.isHardwareBacked)

			if tt.expectAES {
				assert.Equal(t, aead.AES256GCM, algo, "Expected AES-256-GCM")
				assert.True(t, aead.IsAESGCM(algo), "Should be identified as AES-GCM")
				assert.False(t, aead.IsChaCha(algo), "Should not be identified as ChaCha")
			}

			if tt.expectChaCha {
				assert.Equal(t, aead.ChaCha20Poly1305, algo, "Expected ChaCha20-Poly1305")
				assert.True(t, aead.IsChaCha(algo), "Should be identified as ChaCha")
				assert.False(t, aead.IsAESGCM(algo), "Should not be identified as AES-GCM")
			}
		})
	}
}

func TestAEAD_BackendSelection(t *testing.T) {
	tests := []struct {
		name             string
		isHardwareBacked bool
		expected         string
	}{
		{
			name:             "Hardware-backed key selects aes256-gcm",
			isHardwareBacked: true,
			expected:         aead.BackendAES256GCM,
		},
		{
			name:             "Software key with AES-NI selects aes256-gcm",
			isHardwareBacked: false,
			expected: func() string {
				if aead.HasAESNI() {
					return aead.BackendAES256GCM
				}
				return aead.BackendChaCha20Poly1305
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo := aead.SelectOptimalBackend(tt.isHardwareBacked)
			assert.Equal(t, tt.expected, algo)
		})
	}
}

func TestAEAD_AlgorithmConversion(t *testing.T) {
	tests := []struct {
		name    string
		jwe     string
		backend string
	}{
		{
			name:    "AES-128-GCM conversion",
			jwe:     aead.AES128GCM,
			backend: aead.BackendAES128GCM,
		},
		{
			name:    "AES-192-GCM conversion",
			jwe:     aead.AES192GCM,
			backend: aead.BackendAES192GCM,
		},
		{
			name:    "AES-256-GCM conversion",
			jwe:     aead.AES256GCM,
			backend: aead.BackendAES256GCM,
		},
		{
			name:    "ChaCha20-Poly1305 conversion",
			jwe:     aead.ChaCha20Poly1305,
			backend: aead.BackendChaCha20Poly1305,
		},
		{
			name:    "XChaCha20-Poly1305 conversion",
			jwe:     aead.XChaCha20Poly1305,
			backend: aead.BackendXChaCha20Poly1305,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// JWE to Backend
			backendAlgo := aead.ToBackend(tt.jwe)
			assert.Equal(t, tt.backend, backendAlgo)

			// Backend to JWE
			jweAlgo := aead.ToJWE(tt.backend)
			assert.Equal(t, tt.jwe, jweAlgo)

			// Round-trip conversion
			roundTrip := aead.ToJWE(aead.ToBackend(tt.jwe))
			assert.Equal(t, tt.jwe, roundTrip)
		})
	}
}

func TestAEAD_AlgorithmIdentification(t *testing.T) {
	aesAlgorithms := []string{
		aead.AES128GCM,
		aead.AES192GCM,
		aead.AES256GCM,
		aead.BackendAES128GCM,
		aead.BackendAES192GCM,
		aead.BackendAES256GCM,
	}

	chachaAlgorithms := []string{
		aead.ChaCha20Poly1305,
		aead.XChaCha20Poly1305,
		aead.BackendChaCha20Poly1305,
		aead.BackendXChaCha20Poly1305,
	}

	for _, algo := range aesAlgorithms {
		t.Run(fmt.Sprintf("IsAESGCM_%s", algo), func(t *testing.T) {
			assert.True(t, aead.IsAESGCM(algo))
			assert.False(t, aead.IsChaCha(algo))
		})
	}

	for _, algo := range chachaAlgorithms {
		t.Run(fmt.Sprintf("IsChaCha_%s", algo), func(t *testing.T) {
			assert.True(t, aead.IsChaCha(algo))
			assert.False(t, aead.IsAESGCM(algo))
		})
	}

	// Test unknown algorithm
	t.Run("Unknown algorithm", func(t *testing.T) {
		assert.False(t, aead.IsAESGCM("unknown"))
		assert.False(t, aead.IsChaCha("unknown"))
	})
}

func TestNonceTracker_BasicOperations(t *testing.T) {
	tracker := aead.NewNonceTracker(true)
	require.NotNil(t, tracker)
	assert.True(t, tracker.IsEnabled())

	// Generate test nonces
	nonce1 := make([]byte, 12)
	nonce2 := make([]byte, 12)
	_, err := rand.Read(nonce1)
	require.NoError(t, err)
	_, err = rand.Read(nonce2)
	require.NoError(t, err)

	// First use should succeed
	err = tracker.CheckAndRecordNonce(nonce1)
	assert.NoError(t, err)
	assert.Equal(t, 1, tracker.Count())

	// Second use of same nonce should fail
	err = tracker.CheckAndRecordNonce(nonce1)
	assert.Error(t, err)
	assert.ErrorIs(t, err, aead.ErrNonceReuse)

	// Different nonce should succeed
	err = tracker.CheckAndRecordNonce(nonce2)
	assert.NoError(t, err)
	assert.Equal(t, 2, tracker.Count())

	// Check Contains
	assert.True(t, tracker.Contains(nonce1))
	assert.True(t, tracker.Contains(nonce2))

	nonce3 := make([]byte, 12)
	_, err = rand.Read(nonce3)
	require.NoError(t, err)
	assert.False(t, tracker.Contains(nonce3))
}

func TestNonceTracker_DisabledTracking(t *testing.T) {
	tracker := aead.NewNonceTracker(false)
	require.NotNil(t, tracker)
	assert.False(t, tracker.IsEnabled())

	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	// With tracking disabled, should always succeed
	err = tracker.CheckAndRecordNonce(nonce)
	assert.NoError(t, err)

	err = tracker.CheckAndRecordNonce(nonce)
	assert.NoError(t, err)

	assert.Equal(t, 0, tracker.Count())
	assert.False(t, tracker.Contains(nonce))
}

func TestNonceTracker_ConcurrentAccess(t *testing.T) {
	tracker := aead.NewNonceTracker(true)
	const numGoroutines = 100
	const noncesPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*noncesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < noncesPerGoroutine; j++ {
				nonce := make([]byte, 12)
				_, err := rand.Read(nonce)
				if err != nil {
					errors <- err
					return
				}
				err = tracker.CheckAndRecordNonce(nonce)
				if err != nil {
					errors <- err
				}
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors (should be none since all nonces are unique)
	for err := range errors {
		t.Errorf("Unexpected error: %v", err)
	}

	expectedCount := numGoroutines * noncesPerGoroutine
	assert.Equal(t, expectedCount, tracker.Count())
}

func TestNonceTracker_ClearAndReset(t *testing.T) {
	tracker := aead.NewNonceTracker(true)

	// Add some nonces
	for i := 0; i < 10; i++ {
		nonce := make([]byte, 12)
		_, err := rand.Read(nonce)
		require.NoError(t, err)
		err = tracker.CheckAndRecordNonce(nonce)
		require.NoError(t, err)
	}

	assert.Equal(t, 10, tracker.Count())

	// Clear tracker
	tracker.Clear()
	assert.Equal(t, 0, tracker.Count())

	// Should be able to add nonces again
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	err = tracker.CheckAndRecordNonce(nonce)
	assert.NoError(t, err)
	assert.Equal(t, 1, tracker.Count())
}

func TestNonceTracker_EnableDisable(t *testing.T) {
	tracker := aead.NewNonceTracker(true)

	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	// Track a nonce
	err = tracker.CheckAndRecordNonce(nonce)
	assert.NoError(t, err)

	// Disable tracking
	tracker.SetEnabled(false)
	assert.False(t, tracker.IsEnabled())

	// Same nonce should now succeed
	err = tracker.CheckAndRecordNonce(nonce)
	assert.NoError(t, err)

	// Re-enable tracking
	tracker.SetEnabled(true)
	assert.True(t, tracker.IsEnabled())

	// Same nonce should fail again (it's still in the tracker)
	err = tracker.CheckAndRecordNonce(nonce)
	assert.Error(t, err)
}

func TestBytesTracker_BasicOperations(t *testing.T) {
	limit := int64(1024 * 1024) // 1 MB
	tracker := aead.NewBytesTracker(true, limit)
	require.NotNil(t, tracker)
	assert.True(t, tracker.IsEnabled())
	assert.Equal(t, limit, tracker.GetLimit())

	// Should be able to encrypt up to limit
	err := tracker.CheckAndIncrementBytes(512 * 1024)
	assert.NoError(t, err)
	assert.Equal(t, int64(512*1024), tracker.GetBytesEncrypted())
	assert.Equal(t, int64(512*1024), tracker.GetRemainingBytes())

	// Should be able to encrypt more
	err = tracker.CheckAndIncrementBytes(400 * 1024)
	assert.NoError(t, err)
	assert.Equal(t, int64(912*1024), tracker.GetBytesEncrypted())

	// Exceeding limit should fail
	err = tracker.CheckAndIncrementBytes(200 * 1024)
	assert.Error(t, err)
	// Counter should not have incremented
	assert.Equal(t, int64(912*1024), tracker.GetBytesEncrypted())

	// Should be able to encrypt remaining bytes
	remaining := tracker.GetRemainingBytes()
	err = tracker.CheckAndIncrementBytes(remaining)
	assert.NoError(t, err)
	assert.Equal(t, limit, tracker.GetBytesEncrypted())
	assert.Equal(t, int64(0), tracker.GetRemainingBytes())
}

func TestBytesTracker_DefaultLimit(t *testing.T) {
	tracker := aead.NewBytesTracker(true, 0)
	assert.Equal(t, int64(aead.DefaultBytesTrackingLimit), tracker.GetLimit())
}

func TestBytesTracker_DisabledTracking(t *testing.T) {
	tracker := aead.NewBytesTracker(false, 1024)
	assert.False(t, tracker.IsEnabled())
	assert.Equal(t, int64(-1), tracker.GetLimit())
	assert.Equal(t, int64(-1), tracker.GetRemainingBytes())

	// Should always succeed
	err := tracker.CheckAndIncrementBytes(1000000)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), tracker.GetBytesEncrypted())
}

func TestBytesTracker_UsagePercentage(t *testing.T) {
	limit := int64(1000)
	tracker := aead.NewBytesTracker(true, limit)

	tests := []struct {
		bytes           int64
		expectedPercent float64
		shouldWarn      bool
	}{
		{100, 10.0, false},
		{400, 50.0, false},
		{400, 90.0, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Usage_%d_bytes", tt.bytes), func(t *testing.T) {
			err := tracker.CheckAndIncrementBytes(tt.bytes)
			require.NoError(t, err)

			percentage := tracker.GetUsagePercentage()
			assert.InDelta(t, tt.expectedPercent, percentage, 0.1)
			assert.Equal(t, tt.shouldWarn, tracker.ShouldWarnUser())
		})
	}
}

func TestBytesTracker_UsageStats(t *testing.T) {
	limit := int64(2000)
	tracker := aead.NewBytesTracker(true, limit)

	err := tracker.CheckAndIncrementBytes(1000)
	require.NoError(t, err)

	stats := tracker.GetUsageStats()
	assert.Equal(t, true, stats["enabled"])
	assert.Equal(t, int64(1000), stats["bytes_encrypted"])
	assert.Equal(t, limit, stats["limit"])
	assert.Equal(t, int64(1000), stats["bytes_remaining"])
	assert.Equal(t, 50.0, stats["usage_percent"])
	assert.Equal(t, false, stats["warn"])
}

func TestBytesTracker_Reset(t *testing.T) {
	tracker := aead.NewBytesTracker(true, 1000)

	err := tracker.CheckAndIncrementBytes(500)
	require.NoError(t, err)
	assert.Equal(t, int64(500), tracker.GetBytesEncrypted())

	tracker.Reset()
	assert.Equal(t, int64(0), tracker.GetBytesEncrypted())
	assert.Equal(t, int64(1000), tracker.GetRemainingBytes())
}

func TestBytesTracker_SetLimit(t *testing.T) {
	tracker := aead.NewBytesTracker(true, 1000)

	err := tracker.CheckAndIncrementBytes(500)
	require.NoError(t, err)

	// Increase limit
	tracker.SetLimit(2000)
	assert.Equal(t, int64(2000), tracker.GetLimit())
	assert.Equal(t, int64(1500), tracker.GetRemainingBytes())

	// Decrease limit
	tracker.SetLimit(600)
	assert.Equal(t, int64(600), tracker.GetLimit())
	assert.Equal(t, int64(100), tracker.GetRemainingBytes())
}

func TestBytesTracker_EnableDisable(t *testing.T) {
	tracker := aead.NewBytesTracker(false, 1000)
	assert.False(t, tracker.IsEnabled())

	// Enable with existing limit
	tracker.Enable(0)
	assert.True(t, tracker.IsEnabled())
	assert.Equal(t, int64(1000), tracker.GetLimit())

	// Disable
	tracker.Disable()
	assert.False(t, tracker.IsEnabled())

	// Enable with new limit
	tracker.Enable(5000)
	assert.True(t, tracker.IsEnabled())
	assert.Equal(t, int64(5000), tracker.GetLimit())
}

func TestBytesTracker_ConcurrentAccess(t *testing.T) {
	limit := int64(10000)
	tracker := aead.NewBytesTracker(true, limit)
	const numGoroutines = 100
	const bytesPerOp = 10

	var wg sync.WaitGroup
	successCount := int64(0)
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				err := tracker.CheckAndIncrementBytes(bytesPerOp)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	// Total bytes encrypted should equal successful operations
	expectedBytes := successCount * bytesPerOp
	assert.Equal(t, expectedBytes, tracker.GetBytesEncrypted())
	assert.LessOrEqual(t, tracker.GetBytesEncrypted(), limit)
}

func TestBytesTracker_ConservativeLimit(t *testing.T) {
	tracker := aead.NewBytesTracker(true, aead.Conservative68GB)
	assert.Equal(t, int64(aead.Conservative68GB), tracker.GetLimit())

	// Should be significantly less than default limit
	assert.Less(t, int64(aead.Conservative68GB), int64(aead.DefaultBytesTrackingLimit))
}
