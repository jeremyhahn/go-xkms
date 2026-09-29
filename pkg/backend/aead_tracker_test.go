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

package backend

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestDefaultAEADOptions(t *testing.T) {
	opts := types.DefaultAEADOptions()

	if !opts.NonceTracking {
		t.Error("Expected NonceTracking to be enabled by default")
	}

	if !opts.BytesTracking {
		t.Error("Expected BytesTracking to be enabled by default")
	}

	expectedLimit := int64(350 * 1024 * 1024 * 1024) // 350 GB
	if opts.BytesTrackingLimit != expectedLimit {
		t.Errorf("Expected BytesTrackingLimit to be %d, got %d", expectedLimit, opts.BytesTrackingLimit)
	}

	if opts.NonceSize != 12 {
		t.Errorf("Expected NonceSize to be 12, got %d", opts.NonceSize)
	}
}

func TestAEADOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *types.AEADOptions
		wantErr bool
	}{
		{
			name: "valid default options",
			opts: &types.AEADOptions{
				NonceTracking:      true,
				BytesTracking:      true,
				BytesTrackingLimit: 350 * 1024 * 1024 * 1024,
				NonceSize:          12,
			},
			wantErr: false,
		},
		{
			name: "zero nonce size gets default",
			opts: &types.AEADOptions{
				NonceSize: 0,
			},
			wantErr: false,
		},
		{
			name: "nonce size too small",
			opts: &types.AEADOptions{
				NonceSize: 8,
			},
			wantErr: true,
		},
		{
			name: "zero bytes limit gets default",
			opts: &types.AEADOptions{
				BytesTracking:      true,
				BytesTrackingLimit: 0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Check that defaults were applied
			if !tt.wantErr && tt.opts.NonceSize == 0 {
				t.Error("Expected NonceSize to be set to default 12")
			}

			if !tt.wantErr && tt.opts.BytesTracking && tt.opts.BytesTrackingLimit == 0 {
				t.Error("Expected BytesTrackingLimit to be set to default")
			}
		})
	}
}

// Nonce-reuse tracking is no longer part of memoryAEADTracker: go-xkms#1201
// moved it to the single, atomic, optionally-persistent aead.KeyNonceGuard
// every backend's Encrypt path claims through (see ClaimAEADNonce in
// aead_nonce.go and its tests in aead_nonce_test.go). The tests below cover
// this tracker's remaining responsibility, the NIST SP 800-38D
// bytes-encrypted budget.

func TestMemoryAEADTracker_BytesTracking(t *testing.T) {
	tracker := NewMemoryAEADTracker()
	keyID := "test:key:3"

	// Set up tracking with a small limit for testing
	opts := &types.AEADOptions{
		NonceTracking:      false,
		BytesTracking:      true,
		BytesTrackingLimit: 1000,
		NonceSize:          12,
	}
	err := tracker.SetAEADOptions(keyID, opts)
	if err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	// Encrypt 500 bytes - should succeed
	err = tracker.IncrementBytes(keyID, 500)
	if err != nil {
		t.Errorf("IncrementBytes(500) failed: %v", err)
	}

	// Check current bytes
	total, err := tracker.GetBytesEncrypted(keyID)
	if err != nil {
		t.Fatalf("GetBytesEncrypted() failed: %v", err)
	}
	if total != 500 {
		t.Errorf("Expected 500 bytes, got %d", total)
	}

	// Encrypt another 400 bytes - should succeed (900 total)
	err = tracker.IncrementBytes(keyID, 400)
	if err != nil {
		t.Errorf("IncrementBytes(400) failed: %v", err)
	}

	total, _ = tracker.GetBytesEncrypted(keyID)
	if total != 900 {
		t.Errorf("Expected 900 bytes, got %d", total)
	}

	// Try to encrypt 200 more bytes - should fail (would exceed 1000)
	err = tracker.IncrementBytes(keyID, 200)
	if err != ErrBytesLimitExceeded {
		t.Errorf("IncrementBytes() should return ErrBytesLimitExceeded, got: %v", err)
	}

	// Bytes should not have incremented
	total, _ = tracker.GetBytesEncrypted(keyID)
	if total != 900 {
		t.Errorf("Expected bytes to remain at 900, got %d", total)
	}
}

func TestMemoryAEADTracker_BytesTrackingDisabled(t *testing.T) {
	tracker := NewMemoryAEADTracker()
	keyID := "test:key:4"

	// Set up tracking with bytes tracking disabled
	opts := &types.AEADOptions{
		NonceTracking:      false,
		BytesTracking:      false,
		BytesTrackingLimit: 1000,
		NonceSize:          12,
	}
	err := tracker.SetAEADOptions(keyID, opts)
	if err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	// Should be able to encrypt unlimited bytes when tracking is disabled
	err = tracker.IncrementBytes(keyID, 10000)
	if err != nil {
		t.Errorf("IncrementBytes() should succeed when tracking disabled: %v", err)
	}

	// Counter should not have incremented
	total, _ := tracker.GetBytesEncrypted(keyID)
	if total != 0 {
		t.Errorf("Expected 0 bytes when tracking disabled, got %d", total)
	}
}

func TestMemoryAEADTracker_ResetTracking(t *testing.T) {
	tracker := NewMemoryAEADTracker()
	keyID := "test:key:5"

	// Set up tracking
	opts := types.DefaultAEADOptions()
	err := tracker.SetAEADOptions(keyID, opts)
	if err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	// Record some state
	if err := tracker.IncrementBytes(keyID, 1000); err != nil {
		t.Fatal(err)
	}

	total, _ := tracker.GetBytesEncrypted(keyID)
	if total != 1000 {
		t.Errorf("Expected 1000 bytes, got %d", total)
	}

	// Reset tracking
	err = tracker.ResetTracking(keyID)
	if err != nil {
		t.Fatalf("ResetTracking() failed: %v", err)
	}

	total, _ = tracker.GetBytesEncrypted(keyID)
	if total != 0 {
		t.Errorf("Expected 0 bytes after reset, got %d", total)
	}
}

func TestMemoryAEADTracker_GetSetOptions(t *testing.T) {
	tracker := NewMemoryAEADTracker()
	keyID := "test:key:6"

	// Initially no options
	opts, err := tracker.GetAEADOptions(keyID)
	if err != nil {
		t.Fatalf("GetAEADOptions() failed: %v", err)
	}
	if opts != nil {
		t.Error("Expected nil options for unconfigured key")
	}

	// Set options
	testOpts := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      true,
		BytesTrackingLimit: 123456,
		NonceSize:          12,
	}
	err = tracker.SetAEADOptions(keyID, testOpts)
	if err != nil {
		t.Fatalf("SetAEADOptions() failed: %v", err)
	}

	// Get options back
	retrieved, err := tracker.GetAEADOptions(keyID)
	if err != nil {
		t.Fatalf("GetAEADOptions() failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected options, got nil")
		return
	}

	if retrieved.NonceTracking != testOpts.NonceTracking {
		t.Error("NonceTracking mismatch")
	}
	if retrieved.BytesTracking != testOpts.BytesTracking {
		t.Error("BytesTracking mismatch")
	}
	if retrieved.BytesTrackingLimit != testOpts.BytesTrackingLimit {
		t.Error("BytesTrackingLimit mismatch")
	}
	if retrieved.NonceSize != testOpts.NonceSize {
		t.Error("NonceSize mismatch")
	}

	// Verify we got a copy (not the same pointer)
	if retrieved == testOpts {
		t.Error("GetAEADOptions should return a copy, not the original")
	}
}

func TestMemoryAEADTracker_NilOptions(t *testing.T) {
	tracker := NewMemoryAEADTracker()
	keyID := "test:key:7"

	// Setting nil options should fail
	err := tracker.SetAEADOptions(keyID, nil)
	if err == nil {
		t.Error("SetAEADOptions(nil) should return error")
	}
}

func TestMemoryAEADTracker_InvalidOptions(t *testing.T) {
	tracker := NewMemoryAEADTracker()
	keyID := "test:key:8"

	// Setting invalid options should fail
	invalidOpts := &types.AEADOptions{
		NonceSize: 8, // Too small
	}

	err := tracker.SetAEADOptions(keyID, invalidOpts)
	if err == nil {
		t.Error("SetAEADOptions() should fail for invalid options")
	}
}

func TestMemoryAEADTracker_MultipleKeys(t *testing.T) {
	tracker := NewMemoryAEADTracker()

	// Set up tracking for multiple keys
	key1 := "test:key:9"
	key2 := "test:key:10"

	opts1 := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      true,
		BytesTrackingLimit: 1000,
		NonceSize:          12,
	}

	opts2 := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      true,
		BytesTrackingLimit: 2000,
		NonceSize:          12,
	}

	if err := tracker.SetAEADOptions(key1, opts1); err != nil {
		t.Fatal(err)
	}
	if err := tracker.SetAEADOptions(key2, opts2); err != nil {
		t.Fatal(err)
	}

	// Encrypt bytes for each key
	if err := tracker.IncrementBytes(key1, 500); err != nil {
		t.Fatal(err)
	}
	if err := tracker.IncrementBytes(key2, 1500); err != nil {
		t.Fatal(err)
	}

	// Check totals
	total1, _ := tracker.GetBytesEncrypted(key1)
	total2, _ := tracker.GetBytesEncrypted(key2)

	if total1 != 500 {
		t.Errorf("key1: expected 500 bytes, got %d", total1)
	}

	if total2 != 1500 {
		t.Errorf("key2: expected 1500 bytes, got %d", total2)
	}

	// key1 can encrypt 500 more (limit 1000)
	if err := tracker.IncrementBytes(key1, 500); err != nil {
		t.Errorf("key1 should be able to encrypt 500 more bytes: %v", err)
	}

	// key1 cannot encrypt 1 more (would exceed limit)
	if err := tracker.IncrementBytes(key1, 1); err != ErrBytesLimitExceeded {
		t.Errorf("key1 should hit limit: %v", err)
	}

	// key2 can encrypt 500 more (limit 2000)
	if err := tracker.IncrementBytes(key2, 500); err != nil {
		t.Errorf("key2 should be able to encrypt 500 more bytes: %v", err)
	}
}

func BenchmarkMemoryAEADTracker_IncrementBytes(b *testing.B) {
	tracker := NewMemoryAEADTracker()
	keyID := "bench:key:3"

	opts := &types.AEADOptions{
		NonceTracking:      false,
		BytesTracking:      true,
		BytesTrackingLimit: 1024 * 1024 * 1024 * 1024, // 1TB for bench
		NonceSize:          12,
	}
	_ = tracker.SetAEADOptions(keyID, opts)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tracker.IncrementBytes(keyID, 1024)
	}
}
