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
	"sync"
	"testing"
)

func TestNewBytesTracker(t *testing.T) {
	tests := []struct {
		name          string
		enabled       bool
		limit         int64
		expectedLimit int64
	}{
		{
			name:          "default limit when zero",
			enabled:       true,
			limit:         0,
			expectedLimit: DefaultBytesTrackingLimit,
		},
		{
			name:          "custom limit",
			enabled:       true,
			limit:         100 * 1024 * 1024, // 100MB
			expectedLimit: 100 * 1024 * 1024,
		},
		{
			name:          "disabled with zero limit",
			enabled:       false,
			limit:         0,
			expectedLimit: DefaultBytesTrackingLimit,
		},
		{
			name:          "disabled with custom limit",
			enabled:       false,
			limit:         50 * 1024 * 1024,
			expectedLimit: 50 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewBytesTracker(tt.enabled, tt.limit)
			if tracker.IsEnabled() != tt.enabled {
				t.Errorf("IsEnabled() = %v, want %v", tracker.IsEnabled(), tt.enabled)
			}
			if tt.enabled && tracker.GetLimit() != tt.expectedLimit {
				t.Errorf("GetLimit() = %d, want %d", tracker.GetLimit(), tt.expectedLimit)
			}
			if tracker.GetBytesEncrypted() != 0 {
				t.Errorf("GetBytesEncrypted() = %d, want 0", tracker.GetBytesEncrypted())
			}
		})
	}
}

func TestBytesTracker_CheckAndIncrementBytes(t *testing.T) {
	tests := []struct {
		name        string
		limit       int64
		operations  []int64
		expectError bool
		errorOnOp   int // Which operation should fail (0-based)
	}{
		{
			name:        "single small operation",
			limit:       1024,
			operations:  []int64{512},
			expectError: false,
		},
		{
			name:        "multiple operations within limit",
			limit:       1024,
			operations:  []int64{256, 256, 256, 256},
			expectError: false,
		},
		{
			name:        "operation exactly at limit",
			limit:       1024,
			operations:  []int64{1024},
			expectError: false,
		},
		{
			name:        "operation exceeds limit",
			limit:       1024,
			operations:  []int64{2048},
			expectError: true,
			errorOnOp:   0,
		},
		{
			name:        "cumulative exceeds limit",
			limit:       1024,
			operations:  []int64{512, 512, 512},
			expectError: true,
			errorOnOp:   2,
		},
		{
			name:        "zero bytes operation",
			limit:       1024,
			operations:  []int64{0, 512, 0},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewBytesTracker(true, tt.limit)
			var totalEncrypted int64
			errorOccurred := false

			for i, numBytes := range tt.operations {
				err := tracker.CheckAndIncrementBytes(numBytes)
				if err != nil {
					if !tt.expectError {
						t.Errorf("operation %d: unexpected error: %v", i, err)
					}
					if tt.expectError && i != tt.errorOnOp {
						t.Errorf("error on operation %d, expected on operation %d", i, tt.errorOnOp)
					}
					errorOccurred = true
					break
				}
				totalEncrypted += numBytes
			}

			if tt.expectError && !errorOccurred {
				t.Error("expected error but none occurred")
			}

			if !errorOccurred {
				encrypted := tracker.GetBytesEncrypted()
				if encrypted != totalEncrypted {
					t.Errorf("GetBytesEncrypted() = %d, want %d", encrypted, totalEncrypted)
				}
			}
		})
	}
}

func TestBytesTracker_Disabled(t *testing.T) {
	tracker := NewBytesTracker(false, 1024)

	// Should allow any amount when disabled
	err := tracker.CheckAndIncrementBytes(1000000)
	if err != nil {
		t.Errorf("disabled tracker should not error: %v", err)
	}

	// Getters should return expected values when disabled
	if tracker.GetBytesEncrypted() != 0 {
		t.Errorf("GetBytesEncrypted() should return 0 when disabled")
	}
	if tracker.GetRemainingBytes() != -1 {
		t.Errorf("GetRemainingBytes() should return -1 when disabled, got %d", tracker.GetRemainingBytes())
	}
	if tracker.GetUsagePercentage() != 0.0 {
		t.Errorf("GetUsagePercentage() should return 0.0 when disabled")
	}
	if tracker.ShouldWarnUser() {
		t.Error("ShouldWarnUser() should return false when disabled")
	}
}

func TestBytesTracker_GetRemainingBytes(t *testing.T) {
	tracker := NewBytesTracker(true, 1024)

	// Initially, all bytes are available
	if remaining := tracker.GetRemainingBytes(); remaining != 1024 {
		t.Errorf("GetRemainingBytes() = %d, want 1024", remaining)
	}

	// After encrypting some bytes
	err := tracker.CheckAndIncrementBytes(512)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if remaining := tracker.GetRemainingBytes(); remaining != 512 {
		t.Errorf("GetRemainingBytes() = %d, want 512", remaining)
	}

	// After encrypting more bytes
	err = tracker.CheckAndIncrementBytes(256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if remaining := tracker.GetRemainingBytes(); remaining != 256 {
		t.Errorf("GetRemainingBytes() = %d, want 256", remaining)
	}
}

func TestBytesTracker_GetUsagePercentage(t *testing.T) {
	tracker := NewBytesTracker(true, 1000)

	tests := []struct {
		name               string
		bytesToEncrypt     int64
		expectedPercentage float64
		tolerance          float64
	}{
		{"0%", 0, 0.0, 0.01},
		{"25%", 250, 25.0, 0.01},
		{"50%", 250, 50.0, 0.01},
		{"75%", 250, 75.0, 0.01},
		{"100%", 250, 100.0, 0.01},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tracker.CheckAndIncrementBytes(tt.bytesToEncrypt)
			if err != nil && tt.name != "100%" {
				t.Fatalf("unexpected error: %v", err)
			}

			percentage := tracker.GetUsagePercentage()
			diff := percentage - tt.expectedPercentage
			if diff < 0 {
				diff = -diff
			}
			if diff > tt.tolerance {
				t.Errorf("GetUsagePercentage() = %.2f, want %.2f", percentage, tt.expectedPercentage)
			}
		})
	}
}

func TestBytesTracker_ShouldWarnUser(t *testing.T) {
	tracker := NewBytesTracker(true, 1000)

	// Below 90% - no warning
	err := tracker.CheckAndIncrementBytes(800)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tracker.ShouldWarnUser() {
		t.Error("should not warn at 80% usage")
	}

	// At 90% - should warn
	err = tracker.CheckAndIncrementBytes(100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tracker.ShouldWarnUser() {
		t.Error("should warn at 90% usage")
	}

	// Above 90% - should warn
	err = tracker.CheckAndIncrementBytes(50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tracker.ShouldWarnUser() {
		t.Error("should warn at 95% usage")
	}
}

func TestBytesTracker_GetUsageStats(t *testing.T) {
	// Test disabled tracker
	disabledTracker := NewBytesTracker(false, 1000)
	stats := disabledTracker.GetUsageStats()
	if enabled, ok := stats["enabled"].(bool); !ok || enabled {
		t.Error("disabled tracker stats should show enabled=false")
	}
	if len(stats) != 1 {
		t.Errorf("disabled tracker stats should have 1 field, got %d", len(stats))
	}

	// Test enabled tracker
	tracker := NewBytesTracker(true, 1000)
	err := tracker.CheckAndIncrementBytes(500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats = tracker.GetUsageStats()

	// Check all expected fields
	if enabled, ok := stats["enabled"].(bool); !ok || !enabled {
		t.Error("enabled tracker stats should show enabled=true")
	}
	if encrypted, ok := stats["bytes_encrypted"].(int64); !ok || encrypted != 500 {
		t.Errorf("bytes_encrypted = %v, want 500", stats["bytes_encrypted"])
	}
	if limit, ok := stats["limit"].(int64); !ok || limit != 1000 {
		t.Errorf("limit = %v, want 1000", stats["limit"])
	}
	if remaining, ok := stats["bytes_remaining"].(int64); !ok || remaining != 500 {
		t.Errorf("bytes_remaining = %v, want 500", stats["bytes_remaining"])
	}
	if usage, ok := stats["usage_percent"].(float64); !ok || usage < 49.9 || usage > 50.1 {
		t.Errorf("usage_percent = %v, want ~50.0", stats["usage_percent"])
	}
	if warn, ok := stats["warn"].(bool); !ok || warn {
		t.Error("warn should be false at 50% usage")
	}
}

func TestBytesTracker_Reset(t *testing.T) {
	tracker := NewBytesTracker(true, 1000)

	// Encrypt some bytes
	err := tracker.CheckAndIncrementBytes(500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if encrypted := tracker.GetBytesEncrypted(); encrypted != 500 {
		t.Errorf("GetBytesEncrypted() = %d, want 500", encrypted)
	}

	// Reset
	tracker.Reset()

	if encrypted := tracker.GetBytesEncrypted(); encrypted != 0 {
		t.Errorf("after Reset(), GetBytesEncrypted() = %d, want 0", encrypted)
	}

	// Should be able to use full limit again
	err = tracker.CheckAndIncrementBytes(1000)
	if err != nil {
		t.Errorf("after Reset(), should be able to use full limit: %v", err)
	}
}

func TestBytesTracker_SetLimit(t *testing.T) {
	tracker := NewBytesTracker(true, 1000)

	// Encrypt some bytes
	err := tracker.CheckAndIncrementBytes(800)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Increase limit
	tracker.SetLimit(2000)

	// Should be able to encrypt more now
	err = tracker.CheckAndIncrementBytes(1000)
	if err != nil {
		t.Errorf("after increasing limit, should allow more bytes: %v", err)
	}

	// Reset and decrease limit
	tracker.Reset()
	tracker.SetLimit(500)

	// Should fail with smaller limit
	err = tracker.CheckAndIncrementBytes(600)
	if err == nil {
		t.Error("should fail when exceeding decreased limit")
	}
}

func TestBytesTracker_EnableDisable(t *testing.T) {
	tracker := NewBytesTracker(true, 1000)

	// Initially enabled
	if !tracker.IsEnabled() {
		t.Error("tracker should be enabled initially")
	}

	// Encrypt some bytes
	err := tracker.CheckAndIncrementBytes(500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Disable
	tracker.Disable()
	if tracker.IsEnabled() {
		t.Error("tracker should be disabled after Disable()")
	}

	// Should allow any amount when disabled
	err = tracker.CheckAndIncrementBytes(10000)
	if err != nil {
		t.Error("disabled tracker should not enforce limits")
	}

	// Counter should still be at 500 (disable doesn't reset)
	// Re-enable to check
	tracker.Enable(1000)
	if tracker.GetBytesEncrypted() != 500 {
		t.Errorf("counter should be preserved when disabled, got %d", tracker.GetBytesEncrypted())
	}

	// Enable with new limit
	tracker.Reset()
	tracker.Disable()
	tracker.Enable(2000)

	if !tracker.IsEnabled() {
		t.Error("tracker should be enabled after Enable()")
	}
	if tracker.GetLimit() != 2000 {
		t.Errorf("GetLimit() = %d, want 2000", tracker.GetLimit())
	}

	// Enable with zero limit when existing limit is set should keep existing
	tracker.Disable()
	tracker.Enable(0)
	if tracker.GetLimit() != 2000 {
		t.Errorf("Enable(0) should keep existing limit 2000, got %d", tracker.GetLimit())
	}

	// Create new tracker with zero limit - should use default
	tracker2 := NewBytesTracker(false, 0)
	tracker2.SetLimit(0)
	tracker2.Enable(0)
	if tracker2.GetLimit() != DefaultBytesTrackingLimit {
		t.Errorf("Enable(0) on tracker with no limit should set default, got %d", tracker2.GetLimit())
	}
}

func TestBytesTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewBytesTracker(true, 1000000) // 1MB limit
	numGoroutines := 100
	bytesPerGoroutine := int64(1000) // 1KB per goroutine
	var wg sync.WaitGroup

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = tracker.CheckAndIncrementBytes(bytesPerGoroutine)
			}
		}()
	}

	wg.Wait()

	// We can't predict exact count due to some operations failing,
	// but counter should be consistent (not corrupted)
	encrypted := tracker.GetBytesEncrypted()
	if encrypted < 0 || encrypted > 1000000 {
		t.Errorf("counter corrupted: %d (should be between 0 and 1000000)", encrypted)
	}
}

func TestBytesTracker_RollbackOnFailure(t *testing.T) {
	tracker := NewBytesTracker(true, 1000)

	// Encrypt up to near limit
	err := tracker.CheckAndIncrementBytes(900)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try to exceed limit
	err = tracker.CheckAndIncrementBytes(200)
	if err == nil {
		t.Error("should error when exceeding limit")
	}

	// Counter should still be at 900 (failed operation was rolled back)
	if encrypted := tracker.GetBytesEncrypted(); encrypted != 900 {
		t.Errorf("counter should be rolled back on failure, got %d, want 900", encrypted)
	}

	// Should still be able to use remaining space
	err = tracker.CheckAndIncrementBytes(100)
	if err != nil {
		t.Errorf("should be able to use remaining space: %v", err)
	}

	if encrypted := tracker.GetBytesEncrypted(); encrypted != 1000 {
		t.Errorf("GetBytesEncrypted() = %d, want 1000", encrypted)
	}
}

func TestBytesTracker_LargeValues(t *testing.T) {
	// Test with realistic 350GB limit
	tracker := NewBytesTracker(true, DefaultBytesTrackingLimit)

	// Simulate encrypting 1GB chunks
	oneGB := int64(1024 * 1024 * 1024)

	for i := 0; i < 350; i++ {
		err := tracker.CheckAndIncrementBytes(oneGB)
		if err != nil {
			t.Fatalf("failed at iteration %d: %v", i, err)
		}
	}

	// Should be at limit
	if remaining := tracker.GetRemainingBytes(); remaining < 0 || remaining > oneGB {
		t.Errorf("should be near limit, remaining: %d", remaining)
	}

	// One more should fail
	err := tracker.CheckAndIncrementBytes(oneGB)
	if err == nil {
		t.Error("should fail when exceeding 350GB limit")
	}
}

func TestBytesTracker_ErrorMessages(t *testing.T) {
	tracker := NewBytesTracker(true, 1000)

	// Encrypt close to limit
	err := tracker.CheckAndIncrementBytes(900)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Exceed limit and check error message
	err = tracker.CheckAndIncrementBytes(200)
	if err == nil {
		t.Fatal("expected error when exceeding limit")
	}

	// Error message should contain useful information
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("error message should not be empty")
	}
	// Should mention bytes encrypted, limit, and amount exceeded
	// Just verify we got an error with some content
	t.Logf("Error message: %s", errMsg)
}

func BenchmarkBytesTracker_CheckAndIncrement(b *testing.B) {
	tracker := NewBytesTracker(true, DefaultBytesTrackingLimit)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tracker.CheckAndIncrementBytes(1024)
	}
}

func BenchmarkBytesTracker_CheckAndIncrement_Parallel(b *testing.B) {
	tracker := NewBytesTracker(true, DefaultBytesTrackingLimit)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = tracker.CheckAndIncrementBytes(1024)
		}
	})
}

func BenchmarkBytesTracker_GetStats(b *testing.B) {
	tracker := NewBytesTracker(true, DefaultBytesTrackingLimit)
	_ = tracker.CheckAndIncrementBytes(1024 * 1024 * 1024) // 1GB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tracker.GetUsageStats()
	}
}
