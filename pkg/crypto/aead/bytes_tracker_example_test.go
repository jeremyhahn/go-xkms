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

package aead_test

import (
	"fmt"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/aead"
)

// ExampleBytesTracker demonstrates basic usage of bytes tracking.
func ExampleBytesTracker() {
	// Create tracker with default 350GB limit
	tracker := aead.NewBytesTracker(true, 0)

	// Simulate encrypting data
	data1 := make([]byte, 1024*1024) // 1MB
	err := tracker.CheckAndIncrementBytes(int64(len(data1)))
	if err != nil {
		log.Fatal(err)
	}

	data2 := make([]byte, 2*1024*1024) // 2MB
	err = tracker.CheckAndIncrementBytes(int64(len(data2)))
	if err != nil {
		log.Fatal(err)
	}

	// Check usage
	totalBytes := tracker.GetBytesEncrypted()
	remainingBytes := tracker.GetRemainingBytes()
	usagePercent := tracker.GetUsagePercentage()

	fmt.Printf("Total encrypted: %d bytes\n", totalBytes)
	fmt.Printf("Remaining: %d bytes\n", remainingBytes)
	fmt.Printf("Usage: %.4f%%\n", usagePercent)

	// Output:
	// Total encrypted: 3145728 bytes
	// Remaining: 375806492672 bytes
	// Usage: 0.0008%
}

// ExampleBytesTracker_limitExceeded demonstrates limit enforcement.
func ExampleBytesTracker_limitExceeded() {
	// Create tracker with small limit for demonstration
	tracker := aead.NewBytesTracker(true, 1024) // 1KB limit

	// Encrypt some data - succeeds
	data1 := make([]byte, 512)
	err := tracker.CheckAndIncrementBytes(int64(len(data1)))
	if err != nil {
		fmt.Printf("Failed: %v\n", err)
	} else {
		fmt.Println("First encryption: OK")
	}

	// Try to exceed limit - fails
	data2 := make([]byte, 600) // Would exceed 1KB total
	err = tracker.CheckAndIncrementBytes(int64(len(data2)))
	if err != nil {
		fmt.Println("Second encryption: Limit exceeded")
	}

	// Check that counter was rolled back
	fmt.Printf("Bytes encrypted: %d\n", tracker.GetBytesEncrypted())

	// Output:
	// First encryption: OK
	// Second encryption: Limit exceeded
	// Bytes encrypted: 512
}

// ExampleBytesTracker_warning demonstrates usage warnings.
func ExampleBytesTracker_warning() {
	// Create tracker with 1KB limit
	tracker := aead.NewBytesTracker(true, 1000)

	// Encrypt up to 85% - no warning
	tracker.CheckAndIncrementBytes(850)
	if tracker.ShouldWarnUser() {
		fmt.Println("Warning at 85%")
	} else {
		fmt.Println("No warning at 85%")
	}

	// Encrypt to 92% - warning triggered
	tracker.CheckAndIncrementBytes(70)
	if tracker.ShouldWarnUser() {
		fmt.Println("Warning at 92%")
	} else {
		fmt.Println("No warning at 92%")
	}

	// Output:
	// No warning at 85%
	// Warning at 92%
}

// ExampleBytesTracker_GetUsageStats demonstrates usage statistics.
func ExampleBytesTracker_GetUsageStats() {
	tracker := aead.NewBytesTracker(true, 1000)

	// Encrypt some data
	tracker.CheckAndIncrementBytes(750)

	// Get comprehensive stats
	stats := tracker.GetUsageStats()

	fmt.Printf("Enabled: %v\n", stats["enabled"])
	fmt.Printf("Bytes encrypted: %d\n", stats["bytes_encrypted"])
	fmt.Printf("Limit: %d\n", stats["limit"])
	fmt.Printf("Remaining: %d\n", stats["bytes_remaining"])
	fmt.Printf("Usage: %.1f%%\n", stats["usage_percent"])
	fmt.Printf("Should warn: %v\n", stats["warn"])

	// Output:
	// Enabled: true
	// Bytes encrypted: 750
	// Limit: 1000
	// Remaining: 250
	// Usage: 75.0%
	// Should warn: false
}

// ExampleBytesTracker_Reset demonstrates resetting after key rotation.
func ExampleBytesTracker_Reset() {
	tracker := aead.NewBytesTracker(true, 1000)

	// Encrypt some data
	tracker.CheckAndIncrementBytes(500)
	fmt.Printf("Before reset: %d bytes\n", tracker.GetBytesEncrypted())

	// Rotate key and reset counter
	tracker.Reset()
	fmt.Printf("After reset: %d bytes\n", tracker.GetBytesEncrypted())

	// Can now use full limit again
	err := tracker.CheckAndIncrementBytes(1000)
	if err != nil {
		fmt.Println("Failed after reset")
	} else {
		fmt.Println("Full limit available after reset")
	}

	// Output:
	// Before reset: 500 bytes
	// After reset: 0 bytes
	// Full limit available after reset
}

// ExampleBytesTracker_disabled demonstrates disabled tracking.
func ExampleBytesTracker_disabled() {
	// Disabled tracker - no limits enforced
	tracker := aead.NewBytesTracker(false, 1000)

	// Can "encrypt" unlimited data
	tracker.CheckAndIncrementBytes(1000000)

	// Getters return safe values
	fmt.Printf("Bytes encrypted: %d\n", tracker.GetBytesEncrypted())
	fmt.Printf("Remaining: %d\n", tracker.GetRemainingBytes())
	fmt.Printf("Usage: %.1f%%\n", tracker.GetUsagePercentage())

	// Output:
	// Bytes encrypted: 0
	// Remaining: -1
	// Usage: 0.0%
}

// ExampleNewBytesTracker demonstrates different initialization options.
func ExampleNewBytesTracker() {
	// Default 350GB limit
	tracker1 := aead.NewBytesTracker(true, 0)
	fmt.Printf("Default limit: %d GB\n", tracker1.GetLimit()/(1024*1024*1024))

	// Custom 100GB limit
	tracker2 := aead.NewBytesTracker(true, 100*1024*1024*1024)
	fmt.Printf("Custom limit: %d GB\n", tracker2.GetLimit()/(1024*1024*1024))

	// Conservative 68GB limit (for random nonces)
	tracker3 := aead.NewBytesTracker(true, aead.Conservative68GB)
	fmt.Printf("Conservative limit: %d GB\n", tracker3.GetLimit()/(1024*1024*1024))

	// Disabled tracking
	tracker4 := aead.NewBytesTracker(false, 0)
	fmt.Printf("Disabled limit: %d\n", tracker4.GetLimit())

	// Output:
	// Default limit: 350 GB
	// Custom limit: 100 GB
	// Conservative limit: 68 GB
	// Disabled limit: -1
}
