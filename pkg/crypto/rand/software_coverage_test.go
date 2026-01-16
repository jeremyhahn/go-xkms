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

package rand

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

// TestSoftwareResolver_ImplementsResolver verifies SoftwareResolver implements Resolver
func TestSoftwareResolver_ImplementsResolver(t *testing.T) {
	var _ Resolver = &SoftwareResolver{}
	// If the above line compiles, SoftwareResolver implements Resolver
}

// TestSoftwareResolver_ReadImplementsIOReader verifies Read satisfies io.Reader
func TestSoftwareResolver_ReadImplementsIOReader(t *testing.T) {
	resolver := &SoftwareResolver{}
	var reader io.Reader = resolver

	buf := make([]byte, 32)
	n, err := reader.Read(buf)
	if err != nil {
		t.Errorf("io.Reader Read failed: %v", err)
	}
	if n != 32 {
		t.Errorf("Expected 32 bytes, got %d", n)
	}
}

// TestSoftwareResolver_ReadVaryingSizes tests Read with various buffer sizes
func TestSoftwareResolver_ReadVaryingSizes(t *testing.T) {
	resolver := &SoftwareResolver{}

	sizes := []int{0, 1, 7, 15, 16, 17, 31, 32, 33, 64, 128, 256, 512, 1024, 4096}
	for _, size := range sizes {
		buf := make([]byte, size)
		n, err := resolver.Read(buf)
		if err != nil {
			t.Errorf("Read(%d) failed: %v", size, err)
		}
		if n != size {
			t.Errorf("Read(%d) returned %d bytes", size, n)
		}
	}
}

// TestSoftwareResolver_RandVaryingSizes tests Rand with various sizes
func TestSoftwareResolver_RandVaryingSizes(t *testing.T) {
	resolver := &SoftwareResolver{}

	sizes := []int{0, 1, 7, 15, 16, 17, 31, 32, 33, 64, 128, 256, 512, 1024, 4096}
	for _, size := range sizes {
		data, err := resolver.Rand(size)
		if err != nil {
			t.Errorf("Rand(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("Rand(%d) returned %d bytes", size, len(data))
		}
	}
}

// TestSoftwareResolver_ConcurrentReads tests concurrent Read calls
func TestSoftwareResolver_ConcurrentReads(t *testing.T) {
	resolver := &SoftwareResolver{}

	var wg sync.WaitGroup
	numOps := 100
	wg.Add(numOps)

	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 32)
			n, err := resolver.Read(buf)
			if err != nil {
				t.Errorf("Concurrent Read failed: %v", err)
			}
			if n != 32 {
				t.Errorf("Expected 32 bytes, got %d", n)
			}
		}()
	}

	wg.Wait()
}

// TestSoftwareResolver_ConcurrentRands tests concurrent Rand calls
func TestSoftwareResolver_ConcurrentRands(t *testing.T) {
	resolver := &SoftwareResolver{}

	var wg sync.WaitGroup
	numOps := 100
	wg.Add(numOps)

	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			data, err := resolver.Rand(32)
			if err != nil {
				t.Errorf("Concurrent Rand failed: %v", err)
			}
			if len(data) != 32 {
				t.Errorf("Expected 32 bytes, got %d", len(data))
			}
		}()
	}

	wg.Wait()
}

// TestSoftwareResolver_RandomnessQuality tests that generated data is random
func TestSoftwareResolver_RandomnessQuality(t *testing.T) {
	resolver := &SoftwareResolver{}

	// Generate multiple samples
	samples := make([][]byte, 50)
	for i := 0; i < 50; i++ {
		samples[i], _ = resolver.Rand(32)
	}

	// Check for uniqueness
	for i := 0; i < len(samples); i++ {
		for j := i + 1; j < len(samples); j++ {
			if bytes.Equal(samples[i], samples[j]) {
				t.Errorf("Found duplicate samples at indices %d and %d", i, j)
			}
		}
	}
}

// TestSoftwareResolver_SourceAvailable tests Source.Available
func TestSoftwareResolver_SourceAvailable(t *testing.T) {
	resolver := &SoftwareResolver{}
	source := resolver.Source()

	if !source.Available() {
		t.Error("Software source should always be available")
	}
}

// TestSoftwareResolver_SourceClose tests Source.Close
func TestSoftwareResolver_SourceClose(t *testing.T) {
	resolver := &SoftwareResolver{}
	source := resolver.Source()

	err := source.Close()
	if err != nil {
		t.Errorf("Source.Close() returned error: %v", err)
	}
}

// TestSoftwareResolver_SourceRand tests Source.Rand
func TestSoftwareResolver_SourceRand(t *testing.T) {
	resolver := &SoftwareResolver{}
	source := resolver.Source()

	sizes := []int{0, 1, 16, 32, 64, 128}
	for _, size := range sizes {
		data, err := source.Rand(size)
		if err != nil {
			t.Errorf("Source.Rand(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("Source.Rand(%d) returned %d bytes", size, len(data))
		}
	}
}

// TestSoftwareSource_DirectConstruction tests directly constructing softwareSource
func TestSoftwareSource_DirectConstruction(t *testing.T) {
	source := &softwareSource{}

	// Test Rand
	data, err := source.Rand(32)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Test Available
	if !source.Available() {
		t.Error("softwareSource should always be available")
	}

	// Test Close
	if err := source.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// TestSoftwareSource_ConcurrentOperations tests concurrent operations on softwareSource
func TestSoftwareSource_ConcurrentOperations(t *testing.T) {
	source := &softwareSource{}

	var wg sync.WaitGroup
	numOps := 50
	wg.Add(numOps * 3)

	// Concurrent Rand
	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			_, err := source.Rand(16)
			if err != nil {
				t.Errorf("Concurrent Rand failed: %v", err)
			}
		}()
	}

	// Concurrent Available
	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			if !source.Available() {
				t.Error("softwareSource should always be available")
			}
		}()
	}

	// Concurrent Close
	for i := 0; i < numOps; i++ {
		go func() {
			defer wg.Done()
			if err := source.Close(); err != nil {
				t.Errorf("Close failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

// TestNewSoftwareResolver tests newSoftwareResolver function
func TestNewSoftwareResolver(t *testing.T) {
	resolver, err := newSoftwareResolver()
	if err != nil {
		t.Fatalf("newSoftwareResolver failed: %v", err)
	}
	if resolver == nil {
		t.Fatal("newSoftwareResolver returned nil")
	}

	// Verify it works
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}

	// Close
	if err := resolver.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// TestSoftwareResolver_CloseIsIdempotent tests Close can be called multiple times
func TestSoftwareResolver_CloseIsIdempotent(t *testing.T) {
	resolver := &SoftwareResolver{}

	for i := 0; i < 10; i++ {
		if err := resolver.Close(); err != nil {
			t.Errorf("Close call %d failed: %v", i, err)
		}
	}
}

// TestSoftwareResolver_RandAfterClose tests Rand works after Close
func TestSoftwareResolver_RandAfterClose(t *testing.T) {
	resolver := &SoftwareResolver{}
	_ = resolver.Close()

	// Should still work (software resolver has no state)
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand after Close failed: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestSoftwareResolver_ReadAfterClose tests Read works after Close
func TestSoftwareResolver_ReadAfterClose(t *testing.T) {
	resolver := &SoftwareResolver{}
	_ = resolver.Close()

	// Should still work (software resolver has no state)
	buf := make([]byte, 32)
	n, err := resolver.Read(buf)
	if err != nil {
		t.Errorf("Read after Close failed: %v", err)
	}
	if n != 32 {
		t.Errorf("Expected 32 bytes, got %d", n)
	}
}

// TestSoftwareResolver_AvailableAfterClose tests Available after Close
func TestSoftwareResolver_AvailableAfterClose(t *testing.T) {
	resolver := &SoftwareResolver{}
	_ = resolver.Close()

	// Software resolver is always available
	if !resolver.Available() {
		t.Error("Software resolver should always be available")
	}
}

// TestSoftwareResolver_SourceAfterClose tests Source after Close
func TestSoftwareResolver_SourceAfterClose(t *testing.T) {
	resolver := &SoftwareResolver{}
	_ = resolver.Close()

	source := resolver.Source()
	if source == nil {
		t.Fatal("Source should not be nil after Close")
	}

	// Source should work
	data, err := source.Rand(16)
	if err != nil {
		t.Errorf("Source.Rand after Close failed: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}
}

// TestSoftwareResolver_LargeRand tests Rand with large size
func TestSoftwareResolver_LargeRand(t *testing.T) {
	resolver := &SoftwareResolver{}

	sizes := []int{8192, 16384, 32768, 65536}
	for _, size := range sizes {
		data, err := resolver.Rand(size)
		if err != nil {
			t.Errorf("Rand(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("Rand(%d) returned %d bytes", size, len(data))
		}
	}
}

// TestSoftwareResolver_LargeRead tests Read with large buffer
func TestSoftwareResolver_LargeRead(t *testing.T) {
	resolver := &SoftwareResolver{}

	sizes := []int{8192, 16384, 32768, 65536}
	for _, size := range sizes {
		buf := make([]byte, size)
		n, err := resolver.Read(buf)
		if err != nil {
			t.Errorf("Read(%d) failed: %v", size, err)
		}
		if n != size {
			t.Errorf("Read(%d) returned %d bytes", size, n)
		}
	}
}

// TestSoftwareSource_LargeRand tests Source.Rand with large size
func TestSoftwareSource_LargeRand(t *testing.T) {
	source := &softwareSource{}

	sizes := []int{8192, 16384, 32768}
	for _, size := range sizes {
		data, err := source.Rand(size)
		if err != nil {
			t.Errorf("Rand(%d) failed: %v", size, err)
		}
		if len(data) != size {
			t.Errorf("Rand(%d) returned %d bytes", size, len(data))
		}
	}
}
