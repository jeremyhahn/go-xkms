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
	"bytes"
	"crypto/sha256"
	"os"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRandTPM2HardwareIntegration tests TPM2 hardware RNG with SWTPM simulator
func TestRandTPM2HardwareIntegration(t *testing.T) {
	// Try to connect to SWTPM simulator first (for Docker environment)
	swtpmHost := os.Getenv("SWTPM_HOST")
	if swtpmHost == "" {
		swtpmHost = "swtpm" // Docker service name
	}

	// Configure TPM2 RNG with simulator support
	config := &rand.Config{
		Mode: rand.ModeTPM2,
		TPM2Config: &rand.TPM2Config{
			UseSimulator:   true,
			SimulatorType:  "swtpm",
			SimulatorHost:  swtpmHost,
			SimulatorPort:  2321,
			MaxRequestSize: 32,
		},
	}

	resolver, err := rand.NewResolver(config)
	if err != nil {
		t.Skipf("Skipping TPM2 RNG test: %v (TPM device may not be accessible)", err)
		return
	}
	defer resolver.Close()

	t.Run("BasicGeneration", func(t *testing.T) {
		// Generate random bytes from TPM2
		randomBytes, err := resolver.Rand(32)
		require.NoError(t, err, "Failed to generate random bytes from TPM2")
		require.Len(t, randomBytes, 32, "Should generate 32 bytes")

		// Generate again - should be different
		randomBytes2, err := resolver.Rand(32)
		require.NoError(t, err)
		assert.NotEqual(t, randomBytes, randomBytes2, "TPM2 RNG should produce different values")
	})

	t.Run("VariousSizes", func(t *testing.T) {
		sizes := []int{16, 32, 64, 128, 256, 512, 1024}

		for _, size := range sizes {
			randomBytes, err := resolver.Rand(size)
			require.NoError(t, err, "Failed to generate %d bytes from TPM2", size)
			require.Len(t, randomBytes, size)

			// Verify not all zeros
			allZeros := true
			for _, b := range randomBytes {
				if b != 0 {
					allZeros = false
					break
				}
			}
			assert.False(t, allZeros, "TPM2 RNG should not produce all zeros")
		}
	})

	t.Run("Uniqueness", func(t *testing.T) {
		// Generate multiple random values and ensure they're unique
		numSamples := 100
		sampleSize := 32
		samples := make(map[string]bool)

		for i := 0; i < numSamples; i++ {
			randomBytes, err := resolver.Rand(sampleSize)
			require.NoError(t, err)

			hash := sha256.Sum256(randomBytes)
			key := string(hash[:])

			assert.False(t, samples[key], "TPM2 RNG should not generate duplicates")
			samples[key] = true
		}

		assert.Equal(t, numSamples, len(samples), "All TPM2 RNG samples should be unique")
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		// Test thread safety with TPM2 hardware
		numGoroutines := 50
		bytesPerGoroutine := 32
		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines)
		results := make(chan []byte, numGoroutines)

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()

				randomBytes, err := resolver.Rand(bytesPerGoroutine)
				if err != nil {
					errors <- err
					return
				}

				results <- randomBytes
			}()
		}

		wg.Wait()
		close(errors)
		close(results)

		// Check for errors
		for err := range errors {
			t.Errorf("TPM2 concurrent access error: %v", err)
		}

		// Verify uniqueness
		seen := make(map[string]bool)
		duplicates := 0
		for result := range results {
			require.Len(t, result, bytesPerGoroutine)

			key := string(result)
			if seen[key] {
				duplicates++
			}
			seen[key] = true
		}

		assert.Equal(t, 0, duplicates, "TPM2 RNG should not produce duplicates under concurrent access")
	})

	t.Run("Entropy", func(t *testing.T) {
		// Verify TPM2 RNG has good entropy
		randomBytes, err := resolver.Rand(1024)
		require.NoError(t, err)

		entropy := calculateEntropy(randomBytes)
		t.Logf("TPM2 RNG Entropy: %.4f bits/byte", entropy)

		// Hardware RNG should have high entropy
		assert.Greater(t, entropy, 7.5, "TPM2 RNG should have high entropy")
	})

	t.Run("StatisticalProperties", func(t *testing.T) {
		// Test basic statistical properties of TPM2 RNG
		sampleSize := 10000
		randomBytes, err := resolver.Rand(sampleSize)
		require.NoError(t, err)

		// Count byte frequencies
		frequencies := make(map[byte]int)
		for _, b := range randomBytes {
			frequencies[b]++
		}

		// Expected frequency for each byte value (0-255)
		expectedFreq := float64(sampleSize) / 256.0

		// Chi-square test for uniformity
		var chiSquare float64
		for i := 0; i < 256; i++ {
			observed := float64(frequencies[byte(i)])
			diff := observed - expectedFreq
			chiSquare += (diff * diff) / expectedFreq
		}

		t.Logf("TPM2 RNG Chi-square: %.2f", chiSquare)
		assert.Less(t, chiSquare, 400.0, "TPM2 RNG distribution should be reasonably uniform")
	})
}

// TestRandTPM2FallbackIntegration tests TPM2 with software fallback
func TestRandTPM2FallbackIntegration(t *testing.T) {
	// Configure with TPM2 primary, software fallback
	config := &rand.Config{
		Mode:         rand.ModeTPM2,
		FallbackMode: rand.ModeSoftware,
		TPM2Config: &rand.TPM2Config{
			Device:         "/dev/tpmrm0",
			MaxRequestSize: 32,
		},
	}

	resolver, err := rand.NewResolver(config)
	// Should succeed even if TPM2 fails, using fallback
	if err != nil {
		t.Logf("TPM2 creation failed, testing fallback: %v", err)
	} else {
		defer resolver.Close()
	}

	// Should be available via fallback even if TPM2 fails
	if resolver != nil {
		assert.True(t, resolver.Available(), "Should be available via fallback")

		randomBytes, err := resolver.Rand(32)
		require.NoError(t, err)
		require.Len(t, randomBytes, 32)
	}
}

// TestRandPKCS11HardwareIntegration tests PKCS#11 hardware RNG with SoftHSM
func TestRandPKCS11HardwareIntegration(t *testing.T) {
	// Check if PKCS#11 library is configured
	pkcs11Lib := os.Getenv("PKCS11_LIBRARY")
	if pkcs11Lib == "" {
		pkcs11Lib = "/usr/lib/softhsm/libsofthsm2.so"
	}

	// Check if library exists
	if _, err := os.Stat(pkcs11Lib); os.IsNotExist(err) {
		t.Skipf("Skipping PKCS#11 RNG test: library %s not found", pkcs11Lib)
		return
	}

	// Get token PIN from environment
	pin := os.Getenv("PKCS11_PIN")
	if pin == "" {
		pin = "1234" // Default test PIN
	}

	config := &rand.Config{
		Mode: rand.ModePKCS11,
		PKCS11Config: &rand.PKCS11Config{
			Module:      pkcs11Lib,
			SlotID:      0,
			PINRequired: true,
			PIN:         pin,
		},
	}

	resolver, err := rand.NewResolver(config)
	if err != nil {
		t.Skipf("Skipping PKCS#11 RNG test: %v (SoftHSM may not be initialized)", err)
		return
	}
	defer resolver.Close()

	t.Run("BasicGeneration", func(t *testing.T) {
		// Generate random bytes from PKCS#11 HSM
		randomBytes, err := resolver.Rand(32)
		require.NoError(t, err, "Failed to generate random bytes from PKCS#11")
		require.Len(t, randomBytes, 32, "Should generate 32 bytes")

		// Generate again - should be different
		randomBytes2, err := resolver.Rand(32)
		require.NoError(t, err)
		assert.NotEqual(t, randomBytes, randomBytes2, "PKCS#11 RNG should produce different values")
	})

	t.Run("VariousSizes", func(t *testing.T) {
		sizes := []int{16, 32, 64, 128, 256}

		for _, size := range sizes {
			randomBytes, err := resolver.Rand(size)
			require.NoError(t, err, "Failed to generate %d bytes from PKCS#11", size)
			require.Len(t, randomBytes, size)

			// Verify not all zeros
			allZeros := true
			for _, b := range randomBytes {
				if b != 0 {
					allZeros = false
					break
				}
			}
			assert.False(t, allZeros, "PKCS#11 RNG should not produce all zeros")
		}
	})

	t.Run("Uniqueness", func(t *testing.T) {
		// Generate multiple random values and ensure they're unique
		numSamples := 100
		sampleSize := 32
		samples := make(map[string]bool)

		for i := 0; i < numSamples; i++ {
			randomBytes, err := resolver.Rand(sampleSize)
			require.NoError(t, err)

			hash := sha256.Sum256(randomBytes)
			key := string(hash[:])

			assert.False(t, samples[key], "PKCS#11 RNG should not generate duplicates")
			samples[key] = true
		}

		assert.Equal(t, numSamples, len(samples), "All PKCS#11 RNG samples should be unique")
	})

	t.Run("Entropy", func(t *testing.T) {
		// Verify PKCS#11 RNG has good entropy
		randomBytes, err := resolver.Rand(1024)
		require.NoError(t, err)

		entropy := calculateEntropy(randomBytes)
		t.Logf("PKCS#11 RNG Entropy: %.4f bits/byte", entropy)

		// Hardware RNG should have high entropy
		assert.Greater(t, entropy, 7.5, "PKCS#11 RNG should have high entropy")
	})
}

// TestRandAutoHardwareIntegration tests auto mode with hardware detection
func TestRandAutoHardwareIntegration(t *testing.T) {
	// Auto mode should detect and use available hardware
	resolver, err := rand.NewResolver(rand.ModeAuto)
	require.NoError(t, err, "Auto mode should always succeed")
	defer resolver.Close()

	t.Run("HardwareDetection", func(t *testing.T) {
		assert.True(t, resolver.Available(), "Auto mode should find available RNG")

		source := resolver.Source()
		require.NotNil(t, source, "Should have a source")

		t.Logf("Auto mode selected source: %T", source)
	})

	t.Run("BasicOperation", func(t *testing.T) {
		// Should work regardless of which hardware is available
		randomBytes, err := resolver.Rand(64)
		require.NoError(t, err)
		require.Len(t, randomBytes, 64)

		// Verify randomness
		randomBytes2, err := resolver.Rand(64)
		require.NoError(t, err)
		assert.NotEqual(t, randomBytes, randomBytes2)
	})
}

// TestRandHardwareComparison compares output from different RNG sources
func TestRandHardwareComparison(t *testing.T) {
	// Create resolvers for available sources
	sources := make(map[string]rand.Resolver)

	// Always available: software
	softwareResolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer softwareResolver.Close()
	sources["software"] = softwareResolver

	// Try TPM2 (only works with real device, not SWTPM TCP)
	tpm2Resolver, err := rand.NewResolver(&rand.Config{
		Mode: rand.ModeTPM2,
		TPM2Config: &rand.TPM2Config{
			Device:         "/dev/tpmrm0",
			MaxRequestSize: 32,
		},
	})
	if err == nil {
		defer tpm2Resolver.Close()
		sources["tpm2"] = tpm2Resolver
		t.Log("TPM2 RNG available")
	}

	// Try PKCS#11
	pkcs11Lib := os.Getenv("PKCS11_LIBRARY")
	if pkcs11Lib == "" {
		pkcs11Lib = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := os.Stat(pkcs11Lib); err == nil {
		pkcs11Resolver, err := rand.NewResolver(&rand.Config{
			Mode: rand.ModePKCS11,
			PKCS11Config: &rand.PKCS11Config{
				Module:      pkcs11Lib,
				SlotID:      0,
				PINRequired: true,
				PIN:         "1234",
			},
		})
		if err == nil {
			defer pkcs11Resolver.Close()
			sources["pkcs11"] = pkcs11Resolver
			t.Log("PKCS#11 RNG available")
		}
	}

	t.Logf("Testing %d RNG sources", len(sources))

	// Generate samples from all available sources
	sampleSize := 1024
	samples := make(map[string][]byte)

	for name, resolver := range sources {
		randomBytes, err := resolver.Rand(sampleSize)
		require.NoError(t, err, "Failed to generate from %s", name)
		samples[name] = randomBytes

		// Calculate entropy
		entropy := calculateEntropy(randomBytes)
		t.Logf("%s entropy: %.4f bits/byte", name, entropy)

		// All sources should have good entropy
		assert.Greater(t, entropy, 7.5, "%s should have high entropy", name)
	}

	// Verify all sources produce different output
	for name1, sample1 := range samples {
		for name2, sample2 := range samples {
			if name1 != name2 {
				assert.NotEqual(t, sample1, sample2,
					"Different RNG sources (%s vs %s) should produce different output", name1, name2)
			}
		}
	}
}

// TestRandHardwarePerformance benchmarks hardware RNG performance
func TestRandHardwarePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	sources := []struct {
		name   string
		config interface{}
	}{
		{"software", rand.ModeSoftware},
		{"tpm2", &rand.Config{
			Mode: rand.ModeTPM2,
			TPM2Config: &rand.TPM2Config{
				Device:         "/dev/tpmrm0",
				MaxRequestSize: 32,
			},
		}},
	}

	sizes := []int{32, 256, 1024, 4096}

	for _, source := range sources {
		resolver, err := rand.NewResolver(source.config)
		if err != nil {
			t.Logf("Skipping %s: %v", source.name, err)
			continue
		}
		defer resolver.Close()

		for _, size := range sizes {
			iterations := 100

			start := testing.Benchmark(func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))

				for i := 0; i < iterations; i++ {
					_, err := resolver.Rand(size)
					if err != nil {
						b.Fatal(err)
					}
				}
			})

			t.Logf("%s: %d bytes x %d iterations: %v",
				source.name, size, iterations, start)
		}
	}
}

// TestRandHardwareReliability tests reliability under stress
func TestRandHardwareReliability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping reliability test in short mode")
	}

	// Test TPM2 reliability (requires real device)
	resolver, err := rand.NewResolver(&rand.Config{
		Mode: rand.ModeTPM2,
		TPM2Config: &rand.TPM2Config{
			Device:         "/dev/tpmrm0",
			MaxRequestSize: 32,
		},
	})
	if err != nil {
		t.Skipf("TPM2 not available: %v", err)
		return
	}
	defer resolver.Close()

	// Generate 10,000 samples to test reliability
	numSamples := 10000
	failures := 0

	for i := 0; i < numSamples; i++ {
		_, err := resolver.Rand(32)
		if err != nil {
			failures++
			t.Logf("Generation %d failed: %v", i, err)
		}
	}

	failureRate := float64(failures) / float64(numSamples) * 100
	t.Logf("Failure rate: %.2f%% (%d/%d)", failureRate, failures, numSamples)

	// Should have very low failure rate
	assert.Less(t, failureRate, 0.1, "Failure rate should be less than 0.1%%")
}

// TestRandHardwareConsecutive tests consecutive operations
func TestRandHardwareConsecutive(t *testing.T) {
	// Test with TPM2 (requires real device)
	resolver, err := rand.NewResolver(&rand.Config{
		Mode: rand.ModeTPM2,
		TPM2Config: &rand.TPM2Config{
			Device:         "/dev/tpmrm0",
			MaxRequestSize: 32,
		},
	})
	if err != nil {
		t.Skipf("TPM2 not available: %v", err)
		return
	}
	defer resolver.Close()

	// Generate 1000 consecutive samples
	prev, err := resolver.Rand(32)
	require.NoError(t, err)

	duplicates := 0
	for i := 0; i < 1000; i++ {
		current, err := resolver.Rand(32)
		require.NoError(t, err)

		if bytes.Equal(prev, current) {
			duplicates++
		}

		prev = current
	}

	assert.Equal(t, 0, duplicates, "Should have no duplicate consecutive values")
}
