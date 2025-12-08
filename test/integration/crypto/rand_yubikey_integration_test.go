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

//go:build yubikey && pkcs11

package crypto_test

import (
	"crypto/sha256"
	"os"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/rand"
	pkcs11lib "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discoverYubiKeySlot finds the YubiKey PKCS#11 slot dynamically
func discoverYubiKeySlot(t *testing.T, libPath string) uint {
	p := pkcs11lib.New(libPath)
	if p == nil {
		t.Fatal("Failed to load PKCS#11 library")
	}

	err := p.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize PKCS#11: %v", err)
	}
	defer p.Finalize()
	defer p.Destroy()

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		t.Fatalf("No PKCS#11 slots found: %v", err)
	}

	return slots[0]
}

// TestRandYubiKeyIntegration tests RNG with a physical YubiKey device.
// This test requires:
// - A YubiKey device plugged into the system
// - PKCS#11 library installed (e.g., ykcs11 from Yubico)
// - Proper permissions to access the YubiKey
//
// Build and run with: go test -tags yubikey ./test/integration/crypto/...
//
// The YubiKey PKCS#11 library is typically located at:
// - Linux: /usr/lib/x86_64-linux-gnu/libykcs11.so
// - macOS: /usr/local/lib/libykcs11.dylib
// - Windows: C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll
func TestRandYubiKeyIntegration(t *testing.T) {
	// Determine YubiKey PKCS#11 library path
	yubikeyLib := os.Getenv("YUBIKEY_PKCS11_LIBRARY")
	if yubikeyLib == "" {
		// Default to standard Linux location
		yubikeyLib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"

		// If not found, try other common locations
		if _, err := os.Stat(yubikeyLib); os.IsNotExist(err) {
			candidates := []string{
				"/usr/lib/libykcs11.so",
				"/usr/local/lib/libykcs11.so",
				"/usr/local/lib/libykcs11.dylib",
			}

			found := false
			for _, path := range candidates {
				if _, err := os.Stat(path); err == nil {
					yubikeyLib = path
					found = true
					break
				}
			}

			if !found {
				t.Fatal("YubiKey PKCS#11 library not found. Install Yubico PIV Tool or set YUBIKEY_PKCS11_LIBRARY environment variable.")
			}
		}
	}

	t.Logf("Using YubiKey PKCS#11 library: %s", yubikeyLib)

	// Get PIN from environment or use default
	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		pin = "123456" // Default YubiKey PIN
	}

	t.Logf("Using YubiKey PIN: %s", pin)

	// Discover YubiKey slot dynamically
	slotID := discoverYubiKeySlot(t, yubikeyLib)
	t.Logf("Using YubiKey slot ID: %d", slotID)

	// Configure PKCS#11 RNG for YubiKey
	config := &rand.Config{
		Mode: rand.ModePKCS11,
		PKCS11Config: &rand.PKCS11Config{
			Module:      yubikeyLib,
			SlotID:      slotID, // Dynamically discovered slot
			PINRequired: true,
			PIN:         pin,
		},
	}

	resolver, err := rand.NewResolver(config)
	if err != nil {
		t.Fatalf("Skipping YubiKey RNG test: %v (YubiKey may not be connected or accessible)", err)
		return
	}
	defer resolver.Close()

	t.Run("BasicGeneration", func(t *testing.T) {
		// Generate random bytes from YubiKey
		randomBytes, err := resolver.Rand(32)
		require.NoError(t, err, "Failed to generate random bytes from YubiKey")
		require.Len(t, randomBytes, 32, "Should generate 32 bytes")

		// Verify not all zeros
		allZeros := true
		for _, b := range randomBytes {
			if b != 0 {
				allZeros = false
				break
			}
		}
		assert.False(t, allZeros, "YubiKey RNG should not produce all zeros")

		// Generate again - should be different
		randomBytes2, err := resolver.Rand(32)
		require.NoError(t, err)
		assert.NotEqual(t, randomBytes, randomBytes2, "YubiKey RNG should produce different values")
	})

	t.Run("VariousSizes", func(t *testing.T) {
		sizes := []int{16, 32, 64, 128, 256}

		for _, size := range sizes {
			randomBytes, err := resolver.Rand(size)
			require.NoError(t, err, "Failed to generate %d bytes from YubiKey", size)
			require.Len(t, randomBytes, size)

			// Verify not all zeros
			allZeros := true
			for _, b := range randomBytes {
				if b != 0 {
					allZeros = false
					break
				}
			}
			assert.False(t, allZeros, "YubiKey RNG should not produce all zeros for size %d", size)
		}
	})

	t.Run("Uniqueness", func(t *testing.T) {
		// Generate multiple random values and ensure they're unique
		numSamples := 50
		sampleSize := 32
		samples := make(map[string]bool)

		for i := 0; i < numSamples; i++ {
			randomBytes, err := resolver.Rand(sampleSize)
			require.NoError(t, err)

			hash := sha256.Sum256(randomBytes)
			key := string(hash[:])

			// Check for duplicates
			if samples[key] {
				t.Errorf("Duplicate random value detected at iteration %d", i)
			}
			samples[key] = true
		}

		assert.Len(t, samples, numSamples, "All samples should be unique")
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		// Test concurrent access to YubiKey RNG
		numGoroutines := 10
		numIterations := 10

		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines*numIterations)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < numIterations; j++ {
					_, err := resolver.Rand(32)
					if err != nil {
						errors <- err
					}
				}
			}()
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Errorf("Concurrent access error: %v", err)
		}
	})

	t.Run("Entropy", func(t *testing.T) {
		// Generate a large sample and verify entropy
		sampleSize := 1024
		randomBytes, err := resolver.Rand(sampleSize)
		require.NoError(t, err)

		// Count bit frequencies
		bitCounts := make([]int, 8)
		for _, b := range randomBytes {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<bit) != 0 {
					bitCounts[bit]++
				}
			}
		}

		// Each bit should appear roughly 50% of the time
		// Allow for statistical variance (30% - 70%)
		expectedCount := sampleSize / 2
		tolerance := sampleSize * 20 / 100 // 20% tolerance

		for bit := 0; bit < 8; bit++ {
			assert.InDelta(t, expectedCount, bitCounts[bit], float64(tolerance),
				"Bit %d distribution outside expected range", bit)
		}
	})

	t.Run("Availability", func(t *testing.T) {
		// Verify resolver reports available
		assert.True(t, resolver.Available(), "YubiKey RNG should be available")

		// Get Source interface and verify availability
		source := resolver.Source()
		require.NotNil(t, source)
		assert.True(t, source.Available(), "YubiKey RNG source should be available")
	})

	t.Run("ConsistentBehavior", func(t *testing.T) {
		// Generate multiple times and ensure consistent behavior
		for i := 0; i < 10; i++ {
			randomBytes, err := resolver.Rand(32)
			require.NoError(t, err, "Iteration %d failed", i)
			require.Len(t, randomBytes, 32)

			// Verify not all the same value
			allSame := true
			first := randomBytes[0]
			for _, b := range randomBytes {
				if b != first {
					allSame = false
					break
				}
			}
			assert.False(t, allSame, "YubiKey RNG produced all same byte values at iteration %d", i)
		}
	})
}

// TestRandYubiKeyVsSoftware compares YubiKey RNG output with software RNG
func TestRandYubiKeyVsSoftware(t *testing.T) {
	yubikeyLib := os.Getenv("YUBIKEY_PKCS11_LIBRARY")
	if yubikeyLib == "" {
		yubikeyLib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
		if _, err := os.Stat(yubikeyLib); os.IsNotExist(err) {
			t.Fatal("YubiKey PKCS#11 library not found at default location. Set YUBIKEY_PKCS11_LIBRARY environment variable.")
		}
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		pin = "123456"
	}

	// Discover YubiKey slot dynamically
	slotID := discoverYubiKeySlot(t, yubikeyLib)

	// Create YubiKey resolver
	yubikeyConfig := &rand.Config{
		Mode: rand.ModePKCS11,
		PKCS11Config: &rand.PKCS11Config{
			Module:      yubikeyLib,
			SlotID:      slotID,
			PINRequired: true,
			PIN:         pin,
		},
	}

	yubikeyResolver, err := rand.NewResolver(yubikeyConfig)
	if err != nil {
		t.Fatalf("Skipping YubiKey comparison test: %v", err)
		return
	}
	defer yubikeyResolver.Close()

	// Create software resolver
	softwareConfig := &rand.Config{
		Mode: rand.ModeSoftware,
	}

	softwareResolver, err := rand.NewResolver(softwareConfig)
	require.NoError(t, err)
	defer softwareResolver.Close()

	t.Run("DifferentOutputs", func(t *testing.T) {
		// Generate from both sources
		yubikeyBytes, err := yubikeyResolver.Rand(32)
		require.NoError(t, err)

		softwareBytes, err := softwareResolver.Rand(32)
		require.NoError(t, err)

		// They should not be the same (extremely unlikely)
		assert.NotEqual(t, yubikeyBytes, softwareBytes,
			"YubiKey and software RNG should produce different outputs")
	})

	t.Run("SimilarEntropyQuality", func(t *testing.T) {
		// Generate large samples from both
		sampleSize := 1024

		yubikeyBytes, err := yubikeyResolver.Rand(sampleSize)
		require.NoError(t, err)

		softwareBytes, err := softwareResolver.Rand(sampleSize)
		require.NoError(t, err)

		// Count bit frequencies for YubiKey
		yubikeyBitCounts := make([]int, 8)
		for _, b := range yubikeyBytes {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<bit) != 0 {
					yubikeyBitCounts[bit]++
				}
			}
		}

		// Count bit frequencies for software
		softwareBitCounts := make([]int, 8)
		for _, b := range softwareBytes {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<bit) != 0 {
					softwareBitCounts[bit]++
				}
			}
		}

		// Both should have similar entropy (roughly 50% for each bit)
		expectedCount := sampleSize / 2
		tolerance := sampleSize * 20 / 100

		for bit := 0; bit < 8; bit++ {
			assert.InDelta(t, expectedCount, yubikeyBitCounts[bit], float64(tolerance),
				"YubiKey bit %d distribution outside expected range", bit)
			assert.InDelta(t, expectedCount, softwareBitCounts[bit], float64(tolerance),
				"Software bit %d distribution outside expected range", bit)
		}
	})
}

// TestRandYubiKeyReliability tests YubiKey RNG reliability over many operations
func TestRandYubiKeyReliability(t *testing.T) {
	yubikeyLib := os.Getenv("YUBIKEY_PKCS11_LIBRARY")
	if yubikeyLib == "" {
		yubikeyLib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
		if _, err := os.Stat(yubikeyLib); os.IsNotExist(err) {
			t.Fatal("YubiKey PKCS#11 library not found at default location. Set YUBIKEY_PKCS11_LIBRARY environment variable.")
		}
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		pin = "123456"
	}

	// Discover YubiKey slot dynamically
	slotID := discoverYubiKeySlot(t, yubikeyLib)

	config := &rand.Config{
		Mode: rand.ModePKCS11,
		PKCS11Config: &rand.PKCS11Config{
			Module:      yubikeyLib,
			SlotID:      slotID,
			PINRequired: true,
			PIN:         pin,
		},
	}

	resolver, err := rand.NewResolver(config)
	if err != nil {
		t.Fatalf("Skipping YubiKey reliability test: %v", err)
		return
	}
	defer resolver.Close()

	// Generate 1000 random values and track failures
	numIterations := 1000
	failures := 0
	samples := make(map[string]int)

	for i := 0; i < numIterations; i++ {
		randomBytes, err := resolver.Rand(32)
		if err != nil {
			failures++
			continue
		}

		// Track samples for uniqueness
		hash := sha256.Sum256(randomBytes)
		key := string(hash[:])
		samples[key]++
	}

	// Should have very few (ideally zero) failures
	assert.LessOrEqual(t, failures, numIterations/100, // Allow max 1% failure rate
		"Too many failures: %d out of %d", failures, numIterations)

	// All samples should be unique
	duplicates := 0
	for _, count := range samples {
		if count > 1 {
			duplicates++
		}
	}
	assert.Equal(t, 0, duplicates, "Found %d duplicate samples", duplicates)
}

// TestRandYubiKeyPerformance benchmarks YubiKey RNG performance
func TestRandYubiKeyPerformance(t *testing.T) {
	if testing.Short() {
		t.Fatal("Skipping performance test in short mode")
	}

	yubikeyLib := os.Getenv("YUBIKEY_PKCS11_LIBRARY")
	if yubikeyLib == "" {
		yubikeyLib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
		if _, err := os.Stat(yubikeyLib); os.IsNotExist(err) {
			t.Fatal("YubiKey PKCS#11 library not found at default location. Set YUBIKEY_PKCS11_LIBRARY environment variable.")
		}
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		pin = "123456"
	}

	// Discover YubiKey slot dynamically
	slotID := discoverYubiKeySlot(t, yubikeyLib)

	config := &rand.Config{
		Mode: rand.ModePKCS11,
		PKCS11Config: &rand.PKCS11Config{
			Module:      yubikeyLib,
			SlotID:      slotID,
			PINRequired: true,
			PIN:         pin,
		},
	}

	resolver, err := rand.NewResolver(config)
	if err != nil {
		t.Fatalf("Skipping YubiKey performance test: %v", err)
		return
	}
	defer resolver.Close()

	sizes := []int{16, 32, 64, 128, 256, 512, 1024}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			numIterations := 100
			var totalBytes []byte

			for i := 0; i < numIterations; i++ {
				randomBytes, err := resolver.Rand(size)
				require.NoError(t, err)
				totalBytes = append(totalBytes, randomBytes...)
			}

			t.Logf("Generated %d bytes in %d iterations (size: %d)",
				len(totalBytes), numIterations, size)
		})
	}
}
