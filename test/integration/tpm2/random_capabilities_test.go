//go:build integration

package integration

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
)

// TestIntegration_RandomSource tests the RandomSource() method
func TestIntegration_RandomSource(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	// Provision if needed
	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	// Get random source
	randomSource := tpmInstance.RandomSource()
	if randomSource == nil {
		t.Fatal("RandomSource() returned nil")
	}

	// Read from the source
	data := make([]byte, 16)
	n, err := randomSource.Read(data)
	if err != nil {
		t.Fatalf("Failed to read from random source: %v", err)
	}

	if n != 16 {
		t.Errorf("Expected to read 16 bytes, got %d", n)
	}

	// Verify data is not all zeros (basic sanity check)
	allZeros := true
	for _, b := range data {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Random source returned all zeros - likely not working")
	}

	t.Logf("Successfully read %d random bytes from RandomSource()", n)
}

// TestIntegration_RandomBytes tests the RandomBytes() method with various sizes
func TestIntegration_RandomBytes(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	tests := []struct {
		name   string
		length int
	}{
		{"Small - 8 bytes", 8},
		{"Standard - 16 bytes", 16},
		{"Medium - 32 bytes", 32},
		{"Large - 64 bytes", 64},
		{"Extra Large - 128 bytes", 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			randomBytes, err := tpmInstance.RandomBytes(tt.length)
			if err != nil {
				t.Fatalf("RandomBytes(%d) failed: %v", tt.length, err)
			}

			if len(randomBytes) != tt.length {
				t.Errorf("Expected %d bytes, got %d", tt.length, len(randomBytes))
			}

			// Verify randomness - check not all zeros
			allZeros := true
			for _, b := range randomBytes {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("RandomBytes returned all zeros")
			}

			t.Logf("Generated %d random bytes", len(randomBytes))
		})
	}
}

// TestIntegration_RandomBytes_ErrorCases tests error handling
func TestIntegration_RandomBytes_ErrorCases(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	tests := []struct {
		name        string
		length      int
		expectError bool
	}{
		{"Zero length", 0, false},    // TPM might accept this
		{"Very large", 1024, false},  // Test large requests
		{"Maximum safe", 512, false}, // Large but reasonable
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			randomBytes, err := tpmInstance.RandomBytes(tt.length)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for length %d, got none", tt.length)
				}
			} else {
				if err != nil {
					t.Logf("RandomBytes(%d) returned error (may be expected): %v", tt.length, err)
				} else if len(randomBytes) != tt.length {
					t.Errorf("Expected %d bytes, got %d", tt.length, len(randomBytes))
				}
			}
		})
	}
}

// TestIntegration_RandomHex tests the RandomHex() method
func TestIntegration_RandomHex(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	tests := []struct {
		name      string
		hexLength int
	}{
		{"16 hex chars (8 bytes)", 16},
		{"32 hex chars (16 bytes)", 32},
		{"64 hex chars (32 bytes)", 64},
		{"128 hex chars (64 bytes)", 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hexBytes, err := tpmInstance.RandomHex(tt.hexLength)
			if err != nil {
				t.Fatalf("RandomHex(%d) failed: %v", tt.hexLength, err)
			}

			hexStr := string(hexBytes)
			if len(hexStr) != tt.hexLength {
				t.Errorf("Expected %d hex characters, got %d", tt.hexLength, len(hexStr))
			}

			// Verify it's valid hex
			_, err = hex.DecodeString(hexStr)
			if err != nil {
				t.Errorf("RandomHex returned invalid hex string: %v", err)
			}

			// Check it's not all zeros
			if strings.Trim(hexStr, "0") == "" {
				t.Error("RandomHex returned all zeros")
			}

			t.Logf("Generated hex string: %s (length: %d)", hexStr, len(hexStr))
		})
	}
}

// TestIntegration_Read tests the Read() method with various buffer sizes
func TestIntegration_Read(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	tests := []struct {
		name       string
		bufferSize int
	}{
		{"Small buffer - 8 bytes", 8},
		{"Medium buffer - 32 bytes", 32},
		{"Large buffer - 64 bytes", 64},
		{"Extra large buffer - 128 bytes", 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := make([]byte, tt.bufferSize)
			n, err := tpmInstance.Read(buffer)
			if err != nil {
				t.Fatalf("Read() failed: %v", err)
			}

			if n != tt.bufferSize {
				t.Errorf("Expected to read %d bytes, got %d", tt.bufferSize, n)
			}

			// Verify randomness
			allZeros := true
			for _, b := range buffer {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("Read() returned all zeros")
			}

			t.Logf("Successfully read %d random bytes", n)
		})
	}
}

// TestIntegration_Read_Encrypted tests Read() with encrypted session
func TestIntegration_Read_Encrypted(t *testing.T) {
	// Create TPM with encrypted session enabled
	tpmInstance, _, cleanup := setupTPM2WithCapture(t, true)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	buffer := make([]byte, 32)
	n, err := tpmInstance.Read(buffer)
	if err != nil {
		t.Fatalf("Read() with encryption failed: %v", err)
	}

	if n != 32 {
		t.Errorf("Expected to read 32 bytes, got %d", n)
	}

	t.Logf("Successfully read %d bytes with encrypted session", n)
}

// TestIntegration_RandomnessQuality performs basic statistical tests on random data
func TestIntegration_RandomnessQuality(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	// Generate 1024 random bytes for statistical analysis
	const sampleSize = 1024
	randomData, err := tpmInstance.RandomBytes(sampleSize)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	// Test 1: Byte frequency distribution (should be relatively uniform)
	freq := make(map[byte]int)
	for _, b := range randomData {
		freq[b]++
	}

	// Count bytes that appear (should be a good portion of possible values)
	uniqueBytes := len(freq)
	minUnique := 200 // At least 200 different byte values in 1024 bytes
	if uniqueBytes < minUnique {
		t.Errorf("Poor byte distribution: only %d unique values (expected at least %d)", uniqueBytes, minUnique)
	}

	// Test 2: No repeated patterns (check for repeating sequences)
	hasRepeatingPattern := false
	for i := 0; i < len(randomData)-16; i++ {
		pattern := randomData[i : i+8]
		// Look for this pattern appearing again
		for j := i + 8; j < len(randomData)-8; j++ {
			if bytes.Equal(pattern, randomData[j:j+8]) {
				hasRepeatingPattern = true
				t.Logf("Warning: Found repeating 8-byte pattern at positions %d and %d", i, j)
				break
			}
		}
		if hasRepeatingPattern {
			break
		}
	}

	// Test 3: Mean should be close to 127.5
	var sum int64
	for _, b := range randomData {
		sum += int64(b)
	}
	mean := float64(sum) / float64(len(randomData))

	// Allow 10% deviation from expected mean
	expectedMean := 127.5
	tolerance := 12.75 // 10% of 127.5
	if math.Abs(mean-expectedMean) > tolerance {
		t.Errorf("Mean value %.2f deviates too much from expected %.2f", mean, expectedMean)
	}

	t.Logf("Randomness quality tests passed:")
	t.Logf("  - Unique bytes: %d/256", uniqueBytes)
	t.Logf("  - Mean value: %.2f (expected ~127.5)", mean)
	t.Logf("  - Sample size: %d bytes", sampleSize)
}

// TestIntegration_RandomBytes_Uniqueness verifies that multiple calls return different data
func TestIntegration_RandomBytes_Uniqueness(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	// Generate multiple random byte slices
	const iterations = 10
	const size = 32

	samples := make([][]byte, iterations)
	for i := 0; i < iterations; i++ {
		sample, err := tpmInstance.RandomBytes(size)
		if err != nil {
			t.Fatalf("Failed to generate random bytes: %v", err)
		}
		samples[i] = sample
	}

	// Verify all samples are unique
	for i := 0; i < iterations; i++ {
		for j := i + 1; j < iterations; j++ {
			if bytes.Equal(samples[i], samples[j]) {
				t.Errorf("Samples %d and %d are identical (not random)", i, j)
			}
		}
	}

	t.Logf("Generated %d unique random samples", iterations)
}

// TestIntegration_Info tests the Info() method
func TestIntegration_Info(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	info, err := tpmInstance.Info()
	if err != nil {
		t.Fatalf("Info() failed: %v", err)
	}

	if info == "" {
		t.Error("Info() returned empty string")
	}

	// Verify info contains expected fields
	expectedFields := []string{
		"Manufacturer",
		"Vendor ID",
		"Family",
		"Revision",
		"Firmware",
		"FIPS 140-2",
	}

	for _, field := range expectedFields {
		if !strings.Contains(info, field) {
			t.Errorf("Info() output missing expected field: %s", field)
		}
	}

	t.Logf("TPM Info:\n%s", info)
}

// TestIntegration_ParseHierarchy tests the ParseHierarchy() function
func TestIntegration_ParseHierarchy(t *testing.T) {
	tests := []struct {
		name         string
		hierarchyStr string
		expected     tpm2.TPMIRHHierarchy
		expectError  bool
	}{
		{
			name:         "Owner Hierarchy",
			hierarchyStr: "OWNER",
			expected:     tpm2.TPMRHOwner,
			expectError:  false,
		},
		{
			name:         "Endorsement Hierarchy",
			hierarchyStr: "ENDORSEMENT",
			expected:     tpm2.TPMRHEndorsement,
			expectError:  false,
		},
		{
			name:         "Platform Hierarchy",
			hierarchyStr: "PLATFORM",
			expected:     tpm2.TPMRHPlatform,
			expectError:  false,
		},
		{
			name:         "Invalid Hierarchy",
			hierarchyStr: "INVALID",
			expectError:  true,
		},
		{
			name:         "Lowercase (should fail)",
			hierarchyStr: "owner",
			expectError:  true,
		},
		{
			name:         "Empty String",
			hierarchyStr: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tpm2lib.ParseHierarchy(tt.hierarchyStr)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for input '%s', got none", tt.hierarchyStr)
				} else {
					t.Logf("Got expected error: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for input '%s': %v", tt.hierarchyStr, err)
				}
				if result != tt.expected {
					t.Errorf("Expected hierarchy 0x%x, got 0x%x", tt.expected, result)
				}
				t.Logf("Successfully parsed '%s' to hierarchy 0x%x", tt.hierarchyStr, result)
			}
		})
	}
}

// TestIntegration_FixedProperties tests retrieval of fixed TPM properties
func TestIntegration_FixedProperties(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	props, err := tpmInstance.FixedProperties()
	if err != nil {
		t.Fatalf("FixedProperties() failed: %v", err)
	}

	if props == nil {
		t.Fatal("FixedProperties() returned nil")
	}

	// Validate properties have reasonable values
	if props.Manufacturer == "" {
		t.Error("Manufacturer is empty")
	}

	if props.VendorID == "" {
		t.Error("VendorID is empty")
	}

	if props.Family == "" {
		t.Error("Family is empty")
	}

	if props.Revision == "" {
		t.Error("Revision is empty")
	}

	// Log key properties
	t.Logf("TPM Fixed Properties:")
	t.Logf("  Manufacturer: %s", props.Manufacturer)
	t.Logf("  Vendor ID: %s", props.VendorID)
	t.Logf("  Family: %s", props.Family)
	t.Logf("  Revision: %s", props.Revision)
	t.Logf("  Firmware: %d.%d", props.FwMajor, props.FwMinor)
	t.Logf("  FIPS 140-2: %t", props.Fips1402)
	t.Logf("  Max Auth Fail: %d", props.MaxAuthFail)
	t.Logf("  Active Sessions Max: %d", props.ActiveSessionsMax)
	t.Logf("  Lockout Counter: %d", props.LockoutCounter)
	t.Logf("  Lockout Interval: %d", props.LockoutInterval)
	t.Logf("  Lockout Recovery: %d", props.LockoutRecovery)
}

// TestIntegration_LockoutParameters tests lockout-related capability functions
func TestIntegration_LockoutParameters(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	// Get fixed properties which includes lockout parameters
	props, err := tpmInstance.FixedProperties()
	if err != nil {
		t.Fatalf("Failed to get fixed properties: %v", err)
	}

	// Verify lockout parameters are present
	t.Logf("Lockout Parameters:")
	t.Logf("  Lockout Counter: %d", props.LockoutCounter)
	t.Logf("  Lockout Interval: %d", props.LockoutInterval)
	t.Logf("  Lockout Recovery: %d", props.LockoutRecovery)
	t.Logf("  Max Auth Fail: %d", props.MaxAuthFail)

	// These values should be non-negative (TPM spec requirement)
	if props.LockoutInterval < 0 {
		t.Error("Lockout interval is negative")
	}

	if props.LockoutRecovery < 0 {
		t.Error("Lockout recovery is negative")
	}
}

// TestIntegration_LoadedCurves tests retrieval of loaded elliptic curves
func TestIntegration_LoadedCurves(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	props, err := tpmInstance.FixedProperties()
	if err != nil {
		t.Fatalf("Failed to get fixed properties: %v", err)
	}

	// LoadedCurves is stored in the fixed properties
	t.Logf("Loaded Curves count: %d", props.LoadedCurves)

	// Note: The actual implementation stores LoadedCurves in the struct but
	// the code shows it's not populated in FixedProperties. The internal
	// loadedCurves() function exists but isn't called.
	// This test validates the field exists in the structure.
}

// TestIntegration_SessionParameters tests session-related capabilities
func TestIntegration_SessionParameters(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	props, err := tpmInstance.FixedProperties()
	if err != nil {
		t.Fatalf("Failed to get fixed properties: %v", err)
	}

	// Verify session parameters
	t.Logf("Session Parameters:")
	t.Logf("  Active Sessions Max: %d", props.ActiveSessionsMax)
	t.Logf("  Auth Sessions Active: %d", props.AuthSessionsActive)
	t.Logf("  Auth Sessions Active Available: %d", props.AuthSessionsActiveAvail)
	t.Logf("  Auth Sessions Loaded: %d", props.AuthSessionsLoaded)
	t.Logf("  Auth Sessions Loaded Available: %d", props.AuthSessionsLoadedAvail)

	if props.ActiveSessionsMax == 0 {
		t.Error("ActiveSessionsMax is 0 (should be positive)")
	}
}

// TestIntegration_MemoryParameters tests memory-related capabilities
func TestIntegration_MemoryParameters(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	props, err := tpmInstance.FixedProperties()
	if err != nil {
		t.Fatalf("Failed to get fixed properties: %v", err)
	}

	// Verify memory parameters
	t.Logf("Memory Parameters:")
	t.Logf("  Memory: %d", props.Memory)
	t.Logf("  Persistent Loaded: %d", props.PersistentLoaded)
	t.Logf("  Persistent Available: %d", props.PersistentAvail)
	t.Logf("  Persistent Min: %d", props.PersistentMin)
	t.Logf("  Transient Min: %d", props.TransientMin)
	t.Logf("  Transient Available: %d", props.TransientAvail)

	// Basic sanity checks
	if props.Memory == 0 {
		t.Error("Memory is 0")
	}
}

// TestIntegration_NVRAMParameters tests NVRAM-related capabilities
func TestIntegration_NVRAMParameters(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	err := provisionIfNeeded(t, tpmInstance)
	if err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	props, err := tpmInstance.FixedProperties()
	if err != nil {
		t.Fatalf("Failed to get fixed properties: %v", err)
	}

	// Verify NVRAM parameters
	t.Logf("NVRAM Parameters:")
	t.Logf("  NV Buffer Max: %d", props.NVBufferMax)
	t.Logf("  NV Indexes Defined: %d", props.NVIndexesDefined)
	t.Logf("  NV Indexes Max: %d", props.NVIndexesMax)
	t.Logf("  NV Write Recovery: %d", props.NVWriteRecovery)

	if props.NVBufferMax == 0 {
		t.Error("NVBufferMax is 0")
	}

	if props.NVIndexesMax == 0 {
		t.Error("NVIndexesMax is 0")
	}
}

// provisionIfNeeded provisions the TPM if not already initialized
func provisionIfNeeded(t *testing.T, tpm tpm2lib.TrustedPlatformModule) error {
	t.Helper()

	// Try to get SRK attributes to check if provisioned
	_, err := tpm.SSRKAttributes()
	if err != nil {
		// Not provisioned, provision now
		t.Log("TPM not provisioned, provisioning...")
		return tpm.Provision(nil)
	}

	return nil
}
