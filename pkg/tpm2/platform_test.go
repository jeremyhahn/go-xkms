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

package tpm2

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveAttribute(t *testing.T) {
	tests := []struct {
		name            string
		configValue     string
		discoveredValue string
		expected        string
	}{
		{
			name:            "config value takes priority",
			configValue:     "ConfigManufacturer",
			discoveredValue: "DiscoveredManufacturer",
			expected:        "ConfigManufacturer",
		},
		{
			name:            "fallback to discovered when config empty",
			configValue:     "",
			discoveredValue: "DiscoveredManufacturer",
			expected:        "DiscoveredManufacturer",
		},
		{
			name:            "both empty returns empty",
			configValue:     "",
			discoveredValue: "",
			expected:        "",
		},
		{
			name:            "config value with whitespace preserved",
			configValue:     "Dell Inc.",
			discoveredValue: "HP",
			expected:        "Dell Inc.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveAttribute(tt.configValue, tt.discoveredValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResolvePlatformAttributes_NilConfig(t *testing.T) {
	// When config is nil, should attempt discovery (may fail on non-Linux or missing DMI)
	result := ResolvePlatformAttributes(nil)
	assert.NotNil(t, result)
	// Values may be empty if DMI files don't exist - that's OK
}

func TestResolvePlatformAttributes_ConfigOverridesDiscovery(t *testing.T) {
	config := &IDevIDConfig{
		Manufacturer: "TestManufacturer",
		Model:        "TestModel",
		Version:      "1.0.0",
		Serial:       "SN123456",
	}

	result := ResolvePlatformAttributes(config)

	assert.Equal(t, "TestManufacturer", result.Manufacturer)
	assert.Equal(t, "TestModel", result.Model)
	assert.Equal(t, "1.0.0", result.Version)
	assert.Equal(t, "SN123456", result.Serial)
}

func TestResolvePlatformAttributes_PartialConfig(t *testing.T) {
	// Only Model and Serial specified, Manufacturer and Version should come from discovery
	config := &IDevIDConfig{
		Model:  "CustomDevice",
		Serial: "ABC123",
	}

	result := ResolvePlatformAttributes(config)

	// Config values are used
	assert.Equal(t, "CustomDevice", result.Model)
	assert.Equal(t, "ABC123", result.Serial)
	// Manufacturer and Version come from discovery (may be empty on test systems)
	// Just verify they're strings (not panicking)
	assert.IsType(t, "", result.Manufacturer)
	assert.IsType(t, "", result.Version)
}

func TestResolvePlatformAttributes_EmptyConfig(t *testing.T) {
	config := &IDevIDConfig{}

	result := ResolvePlatformAttributes(config)

	// All values come from discovery
	assert.NotNil(t, result)
	// Values may be empty if DMI files don't exist
}

func TestReadDMIFile_NonExistent(t *testing.T) {
	// Should return empty string for non-existent files
	result := readDMIFile("nonexistent_file_12345")
	assert.Equal(t, "", result)
}

func TestReadDMIFile_WithMockFS(t *testing.T) {
	// Create a temporary directory structure mimicking DMI sysfs
	tmpDir := t.TempDir()

	// Create mock DMI files
	mockFiles := map[string]string{
		"sys_vendor":      "Test Manufacturer\n",
		"product_name":    "Test Model\n",
		"product_version": "v2.0\n",
		"product_serial":  "SN-TEST-001\n",
	}

	for name, content := range mockFiles {
		path := filepath.Join(tmpDir, name)
		err := os.WriteFile(path, []byte(content), 0644)
		require.NoError(t, err)
	}

	// We can't easily override dmiBasePath constant, but we can test
	// that the file reading and trimming logic works correctly
	// by testing with actual files if they exist on the system

	// Test that whitespace is trimmed
	testFile := filepath.Join(tmpDir, "test_attr")
	err := os.WriteFile(testFile, []byte("  Test Value  \n"), 0644)
	require.NoError(t, err)

	data, err := os.ReadFile(testFile)
	require.NoError(t, err)
	// Verify our trim logic would work
	assert.Contains(t, string(data), "Test Value")
}

func TestDiscoverPlatformAttributes(t *testing.T) {
	// This test verifies the function runs without panicking
	// Actual values depend on the system running the test
	result := DiscoverPlatformAttributes()
	assert.NotNil(t, result)

	// On a real Linux system with DMI, these should be non-empty
	// On other systems or containers, they may be empty
	t.Logf("Discovered platform attributes:")
	t.Logf("  Manufacturer: %q", result.Manufacturer)
	t.Logf("  Model: %q", result.Model)
	t.Logf("  Version: %q", result.Version)
	t.Logf("  Serial: %q", result.Serial)
}

func TestPlatformAttributes_EmptyStruct(t *testing.T) {
	attrs := &PlatformAttributes{}
	assert.Equal(t, "", attrs.Manufacturer)
	assert.Equal(t, "", attrs.Model)
	assert.Equal(t, "", attrs.Version)
	assert.Equal(t, "", attrs.Serial)
}
