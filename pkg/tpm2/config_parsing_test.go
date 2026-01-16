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
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

func TestParseHierarchy_Extended(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMIRHHierarchy
		expectError bool
	}{
		{"Endorsement", "ENDORSEMENT", tpm2.TPMRHEndorsement, false},
		{"Owner", "OWNER", tpm2.TPMRHOwner, false},
		{"Platform", "PLATFORM", tpm2.TPMRHPlatform, false},
		{"Invalid", "INVALID", 0, true},
		{"Empty", "", 0, true},
		{"Lowercase endorsement", "endorsement", 0, true}, // Case sensitive
		{"Lowercase owner", "owner", 0, true},
		{"Lowercase platform", "platform", 0, true},
		{"Mixed case", "Endorsement", 0, true},
		{"NULL", "NULL", 0, true}, // NULL is not a valid hierarchy for parsing
		{"Whitespace", " OWNER", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHierarchy(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidHierarchyType)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategy_Extended(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{"IAK", "IAK", EnrollmentStrategyIAK},
		{"IAK_IDEVID_SINGLE_PASS", "IAK_IDEVID_SINGLE_PASS", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for invalid", "INVALID", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for empty", "", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Lowercase iak", "iak", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},     // Case sensitive
		{"Partial match", "IAK_", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},    // No partial match
		{"Extra chars", "IAK_EXTRA", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS}, // Falls to default
		{"Whitespace", " IAK", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},       // No whitespace handling
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigStructTags_Extended(t *testing.T) {
	// This test verifies that the Config struct can be properly used
	// with YAML/JSON/mapstructure tags
	config := Config{
		CommandAddress:               "localhost:2321",
		Device:                       "/dev/tpmrm0",
		EncryptSession:               true,
		UseSimulator:                 false,
		Hash:                         "SHA-256",
		PlatformPCR:                  16,
		PlatformPCRBank:              "sha256",
		IdentityProvisioningStrategy: "IAK_IDEVID_SINGLE_PASS",
		UseEntropy:                   true,
		LockoutAuth:                  "test-lockout",
		PlatformAddress:              "localhost:2322",
		GoldenPCRs:                   []uint{0, 7, 9, 10},
		FileIntegrity:                []string{"/etc", "/usr/bin"},
	}

	assert.Equal(t, "localhost:2321", config.CommandAddress)
	assert.Equal(t, "/dev/tpmrm0", config.Device)
	assert.True(t, config.EncryptSession)
	assert.False(t, config.UseSimulator)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, uint(16), config.PlatformPCR)
	assert.Equal(t, "sha256", config.PlatformPCRBank)
	assert.True(t, config.UseEntropy)
	assert.Equal(t, "test-lockout", config.LockoutAuth)
	assert.Equal(t, "localhost:2322", config.PlatformAddress)
	assert.Equal(t, []uint{0, 7, 9, 10}, config.GoldenPCRs)
	assert.Equal(t, []string{"/etc", "/usr/bin"}, config.FileIntegrity)
}

func TestEKConfigStructure_Extended(t *testing.T) {
	config := EKConfig{
		CertHandle:     0x01C00002,
		CN:             "test-ek",
		Debug:          true,
		Handle:         0x81010001,
		HierarchyAuth:  "test-auth",
		KeyAlgorithm:   "RSA",
		Password:       "test-password",
		PlatformPolicy: true,
	}

	assert.Equal(t, uint32(0x01C00002), config.CertHandle)
	assert.Equal(t, "test-ek", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81010001), config.Handle)
	assert.Equal(t, "test-auth", config.HierarchyAuth)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
}

func TestSRKConfigStructure_Extended(t *testing.T) {
	config := SRKConfig{
		CN:             "test-srk",
		Debug:          true,
		Handle:         0x81000001,
		HierarchyAuth:  "test-auth",
		KeyAlgorithm:   "RSA",
		Password:       "test-password",
		PlatformPolicy: true,
	}

	assert.Equal(t, "test-srk", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81000001), config.Handle)
	assert.Equal(t, "test-auth", config.HierarchyAuth)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
}

func TestIDevIDConfigStructure_Extended(t *testing.T) {
	config := IDevIDConfig{
		CertHandle:         0x01C90000,
		CN:                 "test-idevid",
		Debug:              true,
		Handle:             0x81020000,
		Hash:               "SHA-256",
		KeyAlgorithm:       "RSA",
		Manufacturer:       "Test Manufacturer",
		Model:              "Test Model",
		Pad:                true,
		Password:           "test-password",
		PlatformPolicy:     true,
		Serial:             "12345",
		SignatureAlgorithm: "SHA256WithRSAPSS",
		Version:            "1.0",
	}

	assert.Equal(t, uint32(0x01C90000), config.CertHandle)
	assert.Equal(t, "test-idevid", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81020000), config.Handle)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "Test Manufacturer", config.Manufacturer)
	assert.Equal(t, "Test Model", config.Model)
	assert.True(t, config.Pad)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
	assert.Equal(t, "12345", config.Serial)
	assert.Equal(t, "SHA256WithRSAPSS", config.SignatureAlgorithm)
	assert.Equal(t, "1.0", config.Version)
}

func TestIAKConfigStructure_Extended(t *testing.T) {
	config := IAKConfig{
		CertHandle:         0x01C90001,
		CN:                 "test-iak",
		Debug:              true,
		Handle:             0x81010002,
		Hash:               "SHA-256",
		KeyAlgorithm:       "RSA",
		Password:           "test-password",
		PlatformPolicy:     true,
		SignatureAlgorithm: "SHA256WithRSAPSS",
	}

	assert.Equal(t, uint32(0x01C90001), config.CertHandle)
	assert.Equal(t, "test-iak", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81010002), config.Handle)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
	assert.Equal(t, "SHA256WithRSAPSS", config.SignatureAlgorithm)
}

func TestKeyStoreConfigStructure_Extended(t *testing.T) {
	config := KeyStoreConfig{
		CN:             "test-keystore",
		SRKAuth:        "test-srk-auth",
		SRKHandle:      0x81000002,
		PlatformPolicy: true,
	}

	assert.Equal(t, "test-keystore", config.CN)
	assert.Equal(t, "test-srk-auth", config.SRKAuth)
	assert.Equal(t, uint32(0x81000002), config.SRKHandle)
	assert.True(t, config.PlatformPolicy)
}

func TestLDevIDConfigStructure_Extended(t *testing.T) {
	config := LDevIDConfig{
		CertHandle:         0x01C90010,
		CN:                 "test-ldevid",
		Debug:              true,
		Handle:             0x81020010,
		Hash:               "SHA-256",
		KeyAlgorithm:       "RSA",
		Model:              "Test Model",
		Pad:                true,
		Password:           "test-password",
		PlatformPolicy:     true,
		Serial:             "67890",
		SignatureAlgorithm: "SHA256WithRSA",
	}

	assert.Equal(t, uint32(0x01C90010), config.CertHandle)
	assert.Equal(t, "test-ldevid", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81020010), config.Handle)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "Test Model", config.Model)
	assert.True(t, config.Pad)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
	assert.Equal(t, "67890", config.Serial)
	assert.Equal(t, "SHA256WithRSA", config.SignatureAlgorithm)
}

func TestLAKConfigStructure_Extended(t *testing.T) {
	config := LAKConfig{
		CertHandle:         0x01C90011,
		CN:                 "test-lak",
		Debug:              true,
		Handle:             0x81020011,
		Hash:               "SHA-256",
		KeyAlgorithm:       "ECDSA",
		Password:           "test-password",
		PlatformPolicy:     true,
		SignatureAlgorithm: "ECDSAWithSHA256",
	}

	assert.Equal(t, uint32(0x01C90011), config.CertHandle)
	assert.Equal(t, "test-lak", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81020011), config.Handle)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, "ECDSA", config.KeyAlgorithm)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
	assert.Equal(t, "ECDSAWithSHA256", config.SignatureAlgorithm)
}
