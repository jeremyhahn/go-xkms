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
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestConfig_Validate tests configuration validation
func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantErr   bool
		errString string
	}{
		{
			name: "ValidConfigWithDevice",
			config: &Config{
				Device:    "/dev/null", // Use /dev/null to avoid needing real TPM
				KeyDir:    t.TempDir(),
				SRKHandle: 0x81000001,
			},
			wantErr: false,
		},
		{
			name: "ValidConfigWithSimulator",
			config: &Config{
				UseSimulator: true,
				KeyDir:       t.TempDir(),
			},
			wantErr: false,
		},
		{
			name: "DefaultValues",
			config: &Config{
				Device: "/dev/null", // Avoid real TPM check
			},
			wantErr: false,
		},
		{
			name: "NonExistentDevice",
			config: &Config{
				Device: "/dev/nonexistent-tpm-device-xyz",
				KeyDir: t.TempDir(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConfig_Validate_DefaultValues tests that validation sets proper defaults
func TestConfig_Validate_DefaultValues(t *testing.T) {
	config := &Config{
		UseSimulator: true, // Use simulator to avoid device check
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Check defaults were applied with specific expected values
	const (
		expectedKeyDir    = "./tpm2-keys"
		expectedSRKHandle = uint32(0x81000001)
		expectedEKHandle  = uint32(0x81010001)
		expectedHash      = "SHA-256"
		expectedPCRBank   = "SHA256"
		expectedCN        = "keychain"
	)

	if config.KeyDir != expectedKeyDir {
		t.Errorf("KeyDir default: expected %q, got %q", expectedKeyDir, config.KeyDir)
	}

	if config.SRKHandle != expectedSRKHandle {
		t.Errorf("SRKHandle default: expected 0x%x, got 0x%x", expectedSRKHandle, config.SRKHandle)
	}

	if config.EKHandle != expectedEKHandle {
		t.Errorf("EKHandle default: expected 0x%x, got 0x%x", expectedEKHandle, config.EKHandle)
	}

	if config.Hash != expectedHash {
		t.Errorf("Hash default: expected %q, got %q", expectedHash, config.Hash)
	}

	if config.PlatformPCRBank != expectedPCRBank {
		t.Errorf("PlatformPCRBank default: expected %q, got %q", expectedPCRBank, config.PlatformPCRBank)
	}

	if config.CN != expectedCN {
		t.Errorf("CN default: expected %q, got %q", expectedCN, config.CN)
	}
}

// TestConfig_ToTPMConfig tests conversion to underlying TPM2 config
func TestConfig_ToTPMConfig(t *testing.T) {
	config := &Config{
		Device:          "/dev/tpmrm0",
		KeyDir:          "/tmp/tpm-keys",
		UseSimulator:    true,
		EncryptSession:  true,
		SRKHandle:       0x81000001,
		EKHandle:        0x81010001,
		Hash:            "SHA-256",
		PlatformPolicy:  true,
		PlatformPCR:     7,
		PlatformPCRBank: "SHA256",
	}

	tpmConfig := config.ToTPMConfig()

	if tpmConfig == nil {
		t.Fatal("ToTPMConfig returned nil")
	}

	if tpmConfig.Device != config.Device {
		t.Errorf("Device = %s, want %s", tpmConfig.Device, config.Device)
	}

	if tpmConfig.UseSimulator != config.UseSimulator {
		t.Errorf("UseSimulator = %v, want %v", tpmConfig.UseSimulator, config.UseSimulator)
	}

	if tpmConfig.EncryptSession != config.EncryptSession {
		t.Errorf("EncryptSession = %v, want %v", tpmConfig.EncryptSession, config.EncryptSession)
	}

	if tpmConfig.Hash != config.Hash {
		t.Errorf("Hash = %s, want %s", tpmConfig.Hash, config.Hash)
	}

	if tpmConfig.PlatformPCR != config.PlatformPCR {
		t.Errorf("PlatformPCR = %d, want %d", tpmConfig.PlatformPCR, config.PlatformPCR)
	}

	if tpmConfig.PlatformPCRBank != config.PlatformPCRBank {
		t.Errorf("PlatformPCRBank = %s, want %s", tpmConfig.PlatformPCRBank, config.PlatformPCRBank)
	}
}

// TestConfig_ToTPMConfig_WithPresetConfig tests that preset TPMConfig takes precedence
func TestConfig_ToTPMConfig_WithPresetConfig(t *testing.T) {
	pkgtpm2Config := &Config{
		Device: "/dev/custom",
	}

	config := &Config{
		Device:    "/dev/tpmrm0",
		TPMConfig: pkgtpm2Config.ToTPMConfig(),
	}

	tpmConfig := config.ToTPMConfig()

	// Should return the preset config, not the one derived from fields
	if tpmConfig.Device != "/dev/custom" {
		t.Errorf("Expected preset config device /dev/custom, got %s", tpmConfig.Device)
	}
}

// TestBackendType tests the Type method
func TestBackendType(t *testing.T) {
	// We can test Type() by creating a mock backend struct directly
	// without initializing the TPM
	b := &Backend{}
	if b.Type() != backend.BackendTypeTPM2 {
		t.Errorf("Type() = %s, want %s", b.Type(), backend.BackendTypeTPM2)
	}
}

// TestCapabilities tests the Capabilities method
func TestCapabilities(t *testing.T) {
	b := &Backend{}
	caps := b.Capabilities()

	if !caps.HardwareBacked {
		t.Error("Expected HardwareBacked to be true")
	}

	if !caps.Keys {
		t.Error("Expected Keys capability to be true")
	}

	if !caps.Signing {
		t.Error("Expected Signing capability to be true")
	}

	if !caps.Sealing {
		t.Error("Expected Sealing capability to be true")
	}

	if !caps.SymmetricEncryption {
		t.Error("Expected SymmetricEncryption capability to be true")
	}

	if caps.KeyRotation {
		t.Error("Expected KeyRotation to be false for hardware-backed keys")
	}
}

// TestNewBackend_InvalidConfig tests backend creation with invalid configurations
func TestNewBackend_InvalidConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantErr   bool
		errString string
	}{
		{
			name: "NonExistentDevice",
			config: &Config{
				Device: "/dev/nonexistent-tpm-xyz123",
				KeyDir: t.TempDir(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBackend(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBackend() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestBackend_ClosedOperations tests that operations fail after backend is closed
func TestBackend_ClosedOperations(t *testing.T) {
	// Create a closed backend (simulating a properly initialized then closed backend)
	b := &Backend{closed: true}

	rsaAttrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
	}

	// Test GenerateKey
	_, err := b.GenerateKey(rsaAttrs)
	if err != ErrNotInitialized {
		t.Errorf("GenerateKey on closed backend: expected ErrNotInitialized, got %v", err)
	}

	// Test GetKey
	_, err = b.GetKey(rsaAttrs)
	if err != ErrNotInitialized {
		t.Errorf("GetKey on closed backend: expected ErrNotInitialized, got %v", err)
	}

	// Test DeleteKey
	err = b.DeleteKey(rsaAttrs)
	if err != ErrNotInitialized {
		t.Errorf("DeleteKey on closed backend: expected ErrNotInitialized, got %v", err)
	}

	// Test ListKeys
	_, err = b.ListKeys()
	if err != ErrNotInitialized {
		t.Errorf("ListKeys on closed backend: expected ErrNotInitialized, got %v", err)
	}

	// Test Signer
	_, err = b.Signer(rsaAttrs)
	if err != ErrNotInitialized {
		t.Errorf("Signer on closed backend: expected ErrNotInitialized, got %v", err)
	}

	// Test Decrypter
	_, err = b.Decrypter(rsaAttrs)
	if err != ErrNotInitialized {
		t.Errorf("Decrypter on closed backend: expected ErrNotInitialized, got %v", err)
	}
}

// TestBackend_NilAttributes tests operations with nil attributes
func TestBackend_NilAttributes(t *testing.T) {
	// Create a backend that appears to be open
	b := &Backend{closed: false}

	// Test GenerateKey with nil attrs
	_, err := b.GenerateKey(nil)
	if err != ErrInvalidKeyAttributes {
		t.Errorf("GenerateKey(nil): expected ErrInvalidKeyAttributes, got %v", err)
	}

	// Test GetKey with nil attrs
	_, err = b.GetKey(nil)
	if err != ErrInvalidKeyAttributes {
		t.Errorf("GetKey(nil): expected ErrInvalidKeyAttributes, got %v", err)
	}

	// Test DeleteKey with nil attrs
	err = b.DeleteKey(nil)
	if err != ErrInvalidKeyAttributes {
		t.Errorf("DeleteKey(nil): expected ErrInvalidKeyAttributes, got %v", err)
	}
}

// TestBackend_RotateKey tests that key rotation is not supported
func TestBackend_RotateKey(t *testing.T) {
	b := &Backend{}

	err := b.RotateKey(&types.KeyAttributes{CN: "test"})
	if err != ErrKeyRotationNotSupported {
		t.Errorf("RotateKey: expected ErrKeyRotationNotSupported, got %v", err)
	}
}

// TestBackend_DoubleClose tests that closing multiple times is safe
func TestBackend_DoubleClose(t *testing.T) {
	b := &Backend{closed: false}

	// First close
	err := b.Close()
	if err != nil {
		t.Errorf("First Close() error = %v", err)
	}

	// Second close should be safe
	err = b.Close()
	if err != nil {
		t.Errorf("Second Close() error = %v", err)
	}
}

// TestBackend_ListKeys_EmptyDir tests ListKeys with non-existent directory
func TestBackend_ListKeys_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	b := &Backend{
		closed: false,
		config: &Config{
			KeyDir: tmpDir,
		},
	}

	keys, err := b.ListKeys()
	if err != nil {
		t.Errorf("ListKeys() error = %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected 0 keys in empty directory, got %d", len(keys))
	}
}

// TestBackend_ListKeys_NonExistentDir tests ListKeys with directory that doesn't exist
func TestBackend_ListKeys_NonExistentDir(t *testing.T) {
	b := &Backend{
		closed: false,
		config: &Config{
			KeyDir: "/nonexistent/path/xyz123",
		},
	}

	keys, err := b.ListKeys()
	if err != nil {
		t.Errorf("ListKeys() error = %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected 0 keys for non-existent directory, got %d", len(keys))
	}
}

// TestErrors tests that error types are properly defined
func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrNotInitialized", ErrNotInitialized},
		{"ErrAlreadyInitialized", ErrAlreadyInitialized},
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrKeyNotFound", ErrKeyNotFound},
		{"ErrUnsupportedKeyAlgorithm", ErrUnsupportedKeyAlgorithm},
		{"ErrUnsupportedOperation", ErrUnsupportedOperation},
		{"ErrKeyRotationNotSupported", ErrKeyRotationNotSupported},
		{"ErrDecryptionNotSupported", ErrDecryptionNotSupported},
		{"ErrInvalidKeyAttributes", ErrInvalidKeyAttributes},
		{"ErrTPMNotAvailable", ErrTPMNotAvailable},
		{"ErrSessionCreationFailed", ErrSessionCreationFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("Error %s is nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("Error %s has empty message", tt.name)
			}
		})
	}
}
