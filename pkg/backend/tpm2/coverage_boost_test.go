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

package tpm2

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestListKeys_ReadDirError tests ListKeys when os.ReadDir fails with non-NotExist error
func TestListKeys_ReadDirError(t *testing.T) {
	// Create a file instead of a directory to cause ReadDir to fail
	tmpDir := t.TempDir()
	notADir := filepath.Join(tmpDir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("data"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	// Try to list keys from a file (not directory) - this will cause ReadDir to fail
	// with an error that is NOT os.IsNotExist
	b := &Backend{closed: false, config: &Config{KeyDir: notADir}}
	_, err := b.ListKeys()
	if err == nil {
		t.Error("Expected error when listing keys from a file path")
	}
}

// TestDecrypter_KeyDoesNotImplementDecrypter verifies error when key doesn't implement crypto.Decrypter
func TestDecrypter_KeyDoesNotImplementDecrypter(t *testing.T) {
	rsaKey := &rsa.PublicKey{E: 65537}
	mockTpm := &mockTPM{parsePublicKeyValue: rsaKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getData: []byte("mock-blob"), publicData: []byte("mock-public")}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: mockKb, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := b.Decrypter(attrs)
	if err == nil {
		t.Error("Expected error because tpm2Signer does not implement crypto.Decrypter")
	}
	if !errors.Is(err, ErrDecryptionNotSupported) {
		t.Errorf("Expected ErrDecryptionNotSupported, got %v", err)
	}
}

// TestDecrypter_GetKeyError verifies Decrypter returns error when GetKey fails
func TestDecrypter_GetKeyError(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getError: errors.New("key not found")}
	b := &Backend{closed: false, tpm: &mockTPM{}, keyBackend: mockKb, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "nonexistent"}
	_, err := b.Decrypter(attrs)
	if err == nil {
		t.Error("Expected error when GetKey fails")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestSigner_GetKeyError verifies Signer returns error when GetKey fails
func TestSigner_GetKeyError(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getError: errors.New("key not found")}
	b := &Backend{closed: false, tpm: &mockTPM{}, keyBackend: mockKb, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "nonexistent"}
	_, err := b.Signer(attrs)
	if err == nil {
		t.Error("Expected error when GetKey fails")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

// TestConfig_Validate_EmptyDeviceWithoutSimulator tests validation with empty device
func TestConfig_Validate_EmptyDeviceWithoutSimulator(t *testing.T) {
	// Create temp file to simulate existing device
	tmpFile, err := os.CreateTemp("", "tpmrm*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	config := &Config{
		Device:       tmpFile.Name(),
		UseSimulator: false,
	}
	if err := config.Validate(); err != nil {
		t.Errorf("Validate() failed for existing device: %v", err)
	}
}

// TestNewBackend_ValidateError tests NewBackend when config validation fails
func TestNewBackend_ValidateError(t *testing.T) {
	config := &Config{
		Device:       "/dev/nonexistent-tpm-xyz",
		UseSimulator: false,
	}
	_, err := NewBackend(config)
	if err == nil {
		t.Error("Expected error from NewBackend with invalid config")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Expected ErrInvalidConfig, got %v", err)
	}
}

// TestBackend_DeleteKey_PreservesExistingParent verifies DeleteKey preserves an existing parent
func TestBackend_DeleteKey_PreservesExistingParent(t *testing.T) {
	mockTpm := &mockTPM{}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	existingParent := &types.KeyAttributes{CN: "existing-parent"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-key", Parent: existingParent}
	err := b.DeleteKey(attrs)
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
	if attrs.Parent != existingParent {
		t.Error("Expected existing Parent to be preserved")
	}
}

// TestListKeys_SkipsNonBlobFiles verifies ListKeys skips files without .blob extension
func TestListKeys_SkipsNonBlobFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create various files - some blob, some not
	testFiles := map[string]bool{
		"key1" + store.FSEXT_PRIVATE_BLOB: true,  // Should be found
		"key2.txt":                        false, // Should be skipped
		"key3.pub":                        false, // Should be skipped
		"key4" + store.FSEXT_PRIVATE_BLOB: true,  // Should be found
	}

	for name := range testFiles {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	b := &Backend{closed: false, config: &Config{KeyDir: tmpDir}}
	keys, err := b.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	// Should find exactly 2 keys
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}

	// Verify correct keys were found
	foundKeys := make(map[string]bool)
	for _, k := range keys {
		foundKeys[k.CN] = true
	}
	if !foundKeys["key1"] || !foundKeys["key4"] {
		t.Error("Expected to find key1 and key4")
	}
}

// TestConfig_Validate_AllDefaults verifies all defaults are set when empty config
func TestConfig_Validate_AllDefaults(t *testing.T) {
	config := &Config{UseSimulator: true}
	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Verify all defaults
	if config.KeyDir != "./tpm2-keys" {
		t.Errorf("KeyDir: expected ./tpm2-keys, got %s", config.KeyDir)
	}
	if config.SRKHandle != 0x81000001 {
		t.Errorf("SRKHandle: expected 0x81000001, got 0x%x", config.SRKHandle)
	}
	if config.EKHandle != 0x81010001 {
		t.Errorf("EKHandle: expected 0x81010001, got 0x%x", config.EKHandle)
	}
	if config.Hash != "SHA-256" {
		t.Errorf("Hash: expected SHA-256, got %s", config.Hash)
	}
	if config.PlatformPCRBank != "SHA256" {
		t.Errorf("PlatformPCRBank: expected SHA256, got %s", config.PlatformPCRBank)
	}
	if config.CN != "xkms" {
		t.Errorf("CN: expected xkms, got %s", config.CN)
	}
}

// TestDecrypt_NonRSAKey_ReturnsError verifies Decrypt returns error for non-RSA keys
func TestDecrypt_NonRSAKey_ReturnsError(t *testing.T) {
	b := &Backend{closed: false}
	decrypter := &tpm2Decrypter{
		tpm2Signer: &tpm2Signer{
			backend: b,
			attrs:   &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.ECDSA},
		},
	}

	_, err := decrypter.Decrypt(nil, []byte("ciphertext"), nil)
	if err == nil {
		t.Error("Expected error for non-RSA key")
	}
	if !errors.Is(err, ErrDecryptionNotSupported) {
		t.Errorf("Expected ErrDecryptionNotSupported, got %v", err)
	}
}

// TestDecrypt_ClosedBackend_ReturnsError verifies Decrypt returns error when backend is closed
func TestDecrypt_ClosedBackend_ReturnsError(t *testing.T) {
	b := &Backend{closed: true}
	decrypter := &tpm2Decrypter{
		tpm2Signer: &tpm2Signer{
			backend: b,
			attrs:   &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.RSA},
		},
	}

	_, err := decrypter.Decrypt(nil, []byte("ciphertext"), nil)
	if err != ErrNotInitialized {
		t.Errorf("Expected ErrNotInitialized, got %v", err)
	}
}

// TestDecrypt_LoadKeyPairError_ReturnsError verifies Decrypt error handling for LoadKeyPair failure
func TestDecrypt_LoadKeyPairError_ReturnsError(t *testing.T) {
	expectedErr := errors.New("load error")
	mockTpm := &mockTPM{loadKeyPairErr: expectedErr}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}}

	decrypter := &tpm2Decrypter{
		tpm2Signer: &tpm2Signer{
			backend: b,
			attrs:   &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.RSA},
		},
	}

	_, err := decrypter.Decrypt(nil, []byte("ciphertext"), nil)
	if err == nil {
		t.Error("Expected error from LoadKeyPair")
	}
}

// TestBackend_ClosedState_AllMethods tests all methods return proper errors when closed
func TestBackend_ClosedState_AllMethods(t *testing.T) {
	b := &Backend{closed: true}
	attrs := &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.RSA}

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GenerateKey", func() error { _, err := b.GenerateKey(attrs); return err }},
		{"GetKey", func() error { _, err := b.GetKey(attrs); return err }},
		{"DeleteKey", func() error { return b.DeleteKey(attrs) }},
		{"ListKeys", func() error { _, err := b.ListKeys(); return err }},
		{"Signer", func() error { _, err := b.Signer(attrs); return err }},
		{"Decrypter", func() error { _, err := b.Decrypter(attrs); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err != ErrNotInitialized {
				t.Errorf("%s: expected ErrNotInitialized, got %v", tt.name, err)
			}
		})
	}
}

// TestBackend_NilAttributesAllMethods tests all methods handle nil attributes
func TestBackend_NilAttributesAllMethods(t *testing.T) {
	b := &Backend{closed: false}

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GenerateKey", func() error { _, err := b.GenerateKey(nil); return err }},
		{"GetKey", func() error { _, err := b.GetKey(nil); return err }},
		{"DeleteKey", func() error { return b.DeleteKey(nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err != ErrInvalidKeyAttributes {
				t.Errorf("%s: expected ErrInvalidKeyAttributes, got %v", tt.name, err)
			}
		})
	}
}

// TestConfig_ToTPMConfig_CompleteConfig tests ToTPMConfig with all fields set
func TestConfig_ToTPMConfig_CompleteConfig(t *testing.T) {
	config := &Config{
		Device:          "/dev/tpmrm0",
		KeyDir:          "/tmp/keys",
		UseSimulator:    true,
		SimulatorHost:   "localhost",
		SimulatorPort:   2321,
		EncryptSession:  true,
		SRKHandle:       0x81000002,
		EKHandle:        0x81010002,
		Hash:            "SHA-384",
		PlatformPolicy:  true,
		PlatformPCR:     7,
		PlatformPCRBank: "SHA384",
		CN:              "test-cn",
	}

	tpmConfig := config.ToTPMConfig()
	if tpmConfig == nil {
		t.Fatal("ToTPMConfig returned nil")
	}
	if tpmConfig.Device != config.Device {
		t.Errorf("Device: expected %s, got %s", config.Device, tpmConfig.Device)
	}
	if tpmConfig.UseSimulator != config.UseSimulator {
		t.Errorf("UseSimulator: expected %v, got %v", config.UseSimulator, tpmConfig.UseSimulator)
	}
	if tpmConfig.EncryptSession != config.EncryptSession {
		t.Errorf("EncryptSession: expected %v, got %v", config.EncryptSession, tpmConfig.EncryptSession)
	}
	if tpmConfig.Hash != config.Hash {
		t.Errorf("Hash: expected %s, got %s", config.Hash, tpmConfig.Hash)
	}
	if tpmConfig.PlatformPCR != config.PlatformPCR {
		t.Errorf("PlatformPCR: expected %d, got %d", config.PlatformPCR, tpmConfig.PlatformPCR)
	}
	if tpmConfig.PlatformPCRBank != config.PlatformPCRBank {
		t.Errorf("PlatformPCRBank: expected %s, got %s", config.PlatformPCRBank, tpmConfig.PlatformPCRBank)
	}
	if tpmConfig.EK == nil {
		t.Fatal("EK config is nil")
	}
	if tpmConfig.EK.Handle != config.EKHandle {
		t.Errorf("EK.Handle: expected 0x%x, got 0x%x", config.EKHandle, tpmConfig.EK.Handle)
	}
	if tpmConfig.SSRK == nil {
		t.Fatal("SSRK config is nil")
	}
	if tpmConfig.SSRK.Handle != config.SRKHandle {
		t.Errorf("SSRK.Handle: expected 0x%x, got 0x%x", config.SRKHandle, tpmConfig.SSRK.Handle)
	}
}
