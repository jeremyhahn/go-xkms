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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"slices"
	"testing"

	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestDecrypter_KeyDoesNotImplementDecrypter verifies error when key doesn't implement crypto.Decrypter
func TestDecrypter_KeyDoesNotImplementDecrypter(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mockTpm := &mockTPM{parsePublicKeyValue: &ecKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getData: []byte("mock-blob"), publicData: []byte("mock-public")}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: mockKb, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err = b.Decrypter(context.Background(), attrs)
	if err == nil {
		t.Error("Expected error: an EC key agrees, it does not decrypt")
	}
	if !errors.Is(err, ErrDecryptionNotSupported) {
		t.Errorf("Expected ErrDecryptionNotSupported, got %v", err)
	}
}

// TestDecrypter_GetKeyError verifies Decrypter returns error when GetKey fails
func TestDecrypter_GetKeyError(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getError: store.ErrBlobNotFound}
	b := &Backend{closed: false, tpm: &mockTPM{}, keyBackend: mockKb, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "nonexistent"}
	_, err := b.Decrypter(context.Background(), attrs)
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
	mockKb := &mockKeyBackend{getError: store.ErrBlobNotFound}
	b := &Backend{closed: false, tpm: &mockTPM{}, keyBackend: mockKb, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "nonexistent"}
	_, err := b.Signer(context.Background(), attrs)
	if err == nil {
		t.Error("Expected error when GetKey fails")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
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

// TestBackend_ClosedState_AllMethods tests all methods return proper errors when closed
func TestBackend_ClosedState_AllMethods(t *testing.T) {
	b := &Backend{closed: true}
	attrs := &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.RSA}

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GenerateKey", func() error { _, err := b.GenerateKey(context.Background(), attrs); return err }},
		{"GetKey", func() error { _, err := b.GetKey(context.Background(), attrs); return err }},
		{"DeleteKey", func() error { return b.DeleteKey(context.Background(), attrs) }},
		{"ListKeys", func() error { _, err := b.ListKeys(context.Background()); return err }},
		{"Signer", func() error { _, err := b.Signer(context.Background(), attrs); return err }},
		{"Decrypter", func() error { _, err := b.Decrypter(context.Background(), attrs); return err }},
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
		{"GenerateKey", func() error { _, err := b.GenerateKey(context.Background(), nil); return err }},
		{"GetKey", func() error { _, err := b.GetKey(context.Background(), nil); return err }},
		{"DeleteKey", func() error { return b.DeleteKey(context.Background(), nil) }},
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
		UseSimulator:    true,
		SimulatorHost:   "localhost",
		SimulatorPort:   2321,
		SRKHandle:       0x81000002,
		EKHandle:        0x81010002,
		Hash:            "SHA-384",
		PlatformPCRs:    pkgtpm2.PCRSet{7, 11},
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
	// When SimulatorHost is set alongside UseSimulator, ToTPMConfig targets an
	// external TPM daemon (e.g. swtpm) over TCP: it wires CommandAddress and
	// clears UseSimulator so NewTPM2 selects the TCP transport path instead of
	// the in-memory go-tpm-tools simulator.
	if tpmConfig.UseSimulator {
		t.Errorf("UseSimulator: expected false (external TCP via SimulatorHost), got true")
	}
	if tpmConfig.CommandAddress != "localhost:2321" {
		t.Errorf("CommandAddress: expected localhost:2321, got %s", tpmConfig.CommandAddress)
	}
	if tpmConfig.Hash != config.Hash {
		t.Errorf("Hash: expected %s, got %s", config.Hash, tpmConfig.Hash)
	}
	if !slices.Equal(tpmConfig.PlatformPCRs, config.PlatformPCRs) {
		t.Errorf("PlatformPCRs: expected %v, got %v", config.PlatformPCRs, tpmConfig.PlatformPCRs)
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
