// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestUnseal_AsymmetricKeyRejected proves Unseal refuses a well-formed
// asymmetric key's attributes, mirroring TestSeal_AsymmetricKeyRejected.
func TestUnseal_AsymmetricKeyRejected(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	sealed := &types.SealedData{Backend: types.BackendTypeAzureKV}
	attrs := &types.KeyAttributes{CN: "unseal-asymmetric", KeyAlgorithm: x509.RSA}

	if _, err := b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs}); err == nil {
		t.Error("Unseal() expected error for asymmetric key attributes, got nil")
	}
}

// TestSeal_SymmetricEncrypterError proves Seal surfaces a
// SymmetricEncrypter failure (here, a key that was never generated, so
// GetSymmetricKey's local metadata check fails without contacting Azure)
// wrapped rather than panicking.
func TestSeal_SymmetricEncrypterError(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	attrs := &types.KeyAttributes{CN: "seal-key-never-generated", SymmetricAlgorithm: types.SymmetricAES256GCM}
	if _, err := b.Seal(context.Background(), []byte("data"), &types.SealOptions{KeyAttributes: attrs}); err == nil {
		t.Error("Seal() expected error for a key that was never generated, got nil")
	}
}

// TestUnseal_SymmetricEncrypterError mirrors TestSeal_SymmetricEncrypterError
// for Unseal.
func TestUnseal_SymmetricEncrypterError(t *testing.T) {
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	sealed := &types.SealedData{Backend: types.BackendTypeAzureKV}
	attrs := &types.KeyAttributes{CN: "unseal-key-never-generated", SymmetricAlgorithm: types.SymmetricAES256GCM}
	if _, err := b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs}); err == nil {
		t.Error("Unseal() expected error for a key that was never generated, got nil")
	}
}

// TestUnmarshalSealedData_InvalidJSON proves UnmarshalSealedData surfaces a
// JSON decode failure rather than returning a zero-value SealedData.
func TestUnmarshalSealedData_InvalidJSON(t *testing.T) {
	if _, err := UnmarshalSealedData([]byte("not json")); err == nil {
		t.Error("UnmarshalSealedData() expected error for invalid JSON, got nil")
	}
}
