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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestBackendType verifies Type() reports the Azure Key Vault store type,
// the value every KeyAttributes.StoreType comparison in this package relies
// on.
func TestBackendType(t *testing.T) {
	b, _ := testBackend(t)
	if got := b.Type(); got != backend.BackendTypeAzureKV {
		t.Errorf("Type() = %v, want %v", got, backend.BackendTypeAzureKV)
	}
}

// TestGenerateKey verifies GenerateKey creates the Azure key and reports no
// extractable private key material, and rejects nil attrs.
func TestGenerateKey(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "generate-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	priv, err := b.GenerateKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if priv != nil {
		t.Error("GenerateKey() should return nil private key for Azure Key Vault")
	}
	if _, exists := mockClient.keys[attrs.CN]; !exists {
		t.Error("GenerateKey() did not create key in mock vault")
	}

	if _, err := b.GenerateKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GenerateKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestCreateKey_ClientError verifies CreateKey surfaces the Key Vault
// client's error instead of masking it, once the idempotency check (a
// GetKey lookup) has already reported the key does not exist.
func TestCreateKey_ClientError(t *testing.T) {
	b, mockClient := testBackend(t)
	mockClient.SetCreateError(errors.New("mock: quota exceeded"))

	attrs := &types.KeyAttributes{CN: "create-error", KeyAlgorithm: x509.RSA}
	if _, err := b.CreateKey(attrs); err == nil {
		t.Error("CreateKey() expected error from client, got nil")
	}
}

// TestSignVerifyDecryptRotate_ClientErrors verifies Sign, Verify, Decrypt
// and RotateKey all propagate the underlying Key Vault client error rather
// than swallowing it, since a caller cannot distinguish "not signed" from
// "silently failed" otherwise.
func TestSignVerifyDecryptRotate_ClientErrors(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "client-error-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	digest := sha256.Sum256([]byte("data"))

	mockClient.SetSignError(errors.New("mock: throttled"))
	if _, err := b.Sign(attrs, digest[:]); err == nil {
		t.Error("Sign() expected error, got nil")
	}
	mockClient.SetSignError(nil)

	sig, err := b.Sign(attrs, digest[:])
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if err := b.Verify(attrs, digest[:], sig); err != nil {
		t.Fatalf("Verify() sanity check error = %v", err)
	}

	mockClient.SetRotateError(errors.New("mock: rotation denied"))
	if err := b.RotateKey(context.Background(), attrs); err == nil {
		t.Error("RotateKey() expected error, got nil")
	}
	mockClient.SetRotateError(nil)

	mockClient.SetGetError(errors.New("mock: not found"))
	if _, err := b.Signer(context.Background(), attrs); err == nil {
		t.Error("Signer() expected error when GetKey fails, got nil")
	}
	if _, err := b.Decrypter(context.Background(), attrs); err == nil {
		t.Error("Decrypter() expected error when GetKey fails, got nil")
	}
	mockClient.SetGetError(nil)
}

// TestDelete_ClientErrorStillClearsMetadata verifies Delete's documented
// idempotent behavior: even when the underlying DeleteKey call fails (for
// example because the key was already gone), Delete still reports success
// after removing the local metadata entry.
func TestDelete_ClientErrorStillClearsMetadata(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{CN: "delete-error-key", KeyAlgorithm: x509.RSA}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	mockClient.SetDeleteError(errors.New("mock: key not found"))
	if err := b.Delete(attrs); err != nil {
		t.Errorf("Delete() unexpected error = %v", err)
	}

	b.mu.RLock()
	_, exists := b.metadata[attrs.CN]
	b.mu.RUnlock()
	if exists {
		t.Error("Delete() did not remove metadata despite client error")
	}
}
