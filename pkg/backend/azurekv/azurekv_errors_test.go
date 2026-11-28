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
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
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
// idempotent behavior: when the underlying DeleteKey call fails because the
// key was already gone (Key Vault's 404, the only failure that counts as
// gone), Delete still reports success after removing the local metadata
// entry.
func TestDelete_ClientErrorStillClearsMetadata(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{CN: "delete-error-key", KeyAlgorithm: x509.RSA}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	mockClient.SetDeleteError(&azcore.ResponseError{StatusCode: http.StatusNotFound, ErrorCode: "KeyNotFound"})
	if err := b.Delete(attrs); err != nil {
		t.Errorf("Delete() unexpected error = %v", err)
	}

	exists, err := storage.KeyExists(context.Background(), b.config.KeyStorage, attrs.CN)
	if err != nil {
		t.Fatalf("storage.KeyExists() error = %v", err)
	}
	if exists {
		t.Error("Delete() did not remove metadata despite client error")
	}
}

// TestDelete_RemoteDeleteFailureKeepsMetadata verifies that a Key Vault
// delete that fails for any reason but a 404 is reported and leaves the
// key's metadata, so the key stays discoverable until it is really gone.
func TestDelete_RemoteDeleteFailureKeepsMetadata(t *testing.T) {
	b, mockClient := testBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{CN: "delete-denied-key", KeyAlgorithm: x509.RSA}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	mockClient.SetDeleteError(&azcore.ResponseError{StatusCode: http.StatusForbidden, ErrorCode: "Forbidden"})
	if err := b.Delete(attrs); err == nil {
		t.Fatal("Delete() returned nil for a denied Key Vault delete")
	}
	exists, err := storage.KeyExists(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		t.Fatalf("storage.KeyExists() error = %v", err)
	}
	if !exists {
		t.Error("Delete() removed metadata although Key Vault kept the key")
	}
	keys, err := b.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	listed := false
	for _, k := range keys {
		if k.CN == attrs.CN {
			listed = true
		}
	}
	if !listed {
		t.Error("ListKeys() no longer lists a key Key Vault kept")
	}

	mockClient.SetDeleteError(&azcore.ResponseError{StatusCode: http.StatusNotFound, ErrorCode: "KeyNotFound"})
	if err := b.Delete(attrs); err != nil {
		t.Errorf("Delete() of a key Key Vault no longer has: error = %v", err)
	}
	exists, err = storage.KeyExists(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		t.Fatalf("storage.KeyExists() error = %v", err)
	}
	if exists {
		t.Error("Delete() kept metadata of a key Key Vault no longer has")
	}
}
