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

//go:build gcpkms

package gcpkms

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newSealTestBackend builds a Backend with a symmetric key already created
// (via GenerateSymmetricKey against MockKMSClient's built-in reversible
// fake cipher, the same seam TestSymmetricEncrypter_RoundTrip uses), so
// Seal/Unseal tests exercise the real encrypt/decrypt round trip instead of
// only the validation guards sealer_test.go already covers.
func newSealTestBackend(t *testing.T, cn string) (*Backend, *types.KeyAttributes) {
	t.Helper()

	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	mockClient := &MockKMSClient{}
	mockClient.CreateCryptoKeyFunc = func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
		return &kmspb.CryptoKey{
			Name:    req.Parent + "/cryptoKeys/" + req.CryptoKeyId,
			Purpose: req.CryptoKey.Purpose,
			Primary: &kmspb.CryptoKeyVersion{
				Name:      req.Parent + "/cryptoKeys/" + req.CryptoKeyId + "/cryptoKeyVersions/1",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
		}, nil
	}
	mockClient.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
		return &kmspb.CryptoKey{
			Name:    req.Name,
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Primary: &kmspb.CryptoKeyVersion{
				Name:      req.Name + "/cryptoKeyVersions/1",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
		}, nil
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_GCPKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey() error = %v", err)
	}

	return b, attrs
}

// TestSealUnseal_RoundTrip proves Seal followed by Unseal recovers the
// original plaintext through the real Encrypt/Decrypt path (MockKMSClient's
// built-in reversible fake cipher), including the AAD and algorithm
// metadata Seal records and Unseal reads back.
func TestSealUnseal_RoundTrip(t *testing.T) {
	b, attrs := newSealTestBackend(t, "seal-roundtrip-key")

	plaintext := []byte("seal round trip plaintext")
	aad := []byte("seal round trip aad")

	sealed, err := b.Seal(context.Background(), plaintext, &types.SealOptions{KeyAttributes: attrs, AAD: aad})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if sealed.Backend != types.BackendTypeGCPKMS {
		t.Errorf("Seal() Backend = %v, want %v", sealed.Backend, types.BackendTypeGCPKMS)
	}
	if sealed.KeyID != attrs.ID() {
		t.Errorf("Seal() KeyID = %q, want %q", sealed.KeyID, attrs.ID())
	}
	if _, ok := sealed.Metadata["gcpkms:has_aad"]; !ok {
		t.Error("Seal() metadata missing gcpkms:has_aad when AAD was provided")
	}

	got, err := b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs, AAD: aad})
	if err != nil {
		t.Fatalf("Unseal() error = %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("Unseal() = %q, want %q", got, plaintext)
	}
}

// TestSeal_SymmetricEncrypterError proves Seal surfaces a
// SymmetricEncrypter failure (here, GetCryptoKey reporting the key does not
// exist) wrapped rather than panicking or silently sealing with a nil
// encrypter.
func TestSeal_SymmetricEncrypterError(t *testing.T) {
	b, _ := newSealTestBackend(t, "seal-encrypter-error-key")

	mockClient := b.client.(*MockKMSClient)
	mockClient.GetCryptoKeyFunc = func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
		return nil, status.Error(codes.NotFound, "crypto key not found")
	}

	missing := &types.KeyAttributes{
		CN:                 "seal-key-never-created",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_GCPKMS,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.Seal(context.Background(), []byte("data"), &types.SealOptions{KeyAttributes: missing}); err == nil {
		t.Error("Seal() expected error for a key GetCryptoKey reports missing, got nil")
	}
}

// TestUnseal_DecrypterError proves Unseal surfaces a GCP KMS Decrypt RPC
// failure wrapped rather than returning corrupted plaintext.
func TestUnseal_DecrypterError(t *testing.T) {
	b, attrs := newSealTestBackend(t, "unseal-decrypter-error-key")

	sealed, err := b.Seal(context.Background(), []byte("data"), &types.SealOptions{KeyAttributes: attrs})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	mockClient := b.client.(*MockKMSClient)
	mockClient.DecryptFunc = func(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error) {
		return nil, errors.New("kms: decrypt denied")
	}

	if _, err := b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs}); err == nil {
		t.Error("Unseal() expected error when the Decrypt RPC fails, got nil")
	}
}

// TestUnmarshalSealedData_InvalidJSON proves UnmarshalSealedData surfaces a
// JSON decode failure rather than returning a zero-value SealedData.
func TestUnmarshalSealedData_InvalidJSON(t *testing.T) {
	if _, err := UnmarshalSealedData([]byte("not json")); err == nil {
		t.Error("UnmarshalSealedData() expected error for invalid JSON, got nil")
	}
}

// TestMarshalSealedData_RoundTrip proves MarshalSealedData and
// UnmarshalSealedData compose to reproduce a SealedData value.
func TestMarshalSealedData_RoundTrip(t *testing.T) {
	original := &types.SealedData{
		Backend:    types.BackendTypeGCPKMS,
		Ciphertext: []byte("ciphertext"),
		KeyID:      "key-id",
		Metadata:   map[string][]byte{"gcpkms:algorithm": []byte("aes-256-gcm")},
	}
	marshaled, err := MarshalSealedData(original)
	if err != nil {
		t.Fatalf("MarshalSealedData() error = %v", err)
	}
	got, err := UnmarshalSealedData(marshaled)
	if err != nil {
		t.Fatalf("UnmarshalSealedData() error = %v", err)
	}
	if got.KeyID != original.KeyID || string(got.Ciphertext) != string(original.Ciphertext) {
		t.Errorf("UnmarshalSealedData() = %+v, want %+v", got, original)
	}
}
