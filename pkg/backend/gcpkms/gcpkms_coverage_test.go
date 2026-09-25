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

//go:build gcpkms

package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func newCoverageTestConfig() *Config {
	return &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
}

// TestBackendGetKeyLifecycle verifies GetKey's not-found and success paths,
// and that GetSignerByID/GetDecrypterByID reject a key whose "private key"
// (GCP KMS never returns extractable material) does not implement
// crypto.Signer/crypto.Decrypter directly.
func TestBackendGetKeyLifecycle(t *testing.T) {
	config := newCoverageTestConfig()
	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "getkey-lifecycle",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
		KeyAlgorithm: x509.RSA,
	}

	if _, err := b.GetKey(context.Background(), attrs); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("GetKey() before creation error = %v, want ErrKeyNotFound", err)
	}
	if _, err := b.GetKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GetKey(nil) error = %v, want ErrInvalidAttributes", err)
	}

	if _, err := b.GenerateRSA(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateRSA() error = %v", err)
	}

	if _, err := b.GetKey(context.Background(), attrs); err != nil {
		t.Errorf("GetKey() after creation unexpected error = %v", err)
	}

	if _, err := b.GetSignerByID("does-not-exist"); err == nil {
		t.Error("GetSignerByID() expected error for unknown key, got nil")
	}
	if _, err := b.GetSignerByID(attrs.CN); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetSignerByID() error = %v, want ErrInvalidKeyType", err)
	}
	if _, err := b.GetDecrypterByID("does-not-exist"); err == nil {
		t.Error("GetDecrypterByID() expected error for unknown key, got nil")
	}
	if _, err := b.GetDecrypterByID(attrs.CN); !errors.Is(err, backend.ErrInvalidKeyType) {
		t.Errorf("GetDecrypterByID() error = %v, want ErrInvalidKeyType", err)
	}
}

// TestBackendDeleteKey verifies DeleteKey's guard clause and its delegation
// to Delete, including metadata cleanup.
func TestBackendDeleteKey(t *testing.T) {
	config := newCoverageTestConfig()
	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	if err := b.DeleteKey(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("DeleteKey(nil) error = %v, want ErrInvalidAttributes", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "delete-key-test",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.GenerateRSA(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateRSA() error = %v", err)
	}

	if err := b.DeleteKey(context.Background(), attrs); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	if _, err := storage.GetKey(context.Background(), config.KeyStorage, attrs.CN); err == nil {
		t.Error("DeleteKey() did not remove metadata")
	}
}

// TestBackendListKeys verifies ListKeys reconstructs KeyAttributes from
// stored metadata, preserving key type and key algorithm rather than
// silently dropping them (the "silently dropped field" bug class the issue
// calls out for awskms).
func TestBackendListKeys(t *testing.T) {
	config := newCoverageTestConfig()
	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "list-keys-gcp",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.GenerateRSA(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateRSA() error = %v", err)
	}

	// The default ListCryptoKeysFunc always reports an empty collection
	// (see mock_kms.go); override it to surface the key CreateCryptoKey
	// actually recorded in the mock's internal map, mirroring what a real
	// ListCryptoKeys call against the crypto key just created would report.
	mockClient.ListCryptoKeysFunc = func(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...interface{}) ([]*kmspb.CryptoKey, error) {
		created := make([]*kmspb.CryptoKey, 0, len(mockClient.keys))
		for _, k := range mockClient.keys {
			created = append(created, k)
		}
		return created, nil
	}

	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ListKeys() returned %d keys, want 1", len(keys))
	}
	got := keys[0]
	if got.CN != attrs.CN {
		t.Errorf("ListKeys() CN = %q, want %q", got.CN, attrs.CN)
	}
	if got.KeyType != backend.KEY_TYPE_SIGNING {
		t.Errorf("ListKeys() KeyType = %v, want SIGNING (dropped on read)", got.KeyType)
	}
	if got.KeyAlgorithm != x509.RSA {
		t.Errorf("ListKeys() KeyAlgorithm = %v, want RSA (dropped on read)", got.KeyAlgorithm)
	}

	// ListCryptoKeys client error propagates.
	mockClient.ListCryptoKeysFunc = func(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...interface{}) ([]*kmspb.CryptoKey, error) {
		return nil, errors.New("mock: permission denied")
	}
	if _, err := b.ListKeys(context.Background()); err == nil {
		t.Error("ListKeys() expected error from client, got nil")
	}
}

// TestVerify_AllBranches verifies Verify's hash-algorithm dispatch, its
// RSA and ECDSA verification paths, and its guard clauses / error mapping
// -- a real not-found/invalid-signature distinction a caller depends on.
func TestVerify_AllBranches(t *testing.T) {
	config := newCoverageTestConfig()

	// The mock's default AsymmetricSignFunc returns a fixed, non-cryptographic
	// byte pattern (see mock_kms.go) that does not correspond to its default
	// GetPublicKeyFunc's fixed RSA key, so a real Verify() call would never
	// succeed against those defaults. Generate a real key pair and wire both
	// functions to it, so Sign/Verify exercise genuine RSA cryptography.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
			return &kmspb.PublicKey{Pem: pubPEM, Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256}, nil
		},
		AsymmetricSignFunc: func(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error) {
			sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, req.Digest.GetSha256())
			if err != nil {
				return nil, err
			}
			return &kmspb.AsymmetricSignResponse{Signature: sig}, nil
		},
	}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "verify-rsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
		KeyAlgorithm: x509.RSA,
	}
	signer, err := b.GenerateRSA(context.Background(), attrs)
	if err != nil {
		t.Fatalf("GenerateRSA() error = %v", err)
	}

	digest := sha256.Sum256([]byte("verify me"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if err := b.Verify(attrs, digest[:], sig); err != nil {
		t.Errorf("Verify() valid signature error = %v", err)
	}

	wrongDigest := sha256.Sum256([]byte("not the same data"))
	if err := b.Verify(attrs, wrongDigest[:], sig); err == nil {
		t.Error("Verify() with wrong digest expected error, got nil")
	}

	if err := b.Verify(attrs, nil, sig); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("Verify(empty digest) error = %v, want ErrInvalidAttributes", err)
	}
	if err := b.Verify(attrs, digest[:], nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("Verify(empty signature) error = %v, want ErrInvalidAttributes", err)
	}

	// Public key lookup failure is surfaced, not swallowed.
	mockClient.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
		return nil, errors.New("mock: not found")
	}
	if err := b.Verify(attrs, digest[:], sig); err == nil {
		t.Error("Verify() expected error when public key lookup fails, got nil")
	}
}

// TestVerify_ECDSA verifies Verify's ECDSA branch against a real ECDSA
// public key returned by the client, since the default mock only serves an
// RSA key.
func TestVerify_ECDSA(t *testing.T) {
	config := newCoverageTestConfig()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	mockClient := &MockKMSClient{
		GetPublicKeyFunc: func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
			return &kmspb.PublicKey{Pem: pubPEM, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}, nil
		},
	}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{CN: "verify-ecdsa", KeyAlgorithm: x509.ECDSA}
	digest := sha256.Sum256([]byte("ecdsa verify"))
	sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatalf("SignASN1() error = %v", err)
	}

	if err := b.Verify(attrs, digest[:], sig); err != nil {
		t.Errorf("Verify() ECDSA error = %v", err)
	}
}

// TestExportKeyTo verifies ExportKeyTo's guard clauses and its unconditional
// ErrExportToUnsupported result: GCP KMS never releases plaintext key
// material for re-wrapping.
func TestExportKeyTo(t *testing.T) {
	config := newCoverageTestConfig()
	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	if _, err := b.ExportKeyTo(context.Background(), nil, &backend.ImportParameters{}); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyTo(nil attrs) error = %v, want ErrInvalidAttributes", err)
	}
	attrs := &types.KeyAttributes{CN: "export-to-gcp"}
	if _, err := b.ExportKeyTo(context.Background(), attrs, nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyTo(nil dstParams) error = %v, want ErrInvalidAttributes", err)
	}
	if _, err := b.ExportKeyTo(context.Background(), attrs, &backend.ImportParameters{}); !errors.Is(err, backend.ErrExportToUnsupported) {
		t.Errorf("ExportKeyTo() error = %v, want ErrExportToUnsupported", err)
	}
}

// TestExportKeyMaterial verifies ExportKeyMaterial's guard clause and its
// unconditional ErrExportNotSupported result.
func TestExportKeyMaterial(t *testing.T) {
	config := newCoverageTestConfig()
	mockClient := &MockKMSClient{}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	if _, err := b.ExportKeyMaterial(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyMaterial(nil attrs) error = %v, want ErrInvalidAttributes", err)
	}
	attrs := &types.KeyAttributes{CN: "export-material-gcp"}
	if _, err := b.ExportKeyMaterial(context.Background(), attrs); !errors.Is(err, backend.ErrExportNotSupported) {
		t.Errorf("ExportKeyMaterial() error = %v, want ErrExportNotSupported", err)
	}
}
