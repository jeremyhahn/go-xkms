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
	"crypto"
	"crypto/x509"
	"errors"
	"sync"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// rsaPubKeyPEMV1 and rsaPubKeyPEMV2 are distinct RSA public keys used to
// prove that operations resolve the version-specific public key rather than
// a hardcoded one.
const (
	rsaPubKeyPEMV1 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`

	rsaPubKeyPEMV2 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvUodjUbc4jJn8E2SEvWE
qDWD/kJOOCWSIRoL0EfcDR/5StA0ysDpYftpqzeNb1IDYz3KeECgO2DmUHrtppJD
Z35mrRqwp4pLCy+/6gXZ+LujaAHL3YDsH8R8E/O/KibVBSckw4AeJ/knx5VxbXF+
J3Le4X3eK89YDElr86rdP26fjWargDEkm+YmmOIvvDJatxRl4SewYZRKPlZuXn/Y
7dOfm1jhw0giAcRVfo8sl94IT4dEGqAL+jAmtA7tJU/v4HRy1JxPJyyfu1ugggkG
yWJ8Qek1eNMdSExazFcMrZ581FufQvHTDKUpTmsHDF0568BBI8qS/17baRz1ki9r
eQIDAQAB
-----END PUBLIC KEY-----`
)

// newRotationBackend builds a Backend backed by a MockKMSClient whose
// primary version can be advanced with rotate(), simulating GCP KMS
// RotateKey behavior: CreateCryptoKeyVersion followed by
// UpdateCryptoKeyPrimaryVersion.
func newRotationBackend(t *testing.T, keyID string) (*Backend, *sync.Mutex, *string) {
	t.Helper()

	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	var mu sync.Mutex
	primaryVersion := "1"

	cryptoKeyName := "projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/" + keyID

	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			mu.Lock()
			v := primaryVersion
			mu.Unlock()
			return &kmspb.CryptoKey{
				Name:    req.Name,
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				Primary: &kmspb.CryptoKeyVersion{
					Name:      req.Name + "/cryptoKeyVersions/" + v,
					State:     kmspb.CryptoKeyVersion_ENABLED,
					Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
				},
			}, nil
		},
		GetPublicKeyFunc: func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
			pem := rsaPubKeyPEMV1
			if req.Name == cryptoKeyName+"/cryptoKeyVersions/2" {
				pem = rsaPubKeyPEMV2
			}
			return &kmspb.PublicKey{
				Pem:       pem,
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
			}, nil
		},
		AsymmetricSignFunc: func(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error) {
			signature := []byte("signed-by:" + req.Name)
			return &kmspb.AsymmetricSignResponse{
				Signature:       signature,
				SignatureCrc32C: nil,
			}, nil
		},
		CreateCryptoKeyVersionFunc: func(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
			return &kmspb.CryptoKeyVersion{
				Name:      req.Parent + "/cryptoKeyVersions/2",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
			}, nil
		},
		UpdateCryptoKeyPrimaryVersionFunc: func(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			mu.Lock()
			primaryVersion = req.CryptoKeyVersionId
			mu.Unlock()
			return &kmspb.CryptoKey{
				Name:    req.Name,
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				Primary: &kmspb.CryptoKeyVersion{
					Name:      req.Name + "/cryptoKeyVersions/" + req.CryptoKeyVersionId,
					State:     kmspb.CryptoKeyVersion_ENABLED,
					Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
				},
			}, nil
		},
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() unexpected error: %v", err)
	}

	return b, &mu, &primaryVersion
}

// TestBackend_RotateKey_OperationsUseNewVersion verifies that Sign, Get, and
// Signer all resolve to the new primary key version once RotateKey has
// promoted it, instead of remaining pinned to version 1 forever (H11).
func TestBackend_RotateKey_OperationsUseNewVersion(t *testing.T) {
	b, _, _ := newRotationBackend(t, "rotating-key")

	attrs := &types.KeyAttributes{
		CN:           "rotating-key",
		KeyAlgorithm: x509.RSA,
	}

	// Before rotation: Sign() must hit version 1.
	sig, err := b.Sign(attrs, make([]byte, 32), crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() before rotation unexpected error: %v", err)
	}
	wantV1 := "signed-by:projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/rotating-key/cryptoKeyVersions/1"
	if string(sig) != wantV1 {
		t.Errorf("Sign() before rotation signature = %q, want %q", sig, wantV1)
	}

	pem, err := b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	if err != nil {
		t.Fatalf("Get() before rotation unexpected error: %v", err)
	}
	if string(pem) != rsaPubKeyPEMV1 {
		t.Error("Get() before rotation did not return version 1 public key")
	}

	if err := b.RotateKey(context.Background(), attrs); err != nil {
		t.Fatalf("RotateKey() unexpected error: %v", err)
	}

	// After rotation: Sign() must hit version 2, not version 1.
	sig, err = b.Sign(attrs, make([]byte, 32), crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() after rotation unexpected error: %v", err)
	}
	wantV2 := "signed-by:projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/rotating-key/cryptoKeyVersions/2"
	if string(sig) != wantV2 {
		t.Errorf("Sign() after rotation signature = %q, want %q (rotation must not be a no-op)", sig, wantV2)
	}

	pem, err = b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	if err != nil {
		t.Fatalf("Get() after rotation unexpected error: %v", err)
	}
	if string(pem) != rsaPubKeyPEMV2 {
		t.Error("Get() after rotation did not return version 2 public key")
	}

	// A signer constructed after rotation must also resolve version 2.
	signer, err := b.Signer(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Signer() after rotation unexpected error: %v", err)
	}
	if signer.Public() == nil {
		t.Fatal("Signer() after rotation returned nil public key")
	}
	sig, err = signer.Sign(nil, make([]byte, 32), crypto.SHA256)
	if err != nil {
		t.Fatalf("signer.Sign() after rotation unexpected error: %v", err)
	}
	if string(sig) != wantV2 {
		t.Errorf("signer.Sign() after rotation signature = %q, want %q", sig, wantV2)
	}
}

// TestBackend_Signer_PinnedVersionSurvivesRotation verifies that a Signer
// created before a rotation keeps signing with, and reporting the public key
// for, the version it resolved at construction time, so Public() always
// matches the version used to sign even after the backend's primary version
// moves on.
func TestBackend_Signer_PinnedVersionSurvivesRotation(t *testing.T) {
	b, _, _ := newRotationBackend(t, "pinned-key")

	attrs := &types.KeyAttributes{
		CN:           "pinned-key",
		KeyAlgorithm: x509.RSA,
	}

	signer, err := b.Signer(context.Background(), attrs)
	if err != nil {
		t.Fatalf("Signer() unexpected error: %v", err)
	}

	pubKeyBefore := signer.Public()
	if pubKeyBefore == nil {
		t.Fatal("Signer() returned nil public key")
	}

	if err := b.RotateKey(context.Background(), attrs); err != nil {
		t.Fatalf("RotateKey() unexpected error: %v", err)
	}

	// Public() must remain stable: the signer was pinned to version 1 at
	// construction and must not silently start reporting version 2's key.
	pubKeyAfter := signer.Public()
	if pubKeyAfter != pubKeyBefore {
		t.Error("Signer.Public() changed after rotation; signer must stay pinned to its resolved version")
	}

	sig, err := signer.Sign(nil, make([]byte, 32), crypto.SHA256)
	if err != nil {
		t.Fatalf("signer.Sign() after rotation unexpected error: %v", err)
	}
	wantV1 := "signed-by:projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/pinned-key/cryptoKeyVersions/1"
	if string(sig) != wantV1 {
		t.Errorf("signer.Sign() after rotation signature = %q, want %q; pinned signer must keep using its resolved version", sig, wantV1)
	}
}

// TestBackend_ResolvePrimaryVersionName_NoPrimary verifies that resolving an
// ENCRYPT_DECRYPT crypto key with no primary version fails loudly instead of
// silently falling back to a hardcoded version. Asymmetric keys never have a
// primary; TestVersionNameForAsymmetricKey covers them.
func TestBackend_ResolvePrimaryVersionName_NoPrimary(t *testing.T) {
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return &kmspb.CryptoKey{Name: req.Name, Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT}, nil
		},
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() unexpected error: %v", err)
	}

	attrs := &types.KeyAttributes{CN: "no-primary-key", KeyAlgorithm: x509.RSA}

	_, err = b.Sign(attrs, make([]byte, 32), crypto.SHA256)
	if err == nil {
		t.Fatal("Sign() expected error for key with no primary version, got nil")
	}
	if !errors.Is(err, ErrNoPrimaryVersion) {
		t.Errorf("Sign() error = %v, want %v", err, ErrNoPrimaryVersion)
	}
}
