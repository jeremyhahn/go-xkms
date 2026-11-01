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
	"crypto/elliptic"
	"errors"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const testCryptoKeyName = "projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/rsa-key"

// signedVersionName signs with attrs and returns the CryptoKeyVersion the
// AsymmetricSign request named.
func signedVersionName(t *testing.T, b *Backend, mockClient *MockKMSClient, attrs *types.KeyAttributes) string {
	t.Helper()
	var signedWith string
	mockClient.AsymmetricSignFunc = func(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error) {
		signedWith = req.Name
		return (&MockKMSClient{}).AsymmetricSign(ctx, req, opts...)
	}
	if _, err := b.Sign(attrs, make([]byte, 32), crypto.SHA256); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return signedWith
}

// TestGenerateAsymmetricKeyWithoutPrimary verifies that a generated signing
// key uses its initial version even though Cloud KMS, and floci-gcp, report
// no primary on asymmetric keys.
func TestGenerateAsymmetricKeyWithoutPrimary(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{name: "RSA 2048", attrs: rsaAttrs(2048)},
		{name: "ECDSA P-256", attrs: ecdsaAttrs(elliptic.P256())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}
			b := newAlgorithmTestBackend(t, mockClient)

			if _, err := b.GenerateKey(context.Background(), tt.attrs); err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			got := signedVersionName(t, b, mockClient, tt.attrs)
			if want := "/cryptoKeys/" + tt.attrs.CN + "/cryptoKeyVersions/1"; !strings.HasSuffix(got, want) {
				t.Errorf("Sign() used version %q, want suffix %q", got, want)
			}
		})
	}
}

// TestVersionNameForAsymmetricKey verifies that a backend with no cached
// version resolves an asymmetric key to its newest enabled version.
func TestVersionNameForAsymmetricKey(t *testing.T) {
	mockClient := &MockKMSClient{
		ListCryptoKeyVersionsFunc: func(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest, opts ...interface{}) ([]*kmspb.CryptoKeyVersion, error) {
			return []*kmspb.CryptoKeyVersion{
				{Name: req.Parent + "/cryptoKeyVersions/1", State: kmspb.CryptoKeyVersion_ENABLED},
				{Name: req.Parent + "/cryptoKeyVersions/3", State: kmspb.CryptoKeyVersion_DESTROYED},
				{Name: req.Parent + "/cryptoKeyVersions/10", State: kmspb.CryptoKeyVersion_ENABLED},
				{Name: req.Parent + "/cryptoKeyVersions/11", State: kmspb.CryptoKeyVersion_PENDING_GENERATION},
				{Name: req.Parent + "/cryptoKeyVersions/2", State: kmspb.CryptoKeyVersion_ENABLED},
			}, nil
		},
	}
	b := newAlgorithmTestBackend(t, mockClient)

	got := signedVersionName(t, b, mockClient, rsaAttrs(2048))
	if want := testCryptoKeyName + "/cryptoKeyVersions/10"; got != want {
		t.Errorf("Sign() used version %q, want %q", got, want)
	}
}

// TestVersionNameForAsymmetricKeyErrors verifies that an asymmetric key whose
// versions cannot be listed or used fails with a typed error.
func TestVersionNameForAsymmetricKeyErrors(t *testing.T) {
	tests := []struct {
		name     string
		versions []*kmspb.CryptoKeyVersion
		listErr  error
		wantErr  error
	}{
		{
			name: "no enabled version",
			versions: []*kmspb.CryptoKeyVersion{
				{Name: testCryptoKeyName + "/cryptoKeyVersions/1", State: kmspb.CryptoKeyVersion_DESTROYED},
				{Name: testCryptoKeyName + "/cryptoKeyVersions/2", State: kmspb.CryptoKeyVersion_DISABLED},
			},
			wantErr: ErrNoUsableVersion,
		},
		{name: "no versions", wantErr: ErrNoUsableVersion},
		{
			name:     "non-numeric version ID",
			versions: []*kmspb.CryptoKeyVersion{{Name: testCryptoKeyName + "/cryptoKeyVersions/latest", State: kmspb.CryptoKeyVersion_ENABLED}},
			wantErr:  ErrInvalidVersionName,
		},
		{name: "key not found", listErr: status.Error(codes.NotFound, "no such key"), wantErr: backend.ErrKeyNotFound},
		{name: "list fails", listErr: status.Error(codes.Unavailable, "unavailable"), wantErr: ErrKeyRetrievalFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{
				ListCryptoKeyVersionsFunc: func(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest, opts ...interface{}) ([]*kmspb.CryptoKeyVersion, error) {
					return tt.versions, tt.listErr
				},
			}
			b := newAlgorithmTestBackend(t, mockClient)

			_, err := b.Sign(rsaAttrs(2048), make([]byte, 32), crypto.SHA256)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Sign() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestGenerateKeyWithoutUsableVersion verifies that generation fails, and
// releases the backend lock, when the new key has no usable version.
func TestGenerateKeyWithoutUsableVersion(t *testing.T) {
	mockClient := &MockKMSClient{
		ListCryptoKeyVersionsFunc: func(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest, opts ...interface{}) ([]*kmspb.CryptoKeyVersion, error) {
			return nil, nil
		},
	}
	b := newAlgorithmTestBackend(t, mockClient)

	for _, attrs := range []*types.KeyAttributes{rsaAttrs(2048), ecdsaAttrs(elliptic.P256())} {
		_, err := b.GenerateKey(context.Background(), attrs)
		if !errors.Is(err, ErrNoUsableVersion) {
			t.Errorf("GenerateKey(%s) error = %v, want %v", attrs.CN, err, ErrNoUsableVersion)
		}
	}
}
