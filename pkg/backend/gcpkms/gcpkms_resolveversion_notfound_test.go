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
	"crypto/x509"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestBackend_Signer_ResolvePrimaryVersion_NotFound verifies that a gRPC
// NotFound status returned while resolving a key's primary version (the
// GetCryptoKey call resolvePrimaryVersionName makes on behalf of
// Signer/Decrypter/Get) is classified as backend.ErrKeyNotFound
// (go-xkms#808).
func TestBackend_Signer_ResolvePrimaryVersion_NotFound(t *testing.T) {
	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return nil, status.Error(codes.NotFound, "crypto key not found")
		},
	}
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "not-found-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
	}

	_, err = b.Signer(context.Background(), attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestBackend_Signer_ResolvePrimaryVersion_RetrievalError verifies that a
// GetCryptoKey failure that is NOT a gRPC NotFound status (throttling, a
// permission denial, a transport fault) is classified as
// ErrKeyRetrievalFailed and does NOT satisfy
// errors.Is(err, backend.ErrKeyNotFound) -- go-xkms#808. Collapsing this
// into "not found" would let a get-or-create caller silently generate a
// replacement key over a Cloud KMS key the backend merely failed to reach.
func TestBackend_Signer_ResolvePrimaryVersion_RetrievalError(t *testing.T) {
	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return nil, status.Error(codes.PermissionDenied, "caller lacks cloudkms.cryptoKeys.get")
		},
	}
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "transient-failure-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
	}

	_, err = b.Signer(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a permission-denied GetCryptoKey failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}

// TestBackend_Get_GetPublicKey_NotFound verifies that a gRPC NotFound status
// from GetPublicKey (reached from the resolved primary version) is
// classified as backend.ErrKeyNotFound (go-xkms#808).
func TestBackend_Get_GetPublicKey_NotFound(t *testing.T) {
	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return &kmspb.CryptoKey{
				Name:    req.Name,
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				Primary: &kmspb.CryptoKeyVersion{
					Name:      req.Name + "/cryptoKeyVersions/1",
					State:     kmspb.CryptoKeyVersion_ENABLED,
					Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
				},
			}, nil
		},
		GetPublicKeyFunc: func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
			return nil, status.Error(codes.NotFound, "crypto key version not found")
		},
	}
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "not-found-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
	}

	_, err = b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestBackend_Get_GetPublicKey_RetrievalError verifies that a GetPublicKey
// failure that is NOT a gRPC NotFound status is classified as
// ErrKeyRetrievalFailed and does NOT satisfy
// errors.Is(err, backend.ErrKeyNotFound) -- go-xkms#808.
func TestBackend_Get_GetPublicKey_RetrievalError(t *testing.T) {
	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return &kmspb.CryptoKey{
				Name:    req.Name,
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				Primary: &kmspb.CryptoKeyVersion{
					Name:      req.Name + "/cryptoKeyVersions/1",
					State:     kmspb.CryptoKeyVersion_ENABLED,
					Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
				},
			}, nil
		},
		GetPublicKeyFunc: func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
			return nil, status.Error(codes.Unavailable, "transport is closing")
		},
	}
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "transient-failure-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
	}

	_, err = b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "an unavailable GetPublicKey failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}
