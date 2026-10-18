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
	"sync"
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

// newKeyExistsTestBackend returns a backend whose KMS mock rejects a second
// CreateCryptoKey for the same key name with codes.AlreadyExists, as Cloud
// KMS does.
func newKeyExistsTestBackend(t *testing.T) *Backend {
	t.Helper()
	mockClient := &MockKMSClient{}
	var mu sync.Mutex
	created := make(map[string]bool)
	mockClient.CreateCryptoKeyFunc = func(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
		name := req.Parent + "/cryptoKeys/" + req.CryptoKeyId
		mu.Lock()
		defer mu.Unlock()
		if created[name] {
			return nil, status.Error(codes.AlreadyExists, "crypto key already exists")
		}
		created[name] = true
		return &kmspb.CryptoKey{
			Name:    name,
			Purpose: req.CryptoKey.Purpose,
			Primary: &kmspb.CryptoKeyVersion{
				Name:      name + "/cryptoKeyVersions/1",
				State:     kmspb.CryptoKeyVersion_ENABLED,
				Algorithm: req.CryptoKey.VersionTemplate.Algorithm,
			},
		}, nil
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
	return b
}

// TestBackend_Generate_KeyExists proves every generate path reports Cloud
// KMS's AlreadyExists as backend.ErrKeyAlreadyExists (go-xkms#1599), and
// that any other CreateCryptoKey failure does not.
func TestBackend_Generate_KeyExists(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		generate func(*Backend, *types.KeyAttributes) error
	}{
		{
			name:  "RSA",
			attrs: &types.KeyAttributes{CN: "exists-rsa", KeyType: backend.KEY_TYPE_SIGNING, StoreType: backend.STORE_GCPKMS, KeyAlgorithm: x509.RSA},
			generate: func(b *Backend, attrs *types.KeyAttributes) error {
				_, err := b.GenerateRSA(context.Background(), attrs)
				return err
			},
		},
		{
			name:  "ECDSA",
			attrs: &types.KeyAttributes{CN: "exists-ecdsa", KeyType: backend.KEY_TYPE_SIGNING, StoreType: backend.STORE_GCPKMS, KeyAlgorithm: x509.ECDSA},
			generate: func(b *Backend, attrs *types.KeyAttributes) error {
				_, err := b.GenerateECDSA(context.Background(), attrs)
				return err
			},
		},
		{
			name:  "symmetric",
			attrs: &types.KeyAttributes{CN: "exists-symmetric", KeyType: backend.KEY_TYPE_SECRET, StoreType: backend.STORE_GCPKMS, SymmetricAlgorithm: types.SymmetricAES256GCM},
			generate: func(b *Backend, attrs *types.KeyAttributes) error {
				_, err := b.GenerateSymmetricKey(context.Background(), attrs)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newKeyExistsTestBackend(t)
			b.client.(*MockKMSClient).CreateCryptoKeyFunc = func(context.Context, *kmspb.CreateCryptoKeyRequest, ...interface{}) (*kmspb.CryptoKey, error) {
				return nil, status.Error(codes.AlreadyExists, "crypto key already exists")
			}
			err := tt.generate(b, tt.attrs)
			assert.ErrorIs(t, err, backend.ErrKeyAlreadyExists)
			assert.ErrorIs(t, err, ErrKeyAlreadyExists)

			b.client.(*MockKMSClient).CreateCryptoKeyFunc = func(context.Context, *kmspb.CreateCryptoKeyRequest, ...interface{}) (*kmspb.CryptoKey, error) {
				return nil, status.Error(codes.PermissionDenied, "permission denied")
			}
			err = tt.generate(b, tt.attrs)
			require.Error(t, err)
			assert.NotErrorIs(t, err, backend.ErrKeyAlreadyExists)
		})
	}
}

// TestBackend_GenerateRSA_ConcurrentSameKey races two generates of one key:
// exactly one wins and the other reports backend.ErrKeyAlreadyExists.
func TestBackend_GenerateRSA_ConcurrentSameKey(t *testing.T) {
	b := newKeyExistsTestBackend(t)
	attrs := &types.KeyAttributes{CN: "race-rsa", KeyType: backend.KEY_TYPE_SIGNING, StoreType: backend.STORE_GCPKMS, KeyAlgorithm: x509.RSA}

	results := make([]error, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() {
			_, results[i] = b.GenerateRSA(context.Background(), attrs)
		})
	}
	wg.Wait()

	var won, lost int
	for _, err := range results {
		switch {
		case err == nil:
			won++
		case assert.ErrorIs(t, err, backend.ErrKeyAlreadyExists):
			lost++
		}
	}
	assert.Equal(t, 1, won, "exactly one generate must win")
	assert.Equal(t, 1, lost, "the other generate must report the key exists")
}
