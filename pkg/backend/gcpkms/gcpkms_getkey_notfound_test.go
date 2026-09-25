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

// TestBackend_GetKey_NotFound verifies that a gRPC NotFound status from
// GetCryptoKey is classified as backend.ErrKeyNotFound (go-xkms#801).
func TestBackend_GetKey_NotFound(t *testing.T) {
	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return nil, status.Error(codes.NotFound, "crypto key not found")
		},
	}

	keyStorage := storage.New()
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  keyStorage,
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
	// GetKey checks local metadata before calling GetCryptoKey; seed it so
	// the test exercises the gRPC status classification, not the earlier
	// "no local record" gate.
	require.NoError(t, storage.SaveKey(context.Background(), keyStorage, attrs.CN, []byte(`{}`)))

	_, err = b.GetKey(context.Background(), attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestBackend_GetKey_RetrievalError verifies that a GetCryptoKey failure
// that is NOT a gRPC NotFound status (throttling, a permission denial, a
// transport fault) is classified as ErrKeyRetrievalFailed and does NOT
// satisfy errors.Is(err, backend.ErrKeyNotFound) -- go-xkms#801.
// Collapsing this into "not found" would let getOrGenerateCAKey silently
// replace a Cloud KMS CA signing key the backend merely failed to reach.
func TestBackend_GetKey_RetrievalError(t *testing.T) {
	mockClient := &MockKMSClient{
		GetCryptoKeyFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
			return nil, status.Error(codes.PermissionDenied, "caller lacks cloudkms.cryptoKeys.get")
		},
	}

	keyStorage := storage.New()
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  keyStorage,
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
	require.NoError(t, storage.SaveKey(context.Background(), keyStorage, attrs.CN, []byte(`{}`)))

	_, err = b.GetKey(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a permission-denied GetCryptoKey failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}

// TestBackend_GetKey_MetadataRetrievalError verifies that a metadata-store
// failure other than storage.ErrNotFound (an I/O error against
// Config.KeyStorage) is also classified as ErrKeyRetrievalFailed rather
// than ErrKeyNotFound.
func TestBackend_GetKey_MetadataRetrievalError(t *testing.T) {
	mockClient := &MockKMSClient{}
	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  &failingStorage{err: errors.New("disk i/o error")},
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "metadata-io-error-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_GCPKMS,
	}

	_, err = b.GetKey(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a metadata I/O failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}

// failingStorage is a storage.Backend whose Get always fails with a
// non-ErrNotFound error, to simulate a metadata store I/O failure. It
// embeds storage.Backend so only the method under test needs overriding.
type failingStorage struct {
	storage.Backend
	err error
}

func (f *failingStorage) Get(ctx context.Context, key string) ([]byte, error) { return nil, f.err }
