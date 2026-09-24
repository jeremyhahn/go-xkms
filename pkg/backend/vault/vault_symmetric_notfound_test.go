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

//go:build vault

package vault

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFailingTransitServer starts an in-process HTTP server that answers
// every Transit request with a 500, standing in for a reachable Vault whose
// Transit engine cannot service the request (an internal error, a sealed
// backend) -- as opposed to a 404, Vault's genuine not-found signal.
func newFailingTransitServer(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeVaultError(w, http.StatusInternalServerError, "internal error")
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// seedSymmetricMetadata writes the local metadata record GetSymmetricKey
// requires before it will attempt the Transit read, so tests exercise that
// Transit-level classification rather than the earlier "no local record"
// gate.
func seedSymmetricMetadata(t *testing.T, b *Backend, cn, vaultName string) {
	t.Helper()

	metadata := map[string]interface{}{
		"cn":         cn,
		"symmetric":  true,
		"vault_name": vaultName,
	}
	metadataBytes, err := json.Marshal(metadata)
	require.NoError(t, err)
	require.NoError(t, storage.SaveKey(context.Background(), b.config.KeyStorage, cn, metadataBytes))
}

// TestBackend_GetSymmetricKey_TransitNotFound verifies that a nil secret
// with no error -- Vault's convention for a Transit path that does not
// exist -- is classified as backend.ErrKeyNotFound (go-xkms#808).
func TestBackend_GetSymmetricKey_TransitNotFound(t *testing.T) {
	config := getTestVaultConfig(t)
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "not-found-symmetric-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	// Local metadata names a Transit key that was never created in the
	// double, so the read returns Vault's nil-secret not-found signal.
	seedSymmetricMetadata(t, b, attrs.CN, "never-created-in-transit")

	_, err = b.GetSymmetricKey(context.Background(), attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestBackend_GetSymmetricKey_TransitRetrievalError verifies that a Transit
// read failure that is NOT Vault's nil-secret not-found signal (here, the
// server being unreachable) is classified as ErrKeyRetrievalFailed and does
// NOT satisfy errors.Is(err, backend.ErrKeyNotFound) -- go-xkms#808.
// Collapsing this into "not found" would let a get-or-create caller
// silently replace a Vault Transit symmetric key the backend merely failed
// to reach.
func TestBackend_GetSymmetricKey_TransitRetrievalError(t *testing.T) {
	config := &Config{
		Address:     newFailingTransitServer(t),
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	// A vault.Client built directly (MaxRetries: 0) rather than through
	// NewBackend, so this test observes the classification on the first
	// failed response instead of waiting out the client's default retry
	// backoff.
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address
	vaultConfig.MaxRetries = 0
	vaultClient, err := vault.NewClient(vaultConfig)
	require.NoError(t, err)
	vaultClient.SetToken(config.Token)

	b, err := NewBackendWithClient(config, newDefaultVaultClient(vaultClient))
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "transient-failure-symmetric-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	seedSymmetricMetadata(t, b, attrs.CN, "unreachable-key")

	_, err = b.GetSymmetricKey(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "an unreachable Vault server must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}

// TestBackend_Signer_MetadataRetrievalError verifies that a metadata-store
// failure other than storage.ErrNotFound (an I/O error against
// Config.KeyStorage) encountered by Signer's existence check is classified
// as ErrKeyRetrievalFailed rather than ErrKeyNotFound (go-xkms#808).
func TestBackend_Signer_MetadataRetrievalError(t *testing.T) {
	config := &Config{
		Address:     "http://127.0.0.1:8200",
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  &failingStorage{err: errors.New("disk i/o error")},
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, nil)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{CN: "transient-failure-key"}
	_, err = b.Signer(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a metadata I/O failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}

// TestBackend_Decrypter_MetadataRetrievalError verifies that Decrypter's
// existence check applies the same classification as Signer's
// (go-xkms#808).
func TestBackend_Decrypter_MetadataRetrievalError(t *testing.T) {
	config := &Config{
		Address:     "http://127.0.0.1:8200",
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  &failingStorage{err: errors.New("disk i/o error")},
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, nil)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{CN: "transient-failure-key"}
	_, err = b.Decrypter(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a metadata I/O failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}

// TestBackend_Decrypter_MetadataNotFound verifies that Decrypter still
// classifies a genuine storage.ErrNotFound as backend.ErrKeyNotFound.
func TestBackend_Decrypter_MetadataNotFound(t *testing.T) {
	config := &Config{
		Address:     "http://127.0.0.1:8200",
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, nil)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{CN: "not-found-key"}
	_, err = b.Decrypter(context.Background(), attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestBackend_Encrypt_MetadataRetrievalError verifies that Encrypt's
// existence check applies the same classification as Signer's
// (go-xkms#808).
func TestBackend_Encrypt_MetadataRetrievalError(t *testing.T) {
	config := &Config{
		Address:     "http://127.0.0.1:8200",
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  &failingStorage{err: errors.New("disk i/o error")},
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, nil)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{CN: "transient-failure-key", KeyAlgorithm: x509.RSA}
	_, err = b.Encrypt(context.Background(), attrs, []byte("plaintext"))
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a metadata I/O failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}

// TestBackend_Encrypt_MetadataNotFound verifies that Encrypt still
// classifies a genuine storage.ErrNotFound as backend.ErrKeyNotFound.
func TestBackend_Encrypt_MetadataNotFound(t *testing.T) {
	config := &Config{
		Address:     "http://127.0.0.1:8200",
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, nil)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{CN: "not-found-key", KeyAlgorithm: x509.RSA}
	_, err = b.Encrypt(context.Background(), attrs, []byte("plaintext"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}
