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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingStorage is a storage.Backend whose Get always fails with a
// non-ErrNotFound error, to simulate a metadata store I/O failure. It
// embeds storage.Backend so only the method under test needs overriding.
type failingStorage struct {
	storage.Backend
	err error
}

func (f *failingStorage) Get(ctx context.Context, key string) ([]byte, error) { return nil, f.err }

// TestBackend_GetKey_NotFound verifies that a genuine storage.ErrNotFound
// from the local metadata store is classified as backend.ErrKeyNotFound
// (go-xkms#801).
func TestBackend_GetKey_NotFound(t *testing.T) {
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
	_, err = b.GetKey(context.Background(), attrs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotFound), "expected errors.Is(err, backend.ErrKeyNotFound), got %v", err)
}

// TestBackend_GetKey_RetrievalError verifies that a metadata-store failure
// other than storage.ErrNotFound (an I/O error against Config.KeyStorage)
// is classified as ErrKeyRetrievalFailed and does NOT satisfy
// errors.Is(err, backend.ErrKeyNotFound) -- go-xkms#801. Collapsing this
// into "not found" would let getOrGenerateCAKey silently replace a Vault
// Transit CA signing key the backend merely failed to reach.
func TestBackend_GetKey_RetrievalError(t *testing.T) {
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
	_, err = b.GetKey(context.Background(), attrs)
	require.Error(t, err)
	assert.False(t, errors.Is(err, backend.ErrKeyNotFound), "a metadata I/O failure must not satisfy errors.Is(err, backend.ErrKeyNotFound), got %v", err)
	assert.True(t, errors.Is(err, ErrKeyRetrievalFailed), "expected errors.Is(err, ErrKeyRetrievalFailed), got %v", err)
}
