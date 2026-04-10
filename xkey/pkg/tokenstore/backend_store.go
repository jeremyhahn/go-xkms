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

package tokenstore

import (
	"context"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// BackendTokenStore implements TokenStore by delegating to a DAOStore.
// It exists as a backward-compatible wrapper that adapts a storage.Backend
// into the DAO-backed persistence layer. New callers should prefer
// NewDAOStore directly.
type BackendTokenStore struct {
	dao    *DAOStore
	prefix string
}

// Compile-time interface compliance check.
var _ TokenStore = (*BackendTokenStore)(nil)

// NewBackendTokenStore creates a new BackendTokenStore using the given
// storage backend. The prefix is retained for migration compatibility
// but is no longer used for key derivation -- the DAO uses its own
// "tokens" entity namespace.
func NewBackendTokenStore(backend storage.Backend, prefix string) (*BackendTokenStore, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}

	kvStore, err := kvadapter.New(backend)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	daoStore, err := NewDAOStore(kvStore)
	if err != nil {
		return nil, err
	}

	return &BackendTokenStore{
		dao:    daoStore,
		prefix: prefix,
	}, nil
}

// normalizeServer normalizes a server URL for consistent key derivation.
func normalizeServer(serverURL string) string {
	return strings.TrimSuffix(strings.ToLower(serverURL), "/")
}

// Save persists a token entry keyed by its server URL.
func (s *BackendTokenStore) Save(ctx context.Context, entry *TokenEntry) error {
	return s.dao.Save(ctx, entry)
}

// Load retrieves the token entry for the given server URL.
func (s *BackendTokenStore) Load(ctx context.Context, serverURL string) (*TokenEntry, error) {
	return s.dao.Load(ctx, serverURL)
}

// Delete removes the token entry for the given server URL.
func (s *BackendTokenStore) Delete(ctx context.Context, serverURL string) error {
	return s.dao.Delete(ctx, serverURL)
}

// List returns all stored token entries sorted by server URL.
func (s *BackendTokenStore) List(ctx context.Context) ([]*TokenEntry, error) {
	return s.dao.List(ctx)
}

// Close marks the store as closed. The underlying backend is not closed
// since it may be shared with other components.
func (s *BackendTokenStore) Close() error {
	return s.dao.Close()
}
