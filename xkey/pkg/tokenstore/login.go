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
	"errors"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// FileStore is a TokenStore persisted in a directory: a DAOStore over a
// file storage backend it owns. It is the store `xkey auth login` writes,
// and the one every xkey server call reads its login token from.
type FileStore struct {
	*DAOStore
	backend xkms.StorageBackend
}

// Open opens (creating if needed) the file-backed token store in dir.
// Callers own Close, which closes the store and its backend.
func Open(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, ErrInvalidDir
	}
	backend, err := xkms.NewFileStorageBackend(dir)
	if err != nil {
		return nil, &OpenError{Dir: dir, Cause: err}
	}
	kvStore, err := xkms.NewKVStoreAdapter(backend)
	if err != nil {
		return nil, &OpenError{Dir: dir, Cause: errors.Join(err, backend.Close())}
	}
	store, err := NewDAOStore(kvStore)
	if err != nil {
		return nil, &OpenError{Dir: dir, Cause: errors.Join(err, backend.Close())}
	}
	return &FileStore{DAOStore: store, backend: backend}, nil
}

// Close closes the store and its storage backend.
func (s *FileStore) Close() error {
	return errors.Join(s.DAOStore.Close(), s.backend.Close())
}

// LoginToken returns the stored login token for serverURL, the bearer an
// xkey server call presents. No login for the server is not an error: it
// returns "". An expired login is a *LoginExpiredError, so the caller is
// told to refresh or log in again instead of silently calling anonymously.
func LoginToken(ctx context.Context, store TokenStore, serverURL string) (string, error) {
	entry, err := store.Load(ctx, serverURL)
	if errors.Is(err, ErrTokenNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if entry.IsExpired() {
		return "", &LoginExpiredError{ServerURL: entry.ServerURL}
	}
	return entry.Token, nil
}
