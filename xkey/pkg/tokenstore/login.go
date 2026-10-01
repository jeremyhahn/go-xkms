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
	"strings"

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

// ServerRef identifies the server a call goes to, for picking its login.
type ServerRef struct {
	// ID is the server's TLS identity (see TokenEntry.ServerID), observed
	// on a TLS transport. When set it alone selects the login.
	ID string

	// Name is the configured server name, used on a transport without TLS
	// (a Unix socket) to select the login whose ServerName matches.
	Name string
}

// LoginToken returns the stored login token for the server ref names, the
// bearer an xkey server call presents. The login is selected by the
// server's TLS identity, so a login made over one transport serves every
// transport of that server; without TLS it is selected by the configured
// server name, which must name exactly one server. Of several logins to
// the same server the newest is used. No login is not an error: it returns
// "". An expired login is a *LoginExpiredError, so the caller is told to
// refresh or log in again instead of silently calling anonymously.
func LoginToken(ctx context.Context, store TokenStore, ref ServerRef) (string, error) {
	if ref.ID == "" && ref.Name == "" {
		return "", nil
	}
	entries, err := store.List(ctx)
	if err != nil {
		return "", err
	}

	var newest *TokenEntry
	servers := map[string]bool{}
	for _, e := range entries {
		if !ref.matches(e) {
			continue
		}
		servers[e.ServerID] = true
		if newest == nil || e.IssuedAt.After(newest.IssuedAt) {
			newest = e
		}
	}
	if newest == nil {
		return "", nil
	}
	if ref.ID == "" && len(servers) > 1 {
		return "", &AmbiguousServerNameError{Name: ref.Name, Servers: len(servers)}
	}
	if newest.IsExpired() {
		return "", &LoginExpiredError{ServerURL: newest.ServerURL}
	}
	return newest.Token, nil
}

// matches reports whether e is a login to the server r names.
func (r ServerRef) matches(e *TokenEntry) bool {
	if r.ID != "" {
		return e.ServerID == r.ID
	}
	return e.ServerName != "" && strings.EqualFold(e.ServerName, r.Name)
}
