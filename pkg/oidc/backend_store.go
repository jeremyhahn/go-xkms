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

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// BackendTokenStore errors.
var (
	ErrNilBackend         = errors.New("oidc: nil storage backend")
	ErrBackendStoreClosed = errors.New("oidc: backend store is closed")
)

// BackendTokenStore implements TokenStore using a storage.Backend for
// persistence. Each token is stored as an individual JSON entry keyed
// by normalized issuer, enabling encrypted storage when backed by a
// barrier.
type BackendTokenStore struct {
	mu      sync.RWMutex
	backend storage.Backend
	prefix  string
	closed  bool
}

// Compile-time interface compliance check.
var _ TokenStore = (*BackendTokenStore)(nil)

// NewBackendTokenStore creates a new BackendTokenStore using the given
// storage backend. The prefix is prepended to all storage keys (e.g.,
// "oidc/tokens/" produces keys like "oidc/tokens/issuer-key.json").
func NewBackendTokenStore(backend storage.Backend, prefix string) (*BackendTokenStore, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}
	return &BackendTokenStore{
		backend: backend,
		prefix:  prefix,
	}, nil
}

// tokenKey returns the storage key for a normalized issuer.
func (s *BackendTokenStore) tokenKey(issuer string) string {
	// Replace URL characters that are unfriendly as file keys.
	safe := strings.NewReplacer(
		"://", "_",
		"/", "_",
		":", "_",
	).Replace(issuer)
	return s.prefix + safe + ".json"
}

// Save stores tokens for the given issuer.
func (s *BackendTokenStore) Save(issuer string, tokens *TokenResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrBackendStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	if tokens == nil {
		return ErrTokenNotFound
	}

	issuer = normalizeIssuer(issuer)

	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}

	return s.backend.Put(context.Background(), s.tokenKey(issuer), data)
}

// Load retrieves tokens for the given issuer.
func (s *BackendTokenStore) Load(issuer string) (*TokenResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrBackendStoreClosed
	}

	if issuer == "" {
		return nil, ErrInvalidIssuer
	}

	issuer = normalizeIssuer(issuer)

	data, err := s.backend.Get(context.Background(), s.tokenKey(issuer))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	var tokens TokenResponse
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

// Delete removes tokens for the given issuer.
func (s *BackendTokenStore) Delete(issuer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrBackendStoreClosed
	}

	if issuer == "" {
		return ErrInvalidIssuer
	}

	issuer = normalizeIssuer(issuer)

	err := s.backend.Delete(context.Background(), s.tokenKey(issuer))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrTokenNotFound
		}
		return err
	}

	return nil
}

// List returns all issuers with stored tokens.
func (s *BackendTokenStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrBackendStoreClosed
	}

	keys, err := s.backend.List(context.Background(), s.prefix)
	if err != nil {
		return nil, err
	}

	issuers := make([]string, 0, len(keys))
	for _, key := range keys {
		// Strip prefix and .json suffix to recover issuer name.
		name := strings.TrimPrefix(key, s.prefix)
		name = strings.TrimSuffix(name, ".json")
		if name != "" {
			issuers = append(issuers, name)
		}
	}

	sort.Strings(issuers)
	return issuers, nil
}

// Close closes the store and marks it as closed.
// The underlying backend is not closed since it may be shared.
func (s *BackendTokenStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	return nil
}
