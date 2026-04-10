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

package serverregistry

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// BackendServerRegistry implements ServerRegistry using a storage.Backend
// for persistence. When backed by a barrier, server entries are encrypted at rest.
type BackendServerRegistry struct {
	mu      sync.RWMutex
	backend storage.Backend
	prefix  string
	closed  bool
}

// Compile-time interface compliance check.
var _ ServerRegistry = (*BackendServerRegistry)(nil)

// NewBackendServerRegistry creates a new BackendServerRegistry using the given
// storage backend. The prefix is prepended to all storage keys (e.g.,
// "servers/" produces keys like "servers/https_xkms.company.com_8443.json").
func NewBackendServerRegistry(backend storage.Backend, prefix string) (*BackendServerRegistry, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}
	return &BackendServerRegistry{
		backend: backend,
		prefix:  prefix,
	}, nil
}

// serverKey normalizes the URL into a safe storage key by replacing URL
// characters that are unfriendly as file keys.
func (s *BackendServerRegistry) serverKey(url string) string {
	safe := strings.NewReplacer(
		"://", "_",
		"/", "_",
		":", "_",
	).Replace(url)
	return s.prefix + safe + ".json"
}

// Register stores a new server entry. Returns ErrServerExists if the URL
// is already registered.
func (s *BackendServerRegistry) Register(_ context.Context, entry *ServerEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if entry == nil {
		return ErrNilEntry
	}

	if err := entry.Validate(); err != nil {
		return err
	}

	// Check for duplicate registration.
	exists, err := s.backend.Exists(context.Background(), s.serverKey(entry.URL))
	if err != nil {
		return err
	}
	if exists {
		return ErrServerExists
	}

	entry.RegisteredAt = time.Now()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return s.backend.Put(context.Background(), s.serverKey(entry.URL), data)
}

// Lookup retrieves a server entry by URL.
func (s *BackendServerRegistry) Lookup(_ context.Context, url string) (*ServerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	if url == "" {
		return nil, ErrInvalidURL
	}

	data, err := s.backend.Get(context.Background(), s.serverKey(url))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrServerNotFound
		}
		return nil, err
	}

	var entry ServerEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// Update modifies an existing server entry. The entry must already exist.
// LastConnectedAt is automatically set to the current time.
func (s *BackendServerRegistry) Update(_ context.Context, entry *ServerEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if entry == nil {
		return ErrNilEntry
	}

	if err := entry.Validate(); err != nil {
		return err
	}

	// Verify the server exists before updating.
	exists, err := s.backend.Exists(context.Background(), s.serverKey(entry.URL))
	if err != nil {
		return err
	}
	if !exists {
		return ErrServerNotFound
	}

	entry.LastConnectedAt = time.Now()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return s.backend.Put(context.Background(), s.serverKey(entry.URL), data)
}

// List returns all registered server entries sorted by URL.
func (s *BackendServerRegistry) List(_ context.Context) ([]*ServerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	keys, err := s.backend.List(context.Background(), s.prefix)
	if err != nil {
		return nil, err
	}

	entries := make([]*ServerEntry, 0, len(keys))
	for _, key := range keys {
		data, err := s.backend.Get(context.Background(), key)
		if err != nil {
			// Skip entries that disappeared between List and Get.
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			return nil, err
		}

		var entry ServerEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, err
		}
		entries = append(entries, &entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].URL < entries[j].URL
	})

	return entries, nil
}

// Delete removes a server entry by URL.
func (s *BackendServerRegistry) Delete(_ context.Context, url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if url == "" {
		return ErrInvalidURL
	}

	err := s.backend.Delete(context.Background(), s.serverKey(url))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrServerNotFound
		}
		return err
	}

	return nil
}

// Close marks the registry as closed. The underlying backend is not closed
// since it may be shared with other components.
func (s *BackendServerRegistry) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	return nil
}
