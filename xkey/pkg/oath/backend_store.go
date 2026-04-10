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

package oath

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// BackendStore errors.
var (
	ErrNilBackend          = errors.New("oath: nil storage backend")
	ErrBackendStoreClosed  = errors.New("oath: backend store is closed")
	ErrDuplicateCredential = errors.New("oath: duplicate credential")
)

// BackendStore implements Store using a storage.Backend for persistence.
// Each credential is stored as an individual JSON entry keyed by its ID,
// enabling encrypted storage when backed by a barrier.
type BackendStore struct {
	mu      sync.RWMutex
	backend storage.Backend
	prefix  string
	closed  bool
}

// NewBackendStore creates a new BackendStore using the given storage backend.
// The prefix is prepended to all storage keys (e.g., "oath/" produces keys
// like "oath/cred-id.json").
func NewBackendStore(backend storage.Backend, prefix string) (*BackendStore, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}
	return &BackendStore{
		backend: backend,
		prefix:  prefix,
	}, nil
}

// credKey returns the storage key for a credential ID.
func (s *BackendStore) credKey(id string) string {
	return s.prefix + id + ".json"
}

// Add adds a new credential to the store.
func (s *BackendStore) Add(cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrBackendStoreClosed
	}

	if err := cred.Validate(); err != nil {
		return err
	}

	// Check for duplicate by ID
	exists, err := s.backend.Exists(context.Background(), s.credKey(cred.ID))
	if err != nil {
		return err
	}
	if exists {
		return ErrDuplicateCredential
	}

	// Check for duplicate by name (case-insensitive)
	if err := s.checkDuplicateName(cred.Name, ""); err != nil {
		return err
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	return s.backend.Put(context.Background(), s.credKey(cred.ID), data)
}

// Get retrieves a credential by ID or name (case-insensitive).
func (s *BackendStore) Get(idOrName string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrBackendStoreClosed
	}

	// Try direct lookup by ID
	data, err := s.backend.Get(context.Background(), s.credKey(idOrName))
	if err == nil {
		var cred Credential
		if unmarshalErr := json.Unmarshal(data, &cred); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		return &cred, nil
	}

	// If the error is not "not found", propagate it
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}

	// Scan all credentials to find by name or case-insensitive ID
	return s.findByNameOrID(idOrName)
}

// List returns all credentials sorted by name.
func (s *BackendStore) List() ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrBackendStoreClosed
	}

	keys, err := s.backend.List(context.Background(), s.prefix)
	if err != nil {
		return nil, err
	}

	creds := make([]*Credential, 0, len(keys))
	for _, key := range keys {
		data, err := s.backend.Get(context.Background(), key)
		if err != nil {
			// Skip entries that disappeared between List and Get
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			return nil, err
		}

		var cred Credential
		if err := json.Unmarshal(data, &cred); err != nil {
			return nil, err
		}
		creds = append(creds, &cred)
	}

	sort.Slice(creds, func(i, j int) bool {
		return strings.ToLower(creds[i].Name) < strings.ToLower(creds[j].Name)
	})

	return creds, nil
}

// Update updates an existing credential.
func (s *BackendStore) Update(cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrBackendStoreClosed
	}

	if err := cred.Validate(); err != nil {
		return err
	}

	// Verify the credential exists
	exists, err := s.backend.Exists(context.Background(), s.credKey(cred.ID))
	if err != nil {
		return err
	}
	if !exists {
		return ErrCredentialNotFound
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	return s.backend.Put(context.Background(), s.credKey(cred.ID), data)
}

// Delete removes a credential by ID or name.
func (s *BackendStore) Delete(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrBackendStoreClosed
	}

	// Try direct delete by ID
	err := s.backend.Delete(context.Background(), s.credKey(idOrName))
	if err == nil {
		return nil
	}

	// If the error is not "not found", propagate it
	if !errors.Is(err, storage.ErrNotFound) {
		return err
	}

	// Scan to find by name or case-insensitive ID
	cred, findErr := s.findByNameOrID(idOrName)
	if findErr != nil {
		return findErr
	}

	return s.backend.Delete(context.Background(), s.credKey(cred.ID))
}

// Close marks the store as closed. It does NOT close the backend
// since it may be shared with other components.
func (s *BackendStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	return nil
}

// findByNameOrID scans all credentials to find one matching the given
// string by case-insensitive name or ID. Must be called with at least
// a read lock held.
func (s *BackendStore) findByNameOrID(idOrName string) (*Credential, error) {
	keys, err := s.backend.List(context.Background(), s.prefix)
	if err != nil {
		return nil, err
	}

	lower := strings.ToLower(idOrName)
	for _, key := range keys {
		data, err := s.backend.Get(context.Background(), key)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			return nil, err
		}

		var cred Credential
		if err := json.Unmarshal(data, &cred); err != nil {
			return nil, err
		}

		if strings.ToLower(cred.ID) == lower || strings.ToLower(cred.Name) == lower {
			return &cred, nil
		}
	}

	return nil, ErrCredentialNotFound
}

// checkDuplicateName scans all credentials to check if a name already exists
// (case-insensitive). The excludeID parameter allows excluding a specific
// credential from the check (used during updates). Must be called with the
// write lock held.
func (s *BackendStore) checkDuplicateName(name, excludeID string) error {
	keys, err := s.backend.List(context.Background(), s.prefix)
	if err != nil {
		return err
	}

	lowerName := strings.ToLower(name)
	for _, key := range keys {
		data, err := s.backend.Get(context.Background(), key)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			return err
		}

		var cred Credential
		if err := json.Unmarshal(data, &cred); err != nil {
			return err
		}

		if cred.ID == excludeID {
			continue
		}

		if strings.ToLower(cred.Name) == lowerName {
			return ErrDuplicateCredential
		}
	}

	return nil
}
