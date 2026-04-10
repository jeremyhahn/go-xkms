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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Store errors.
var (
	ErrStoreNotInitialized = errors.New("oath: store not initialized")
	ErrStoreClosed         = errors.New("oath: store is closed")
)

// Store defines the interface for OATH credential persistence.
type Store interface {
	// Add adds a new credential to the store.
	Add(cred *Credential) error

	// Get retrieves a credential by ID or name.
	Get(idOrName string) (*Credential, error)

	// List returns all credentials in the store.
	List() ([]*Credential, error)

	// Update updates an existing credential.
	Update(cred *Credential) error

	// Delete removes a credential by ID or name.
	Delete(idOrName string) error

	// Close closes the store and releases resources.
	Close() error
}

// FileStore implements Store using a JSON file for persistence.
type FileStore struct {
	mu     sync.RWMutex
	path   string
	creds  map[string]*Credential
	closed bool
}

// storeData is the JSON structure for the credential file.
type storeData struct {
	Credentials []*Credential `json:"credentials"`
}

// NewFileStore creates a new file-based credential store.
// If the file doesn't exist, an empty store is created.
func NewFileStore(path string) (*FileStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	store := &FileStore{
		path:  path,
		creds: make(map[string]*Credential),
	}

	// Load existing credentials if file exists
	if _, err := os.Stat(path); err == nil {
		if err := store.load(); err != nil {
			return nil, err
		}
	}

	return store, nil
}

// Add adds a new credential to the store.
func (s *FileStore) Add(cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if err := cred.Validate(); err != nil {
		return err
	}

	// Check if credential already exists
	if _, exists := s.creds[cred.ID]; exists {
		return ErrCredentialExists
	}

	// Also check by name (case-insensitive)
	for _, existing := range s.creds {
		if strings.EqualFold(existing.Name, cred.Name) {
			return ErrCredentialExists
		}
	}

	s.creds[cred.ID] = cred
	return s.save()
}

// Get retrieves a credential by ID or name (case-insensitive).
func (s *FileStore) Get(idOrName string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	// Try exact ID match first
	if cred, exists := s.creds[idOrName]; exists {
		return cred, nil
	}

	// Try case-insensitive name match
	lower := strings.ToLower(idOrName)
	for _, cred := range s.creds {
		if strings.ToLower(cred.ID) == lower || strings.ToLower(cred.Name) == lower {
			return cred, nil
		}
	}

	return nil, ErrCredentialNotFound
}

// List returns all credentials sorted by name.
func (s *FileStore) List() ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	creds := make([]*Credential, 0, len(s.creds))
	for _, cred := range s.creds {
		creds = append(creds, cred)
	}

	// Sort by name
	sort.Slice(creds, func(i, j int) bool {
		return strings.ToLower(creds[i].Name) < strings.ToLower(creds[j].Name)
	})

	return creds, nil
}

// Update updates an existing credential.
func (s *FileStore) Update(cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if err := cred.Validate(); err != nil {
		return err
	}

	if _, exists := s.creds[cred.ID]; !exists {
		return ErrCredentialNotFound
	}

	s.creds[cred.ID] = cred
	return s.save()
}

// Delete removes a credential by ID or name.
func (s *FileStore) Delete(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	// Try exact ID match first
	if _, exists := s.creds[idOrName]; exists {
		delete(s.creds, idOrName)
		return s.save()
	}

	// Try case-insensitive name match
	lower := strings.ToLower(idOrName)
	for id, cred := range s.creds {
		if strings.ToLower(cred.ID) == lower || strings.ToLower(cred.Name) == lower {
			delete(s.creds, id)
			return s.save()
		}
	}

	return ErrCredentialNotFound
}

// Close closes the store.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	return nil
}

// load reads credentials from the file.
func (s *FileStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	var sd storeData
	if err := json.Unmarshal(data, &sd); err != nil {
		return err
	}

	s.creds = make(map[string]*Credential)
	for _, cred := range sd.Credentials {
		s.creds[cred.ID] = cred
	}

	return nil
}

// save writes credentials to the file.
func (s *FileStore) save() error {
	creds := make([]*Credential, 0, len(s.creds))
	for _, cred := range s.creds {
		creds = append(creds, cred)
	}

	// Sort for consistent output
	sort.Slice(creds, func(i, j int) bool {
		return creds[i].ID < creds[j].ID
	})

	sd := storeData{Credentials: creds}
	data, err := json.MarshalIndent(sd, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, s.path)
}

// MemoryStore implements Store using in-memory storage (no persistence).
type MemoryStore struct {
	mu     sync.RWMutex
	creds  map[string]*Credential
	closed bool
}

// NewMemoryStore creates a new in-memory credential store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		creds: make(map[string]*Credential),
	}
}

// Add adds a new credential to the store.
func (s *MemoryStore) Add(cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if err := cred.Validate(); err != nil {
		return err
	}

	if _, exists := s.creds[cred.ID]; exists {
		return ErrCredentialExists
	}

	s.creds[cred.ID] = cred
	return nil
}

// Get retrieves a credential by ID or name.
func (s *MemoryStore) Get(idOrName string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	if cred, exists := s.creds[idOrName]; exists {
		return cred, nil
	}

	lower := strings.ToLower(idOrName)
	for _, cred := range s.creds {
		if strings.ToLower(cred.ID) == lower || strings.ToLower(cred.Name) == lower {
			return cred, nil
		}
	}

	return nil, ErrCredentialNotFound
}

// List returns all credentials.
func (s *MemoryStore) List() ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	creds := make([]*Credential, 0, len(s.creds))
	for _, cred := range s.creds {
		creds = append(creds, cred)
	}

	sort.Slice(creds, func(i, j int) bool {
		return strings.ToLower(creds[i].Name) < strings.ToLower(creds[j].Name)
	})

	return creds, nil
}

// Update updates an existing credential.
func (s *MemoryStore) Update(cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if _, exists := s.creds[cred.ID]; !exists {
		return ErrCredentialNotFound
	}

	s.creds[cred.ID] = cred
	return nil
}

// Delete removes a credential.
func (s *MemoryStore) Delete(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if _, exists := s.creds[idOrName]; exists {
		delete(s.creds, idOrName)
		return nil
	}

	lower := strings.ToLower(idOrName)
	for id, cred := range s.creds {
		if strings.ToLower(cred.ID) == lower || strings.ToLower(cred.Name) == lower {
			delete(s.creds, id)
			return nil
		}
	}

	return ErrCredentialNotFound
}

// Close closes the store.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
