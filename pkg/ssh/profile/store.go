// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	// defaultKeyPrefix is the storage namespace for profile entries.
	defaultKeyPrefix = "ssh/profiles/"

	// folderMarkerSuffix sub-namespaces empty folder markers so folders
	// survive restarts even without entries.
	folderMarkerSuffix = "__folders__/"
)

// Store is the persistence interface for SSH connection profiles. It mirrors
// the static-password store's folder semantics (flat slash-delimited paths plus
// explicit folder markers). Implementations MUST be safe for concurrent use.
type Store interface {
	Add(p *Profile) error
	Get(idOrName string) (*Profile, error)
	List() ([]*Profile, error)
	Update(p *Profile) error
	Delete(idOrName string) error

	// ListByFolder returns entries in folderPath and all subfolders (empty ⇒ all).
	ListByFolder(folderPath string) ([]*Profile, error)
	// ListByFolderDirect returns entries directly in folderPath (no subfolders).
	ListByFolderDirect(folderPath string) ([]*Profile, error)
	// ListFolders returns every unique folder path (derived + persisted), sorted.
	ListFolders() ([]string, error)
	// MoveToFolder moves an entry to folderPath, regenerating its ID.
	MoveToFolder(idOrName, folderPath string) error
	// CreateFolder / RemoveFolder manage empty folder markers.
	CreateFolder(path string) error
	RemoveFolder(path string) error
	// RenameFolder renames a folder and every entry/marker beneath it.
	RenameFolder(oldPath, newPath string) error
	// DeleteFolder removes a folder, its markers, and all entries within it.
	DeleteFolder(path string) error
	// Search returns entries whose name/host/user/folder contains query.
	Search(query string) ([]*Profile, error)

	Close() error
}

// BackendStore implements Store over a storage.Backend.
type BackendStore struct {
	mu        sync.RWMutex
	backend   storage.Backend
	keyPrefix string
	closed    bool
}

// NewStore constructs a BackendStore. Returns ErrNilBackend if backend is nil.
func NewStore(backend storage.Backend) (*BackendStore, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}
	return &BackendStore{backend: backend, keyPrefix: defaultKeyPrefix}, nil
}

// Add stores a new profile, generating its deterministic ID.
func (s *BackendStore) Add(p *Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := p.Validate(); err != nil {
		return err
	}
	p.ID = generateID(p.Name, p.FolderPath)
	now := time.Now().UTC()
	p.CreatedAt = now
	p.UpdatedAt = now

	key := s.storageKey(p.ID)
	exists, err := s.backend.Exists(context.Background(), key)
	if err != nil {
		return &errs.Detail{Err: ErrExists, Detail: fmt.Sprintf("%v", err)}
	}
	if exists {
		return ErrExists
	}
	data, err := json.Marshal(p)
	if err != nil {
		return &errs.Detail{Err: ErrMarshalFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return s.backend.Put(context.Background(), key, data)
}

// Get retrieves a profile by ID or (case-insensitive) name.
func (s *BackendStore) Get(idOrName string) (*Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	return s.getUnlocked(idOrName)
}

// List returns all profiles sorted by name.
func (s *BackendStore) List() ([]*Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	return s.listUnlocked()
}

func (s *BackendStore) listUnlocked() ([]*Profile, error) {
	keys, err := s.backend.List(context.Background(), s.keyPrefix)
	if err != nil {
		return nil, &errs.Detail{Err: ErrNotFound, Detail: fmt.Sprintf("%v", err)}
	}
	out := make([]*Profile, 0, len(keys))
	for _, key := range keys {
		if s.isFolderMarkerKey(key) {
			continue
		}
		data, getErr := s.backend.Get(context.Background(), key)
		if getErr != nil {
			continue
		}
		p, uErr := unmarshalProfile(data)
		if uErr != nil {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// Update modifies an existing profile, regenerating its ID if name/folder moved.
func (s *BackendStore) Update(p *Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := p.Validate(); err != nil {
		return err
	}
	oldKey := s.storageKey(p.ID)
	existingData, err := s.backend.Get(context.Background(), oldKey)
	if err != nil {
		return ErrNotFound
	}
	existing, err := unmarshalProfile(existingData)
	if err != nil {
		return err
	}
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = time.Now().UTC()

	newID := generateID(p.Name, p.FolderPath)
	if newID != p.ID {
		if delErr := s.backend.Delete(context.Background(), oldKey); delErr != nil {
			return &errs.Detail{Err: ErrNotFound, Detail: fmt.Sprintf("%v", delErr)}
		}
		p.ID = newID
	}
	data, err := json.Marshal(p)
	if err != nil {
		return &errs.Detail{Err: ErrMarshalFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return s.backend.Put(context.Background(), s.storageKey(p.ID), data)
}

// Delete removes a profile by ID or name.
func (s *BackendStore) Delete(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	p, err := s.getUnlocked(idOrName)
	if err != nil {
		return err
	}
	return s.backend.Delete(context.Background(), s.storageKey(p.ID))
}

// ListByFolder returns entries in folderPath and its subfolders.
func (s *BackendStore) ListByFolder(folderPath string) ([]*Profile, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	out := make([]*Profile, 0)
	for _, p := range all {
		if folderPath == "" || p.FolderPath == folderPath || strings.HasPrefix(p.FolderPath, folderPath+"/") {
			out = append(out, p)
		}
	}
	return out, nil
}

// ListByFolderDirect returns entries directly in folderPath (no subfolders).
func (s *BackendStore) ListByFolderDirect(folderPath string) ([]*Profile, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	out := make([]*Profile, 0)
	for _, p := range all {
		if p.FolderPath == folderPath {
			out = append(out, p)
		}
	}
	return out, nil
}

// ListFolders returns all unique folder paths (derived + persisted markers).
func (s *BackendStore) ListFolders() ([]string, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	unique := make(map[string]struct{})
	for _, p := range all {
		if p.FolderPath == "" {
			continue
		}
		parts := strings.Split(p.FolderPath, "/")
		for i := range parts {
			unique[strings.Join(parts[:i+1], "/")] = struct{}{}
		}
	}
	s.mu.RLock()
	markerPrefix := s.keyPrefix + folderMarkerSuffix
	markerKeys, listErr := s.backend.List(context.Background(), markerPrefix)
	s.mu.RUnlock()
	if listErr == nil {
		for _, key := range markerKeys {
			if folder := strings.TrimPrefix(key, markerPrefix); folder != "" {
				unique[folder] = struct{}{}
			}
		}
	}
	folders := make([]string, 0, len(unique))
	for f := range unique {
		folders = append(folders, f)
	}
	sort.Strings(folders)
	return folders, nil
}

// MoveToFolder moves an entry to folderPath, regenerating its ID.
func (s *BackendStore) MoveToFolder(idOrName, folderPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	p, err := s.getUnlocked(idOrName)
	if err != nil {
		return err
	}
	if p.FolderPath == folderPath {
		return ErrMoveToSameFolder
	}
	oldKey := s.storageKey(p.ID)
	if delErr := s.backend.Delete(context.Background(), oldKey); delErr != nil {
		return &errs.Detail{Err: ErrNotFound, Detail: fmt.Sprintf("%v", delErr)}
	}
	p.FolderPath = folderPath
	p.ID = generateID(p.Name, p.FolderPath)
	p.UpdatedAt = time.Now().UTC()
	newKey := s.storageKey(p.ID)
	exists, err := s.backend.Exists(context.Background(), newKey)
	if err != nil {
		return &errs.Detail{Err: ErrExists, Detail: fmt.Sprintf("%v", err)}
	}
	if exists {
		return ErrExists
	}
	data, err := json.Marshal(p)
	if err != nil {
		return &errs.Detail{Err: ErrMarshalFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return s.backend.Put(context.Background(), newKey, data)
}

// CreateFolder persists an empty folder marker.
func (s *BackendStore) CreateFolder(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}
	return s.backend.Put(context.Background(), s.keyPrefix+folderMarkerSuffix+path, []byte(`{}`))
}

// RemoveFolder removes a folder marker (idempotent). Does not affect entries.
func (s *BackendStore) RemoveFolder(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}
	err := s.backend.Delete(context.Background(), s.keyPrefix+folderMarkerSuffix+path)
	if err != nil && errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	return err
}

// RenameFolder renames a folder and every entry and marker beneath it.
func (s *BackendStore) RenameFolder(oldPath, newPath string) error {
	if oldPath == "" || newPath == "" {
		return ErrFolderEmpty
	}
	if oldPath == newPath {
		return ErrMoveToSameFolder
	}
	all, err := s.List()
	if err != nil {
		return err
	}
	for _, p := range all {
		if p.FolderPath == oldPath || strings.HasPrefix(p.FolderPath, oldPath+"/") {
			newFolder := newPath + strings.TrimPrefix(p.FolderPath, oldPath)
			if err := s.MoveToFolder(p.ID, newFolder); err != nil && !errors.Is(err, ErrMoveToSameFolder) {
				return err
			}
		}
	}
	// Migrate folder markers.
	folders, err := s.ListFolders()
	if err != nil {
		return err
	}
	for _, f := range folders {
		if f == oldPath || strings.HasPrefix(f, oldPath+"/") {
			_ = s.RemoveFolder(f)
			if cErr := s.CreateFolder(newPath + strings.TrimPrefix(f, oldPath)); cErr != nil {
				return cErr
			}
		}
	}
	return nil
}

// DeleteFolder removes a folder, its markers, and all entries within it.
func (s *BackendStore) DeleteFolder(path string) error {
	if path == "" {
		return ErrFolderEmpty
	}
	entries, err := s.ListByFolder(path)
	if err != nil {
		return err
	}
	for _, p := range entries {
		if err := s.Delete(p.ID); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	folders, err := s.ListFolders()
	if err != nil {
		return err
	}
	for _, f := range folders {
		if f == path || strings.HasPrefix(f, path+"/") {
			_ = s.RemoveFolder(f)
		}
	}
	return nil
}

// Search returns profiles whose name/host/user/folder contains query (case-insensitive).
func (s *BackendStore) Search(query string) ([]*Profile, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return all, nil
	}
	out := make([]*Profile, 0)
	for _, p := range all {
		if strings.Contains(strings.ToLower(p.Name), q) ||
			strings.Contains(strings.ToLower(p.Host), q) ||
			strings.Contains(strings.ToLower(p.User), q) ||
			strings.Contains(strings.ToLower(p.FolderPath), q) {
			out = append(out, p)
		}
	}
	return out, nil
}

// Close marks the store closed and closes the backend.
func (s *BackendStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.backend.Close()
}

func (s *BackendStore) isFolderMarkerKey(key string) bool {
	return strings.Contains(key, folderMarkerSuffix)
}

func (s *BackendStore) storageKey(id string) string {
	return s.keyPrefix + id + ".json"
}

func unmarshalProfile(data []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, &errs.Detail{Err: ErrUnmarshalFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return &p, nil
}

// getUnlocked resolves a profile by exact ID, hashed-name ID, then name scan.
func (s *BackendStore) getUnlocked(idOrName string) (*Profile, error) {
	key := s.storageKey(idOrName)
	if data, err := s.backend.Get(context.Background(), key); err == nil {
		return unmarshalProfile(data)
	}
	if hashedID := generateID(idOrName, ""); hashedID != idOrName {
		if data, err := s.backend.Get(context.Background(), s.storageKey(hashedID)); err == nil {
			return unmarshalProfile(data)
		}
	}
	return s.findByName(idOrName)
}

func (s *BackendStore) findByName(name string) (*Profile, error) {
	keys, err := s.backend.List(context.Background(), s.keyPrefix)
	if err != nil {
		return nil, ErrNotFound
	}
	lower := strings.ToLower(name)
	for _, key := range keys {
		if s.isFolderMarkerKey(key) {
			continue
		}
		data, getErr := s.backend.Get(context.Background(), key)
		if getErr != nil {
			continue
		}
		p, uErr := unmarshalProfile(data)
		if uErr != nil {
			continue
		}
		if strings.ToLower(p.Name) == lower {
			return p, nil
		}
	}
	return nil, ErrNotFound
}

// compile-time interface assertion.
var _ Store = (*BackendStore)(nil)
