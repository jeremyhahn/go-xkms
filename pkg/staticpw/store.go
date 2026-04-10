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

package staticpw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const defaultKeyPrefix = "staticpw/"

// folderMarkerSuffix is the sub-prefix used to persist empty folder markers
// so they survive across restarts even without entries.
const folderMarkerSuffix = "__folders__/"

// maxTenantIDLength is the maximum allowed length for a tenant identifier.
const maxTenantIDLength = 64

// maxUserIDLength is the maximum allowed length for a user identifier.
const maxUserIDLength = 128

// tenantIDPattern matches alphanumeric characters, hyphens, and underscores.
var tenantIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// userIDPattern matches alphanumeric characters, hyphens, underscores, dots,
// and the @ sign (for email-style user IDs).
var userIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$`)

// Store defines the interface for static password persistence.
type Store interface {
	// Add stores a new static password entry.
	Add(pw *StaticPassword) error

	// Get retrieves a static password by ID or name (case-insensitive).
	Get(idOrName string) (*StaticPassword, error)

	// List returns all stored static passwords sorted by name.
	List() ([]*StaticPassword, error)

	// Update modifies an existing static password entry.
	Update(pw *StaticPassword) error

	// Delete removes a static password by ID or name (case-insensitive).
	// Returns ErrPasswordReadOnly for read-only entries.
	Delete(idOrName string) error

	// ForceDelete removes a static password by ID or name, bypassing the
	// read-only check. Used for administrative cleanup operations.
	ForceDelete(idOrName string) error

	// ListByFolder returns all entries within the given folder path and its
	// subfolders. An empty folderPath returns all entries.
	ListByFolder(folderPath string) ([]*StaticPassword, error)

	// ListByFolderDirect returns only entries directly in the specified folder,
	// excluding entries in subfolders. An empty folderPath returns root-level entries.
	ListByFolderDirect(folderPath string) ([]*StaticPassword, error)

	// ListFolders returns all unique folder paths sorted alphabetically,
	// including parent paths derived from nested folders.
	ListFolders() ([]string, error)

	// MoveToFolder moves an entry to a new folder, regenerating its ID.
	MoveToFolder(idOrName string, folderPath string) error

	// CreateFolder persists an empty folder marker so the folder survives
	// across restarts even without entries.
	CreateFolder(path string) error

	// RemoveFolder removes a persisted folder marker. Does not affect
	// entries within the folder.
	RemoveFolder(path string) error

	// Close releases resources held by the store.
	Close() error
}

// BackendStore implements Store backed by a storage.Backend with optional
// multi-tenant support.
type BackendStore struct {
	mu        sync.RWMutex
	backend   storage.Backend
	tenantID  string
	keyPrefix string
	closed    bool
}

// NewStore creates a new BackendStore wrapping the provided storage backend
// with no tenant isolation (single-tenant mode).
func NewStore(backend storage.Backend) *BackendStore {
	return &BackendStore{
		backend:   backend,
		keyPrefix: defaultKeyPrefix,
	}
}

// NewTenantStore creates a new BackendStore with tenant isolation. All keys
// are prefixed with the tenant ID to provide namespace separation. The
// tenantID must be non-empty, at most 64 characters, start with an
// alphanumeric character, and contain only alphanumeric characters, hyphens,
// and underscores.
func NewTenantStore(backend storage.Backend, tenantID string) (*BackendStore, error) {
	if !isValidTenantID(tenantID) {
		return nil, ErrInvalidTenantID
	}
	return &BackendStore{
		backend:   backend,
		tenantID:  tenantID,
		keyPrefix: tenantID + "/" + defaultKeyPrefix,
	}, nil
}

// NewSharedTenantStore creates a BackendStore for tenant-wide shared passwords.
// Keys are prefixed with "{tenantID}/staticpw/shared/".
func NewSharedTenantStore(backend storage.Backend, tenantID string) (*BackendStore, error) {
	if !isValidTenantID(tenantID) {
		return nil, ErrInvalidTenantID
	}
	return &BackendStore{
		backend:   backend,
		tenantID:  tenantID,
		keyPrefix: tenantID + "/" + defaultKeyPrefix + "shared/",
	}, nil
}

// NewPersonalTenantStore creates a BackendStore for a specific user's personal
// passwords within a tenant. Keys are prefixed with
// "{tenantID}/staticpw/users/{userID}/".
func NewPersonalTenantStore(backend storage.Backend, tenantID string, userID string) (*BackendStore, error) {
	if !isValidTenantID(tenantID) {
		return nil, ErrInvalidTenantID
	}
	if !isValidUserID(userID) {
		return nil, ErrInvalidUserID
	}
	return &BackendStore{
		backend:   backend,
		tenantID:  tenantID,
		keyPrefix: tenantID + "/" + defaultKeyPrefix + "users/" + userID + "/",
	}, nil
}

// TenantID returns the tenant identifier for this store, or an empty string
// if running in single-tenant mode.
func (s *BackendStore) TenantID() string {
	return s.tenantID
}

// Add stores a new static password entry. It validates the password, generates
// a deterministic ID from the name and folder path, checks for duplicates by
// both ID and name (case-insensitive), and persists the entry as JSON.
func (s *BackendStore) Add(pw *StaticPassword) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if err := pw.Validate(); err != nil {
		return err
	}

	pw.ID = generateID(pw.Name, pw.FolderPath)
	now := time.Now()
	pw.CreatedAt = now
	pw.UpdatedAt = now

	// Check for duplicate by ID (exact key lookup).
	key := s.storageKey(pw.ID)
	exists, err := s.backend.Exists(context.Background(), key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPassword, err)
	}
	if exists {
		return ErrPasswordExists
	}

	// Check for duplicate by name (case-insensitive scan).
	if err := s.checkNameConflict(pw.Name, pw.FolderPath, ""); err != nil {
		return err
	}

	data, err := json.Marshal(pw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMarshalFailed, err)
	}

	return s.backend.Put(context.Background(), key, data)
}

// Get retrieves a static password by ID or name. It first attempts an exact
// key lookup by treating idOrName as an ID. If that fails, it hashes the
// input as a name (with empty folder) for an O(1) lookup. Finally, it scans
// all entries for a case-insensitive name match.
func (s *BackendStore) Get(idOrName string) (*StaticPassword, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	return s.getUnlocked(idOrName)
}

// List returns all stored static passwords sorted by name (case-insensitive).
func (s *BackendStore) List() ([]*StaticPassword, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	keys, err := s.backend.List(context.Background(), s.keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasswordNotFound, err)
	}

	passwords := make([]*StaticPassword, 0, len(keys))
	for _, key := range keys {
		if s.isFolderMarkerKey(key) {
			continue
		}
		data, getErr := s.backend.Get(context.Background(), key)
		if getErr != nil {
			continue
		}
		pw, unmarshalErr := unmarshalPassword(data)
		if unmarshalErr != nil {
			continue
		}
		passwords = append(passwords, pw)
	}

	sort.Slice(passwords, func(i, j int) bool {
		return strings.ToLower(passwords[i].Name) < strings.ToLower(passwords[j].Name)
	})

	return passwords, nil
}

// Update modifies an existing static password entry. The entry must already
// exist by its ID. The UpdatedAt timestamp is refreshed automatically.
// Read-only entries cannot be updated. If the name or folder changes, the
// old entry is deleted and a new entry is created with the updated ID.
func (s *BackendStore) Update(pw *StaticPassword) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	if err := pw.Validate(); err != nil {
		return err
	}

	// Verify the entry exists by ID and preserve CreatedAt.
	oldKey := s.storageKey(pw.ID)
	existingData, err := s.backend.Get(context.Background(), oldKey)
	if err != nil {
		return ErrPasswordNotFound
	}
	existing, err := unmarshalPassword(existingData)
	if err != nil {
		return err
	}

	if existing.ReadOnly {
		return ErrPasswordReadOnly
	}

	pw.CreatedAt = existing.CreatedAt
	pw.UpdatedAt = time.Now()

	// Recompute ID in case name or folder changed.
	newID := generateID(pw.Name, pw.FolderPath)

	if newID != pw.ID {
		// Name or folder changed — delete old entry, write under new key.
		if err := s.backend.Delete(context.Background(), oldKey); err != nil {
			return fmt.Errorf("%w: %v", ErrPasswordNotFound, err)
		}
		pw.ID = newID
	}

	newKey := s.storageKey(pw.ID)
	data, err := json.Marshal(pw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMarshalFailed, err)
	}

	return s.backend.Put(context.Background(), newKey, data)
}

// Delete removes a static password by ID or name. It first attempts an exact
// key lookup by treating idOrName as an ID, then tries a hashed-ID lookup,
// and finally scans for a case-insensitive name match.
// Read-only entries cannot be deleted.
func (s *BackendStore) Delete(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	pw, err := s.getUnlocked(idOrName)
	if err != nil {
		return err
	}

	if pw.ReadOnly {
		return ErrPasswordReadOnly
	}

	return s.backend.Delete(context.Background(), s.storageKey(pw.ID))
}

// ForceDelete removes a static password by ID or name, bypassing the
// read-only check. Used for administrative cleanup operations.
func (s *BackendStore) ForceDelete(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	pw, err := s.getUnlocked(idOrName)
	if err != nil {
		return err
	}

	return s.backend.Delete(context.Background(), s.storageKey(pw.ID))
}

// ListByFolder returns all entries within the given folder path and its subfolders.
// This supports hierarchical folder navigation: querying "Work" returns passwords
// in "Work", "Work/Email", "Work/Email/Personal", etc.
// An empty folderPath returns all entries (root includes everything).
func (s *BackendStore) ListByFolder(folderPath string) ([]*StaticPassword, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}

	result := make([]*StaticPassword, 0)
	for _, pw := range all {
		if folderPath == "" {
			// Root: include all entries
			result = append(result, pw)
		} else if pw.FolderPath == folderPath || strings.HasPrefix(pw.FolderPath, folderPath+"/") {
			// Include exact match AND all subfolders
			result = append(result, pw)
		}
	}
	return result, nil
}

// ListByFolderDirect returns entries that are directly in the specified folder,
// excluding entries in subfolders. This is useful for displaying only immediate
// children of a folder without nested content.
// An empty folderPath returns only root-level entries (entries with no folder).
func (s *BackendStore) ListByFolderDirect(folderPath string) ([]*StaticPassword, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}

	result := make([]*StaticPassword, 0)
	for _, pw := range all {
		if pw.FolderPath == folderPath {
			result = append(result, pw)
		}
	}
	return result, nil
}

// ListFolders returns all unique folder paths sorted alphabetically.
// Parent paths are derived from nested folders (e.g. "Work/Email" also
// yields "Work"). Persisted folder markers are merged with implicit
// folders derived from entry FolderPath fields.
func (s *BackendStore) ListFolders() ([]string, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}

	unique := make(map[string]struct{})
	for _, pw := range all {
		if pw.FolderPath == "" {
			continue
		}
		// Add the full path and all parent segments.
		parts := strings.Split(pw.FolderPath, "/")
		for i := range parts {
			parent := strings.Join(parts[:i+1], "/")
			unique[parent] = struct{}{}
		}
	}

	// Merge persisted folder markers.
	s.mu.RLock()
	markerPrefix := s.keyPrefix + folderMarkerSuffix
	markerKeys, listErr := s.backend.List(context.Background(), markerPrefix)
	s.mu.RUnlock()
	if listErr == nil {
		for _, key := range markerKeys {
			folder := strings.TrimPrefix(key, markerPrefix)
			if folder != "" {
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

// MoveToFolder moves an entry to a new folder. The entry is deleted under
// its old key, the FolderPath and ID are updated, and it is re-added.
// Read-only entries cannot be moved.
func (s *BackendStore) MoveToFolder(idOrName string, folderPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	// Find the entry (need to inline the lookup since we hold the lock).
	pw, err := s.getUnlocked(idOrName)
	if err != nil {
		return err
	}

	if pw.ReadOnly {
		return ErrPasswordReadOnly
	}

	if pw.FolderPath == folderPath {
		return ErrMoveToSameFolder
	}

	// Delete the old entry.
	oldKey := s.storageKey(pw.ID)
	if delErr := s.backend.Delete(context.Background(), oldKey); delErr != nil {
		return fmt.Errorf("%w: %v", ErrPasswordNotFound, delErr)
	}

	// Update folder and regenerate ID.
	pw.FolderPath = folderPath
	pw.ID = generateID(pw.Name, pw.FolderPath)
	pw.UpdatedAt = time.Now()

	// Check for duplicate at new location.
	newKey := s.storageKey(pw.ID)
	exists, err := s.backend.Exists(context.Background(), newKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPassword, err)
	}
	if exists {
		return ErrPasswordExists
	}

	data, err := json.Marshal(pw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMarshalFailed, err)
	}

	return s.backend.Put(context.Background(), newKey, data)
}

// CreateFolder persists an empty folder marker so the folder survives
// across restarts even without entries.
func (s *BackendStore) CreateFolder(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}
	key := s.keyPrefix + folderMarkerSuffix + path
	return s.backend.Put(context.Background(), key, []byte(`{}`))
}

// RemoveFolder removes a persisted folder marker. Does not affect
// entries within the folder. The operation is idempotent; removing a
// non-existent folder is not an error.
func (s *BackendStore) RemoveFolder(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}
	key := s.keyPrefix + folderMarkerSuffix + path
	err := s.backend.Delete(context.Background(), key)
	if err != nil && errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	return err
}

// Close marks the store as closed and closes the underlying backend.
func (s *BackendStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	return s.backend.Close()
}

// isFolderMarkerKey returns true if the key belongs to a folder marker
// rather than a password entry.
func (s *BackendStore) isFolderMarkerKey(key string) bool {
	return strings.Contains(key, folderMarkerSuffix)
}

// storageKey returns the backend key for the given password ID,
// incorporating the tenant prefix when present.
func (s *BackendStore) storageKey(id string) string {
	return s.keyPrefix + id + ".json"
}

// unmarshalPassword deserializes a StaticPassword from JSON bytes.
func unmarshalPassword(data []byte) (*StaticPassword, error) {
	var pw StaticPassword
	if err := json.Unmarshal(data, &pw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnmarshalFailed, err)
	}
	return &pw, nil
}

// getUnlocked retrieves a password without acquiring the lock.
// Must be called while holding the appropriate lock.
//
// Lookup order:
//  1. Exact key lookup treating idOrName as an ID.
//  2. Hash idOrName as a name (empty folder) for an O(1) hashed-ID lookup.
//  3. Full scan for a case-insensitive name match (covers legacy entries
//     and entries in folders).
func (s *BackendStore) getUnlocked(idOrName string) (*StaticPassword, error) {
	// 1. Exact ID key lookup.
	key := s.storageKey(idOrName)
	data, err := s.backend.Get(context.Background(), key)
	if err == nil {
		pw, unmarshalErr := unmarshalPassword(data)
		if unmarshalErr != nil {
			return nil, unmarshalErr
		}
		return pw, nil
	}

	// 2. Hash the input as a name (no folder) and try O(1) lookup.
	hashedID := generateID(idOrName, "")
	if hashedID != idOrName {
		key = s.storageKey(hashedID)
		data, err = s.backend.Get(context.Background(), key)
		if err == nil {
			pw, unmarshalErr := unmarshalPassword(data)
			if unmarshalErr != nil {
				return nil, unmarshalErr
			}
			return pw, nil
		}
	}

	// 3. Scan for case-insensitive name match.
	return s.findByName(idOrName)
}

// findByName scans all stored passwords for a case-insensitive name match.
// Must be called while holding at least a read lock.
func (s *BackendStore) findByName(name string) (*StaticPassword, error) {
	keys, err := s.backend.List(context.Background(), s.keyPrefix)
	if err != nil {
		return nil, ErrPasswordNotFound
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
		pw, unmarshalErr := unmarshalPassword(data)
		if unmarshalErr != nil {
			continue
		}
		if strings.ToLower(pw.Name) == lower {
			return pw, nil
		}
	}

	return nil, ErrPasswordNotFound
}

// checkNameConflict scans all stored passwords for a case-insensitive name
// collision within the same folder, optionally excluding an ID (for update
// scenarios). Must be called while holding the write lock.
func (s *BackendStore) checkNameConflict(name string, folderPath string, excludeID string) error {
	keys, err := s.backend.List(context.Background(), s.keyPrefix)
	if err != nil {
		return nil
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
		pw, unmarshalErr := unmarshalPassword(data)
		if unmarshalErr != nil {
			continue
		}
		if excludeID != "" && pw.ID == excludeID {
			continue
		}
		if strings.ToLower(pw.Name) == lower && pw.FolderPath == folderPath {
			return ErrPasswordExists
		}
	}

	return nil
}

// isValidTenantID checks that a tenant ID is non-empty, at most 64 characters,
// starts with an alphanumeric character, and contains only alphanumeric
// characters, hyphens, and underscores.
func isValidTenantID(tenantID string) bool {
	if tenantID == "" {
		return false
	}
	if len(tenantID) > maxTenantIDLength {
		return false
	}
	return tenantIDPattern.MatchString(tenantID)
}

// isValidUserID checks that a user ID is non-empty, at most 128 characters,
// starts with an alphanumeric character, and contains only alphanumeric
// characters, hyphens, underscores, dots, and @ signs.
func isValidUserID(userID string) bool {
	if userID == "" {
		return false
	}
	if len(userID) > maxUserIDLength {
		return false
	}
	return userIDPattern.MatchString(userID)
}
