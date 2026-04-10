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
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// folderMarkerName is the special Name value used to persist empty folder
// markers. These entities are excluded from password
// listings.
const folderMarkerName = "__folder_marker__"

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("staticpw: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}

// ErrNilKVStore is returned when a nil kvstore.KVStore is provided.
type ErrNilKVStore struct{}

// Error implements the error interface.
func (e ErrNilKVStore) Error() string {
	return "staticpw: nil kvstore"
}

// DAOStore implements Store using a go-qrdb GenericDAO backed by a
// kvstore.KVStore. Each static password entry is stored as a PasswordEntity
// with indexed fields for efficient lookup.
type DAOStore struct {
	closed atomic.Bool
	dao    qrdbsdk.GenericDAO[*PasswordEntity]
}

// Compile-time interface compliance check.
var _ Store = (*DAOStore)(nil)

// NewDAOStore creates a new DAOStore using the given kvstore.KVStore.
// The entity type namespace is "static_passwords".
func NewDAOStore(kvStore qrdbsdk.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore{}
	}

	pwDAO, err := qrdbsdk.NewDAO[*PasswordEntity](
		kvStore,
		"static_passwords",
		func() *PasswordEntity { return &PasswordEntity{} },
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOStore{
		dao: pwDAO,
	}, nil
}

// Add stores a new static password entry. It validates the password,
// generates a deterministic ID, checks for duplicate names
// (case-insensitive within the same folder), and persists the entry.
func (s *DAOStore) Add(pw *StaticPassword) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if err := pw.Validate(); err != nil {
		return err
	}

	ctx := context.Background()

	pw.ID = generateID(pw.Name, pw.FolderPath)
	now := time.Now()
	pw.CreatedAt = now
	pw.UpdatedAt = now

	// Check for duplicate name (case-insensitive) in the same folder.
	if err := s.checkNameConflict(ctx, pw.Name, pw.FolderPath, 0); err != nil {
		return err
	}

	entity := passwordToEntity(pw)
	return s.dao.Save(ctx, entity)
}

// Get retrieves a static password by ID or name (case-insensitive).
// It first attempts a match by the hex ID, then tries hashing the
// input as a name, and finally scans for a case-insensitive name match.
func (s *DAOStore) Get(idOrName string) (*StaticPassword, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	ctx := context.Background()
	return s.getInternal(ctx, idOrName)
}

// List returns all stored static passwords sorted by name (case-insensitive).
func (s *DAOStore) List() ([]*StaticPassword, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	ctx := context.Background()
	entities, err := s.allPasswordEntities(ctx)
	if err != nil {
		return nil, err
	}

	passwords := make([]*StaticPassword, 0, len(entities))
	for _, entity := range entities {
		passwords = append(passwords, entityToPassword(entity))
	}

	sort.Slice(passwords, func(i, j int) bool {
		return strings.ToLower(passwords[i].Name) < strings.ToLower(passwords[j].Name)
	})

	return passwords, nil
}

// Update modifies an existing static password entry. The entry must already
// exist by its hex ID. Read-only entries cannot be updated. If the name or
// folder changes, the old entity is deleted and a new one created.
func (s *DAOStore) Update(pw *StaticPassword) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if err := pw.Validate(); err != nil {
		return err
	}

	ctx := context.Background()

	// Find the existing entity by the password's current hex ID.
	existing, err := s.findEntityByHexID(ctx, pw.ID)
	if err != nil {
		return ErrPasswordNotFound
	}

	pw.CreatedAt = existing.CreatedAt
	pw.UpdatedAt = time.Now()

	newID := generateID(pw.Name, pw.FolderPath)

	if newID != pw.ID {
		// Name or folder changed. Check for collision at the new location,
		// then delete the old entity and save under the new key.
		if err := s.checkNameConflict(ctx, pw.Name, pw.FolderPath, 0); err != nil {
			return err
		}
		if err := s.dao.Delete(ctx, existing); err != nil {
			return ErrPasswordNotFound
		}
		pw.ID = newID
		entity := passwordToEntity(pw)
		return s.dao.Save(ctx, entity)
	}

	// Name and folder unchanged. Check for name collision excluding self.
	if err := s.checkNameConflict(ctx, pw.Name, pw.FolderPath, existing.EntityID()); err != nil {
		return err
	}

	updated := passwordToEntity(pw)
	updated.SetEntityID(existing.EntityID())
	return s.dao.Save(ctx, updated)
}

// Delete removes a static password by ID or name (case-insensitive).
func (s *DAOStore) Delete(idOrName string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	ctx := context.Background()
	entity, err := s.findEntity(ctx, idOrName)
	if err != nil {
		return err
	}

	return s.dao.Delete(ctx, entity)
}

// ForceDelete removes a static password by ID or name. This is identical
// to Delete since all passwords are editable.
func (s *DAOStore) ForceDelete(idOrName string) error {
	return s.Delete(idOrName)
}

// ListByFolder returns all entries within the given folder path and its
// subfolders. An empty folderPath returns all entries.
func (s *DAOStore) ListByFolder(folderPath string) ([]*StaticPassword, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}

	result := make([]*StaticPassword, 0)
	for _, pw := range all {
		if folderPath == "" {
			result = append(result, pw)
		} else if pw.FolderPath == folderPath || strings.HasPrefix(pw.FolderPath, folderPath+"/") {
			result = append(result, pw)
		}
	}
	return result, nil
}

// ListByFolderDirect returns entries that are directly in the specified folder,
// excluding entries in subfolders. An empty folderPath returns root-level entries.
func (s *DAOStore) ListByFolderDirect(folderPath string) ([]*StaticPassword, error) {
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
// Parent paths are derived from nested folders. Persisted folder markers
// are merged with implicit folders derived from entry FolderPath fields.
func (s *DAOStore) ListFolders() ([]string, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	ctx := context.Background()
	entities, err := s.allEntities(ctx)
	if err != nil {
		return nil, err
	}

	unique := make(map[string]struct{})
	for _, entity := range entities {
		if entity.Name == folderMarkerName {
			// This is a folder marker entity.
			if entity.FolderPath != "" {
				unique[entity.FolderPath] = struct{}{}
			}
			continue
		}
		if entity.FolderPath == "" {
			continue
		}
		parts := strings.Split(entity.FolderPath, "/")
		for i := range parts {
			parent := strings.Join(parts[:i+1], "/")
			unique[parent] = struct{}{}
		}
	}

	folders := make([]string, 0, len(unique))
	for f := range unique {
		folders = append(folders, f)
	}
	sort.Strings(folders)
	return folders, nil
}

// MoveToFolder moves an entry to a new folder, regenerating its ID.
// MoveToFolder moves a password to a different folder.
func (s *DAOStore) MoveToFolder(idOrName string, folderPath string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	ctx := context.Background()
	entity, err := s.findEntity(ctx, idOrName)
	if err != nil {
		return err
	}

	pw := entityToPassword(entity)
	if pw.FolderPath == folderPath {
		return ErrMoveToSameFolder
	}

	// Delete old entity.
	if err := s.dao.Delete(ctx, entity); err != nil {
		return ErrPasswordNotFound
	}

	// Update folder and regenerate ID.
	pw.FolderPath = folderPath
	pw.ID = generateID(pw.Name, pw.FolderPath)
	pw.UpdatedAt = time.Now()

	// Check for duplicate at new location.
	if err := s.checkNameConflict(ctx, pw.Name, pw.FolderPath, 0); err != nil {
		return err
	}

	newEntity := passwordToEntity(pw)
	return s.dao.Save(ctx, newEntity)
}

// CreateFolder persists an empty folder marker so the folder survives
// across restarts even without entries.
func (s *DAOStore) CreateFolder(path string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}

	ctx := context.Background()

	// Check if marker already exists.
	existing, _ := s.findFolderMarker(ctx, path)
	if existing != nil {
		return nil // Idempotent.
	}

	marker := &PasswordEntity{
		Name:       folderMarkerName,
		FolderPath: path,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	return s.dao.Save(ctx, marker)
}

// RemoveFolder removes a persisted folder marker. Does not affect
// entries within the folder. The operation is idempotent; removing a
// non-existent folder is not an error.
func (s *DAOStore) RemoveFolder(path string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}
	if path == "" {
		return ErrFolderEmpty
	}

	ctx := context.Background()
	marker, err := s.findFolderMarker(ctx, path)
	if err != nil {
		return nil // Idempotent.
	}
	return s.dao.Delete(ctx, marker)
}

// Page retrieves a paginated set of password entities.
func (s *DAOStore) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*PasswordEntity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*PasswordEntity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, query)
}

// Close marks the store as closed.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}

// getInternal retrieves a password without checking closed state.
// Lookup order: hex ID, hashed name (empty folder), case-insensitive name scan.
func (s *DAOStore) getInternal(ctx context.Context, idOrName string) (*StaticPassword, error) {
	// 1. Try finding by hex ID.
	entity, err := s.findEntityByHexID(ctx, idOrName)
	if err == nil {
		return entityToPassword(entity), nil
	}

	// 2. Hash as name (no folder) and try again.
	hashedID := generateID(idOrName, "")
	if hashedID != idOrName {
		entity, err = s.findEntityByHexID(ctx, hashedID)
		if err == nil {
			return entityToPassword(entity), nil
		}
	}

	// 3. Case-insensitive name scan.
	entity, err = s.findEntityByName(ctx, idOrName)
	if err != nil {
		return nil, ErrPasswordNotFound
	}
	return entityToPassword(entity), nil
}

// findEntity locates an entity by hex ID or name.
func (s *DAOStore) findEntity(ctx context.Context, idOrName string) (*PasswordEntity, error) {
	// Try hex ID first.
	entity, err := s.findEntityByHexID(ctx, idOrName)
	if err == nil {
		return entity, nil
	}

	// Try hashed name.
	hashedID := generateID(idOrName, "")
	if hashedID != idOrName {
		entity, err = s.findEntityByHexID(ctx, hashedID)
		if err == nil {
			return entity, nil
		}
	}

	// Case-insensitive name scan.
	entity, err = s.findEntityByName(ctx, idOrName)
	if err != nil {
		return nil, ErrPasswordNotFound
	}
	return entity, nil
}

// findEntityByHexID scans all password entities for one whose reconstructed
// hex ID matches the given value.
func (s *DAOStore) findEntityByHexID(ctx context.Context, hexID string) (*PasswordEntity, error) {
	var found *PasswordEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 500}, func(result qrdbsdk.PageResult[*PasswordEntity]) error {
		for _, entity := range result.Entities {
			if entity.Name == folderMarkerName {
				continue
			}
			reconstructedID := GenerateID(entity.Name, entity.FolderPath)
			if reconstructedID == hexID {
				found = entity
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrPasswordNotFound
	}
	return found, nil
}

// findEntityByName scans all entities for a case-insensitive name match,
// excluding folder markers.
func (s *DAOStore) findEntityByName(ctx context.Context, name string) (*PasswordEntity, error) {
	lower := strings.ToLower(name)

	var found *PasswordEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 500}, func(result qrdbsdk.PageResult[*PasswordEntity]) error {
		for _, entity := range result.Entities {
			if entity.Name == folderMarkerName {
				continue
			}
			if strings.ToLower(entity.Name) == lower {
				found = entity
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrPasswordNotFound
	}
	return found, nil
}

// findFolderMarker locates a folder marker entity by path.
func (s *DAOStore) findFolderMarker(ctx context.Context, path string) (*PasswordEntity, error) {
	var found *PasswordEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 500}, func(result qrdbsdk.PageResult[*PasswordEntity]) error {
		for _, entity := range result.Entities {
			if entity.Name == folderMarkerName && entity.FolderPath == path {
				found = entity
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrPasswordNotFound
	}
	return found, nil
}

// checkNameConflict scans for a case-insensitive name collision within the
// same folder, optionally excluding an entity ID (for update scenarios).
func (s *DAOStore) checkNameConflict(ctx context.Context, name string, folderPath string, excludeEntityID uint64) error {
	lower := strings.ToLower(name)

	var conflict bool
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 500}, func(result qrdbsdk.PageResult[*PasswordEntity]) error {
		for _, entity := range result.Entities {
			if entity.Name == folderMarkerName {
				continue
			}
			if excludeEntityID != 0 && entity.EntityID() == excludeEntityID {
				continue
			}
			if strings.ToLower(entity.Name) == lower && entity.FolderPath == folderPath {
				conflict = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if conflict {
		return ErrPasswordExists
	}
	return nil
}

// allEntities retrieves all entities (including folder markers) using pagination.
func (s *DAOStore) allEntities(ctx context.Context) ([]*PasswordEntity, error) {
	var entities []*PasswordEntity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*PasswordEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	return entities, err
}

// allPasswordEntities retrieves all entities excluding folder markers.
func (s *DAOStore) allPasswordEntities(ctx context.Context) ([]*PasswordEntity, error) {
	entities, err := s.allEntities(ctx)
	if err != nil {
		return nil, err
	}

	passwords := make([]*PasswordEntity, 0, len(entities))
	for _, e := range entities {
		if e.Name != folderMarkerName {
			passwords = append(passwords, e)
		}
	}
	return passwords, nil
}

// passwordToEntity converts a StaticPassword to a PasswordEntity.
func passwordToEntity(pw *StaticPassword) *PasswordEntity {
	return &PasswordEntity{
		Name:          pw.Name,
		Title:         pw.Title,
		Username:      pw.Username,
		Password:      pw.Password,
		URL:           pw.URL,
		MatchPatterns: pw.MatchPatterns,
		Notes:         pw.Notes,
		FolderPath:    pw.FolderPath,
		ExpiresAt:     pw.ExpiresAt,
		CreatedAt:     pw.CreatedAt,
		UpdatedAt:     pw.UpdatedAt,
		OwnerID:       pw.OwnerID,
		Shared:        pw.Shared,
	}
}

// entityToPassword converts a PasswordEntity to a StaticPassword.
func entityToPassword(entity *PasswordEntity) *StaticPassword {
	return &StaticPassword{
		ID:            GenerateID(entity.Name, entity.FolderPath),
		Name:          entity.Name,
		Title:         entity.Title,
		Username:      entity.Username,
		Password:      entity.Password,
		URL:           entity.URL,
		MatchPatterns: entity.MatchPatterns,
		Notes:         entity.Notes,
		FolderPath:    entity.FolderPath,
		ExpiresAt:     entity.ExpiresAt,
		CreatedAt:     entity.CreatedAt,
		UpdatedAt:     entity.UpdatedAt,
		OwnerID:       entity.OwnerID,
		Shared:        entity.Shared,
	}
}
