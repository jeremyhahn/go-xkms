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
	"sort"
	"strings"
)

// ScopedStore is a composite Store that routes password operations to
// separate personal and shared BackendStores. Personal passwords are
// namespaced per-user, while shared passwords are visible tenant-wide.
//
// Get, Delete, and MoveToFolder try the personal store first, then fall
// back to the shared store. Add routes based on the password's Shared flag.
// List merges results from both stores.
type ScopedStore struct {
	shared   *BackendStore
	personal *BackendStore
	ownerID  string
}

// NewScopedStore creates a ScopedStore wrapping a shared and personal
// BackendStore. The ownerID is stamped on every password added through
// this store.
func NewScopedStore(shared *BackendStore, personal *BackendStore, ownerID string) (*ScopedStore, error) {
	if shared == nil || personal == nil {
		return nil, ErrNilStore
	}
	if !isValidUserID(ownerID) {
		return nil, ErrInvalidUserID
	}
	return &ScopedStore{
		shared:   shared,
		personal: personal,
		ownerID:  ownerID,
	}, nil
}

// Add stores a new password entry. If pw.Shared is true the entry goes to
// the shared store; otherwise it goes to the personal store. The OwnerID
// is always set to the current user.
func (s *ScopedStore) Add(pw *StaticPassword) error {
	pw.OwnerID = s.ownerID
	if pw.Shared {
		return s.shared.Add(pw)
	}
	return s.personal.Add(pw)
}

// Get retrieves a password by ID or name. It checks the personal store
// first, falling back to the shared store.
func (s *ScopedStore) Get(idOrName string) (*StaticPassword, error) {
	pw, err := s.personal.Get(idOrName)
	if err == nil {
		return pw, nil
	}
	return s.shared.Get(idOrName)
}

// List returns all passwords from both stores, sorted by name.
func (s *ScopedStore) List() ([]*StaticPassword, error) {
	return s.ListByScope(ScopeAll)
}

// ListByScope returns passwords filtered by scope. ScopePersonal returns
// only the user's personal passwords; ScopeShared returns only shared
// passwords; ScopeAll returns the merged set.
func (s *ScopedStore) ListByScope(scope PasswordScope) ([]*StaticPassword, error) {
	switch scope {
	case ScopePersonal:
		return s.personal.List()
	case ScopeShared:
		return s.shared.List()
	case ScopeAll:
		return s.mergedList()
	default:
		return nil, ErrInvalidScope
	}
}

// Update modifies an existing password. Shared passwords are updated in
// the shared store; personal passwords in the personal store. If the
// password's Shared flag cannot determine the store, it tries personal
// first, then shared.
func (s *ScopedStore) Update(pw *StaticPassword) error {
	if pw.Shared {
		return s.shared.Update(pw)
	}
	err := s.personal.Update(pw)
	if err == nil {
		return nil
	}
	return s.shared.Update(pw)
}

// Delete removes a password by ID or name. It tries the personal store
// first, falling back to the shared store.
func (s *ScopedStore) Delete(idOrName string) error {
	err := s.personal.Delete(idOrName)
	if err == nil {
		return nil
	}
	return s.shared.Delete(idOrName)
}

// ForceDelete removes a password by ID or name, bypassing the read-only
// check. Tries personal first, then shared.
func (s *ScopedStore) ForceDelete(idOrName string) error {
	err := s.personal.ForceDelete(idOrName)
	if err == nil {
		return nil
	}
	return s.shared.ForceDelete(idOrName)
}

// ListByFolder returns entries from both stores within the folder and subfolders.
func (s *ScopedStore) ListByFolder(folderPath string) ([]*StaticPassword, error) {
	personalEntries, err := s.personal.ListByFolder(folderPath)
	if err != nil {
		return nil, err
	}
	sharedEntries, err := s.shared.ListByFolder(folderPath)
	if err != nil {
		return nil, err
	}
	merged := append(personalEntries, sharedEntries...)
	sort.Slice(merged, func(i, j int) bool {
		return strings.ToLower(merged[i].Name) < strings.ToLower(merged[j].Name)
	})
	return merged, nil
}

// ListByFolderDirect returns entries from both stores directly in the folder,
// excluding subfolders.
func (s *ScopedStore) ListByFolderDirect(folderPath string) ([]*StaticPassword, error) {
	personalEntries, err := s.personal.ListByFolderDirect(folderPath)
	if err != nil {
		return nil, err
	}
	sharedEntries, err := s.shared.ListByFolderDirect(folderPath)
	if err != nil {
		return nil, err
	}
	merged := append(personalEntries, sharedEntries...)
	sort.Slice(merged, func(i, j int) bool {
		return strings.ToLower(merged[i].Name) < strings.ToLower(merged[j].Name)
	})
	return merged, nil
}

// ListFolders returns the deduplicated union of folder paths from both stores.
func (s *ScopedStore) ListFolders() ([]string, error) {
	personalFolders, err := s.personal.ListFolders()
	if err != nil {
		return nil, err
	}
	sharedFolders, err := s.shared.ListFolders()
	if err != nil {
		return nil, err
	}

	unique := make(map[string]struct{}, len(personalFolders)+len(sharedFolders))
	for _, f := range personalFolders {
		unique[f] = struct{}{}
	}
	for _, f := range sharedFolders {
		unique[f] = struct{}{}
	}

	folders := make([]string, 0, len(unique))
	for f := range unique {
		folders = append(folders, f)
	}
	sort.Strings(folders)
	return folders, nil
}

// CreateFolder delegates to the personal store.
func (s *ScopedStore) CreateFolder(path string) error {
	return s.personal.CreateFolder(path)
}

// RemoveFolder delegates to the personal store.
func (s *ScopedStore) RemoveFolder(path string) error {
	return s.personal.RemoveFolder(path)
}

// MoveToFolder moves a password to a new folder. Tries personal first,
// then shared.
func (s *ScopedStore) MoveToFolder(idOrName string, folderPath string) error {
	err := s.personal.MoveToFolder(idOrName, folderPath)
	if err == nil {
		return nil
	}
	return s.shared.MoveToFolder(idOrName, folderPath)
}

// Close closes both underlying stores.
func (s *ScopedStore) Close() error {
	pErr := s.personal.Close()
	sErr := s.shared.Close()
	if pErr != nil {
		return pErr
	}
	return sErr
}

// mergedList returns the union of both stores sorted by name.
func (s *ScopedStore) mergedList() ([]*StaticPassword, error) {
	personalPWs, err := s.personal.List()
	if err != nil {
		return nil, err
	}
	sharedPWs, err := s.shared.List()
	if err != nil {
		return nil, err
	}
	merged := append(personalPWs, sharedPWs...)
	sort.Slice(merged, func(i, j int) bool {
		return strings.ToLower(merged[i].Name) < strings.ToLower(merged[j].Name)
	})
	return merged, nil
}
