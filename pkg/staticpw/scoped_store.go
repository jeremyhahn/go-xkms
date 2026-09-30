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
	"errors"
	"slices"
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
//
// A ScopedStore built by NewLockedScopedStore has no personal store: the
// user's personal session is locked. Shared entries stay fully usable;
// every operation that needs the personal entries reports ErrStoreLocked,
// and a listing of all entries holds the shared ones only.
type ScopedStore struct {
	shared   *BackendStore
	personal *BackendStore // nil while the personal session is locked
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

// NewLockedScopedStore creates the ScopedStore of a user whose personal
// session is locked: shared entries only.
func NewLockedScopedStore(shared *BackendStore, ownerID string) (*ScopedStore, error) {
	if shared == nil {
		return nil, ErrNilStore
	}
	if !isValidUserID(ownerID) {
		return nil, ErrInvalidUserID
	}
	return &ScopedStore{shared: shared, ownerID: ownerID}, nil
}

// PersonalLocked reports whether the user's personal session is locked.
func (s *ScopedStore) PersonalLocked() bool { return s.personal == nil }

// personalStore returns the personal store, or ErrStoreLocked.
func (s *ScopedStore) personalStore() (*BackendStore, error) {
	if s.personal == nil {
		return nil, ErrStoreLocked
	}
	return s.personal, nil
}

// sharedOrLocked runs op on the personal store when it is open, then on the
// shared store. With the personal session locked, an entry the shared store
// does not hold may be a personal one, so its absence is ErrStoreLocked.
func (s *ScopedStore) sharedOrLocked(op func(*BackendStore) error) error {
	if s.personal != nil {
		if err := op(s.personal); err == nil {
			return nil
		}
	}
	err := op(s.shared)
	if s.personal == nil && errors.Is(err, ErrPasswordNotFound) {
		return ErrStoreLocked
	}
	return err
}

// Add stores a new password entry. If pw.Shared is true the entry goes to
// the shared store; otherwise it goes to the personal store. The OwnerID
// is always set to the current user.
func (s *ScopedStore) Add(pw *StaticPassword) error {
	pw.OwnerID = s.ownerID
	if pw.Shared {
		return s.shared.Add(pw)
	}
	personal, err := s.personalStore()
	if err != nil {
		return err
	}
	return personal.Add(pw)
}

// Get retrieves a password by ID or name. It checks the personal store
// first, falling back to the shared store.
func (s *ScopedStore) Get(idOrName string) (*StaticPassword, error) {
	var found *StaticPassword
	err := s.sharedOrLocked(func(b *BackendStore) error {
		pw, err := b.Get(idOrName)
		found = pw
		return err
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// List returns all passwords the user can read now, sorted by name.
func (s *ScopedStore) List() ([]*StaticPassword, error) {
	return s.ListByScope(ScopeAll)
}

// ListByScope returns passwords filtered by scope. ScopePersonal returns
// only the user's personal passwords (ErrStoreLocked while locked);
// ScopeShared returns only shared passwords; ScopeAll returns the merged set,
// the shared ones only while the personal session is locked.
func (s *ScopedStore) ListByScope(scope PasswordScope) ([]*StaticPassword, error) {
	switch scope {
	case ScopePersonal:
		personal, err := s.personalStore()
		if err != nil {
			return nil, err
		}
		return personal.List()
	case ScopeShared:
		return s.shared.List()
	case ScopeAll:
		if s.personal == nil {
			return s.shared.List()
		}
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
	return s.sharedOrLocked(func(b *BackendStore) error { return b.Update(pw) })
}

// Delete removes a password by ID or name. It tries the personal store
// first, falling back to the shared store.
func (s *ScopedStore) Delete(idOrName string) error {
	return s.sharedOrLocked(func(b *BackendStore) error { return b.Delete(idOrName) })
}

// ForceDelete removes a password by ID or name, bypassing the read-only
// check. Tries personal first, then shared.
func (s *ScopedStore) ForceDelete(idOrName string) error {
	return s.sharedOrLocked(func(b *BackendStore) error { return b.ForceDelete(idOrName) })
}

// ListByFolder returns entries from both stores within the folder and subfolders.
func (s *ScopedStore) ListByFolder(folderPath string) ([]*StaticPassword, error) {
	return s.mergeFrom(func(b *BackendStore) ([]*StaticPassword, error) { return b.ListByFolder(folderPath) })
}

// ListByFolderDirect returns entries from both stores directly in the folder,
// excluding subfolders.
func (s *ScopedStore) ListByFolderDirect(folderPath string) ([]*StaticPassword, error) {
	return s.mergeFrom(func(b *BackendStore) ([]*StaticPassword, error) { return b.ListByFolderDirect(folderPath) })
}

// ListFolders returns the deduplicated union of folder paths from both stores.
func (s *ScopedStore) ListFolders() ([]string, error) {
	unique := map[string]struct{}{}
	for _, b := range s.stores() {
		folders, err := b.ListFolders()
		if err != nil {
			return nil, err
		}
		for _, f := range folders {
			unique[f] = struct{}{}
		}
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
	personal, err := s.personalStore()
	if err != nil {
		return err
	}
	return personal.CreateFolder(path)
}

// RemoveFolder delegates to the personal store.
func (s *ScopedStore) RemoveFolder(path string) error {
	personal, err := s.personalStore()
	if err != nil {
		return err
	}
	return personal.RemoveFolder(path)
}

// MoveToFolder moves a password to a new folder. Tries personal first,
// then shared.
func (s *ScopedStore) MoveToFolder(idOrName string, folderPath string) error {
	return s.sharedOrLocked(func(b *BackendStore) error { return b.MoveToFolder(idOrName, folderPath) })
}

// Close closes the underlying stores.
func (s *ScopedStore) Close() error {
	var errs []error
	for _, b := range s.stores() {
		errs = append(errs, b.Close())
	}
	return errors.Join(errs...)
}

// stores returns the stores the user can read now: personal (when open),
// then shared.
func (s *ScopedStore) stores() []*BackendStore {
	if s.personal == nil {
		return []*BackendStore{s.shared}
	}
	return []*BackendStore{s.personal, s.shared}
}

// mergeFrom concatenates list over every readable store, sorted by name.
func (s *ScopedStore) mergeFrom(list func(*BackendStore) ([]*StaticPassword, error)) ([]*StaticPassword, error) {
	var merged []*StaticPassword
	for _, b := range s.stores() {
		entries, err := list(b)
		if err != nil {
			return nil, err
		}
		merged = slices.Concat(merged, entries)
	}
	sort.Slice(merged, func(i, j int) bool {
		return strings.ToLower(merged[i].Name) < strings.ToLower(merged[j].Name)
	})
	return merged, nil
}

// mergedList returns the union of both stores sorted by name.
func (s *ScopedStore) mergedList() ([]*StaticPassword, error) {
	return s.mergeFrom(func(b *BackendStore) ([]*StaticPassword, error) { return b.List() })
}
