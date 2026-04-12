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
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
)

// AccessMode identifies the access control strategy for the password store.
type AccessMode string

const (
	// AccessPINPerOperation requires a PIN for every decryption operation.
	AccessPINPerOperation AccessMode = "pin_per_operation"

	// AccessSessionBased requires a single PIN unlock, then allows free access
	// until the store is locked again.
	AccessSessionBased AccessMode = "session_based"
)

// PINAccessStore requires the user PIN for every decryption operation.
// Non-decrypting operations (Add, Get, List, etc.) delegate directly to the
// inner EncryptedStore without PIN verification.
type PINAccessStore struct {
	inner      *EncryptedStore
	pinManager pin.PINBackend
}

// NewPINAccessStore creates a PINAccessStore. Both inner and pinManager must be non-nil.
func NewPINAccessStore(inner *EncryptedStore, pinManager pin.PINBackend) (*PINAccessStore, error) {
	if inner == nil {
		return nil, ErrNilInnerStore
	}
	if pinManager == nil {
		return nil, ErrNilPINManager
	}
	return &PINAccessStore{
		inner:      inner,
		pinManager: pinManager,
	}, nil
}

// Add delegates to the inner encrypted store.
func (s *PINAccessStore) Add(pw *StaticPassword) error {
	return s.inner.Add(pw)
}

// Get returns the entry with the password still encrypted.
func (s *PINAccessStore) Get(idOrName string) (*StaticPassword, error) {
	return s.inner.Get(idOrName)
}

// GetDecrypted verifies the user PIN and returns the entry with a decrypted password.
func (s *PINAccessStore) GetDecrypted(idOrName, userPIN string) (*StaticPassword, error) {
	if userPIN == "" {
		return nil, ErrPINRequired
	}
	if err := s.pinManager.VerifyUserPIN(userPIN); err != nil {
		return nil, err
	}
	return s.inner.GetDecrypted(idOrName)
}

// List delegates to the inner encrypted store.
func (s *PINAccessStore) List() ([]*StaticPassword, error) {
	return s.inner.List()
}

// Update delegates to the inner encrypted store.
func (s *PINAccessStore) Update(pw *StaticPassword) error {
	return s.inner.Update(pw)
}

// Delete delegates to the inner encrypted store.
func (s *PINAccessStore) Delete(idOrName string) error {
	return s.inner.Delete(idOrName)
}

// ForceDelete removes an entry bypassing the read-only check.
func (s *PINAccessStore) ForceDelete(idOrName string) error {
	return s.inner.ForceDelete(idOrName)
}

// ListByFolder delegates to the inner encrypted store.
func (s *PINAccessStore) ListByFolder(folderPath string) ([]*StaticPassword, error) {
	return s.inner.ListByFolder(folderPath)
}

// ListByFolderDirect delegates to the inner encrypted store.
func (s *PINAccessStore) ListByFolderDirect(folderPath string) ([]*StaticPassword, error) {
	return s.inner.ListByFolderDirect(folderPath)
}

// ListFolders delegates to the inner encrypted store.
func (s *PINAccessStore) ListFolders() ([]string, error) {
	return s.inner.ListFolders()
}

// CreateFolder delegates to the inner store.
func (s *PINAccessStore) CreateFolder(path string) error {
	return s.inner.CreateFolder(path)
}

// RemoveFolder delegates to the inner store.
func (s *PINAccessStore) RemoveFolder(path string) error {
	return s.inner.RemoveFolder(path)
}

// MoveToFolder delegates to the inner encrypted store.
func (s *PINAccessStore) MoveToFolder(idOrName string, folderPath string) error {
	return s.inner.MoveToFolder(idOrName, folderPath)
}

// Close delegates to the inner encrypted store.
func (s *PINAccessStore) Close() error {
	return s.inner.Close()
}

// SessionStore requires a single Unlock call with a valid user PIN. Once
// unlocked, decryption operations succeed until Lock is called.
type SessionStore struct {
	inner      *EncryptedStore
	pinManager pin.PINBackend
	unlocked   atomic.Bool
}

// NewSessionStore creates a SessionStore. Both inner and pinManager must be non-nil.
// The store starts in the locked state.
func NewSessionStore(inner *EncryptedStore, pinManager pin.PINBackend) (*SessionStore, error) {
	if inner == nil {
		return nil, ErrNilInnerStore
	}
	if pinManager == nil {
		return nil, ErrNilPINManager
	}
	return &SessionStore{
		inner:      inner,
		pinManager: pinManager,
	}, nil
}

// Unlock verifies the user PIN and transitions the store to the unlocked state.
func (s *SessionStore) Unlock(userPIN string) error {
	if userPIN == "" {
		return ErrPINRequired
	}
	if s.unlocked.Load() {
		return ErrStoreNotLocked
	}
	if err := s.pinManager.VerifyUserPIN(userPIN); err != nil {
		return err
	}
	s.unlocked.Store(true)
	return nil
}

// Lock transitions the store to the locked state.
func (s *SessionStore) Lock() error {
	if !s.unlocked.Load() {
		return ErrStoreAlreadyLocked
	}
	s.unlocked.Store(false)
	return nil
}

// IsLocked returns true if the store is currently locked.
func (s *SessionStore) IsLocked() bool {
	return !s.unlocked.Load()
}

// Add delegates to the inner encrypted store.
func (s *SessionStore) Add(pw *StaticPassword) error {
	return s.inner.Add(pw)
}

// Get returns the entry with the password still encrypted.
func (s *SessionStore) Get(idOrName string) (*StaticPassword, error) {
	return s.inner.Get(idOrName)
}

// GetDecrypted returns the entry with a decrypted password. The store must be
// unlocked; otherwise ErrStoreLocked is returned.
func (s *SessionStore) GetDecrypted(idOrName string) (*StaticPassword, error) {
	if !s.unlocked.Load() {
		return nil, ErrStoreLocked
	}
	return s.inner.GetDecrypted(idOrName)
}

// List delegates to the inner encrypted store.
func (s *SessionStore) List() ([]*StaticPassword, error) {
	return s.inner.List()
}

// Update delegates to the inner encrypted store.
func (s *SessionStore) Update(pw *StaticPassword) error {
	return s.inner.Update(pw)
}

// Delete delegates to the inner encrypted store.
func (s *SessionStore) Delete(idOrName string) error {
	return s.inner.Delete(idOrName)
}

// ForceDelete removes an entry bypassing the read-only check.
func (s *SessionStore) ForceDelete(idOrName string) error {
	return s.inner.ForceDelete(idOrName)
}

// ListByFolder delegates to the inner encrypted store.
func (s *SessionStore) ListByFolder(folderPath string) ([]*StaticPassword, error) {
	return s.inner.ListByFolder(folderPath)
}

// ListByFolderDirect delegates to the inner encrypted store.
func (s *SessionStore) ListByFolderDirect(folderPath string) ([]*StaticPassword, error) {
	return s.inner.ListByFolderDirect(folderPath)
}

// ListFolders delegates to the inner encrypted store.
func (s *SessionStore) ListFolders() ([]string, error) {
	return s.inner.ListFolders()
}

// CreateFolder delegates to the inner store.
func (s *SessionStore) CreateFolder(path string) error {
	return s.inner.CreateFolder(path)
}

// RemoveFolder delegates to the inner store.
func (s *SessionStore) RemoveFolder(path string) error {
	return s.inner.RemoveFolder(path)
}

// MoveToFolder delegates to the inner encrypted store.
func (s *SessionStore) MoveToFolder(idOrName string, folderPath string) error {
	return s.inner.MoveToFolder(idOrName, folderPath)
}

// Close delegates to the inner encrypted store.
func (s *SessionStore) Close() error {
	return s.inner.Close()
}
