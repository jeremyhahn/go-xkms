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
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPINManager implements pin.PINManager for testing.
type mockPINManager struct {
	userPIN string
	soPIN   string
}

func (m *mockPINManager) Strategy() pin.StrategyID             { return "mock" }
func (m *mockPINManager) SetSOPIN(_, _ string) error           { return nil }
func (m *mockPINManager) SetUserPIN(_, _ string) error         { return nil }
func (m *mockPINManager) ChangeSOPIN(_, _ string) error        { return nil }
func (m *mockPINManager) ChangeUserPIN(_, _ string) error      { return nil }
func (m *mockPINManager) GetLockoutStatus() *pin.LockoutStatus { return &pin.LockoutStatus{} }
func (m *mockPINManager) ResetLockout(_ string) error          { return nil }
func (m *mockPINManager) SetMaxAttempts(_ int)                 {}
func (m *mockPINManager) IsInitialized() bool                  { return true }
func (m *mockPINManager) SOPINSet() bool                       { return m.soPIN != "" }
func (m *mockPINManager) UserPINSet() bool                     { return m.userPIN != "" }

var errInvalidPIN = errors.New("mock: invalid PIN")

func (m *mockPINManager) VerifySOPIN(p string) error {
	if p != m.soPIN {
		return errInvalidPIN
	}
	return nil
}

func (m *mockPINManager) VerifyUserPIN(p string) error {
	if p != m.userPIN {
		return errInvalidPIN
	}
	return nil
}

func newTestPINAccessStore(t *testing.T) (*PINAccessStore, *EncryptedStore) {
	t.Helper()
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)

	pas, err := NewPINAccessStore(es, &mockPINManager{userPIN: "123456"})
	require.NoError(t, err)
	return pas, es
}

func newTestSessionStore(t *testing.T) (*SessionStore, *EncryptedStore) {
	t.Helper()
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)

	ss, err := NewSessionStore(es, &mockPINManager{userPIN: "123456"})
	require.NoError(t, err)
	return ss, es
}

// PINAccessStore tests

func TestNewPINAccessStore_NilInner(t *testing.T) {
	_, err := NewPINAccessStore(nil, &mockPINManager{userPIN: "123456"})
	assert.ErrorIs(t, err, ErrNilInnerStore)
}

func TestNewPINAccessStore_NilPINManager(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)

	_, err = NewPINAccessStore(es, nil)
	assert.ErrorIs(t, err, ErrNilPINManager)
}

func TestPINAccessStore_Add(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, pas.Add(pw))
}

func TestPINAccessStore_Get_ReturnsEncrypted(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, pas.Add(pw))

	retrieved, err := pas.Get(pw.ID)
	require.NoError(t, err)
	assert.NotEqual(t, "secret", retrieved.Password) // should be encrypted
}

func TestPINAccessStore_GetDecrypted_ValidPIN(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, pas.Add(pw))

	decrypted, err := pas.GetDecrypted(pw.ID, "123456")
	require.NoError(t, err)
	assert.Equal(t, "secret", decrypted.Password)
}

func TestPINAccessStore_GetDecrypted_InvalidPIN(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, pas.Add(pw))

	_, err := pas.GetDecrypted(pw.ID, "wrong-pin")
	assert.Error(t, err)
}

func TestPINAccessStore_GetDecrypted_EmptyPIN(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, pas.Add(pw))

	_, err := pas.GetDecrypted(pw.ID, "")
	assert.ErrorIs(t, err, ErrPINRequired)
}

func TestPINAccessStore_GetDecrypted_NotFound(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	_, err := pas.GetDecrypted("nonexistent", "123456")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestPINAccessStore_List(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	require.NoError(t, pas.Add(&StaticPassword{Name: "a", Password: "p1"}))
	require.NoError(t, pas.Add(&StaticPassword{Name: "b", Password: "p2"}))

	entries, err := pas.List()
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestPINAccessStore_Update(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "test", Password: "old"}
	require.NoError(t, pas.Add(pw))

	updated := &StaticPassword{ID: pw.ID, Name: "test", Password: "new"}
	require.NoError(t, pas.Update(updated))
}

func TestPINAccessStore_Delete(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, pas.Add(pw))
	require.NoError(t, pas.Delete(pw.ID))

	_, err := pas.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestPINAccessStore_ListByFolder(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	require.NoError(t, pas.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "f1"}))

	entries, err := pas.ListByFolder("f1")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestPINAccessStore_ListFolders(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	require.NoError(t, pas.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "f1"}))

	folders, err := pas.ListFolders()
	require.NoError(t, err)
	assert.Len(t, folders, 1)
}

func TestPINAccessStore_MoveToFolder(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret", FolderPath: "old"}
	require.NoError(t, pas.Add(pw))
	require.NoError(t, pas.MoveToFolder(pw.ID, "new"))
}

func TestPINAccessStore_ImplementsStoreInterface(t *testing.T) {
	var _ Store = (*PINAccessStore)(nil)
}

// SessionStore tests

func TestNewSessionStore_NilInner(t *testing.T) {
	_, err := NewSessionStore(nil, &mockPINManager{userPIN: "123456"})
	assert.ErrorIs(t, err, ErrNilInnerStore)
}

func TestNewSessionStore_NilPINManager(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)

	_, err = NewSessionStore(es, nil)
	assert.ErrorIs(t, err, ErrNilPINManager)
}

func TestSessionStore_StartsLocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()
	assert.True(t, ss.IsLocked())
}

func TestSessionStore_Unlock_ValidPIN(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.Unlock("123456"))
	assert.False(t, ss.IsLocked())
}

func TestSessionStore_Unlock_InvalidPIN(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	err := ss.Unlock("wrong")
	assert.Error(t, err)
	assert.True(t, ss.IsLocked())
}

func TestSessionStore_Unlock_EmptyPIN(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	err := ss.Unlock("")
	assert.ErrorIs(t, err, ErrPINRequired)
}

func TestSessionStore_Unlock_AlreadyUnlocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.Unlock("123456"))
	assert.ErrorIs(t, ss.Unlock("123456"), ErrStoreNotLocked)
}

func TestSessionStore_Lock(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.Unlock("123456"))
	require.NoError(t, ss.Lock())
	assert.True(t, ss.IsLocked())
}

func TestSessionStore_Lock_AlreadyLocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	assert.ErrorIs(t, ss.Lock(), ErrStoreAlreadyLocked)
}

func TestSessionStore_GetDecrypted_WhenUnlocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, ss.Add(pw))
	require.NoError(t, ss.Unlock("123456"))

	decrypted, err := ss.GetDecrypted(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, "secret", decrypted.Password)
}

func TestSessionStore_GetDecrypted_WhenLocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, ss.Add(pw))

	_, err := ss.GetDecrypted(pw.ID)
	assert.ErrorIs(t, err, ErrStoreLocked)
}

func TestSessionStore_GetDecrypted_AfterRelock(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, ss.Add(pw))
	require.NoError(t, ss.Unlock("123456"))

	// Verify access works
	_, err := ss.GetDecrypted(pw.ID)
	require.NoError(t, err)

	// Lock again
	require.NoError(t, ss.Lock())

	// Should be denied now
	_, err = ss.GetDecrypted(pw.ID)
	assert.ErrorIs(t, err, ErrStoreLocked)
}

func TestSessionStore_Add_WorksWhileLocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, ss.Add(pw))
}

func TestSessionStore_Get_WorksWhileLocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, ss.Add(pw))

	_, err := ss.Get(pw.ID)
	require.NoError(t, err)
}

func TestSessionStore_List_WorksWhileLocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.Add(&StaticPassword{Name: "a", Password: "p"}))

	entries, err := ss.List()
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestSessionStore_Update_WorksWhileLocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "test", Password: "old"}
	require.NoError(t, ss.Add(pw))

	updated := &StaticPassword{ID: pw.ID, Name: "test", Password: "new"}
	require.NoError(t, ss.Update(updated))
}

func TestSessionStore_Delete_WorksWhileLocked(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, ss.Add(pw))
	require.NoError(t, ss.Delete(pw.ID))
}

func TestSessionStore_ListByFolder(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "f1"}))

	entries, err := ss.ListByFolder("f1")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestSessionStore_ListFolders(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "f1"}))

	folders, err := ss.ListFolders()
	require.NoError(t, err)
	assert.Len(t, folders, 1)
}

func TestSessionStore_MoveToFolder(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret", FolderPath: "old"}
	require.NoError(t, ss.Add(pw))
	require.NoError(t, ss.MoveToFolder(pw.ID, "new"))
}

func TestSessionStore_ImplementsStoreInterface(t *testing.T) {
	var _ Store = (*SessionStore)(nil)
}

func TestSessionStore_Close(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	require.NoError(t, ss.Close())

	_, err := ss.Get("anything")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

// Verify ExpiresAt handling through access stores
func TestPINAccessStore_ExpiresAt(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{
		Name:      "expiring",
		Password:  "secret",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}
	require.NoError(t, pas.Add(pw))

	retrieved, err := pas.GetDecrypted(pw.ID, "123456")
	require.NoError(t, err)
	assert.True(t, retrieved.ExpiresAt.Before(time.Now()))
}

// --- Targeted coverage tests ---

func TestPINAccessStore_ForceDelete(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	pw := &StaticPassword{Name: "readonly-entry", Password: "secret", ReadOnly: true}
	require.NoError(t, pas.Add(pw))

	// Regular delete should fail for read-only entries.
	err := pas.Delete(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordReadOnly)

	// ForceDelete bypasses read-only check.
	require.NoError(t, pas.ForceDelete(pw.ID))

	_, err = pas.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestSessionStore_ForceDelete(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	pw := &StaticPassword{Name: "readonly-entry", Password: "secret", ReadOnly: true}
	require.NoError(t, ss.Add(pw))

	// Regular delete should fail for read-only entries.
	err := ss.Delete(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordReadOnly)

	// ForceDelete bypasses read-only check.
	require.NoError(t, ss.ForceDelete(pw.ID))

	_, err = ss.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}
