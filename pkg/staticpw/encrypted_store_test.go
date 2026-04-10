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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEncrypter implements types.SymmetricEncrypter using XOR with 0xFF.
type mockEncrypter struct {
	encryptErr error
	decryptErr error
}

func (m *mockEncrypter) Encrypt(plaintext []byte, _ *types.EncryptOptions) (*types.EncryptedData, error) {
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	ct := make([]byte, len(plaintext))
	for i, b := range plaintext {
		ct[i] = b ^ 0xFF
	}
	return &types.EncryptedData{
		Ciphertext: ct,
		Nonce:      []byte("mock-nonce"),
		Algorithm:  "mock-xor",
	}, nil
}

func (m *mockEncrypter) Decrypt(data *types.EncryptedData, _ *types.DecryptOptions) ([]byte, error) {
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	pt := make([]byte, len(data.Ciphertext))
	for i, b := range data.Ciphertext {
		pt[i] = b ^ 0xFF
	}
	return pt, nil
}

func newTestEncryptedStore(t *testing.T) (*EncryptedStore, *BackendStore) {
	t.Helper()
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)
	return es, inner
}

func TestNewEncryptedStore_NilInner(t *testing.T) {
	_, err := NewEncryptedStore(nil, &mockEncrypter{})
	assert.ErrorIs(t, err, ErrNilStore)
}

func TestNewEncryptedStore_NilEncrypter(t *testing.T) {
	inner := NewStore(storage.New())
	_, err := NewEncryptedStore(inner, nil)
	assert.ErrorIs(t, err, ErrNilEncrypter)
}

func TestEncryptedStore_Add_EncryptsPassword(t *testing.T) {
	es, inner := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, es.Add(pw))

	// Fetch directly from inner store to verify encryption
	raw, err := inner.Get(pw.ID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(raw.Password, encryptedPrefix),
		"password should be encrypted with ENC: prefix")
	assert.NotEqual(t, "secret", raw.Password)
}

func TestEncryptedStore_Get_ReturnsEncrypted(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, es.Add(pw))

	retrieved, err := es.Get(pw.ID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(retrieved.Password, encryptedPrefix))
	assert.NotEqual(t, "secret", retrieved.Password)
}

func TestEncryptedStore_GetDecrypted_RoundTrip(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, es.Add(pw))

	decrypted, err := es.GetDecrypted(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, "secret", decrypted.Password)
}

func TestEncryptedStore_GetDecrypted_ByName(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "mysecret"}
	require.NoError(t, es.Add(pw))

	decrypted, err := es.GetDecrypted("test")
	require.NoError(t, err)
	assert.Equal(t, "mysecret", decrypted.Password)
}

func TestEncryptedStore_GetDecrypted_NotFound(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	_, err := es.GetDecrypted("nonexistent")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestEncryptedStore_Update_EncryptsNewPassword(t *testing.T) {
	es, inner := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "old-secret"}
	require.NoError(t, es.Add(pw))

	updated := &StaticPassword{ID: pw.ID, Name: "test", Password: "new-secret"}
	require.NoError(t, es.Update(updated))

	// Verify inner store has encrypted data
	raw, err := inner.Get(pw.ID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(raw.Password, encryptedPrefix))

	// Verify decryption returns new password
	decrypted, err := es.GetDecrypted(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-secret", decrypted.Password)
}

func TestEncryptedStore_Delete(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, es.Add(pw))
	require.NoError(t, es.Delete(pw.ID))

	_, err := es.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestEncryptedStore_List(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	require.NoError(t, es.Add(&StaticPassword{Name: "a", Password: "p1"}))
	require.NoError(t, es.Add(&StaticPassword{Name: "b", Password: "p2"}))

	entries, err := es.List()
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	// Passwords should still be encrypted
	for _, e := range entries {
		assert.True(t, strings.HasPrefix(e.Password, encryptedPrefix))
	}
}

func TestEncryptedStore_ListByFolder(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	require.NoError(t, es.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "email"}))
	require.NoError(t, es.Add(&StaticPassword{Name: "b", Password: "p", FolderPath: "work"}))

	entries, err := es.ListByFolder("email")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestEncryptedStore_ListFolders(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	require.NoError(t, es.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "email"}))
	require.NoError(t, es.Add(&StaticPassword{Name: "b", Password: "p", FolderPath: "work"}))

	folders, err := es.ListFolders()
	require.NoError(t, err)
	assert.Len(t, folders, 2)
}

func TestEncryptedStore_MoveToFolder(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret", FolderPath: "old"}
	require.NoError(t, es.Add(pw))

	require.NoError(t, es.MoveToFolder(pw.ID, "new"))

	moved, err := es.GetDecrypted("test")
	require.NoError(t, err)
	assert.Equal(t, "new", moved.FolderPath)
	assert.Equal(t, "secret", moved.Password)
}

func TestEncryptedStore_MoveToFolder_SameFolder(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret", FolderPath: "same"}
	require.NoError(t, es.Add(pw))

	assert.ErrorIs(t, es.MoveToFolder(pw.ID, "same"), ErrMoveToSameFolder)
}

func TestEncryptedStore_MoveToFolder_NotFound(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	assert.Error(t, es.MoveToFolder("nonexistent", "folder"))
}

func TestEncryptedStore_DoubleEncryptPrevention(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	// Add with a password that already has ENC: prefix
	pw := &StaticPassword{Name: "test", Password: "ENC:already-encrypted"}
	require.NoError(t, es.Add(pw))

	// Get should return it unchanged (still the ENC: prefixed value)
	retrieved, err := es.Get(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, "ENC:already-encrypted", retrieved.Password)
}

func TestEncryptedStore_PlaintextBackwardCompat(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	// Store plaintext directly in inner store
	pw := &StaticPassword{Name: "legacy", Password: "plaintext-password"}
	require.NoError(t, inner.Add(pw))

	// GetDecrypted should handle plaintext gracefully
	decrypted, err := es.GetDecrypted("legacy")
	require.NoError(t, err)
	assert.Equal(t, "plaintext-password", decrypted.Password)
}

func TestEncryptedStore_EncryptError(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{
		encryptErr: errors.New("encrypt failure"),
	})
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "test", Password: "secret"}
	err = es.Add(pw)
	assert.ErrorIs(t, err, ErrEncryptFailed)
}

func TestEncryptedStore_DecryptError(t *testing.T) {
	inner := NewStore(storage.New())
	goodEnc := &mockEncrypter{}
	es, err := NewEncryptedStore(inner, goodEnc)
	require.NoError(t, err)

	// Add with good encrypter
	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, es.Add(pw))

	// Replace with failing encrypter
	es.encrypter = &mockEncrypter{decryptErr: errors.New("decrypt failure")}

	_, err = es.GetDecrypted(pw.ID)
	assert.ErrorIs(t, err, ErrDecryptFailed)
}

func TestEncryptedStore_Close(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	require.NoError(t, es.Close())

	_, err := es.Get("anything")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestEncryptedStore_ImplementsStoreInterface(t *testing.T) {
	var _ Store = (*EncryptedStore)(nil)
}

// --- Targeted coverage tests ---

func TestEncryptedStore_ForceDelete(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	pw := &StaticPassword{Name: "readonly-entry", Password: "secret", ReadOnly: true}
	require.NoError(t, es.Add(pw))

	// Regular delete should fail for read-only entries.
	err := es.Delete(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordReadOnly)

	// ForceDelete bypasses read-only check.
	require.NoError(t, es.ForceDelete(pw.ID))

	_, err = es.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestEncryptedStore_ForceDelete_NotFound(t *testing.T) {
	es, _ := newTestEncryptedStore(t)
	defer func() { _ = es.Close() }()

	err := es.ForceDelete("nonexistent")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestEncryptedStore_MigrateToEncrypted_Success(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	// Add plaintext entries directly to the inner store (simulating legacy data).
	require.NoError(t, inner.Add(&StaticPassword{Name: "pw1", Password: "plaintext1"}))
	require.NoError(t, inner.Add(&StaticPassword{Name: "pw2", Password: "plaintext2"}))

	// Run migration.
	err = es.MigrateToEncrypted()
	require.NoError(t, err)

	// Verify all entries are now encrypted in the inner store.
	entries, err := inner.List()
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, strings.HasPrefix(e.Password, encryptedPrefix),
			"entry %s should be encrypted after migration", e.Name)
	}

	// Verify decryption round-trip works.
	d1, err := es.GetDecrypted("pw1")
	require.NoError(t, err)
	assert.Equal(t, "plaintext1", d1.Password)

	d2, err := es.GetDecrypted("pw2")
	require.NoError(t, err)
	assert.Equal(t, "plaintext2", d2.Password)
}

func TestEncryptedStore_MigrateToEncrypted_SkipsAlreadyEncrypted(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	// Add one plaintext entry and one encrypted entry.
	require.NoError(t, inner.Add(&StaticPassword{Name: "plain", Password: "plaintext"}))
	require.NoError(t, es.Add(&StaticPassword{Name: "already-enc", Password: "secret"}))

	// Run migration.
	err = es.MigrateToEncrypted()
	require.NoError(t, err)

	// Both should be encrypted.
	entries, err := inner.List()
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, strings.HasPrefix(e.Password, encryptedPrefix),
			"entry %s should be encrypted", e.Name)
	}
}

func TestEncryptedStore_MigrateToEncrypted_EmptyStore(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	// Migration on an empty store should succeed with no-op.
	err = es.MigrateToEncrypted()
	require.NoError(t, err)
}

func TestEncryptedStore_Update_EncryptError(t *testing.T) {
	inner := NewStore(storage.New())
	goodEnc := &mockEncrypter{}
	es, err := NewEncryptedStore(inner, goodEnc)
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	// Add with good encrypter.
	pw := &StaticPassword{Name: "test", Password: "secret"}
	require.NoError(t, es.Add(pw))

	// Replace with failing encrypter.
	es.encrypter = &mockEncrypter{encryptErr: errors.New("encrypt failure")}

	updated := &StaticPassword{ID: pw.ID, Name: "test", Password: "new-secret"}
	err = es.Update(updated)
	assert.ErrorIs(t, err, ErrEncryptFailed)
}
