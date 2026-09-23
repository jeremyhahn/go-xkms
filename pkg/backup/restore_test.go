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

package backup

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memoryKeyStore is a KeyRestorer that keeps restored keys in memory so a
// test can read back exactly what a restore wrote.
type memoryKeyStore struct {
	mu   sync.Mutex
	keys map[string]*BackupKey

	// hasKeyErr, when set, is returned by every HasKey call.
	hasKeyErr error

	// restoreErr, when set, is returned by RestoreKey for the named key.
	restoreErr   error
	restoreErrID string
}

func newMemoryKeyStore() *memoryKeyStore {
	return &memoryKeyStore{keys: make(map[string]*BackupKey)}
}

// HasKey reports whether the store already holds the key.
func (s *memoryKeyStore) HasKey(_ context.Context, key *BackupKey) (bool, error) {
	if s.hasKeyErr != nil {
		return false, s.hasKeyErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.keys[key.ID]
	return ok, nil
}

// RestoreKey writes one key into the store.
func (s *memoryKeyStore) RestoreKey(_ context.Context, key *BackupKey) error {
	if s.restoreErr != nil && (s.restoreErrID == "" || s.restoreErrID == key.ID) {
		return s.restoreErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.ID] = key
	return nil
}

// key returns a restored key by identifier.
func (s *memoryKeyStore) key(id string) (*BackupKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[id]
	return key, ok
}

// count returns the number of keys held by the store.
func (s *memoryKeyStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

// newRestoreAdapter returns an adapter wired to a fresh in-memory key store.
func newRestoreAdapter(t *testing.T) (*FileBackupAdapter, *memoryKeyStore) {
	t.Helper()

	store := newMemoryKeyStore()
	adapter, err := NewFileBackupAdapter(t.TempDir(), WithKeyRestorer(store))
	require.NoError(t, err)

	return adapter, store
}

// --- Restore writes keys to the target ---

func TestFileBackupAdapter_RestoreBackup_WritesKeysToTarget(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 3)
	sourceKeys := make(map[string]*BackupKey, len(data.Keys))
	for _, key := range data.Keys {
		sourceKeys[key.ID] = key
	}

	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{})
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	require.Equal(t, 3, store.count(), "every backed-up key must land in the target")
	for id, source := range sourceKeys {
		restored, ok := store.key(id)
		require.True(t, ok, "key %s was reported restored but is not in the target", id)
		assert.Equal(t, source.PrivateKeyBytes(), restored.PrivateKeyBytes())
		assert.Equal(t, source.PublicKey, restored.PublicKey)
		require.NotNil(t, restored.Attributes)
		assert.Equal(t, source.Attributes.CN, restored.Attributes.CN)
	}
}

func TestFileBackupAdapter_RestoreBackup_EncryptedRoundTripLandsInTarget(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	encKey := make([]byte, 32)
	_, err := rand.Read(encKey)
	require.NoError(t, err)

	data := createTestBackupData(t, 2)
	keyID := data.Keys[0].ID
	privateKey := data.Keys[0].PrivateKeyBytes()

	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{
		Format:        BackupFormatEncrypted,
		EncryptionKey: encKey,
		Compress:      true,
	})
	require.NoError(t, err)

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{DecryptionKey: encKey})
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	restored, ok := store.key(keyID)
	require.True(t, ok)
	assert.Equal(t, privateKey, restored.PrivateKeyBytes())
}

func TestFileBackupAdapter_RestoreBackup_FilteredRestoreWritesOnlySelected(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 4)
	selected := data.Keys[1].ID
	skipped := data.Keys[2].ID

	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{KeyIDs: []string{selected}})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	assert.Equal(t, 1, store.count())
	_, ok := store.key(selected)
	assert.True(t, ok, "the selected key must be restored")
	_, ok = store.key(skipped)
	assert.False(t, ok, "unselected keys must not be written")
}

// --- Fail-closed paths ---

func TestFileBackupAdapter_RestoreBackup_NoTargetFailsClosed(t *testing.T) {
	// Regression guard: an adapter with nowhere to put keys used to report
	// the key count as if it had restored them.
	adapter, err := NewFileBackupAdapter(t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()

	data := createTestBackupData(t, 3)
	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoRestoreTarget)
	assert.Equal(t, 0, count, "a refused restore must not report restored keys")
}

func TestFileBackupAdapter_RestoreBackup_ExistingKeyRefusedWithoutOverwrite(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 3)
	conflicting := data.Keys[2]

	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	// Seed the destination with one of the backed-up keys.
	seed := &BackupKey{ID: conflicting.ID}
	require.NoError(t, seed.SetPrivateKey([]byte("existing")))
	require.NoError(t, store.RestoreKey(ctx, seed))

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyAlreadyExists)
	assert.Equal(t, 0, count)

	assert.Equal(t, 1, store.count(), "a refused restore must leave the destination untouched")
	existing, ok := store.key(conflicting.ID)
	require.True(t, ok)
	assert.Equal(t, []byte("existing"), existing.PrivateKeyBytes(), "the existing key must not be overwritten")
}

func TestFileBackupAdapter_RestoreBackup_OverwriteReplacesExisting(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 2)
	conflicting := data.Keys[0]

	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	stale := &BackupKey{ID: conflicting.ID}
	require.NoError(t, stale.SetPrivateKey([]byte("stale")))
	require.NoError(t, store.RestoreKey(ctx, stale))

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{Overwrite: true})
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	restored, ok := store.key(conflicting.ID)
	require.True(t, ok)
	assert.Equal(t, conflicting.PrivateKeyBytes(), restored.PrivateKeyBytes())
}

func TestFileBackupAdapter_RestoreBackup_DryRunWritesNothing(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 3)
	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{DryRun: true})
	require.NoError(t, err)
	assert.Equal(t, 3, count, "a dry run reports what would be restored")
	assert.Equal(t, 0, store.count(), "a dry run must not write to the destination")
}

func TestFileBackupAdapter_RestoreBackup_CorruptArchiveWritesNothing(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 2)
	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(adapter.getBackupPath(metadata.ID), []byte("corrupted"), 0600))

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrChecksumMismatch)
	assert.Equal(t, 0, count)
	assert.Equal(t, 0, store.count())
}

func TestFileBackupAdapter_RestoreBackup_WrongKeyWritesNothing(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	encKey := make([]byte, 32)
	_, err := rand.Read(encKey)
	require.NoError(t, err)
	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	require.NoError(t, err)

	data := createTestBackupData(t, 2)
	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{
		Format:        BackupFormatEncrypted,
		EncryptionKey: encKey,
	})
	require.NoError(t, err)

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{DecryptionKey: wrongKey})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
	assert.Equal(t, 0, count)
	assert.Equal(t, 0, store.count())
}

func TestFileBackupAdapter_RestoreBackup_MissingKeyIdentifier(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 1)
	data.Keys[0].ID = ""

	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingKeyIdentifier)
	assert.Equal(t, 0, count)
	assert.Equal(t, 0, store.count())
}

func TestFileBackupAdapter_RestoreBackup_HasKeyErrorPropagates(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 2)
	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	lookupErr := errors.New("key store unavailable")
	store.hasKeyErr = lookupErr

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, lookupErr)
	assert.Equal(t, 0, count)
	assert.Equal(t, 0, store.count())
}

func TestFileBackupAdapter_RestoreBackup_RestorerErrorReportsPartialCount(t *testing.T) {
	adapter, store := newRestoreAdapter(t)
	ctx := context.Background()

	data := createTestBackupData(t, 3)
	failing := data.Keys[1].ID

	metadata, err := adapter.CreateBackup(ctx, data, &BackupOptions{Format: BackupFormatJSON})
	require.NoError(t, err)

	writeErr := errors.New("hsm rejected the key")
	store.restoreErr = writeErr
	store.restoreErrID = failing

	count, err := adapter.RestoreBackup(ctx, metadata.ID, &RestoreOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, writeErr)
	assert.Equal(t, 1, count, "only the keys written before the failure are counted")
	assert.Equal(t, 1, store.count())
	_, ok := store.key(failing)
	assert.False(t, ok, "the rejected key must not appear in the destination")
}
