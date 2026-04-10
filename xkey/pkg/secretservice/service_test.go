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

package secretservice

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// memoryStore is a simple in-memory implementation for testing.
type memoryStore struct {
	passwords map[string]*staticpw.StaticPassword
	folders   map[string]bool
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		passwords: make(map[string]*staticpw.StaticPassword),
		folders:   make(map[string]bool),
	}
}

func (s *memoryStore) Add(pw *staticpw.StaticPassword) error {
	if pw.ID == "" {
		pw.ID = staticpw.GenerateID(pw.Name, pw.FolderPath)
	}
	if _, exists := s.passwords[pw.ID]; exists {
		return staticpw.ErrPasswordExists
	}
	s.passwords[pw.ID] = pw
	if pw.FolderPath != "" {
		s.folders[pw.FolderPath] = true
	}
	return nil
}

func (s *memoryStore) Get(idOrName string) (*staticpw.StaticPassword, error) {
	if pw, ok := s.passwords[idOrName]; ok {
		return pw, nil
	}
	for _, pw := range s.passwords {
		if pw.Name == idOrName {
			return pw, nil
		}
	}
	return nil, staticpw.ErrPasswordNotFound
}

func (s *memoryStore) List() ([]*staticpw.StaticPassword, error) {
	result := make([]*staticpw.StaticPassword, 0, len(s.passwords))
	for _, pw := range s.passwords {
		result = append(result, pw)
	}
	return result, nil
}

func (s *memoryStore) Update(pw *staticpw.StaticPassword) error {
	if _, exists := s.passwords[pw.ID]; !exists {
		return staticpw.ErrPasswordNotFound
	}
	s.passwords[pw.ID] = pw
	return nil
}

func (s *memoryStore) Delete(idOrName string) error {
	if _, exists := s.passwords[idOrName]; exists {
		delete(s.passwords, idOrName)
		return nil
	}
	for id, pw := range s.passwords {
		if pw.Name == idOrName {
			delete(s.passwords, id)
			return nil
		}
	}
	return staticpw.ErrPasswordNotFound
}

func (s *memoryStore) ForceDelete(idOrName string) error {
	return s.Delete(idOrName)
}

func (s *memoryStore) ListByFolder(folderPath string) ([]*staticpw.StaticPassword, error) {
	result := make([]*staticpw.StaticPassword, 0)
	for _, pw := range s.passwords {
		if folderPath == "" || pw.FolderPath == folderPath {
			result = append(result, pw)
		}
	}
	return result, nil
}

func (s *memoryStore) ListByFolderDirect(folderPath string) ([]*staticpw.StaticPassword, error) {
	result := make([]*staticpw.StaticPassword, 0)
	for _, pw := range s.passwords {
		if pw.FolderPath == folderPath {
			result = append(result, pw)
		}
	}
	return result, nil
}

func (s *memoryStore) ListFolders() ([]string, error) {
	result := make([]string, 0, len(s.folders))
	for folder := range s.folders {
		result = append(result, folder)
	}
	return result, nil
}

func (s *memoryStore) MoveToFolder(idOrName string, folderPath string) error {
	pw, err := s.Get(idOrName)
	if err != nil {
		return err
	}
	pw.FolderPath = folderPath
	return s.Update(pw)
}

func (s *memoryStore) CreateFolder(path string) error {
	if path == "" {
		return staticpw.ErrFolderEmpty
	}
	s.folders[path] = true
	return nil
}

func (s *memoryStore) RemoveFolder(path string) error {
	delete(s.folders, path)
	return nil
}

func (s *memoryStore) Close() error {
	return nil
}

func TestNewDaemon(t *testing.T) {
	store := newMemoryStore()

	t.Run("success", func(t *testing.T) {
		daemon, err := NewDaemon(store, nil, nil)
		require.NoError(t, err)
		assert.NotNil(t, daemon)
		assert.NotNil(t, daemon.mapper)
		assert.NotNil(t, daemon.config)
		assert.False(t, daemon.IsRunning())
	})

	t.Run("nil_store", func(t *testing.T) {
		_, err := NewDaemon(nil, nil, nil)
		assert.ErrorIs(t, err, ErrNilPasswordStore)
	})

	t.Run("custom_config", func(t *testing.T) {
		config := &ServiceConfig{
			Bus:        "system",
			AutoUnlock: false,
		}
		daemon, err := NewDaemon(store, config, nil)
		require.NoError(t, err)
		assert.Equal(t, "system", daemon.config.Bus)
		assert.False(t, daemon.config.AutoUnlock)
	})
}

func TestDaemon_SessionManagement(t *testing.T) {
	store := newMemoryStore()
	daemon, err := NewDaemon(store, nil, nil)
	require.NoError(t, err)

	t.Run("create_plain_session", func(t *testing.T) {
		// Simulate OpenSession call (without actual D-Bus connection)
		sessionID := "test-session-1"
		sessionPath := daemon.mapper.SessionPath(sessionID)

		session := &SessionInfo{
			Path:      sessionPath,
			Algorithm: AlgorithmPlain,
		}

		daemon.sessionsMu.Lock()
		daemon.sessions[sessionPath] = session
		daemon.sessionsMu.Unlock()

		// Verify session was created
		sess, exists := daemon.getSession(sessionPath)
		assert.True(t, exists)
		assert.Equal(t, AlgorithmPlain, sess.Algorithm)
	})

	t.Run("create_dh_session", func(t *testing.T) {
		sessionID := "test-session-2"
		sessionPath := daemon.mapper.SessionPath(sessionID)

		// Generate DH keys
		keyPair, err := GenerateDHKeyPair()
		require.NoError(t, err)

		clientKeyPair, err := GenerateDHKeyPair()
		require.NoError(t, err)

		sharedSecret := ComputeSharedSecret(keyPair.Private, clientKeyPair.Public)
		aesKey := DeriveAESKey(sharedSecret)

		session := &SessionInfo{
			Path:      sessionPath,
			Algorithm: AlgorithmDH,
			AESKey:    aesKey,
		}

		daemon.sessionsMu.Lock()
		daemon.sessions[sessionPath] = session
		daemon.sessionsMu.Unlock()

		// Verify session was created with AES key
		sess, exists := daemon.getSession(sessionPath)
		assert.True(t, exists)
		assert.Equal(t, AlgorithmDH, sess.Algorithm)
		assert.Len(t, sess.AESKey, 16)
	})

	t.Run("close_session", func(t *testing.T) {
		sessionID := "test-session-close"
		sessionPath := daemon.mapper.SessionPath(sessionID)

		session := &SessionInfo{
			Path:      sessionPath,
			Algorithm: AlgorithmPlain,
		}

		daemon.sessionsMu.Lock()
		daemon.sessions[sessionPath] = session
		daemon.sessionsMu.Unlock()

		// Close the session
		err := daemon.CloseSession(sessionPath)
		assert.Nil(t, err)

		// Verify session was removed
		_, exists := daemon.getSession(sessionPath)
		assert.False(t, exists)
	})

	t.Run("close_nonexistent_session", func(t *testing.T) {
		dbusErr := daemon.CloseSession(dbus.ObjectPath("/nonexistent"))
		assert.NotNil(t, dbusErr)
	})
}

func TestDaemon_CollectionOperations(t *testing.T) {
	store := newMemoryStore()
	daemon, err := NewDaemon(store, nil, nil)
	require.NoError(t, err)

	t.Run("collections_empty", func(t *testing.T) {
		collections, dbusErr := daemon.Collections()
		assert.Nil(t, dbusErr)

		// Should have at least the default collection
		assert.GreaterOrEqual(t, len(collections), 1)
	})

	t.Run("collections_with_folders", func(t *testing.T) {
		// Add passwords in different folders
		err := store.Add(&staticpw.StaticPassword{
			Name:       "test1",
			Password:   "secret1",
			FolderPath: "Work",
		})
		require.NoError(t, err)

		err = store.Add(&staticpw.StaticPassword{
			Name:       "test2",
			Password:   "secret2",
			FolderPath: "Personal",
		})
		require.NoError(t, err)

		collections, dbusErr := daemon.Collections()
		assert.Nil(t, dbusErr)

		// Should have default + Work + Personal
		assert.GreaterOrEqual(t, len(collections), 3)
	})
}

func TestDaemon_SearchItems(t *testing.T) {
	store := newMemoryStore()
	daemon, err := NewDaemon(store, nil, nil)
	require.NoError(t, err)

	// Add test passwords
	err = store.Add(&staticpw.StaticPassword{
		ID:       "pw1",
		Name:     "GitHub",
		Username: "user@example.com",
		URL:      "https://github.com",
		Password: "secret1",
	})
	require.NoError(t, err)

	err = store.Add(&staticpw.StaticPassword{
		ID:       "pw2",
		Name:     "GitLab",
		Username: "admin@example.com",
		URL:      "https://gitlab.com",
		Password: "secret2",
	})
	require.NoError(t, err)

	t.Run("search_by_service", func(t *testing.T) {
		unlocked, locked, dbusErr := daemon.SearchItems(map[string]string{
			"service": "GitHub",
		})
		assert.Nil(t, dbusErr)
		assert.Len(t, unlocked, 1)
		assert.Empty(t, locked)
	})

	t.Run("search_by_username", func(t *testing.T) {
		unlocked, locked, dbusErr := daemon.SearchItems(map[string]string{
			"username": "user@example.com",
		})
		assert.Nil(t, dbusErr)
		assert.Len(t, unlocked, 1)
		assert.Empty(t, locked)
	})

	t.Run("search_no_match", func(t *testing.T) {
		unlocked, locked, dbusErr := daemon.SearchItems(map[string]string{
			"service": "NonExistent",
		})
		assert.Nil(t, dbusErr)
		assert.Empty(t, unlocked)
		assert.Empty(t, locked)
	})

	t.Run("search_empty_attributes", func(t *testing.T) {
		unlocked, locked, dbusErr := daemon.SearchItems(map[string]string{})
		assert.Nil(t, dbusErr)
		// Empty search should return all items
		assert.GreaterOrEqual(t, len(unlocked), 2)
		assert.Empty(t, locked)
	})
}

func TestDaemon_GetSecrets(t *testing.T) {
	store := newMemoryStore()
	daemon, err := NewDaemon(store, nil, nil)
	require.NoError(t, err)

	// Add a test password
	pw := &staticpw.StaticPassword{
		ID:       "test-pw",
		Name:     "TestService",
		Password: "supersecret",
	}
	err = store.Add(pw)
	require.NoError(t, err)

	t.Run("get_secrets_plain_session", func(t *testing.T) {
		// Create a plain session
		sessionPath := daemon.mapper.SessionPath("plain-session")
		session := &SessionInfo{
			Path:      sessionPath,
			Algorithm: AlgorithmPlain,
		}
		daemon.sessionsMu.Lock()
		daemon.sessions[sessionPath] = session
		daemon.sessionsMu.Unlock()

		// Get item path
		collectionPath := daemon.mapper.CollectionPathFromFolder("")
		itemPath := daemon.mapper.ItemPathFromPassword(collectionPath, "test-pw")

		secrets, dbusErr := daemon.GetSecrets([]dbus.ObjectPath{itemPath}, sessionPath)
		assert.Nil(t, dbusErr)
		assert.Len(t, secrets, 1)

		secret := secrets[itemPath]
		assert.Equal(t, sessionPath, secret.Session)
		assert.Equal(t, []byte("supersecret"), secret.Value)
		assert.Empty(t, secret.Parameters) // Plain session has no IV
	})

	t.Run("get_secrets_dh_session", func(t *testing.T) {
		// Create a DH session with encryption
		sessionPath := daemon.mapper.SessionPath("dh-session")

		keyPair, err := GenerateDHKeyPair()
		require.NoError(t, err)
		clientKeyPair, err := GenerateDHKeyPair()
		require.NoError(t, err)

		sharedSecret := ComputeSharedSecret(keyPair.Private, clientKeyPair.Public)
		aesKey := DeriveAESKey(sharedSecret)

		session := &SessionInfo{
			Path:      sessionPath,
			Algorithm: AlgorithmDH,
			AESKey:    aesKey,
		}
		daemon.sessionsMu.Lock()
		daemon.sessions[sessionPath] = session
		daemon.sessionsMu.Unlock()

		// Get item path
		collectionPath := daemon.mapper.CollectionPathFromFolder("")
		itemPath := daemon.mapper.ItemPathFromPassword(collectionPath, "test-pw")

		secrets, dbusErr := daemon.GetSecrets([]dbus.ObjectPath{itemPath}, sessionPath)
		assert.Nil(t, dbusErr)
		assert.Len(t, secrets, 1)

		secret := secrets[itemPath]
		assert.Equal(t, sessionPath, secret.Session)
		assert.NotEmpty(t, secret.Parameters) // DH session has IV
		assert.NotEmpty(t, secret.Value)      // Encrypted value

		// Decrypt and verify
		crypto := NewSessionCryptoFromKey(aesKey)
		decrypted, err := crypto.Decrypt(secret.Parameters, secret.Value)
		require.NoError(t, err)
		assert.Equal(t, "supersecret", string(decrypted))
	})

	t.Run("get_secrets_invalid_session", func(t *testing.T) {
		collectionPath := daemon.mapper.CollectionPathFromFolder("")
		itemPath := daemon.mapper.ItemPathFromPassword(collectionPath, "test-pw")

		_, dbusErr := daemon.GetSecrets([]dbus.ObjectPath{itemPath}, "/invalid/session")
		assert.NotNil(t, dbusErr)
	})
}

func TestDaemon_UnlockLock(t *testing.T) {
	store := newMemoryStore()
	daemon, err := NewDaemon(store, nil, nil)
	require.NoError(t, err)

	collectionPath := daemon.mapper.CollectionPathFromFolder("Work")

	t.Run("unlock", func(t *testing.T) {
		unlocked, promptPath, dbusErr := daemon.Unlock([]dbus.ObjectPath{collectionPath})
		assert.Nil(t, dbusErr)

		// All objects are unlocked since go-xkms handles encryption internally
		assert.Len(t, unlocked, 1)
		assert.Equal(t, collectionPath, unlocked[0])
		assert.Equal(t, dbus.ObjectPath("/"), promptPath)
	})

	t.Run("lock", func(t *testing.T) {
		locked, promptPath, dbusErr := daemon.Lock([]dbus.ObjectPath{collectionPath})
		assert.Nil(t, dbusErr)

		// Lock is a no-op for go-xkms
		assert.Empty(t, locked)
		assert.Equal(t, dbus.ObjectPath("/"), promptPath)
	})
}

func TestDaemon_ReadWriteAlias(t *testing.T) {
	store := newMemoryStore()
	daemon, err := NewDaemon(store, nil, nil)
	require.NoError(t, err)

	t.Run("read_default_alias", func(t *testing.T) {
		collectionPath, dbusErr := daemon.ReadAlias("default")
		assert.Nil(t, dbusErr)
		assert.Equal(t, daemon.mapper.CollectionPathFromFolder(""), collectionPath)
	})

	t.Run("read_login_alias", func(t *testing.T) {
		collectionPath, dbusErr := daemon.ReadAlias("login")
		assert.Nil(t, dbusErr)
		assert.Equal(t, daemon.mapper.CollectionPathFromFolder(""), collectionPath)
	})

	t.Run("read_ssh_alias", func(t *testing.T) {
		collectionPath, dbusErr := daemon.ReadAlias("ssh")
		assert.Nil(t, dbusErr)
		assert.Equal(t, daemon.mapper.CollectionPathFromFolder("ssh"), collectionPath)
	})

	t.Run("set_alias", func(t *testing.T) {
		collectionPath := daemon.mapper.CollectionPathFromFolder("Custom")
		dbusErr := daemon.SetAlias("custom", collectionPath)

		// SetAlias is a no-op for now, just verify no error
		assert.Nil(t, dbusErr)
	})
}

func TestDaemon_CreateCollection(t *testing.T) {
	// CreateCollection emits a D-Bus signal which requires an active connection.
	// These tests verify the path mapping logic using the PathMapper directly
	// since we can't test the full CreateCollection without a D-Bus connection.

	mapper := NewPathMapper(DefaultConfig())

	t.Run("verify_alias_mapping", func(t *testing.T) {
		// Verify that aliases map to the expected folder paths
		collectionPath := mapper.CollectionPathFromFolder("mycollection")
		assert.Equal(t, dbus.ObjectPath(CollectionPathPrefix+"mycollection"), collectionPath)
	})

	t.Run("verify_label_mapping", func(t *testing.T) {
		// Labels map to folders with the same name (URL-encoded)
		collectionPath := mapper.CollectionPathFromFolder("Work Passwords")
		assert.Equal(t, dbus.ObjectPath(CollectionPathPrefix+"Work%20Passwords"), collectionPath)
	})

	t.Run("verify_default_alias", func(t *testing.T) {
		// Default alias maps to root folder
		folder := mapper.FolderFromAlias("default")
		assert.Equal(t, "", folder)

		collectionPath := mapper.CollectionPathFromFolder(folder)
		assert.Equal(t, dbus.ObjectPath(CollectionPathPrefix+"default"), collectionPath)
	})
}

func TestDaemon_IsRunning(t *testing.T) {
	store := newMemoryStore()
	daemon, err := NewDaemon(store, nil, nil)
	require.NoError(t, err)

	assert.False(t, daemon.IsRunning())

	// We can't call Start() without a D-Bus connection,
	// but we can manually set the running flag for testing.
	daemon.running.Store(true)
	assert.True(t, daemon.IsRunning())

	daemon.running.Store(false)
	assert.False(t, daemon.IsRunning())
}

func TestNewDaemon_WithRealStore(t *testing.T) {
	// Test with a real staticpw.BackendStore
	memBackend := storage.NewMemory()
	store := staticpw.NewStore(memBackend)

	daemon, err := NewDaemon(store, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, daemon)

	// Add a password and verify it can be retrieved
	err = store.Add(&staticpw.StaticPassword{
		Name:     "RealStoreTest",
		Password: "realpassword",
	})
	require.NoError(t, err)

	passwords, err := store.List()
	require.NoError(t, err)
	assert.Len(t, passwords, 1)

	// Create a session and get the secret
	sessionPath := daemon.mapper.SessionPath("real-session")
	session := &SessionInfo{
		Path:      sessionPath,
		Algorithm: AlgorithmPlain,
	}
	daemon.sessionsMu.Lock()
	daemon.sessions[sessionPath] = session
	daemon.sessionsMu.Unlock()

	collectionPath := daemon.mapper.CollectionPathFromFolder("")
	itemPath := daemon.mapper.ItemPathFromPassword(collectionPath, passwords[0].ID)

	secrets, dbusErr := daemon.GetSecrets([]dbus.ObjectPath{itemPath}, sessionPath)
	assert.Nil(t, dbusErr)
	assert.Len(t, secrets, 1)

	secret := secrets[itemPath]
	assert.Equal(t, []byte("realpassword"), secret.Value)
}
