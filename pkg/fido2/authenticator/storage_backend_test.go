// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/require"
)

func TestNewBackendStorage(t *testing.T) {
	t.Run("creates storage with backend", func(t *testing.T) {
		backend := storage.NewMemory()
		defer func() { _ = backend.Close() }()

		s, err := NewBackendStorage(backend, "test/")
		if err != nil {
			t.Fatalf("NewBackendStorage failed: %v", err)
		}
		if s == nil {
			t.Fatal("NewBackendStorage returned nil")
		}
		if s.prefix != "test/" {
			t.Errorf("expected prefix 'test/', got '%s'", s.prefix)
		}
	})

	t.Run("uses default prefix when empty", func(t *testing.T) {
		backend := storage.NewMemory()
		defer func() { _ = backend.Close() }()

		s, err := NewBackendStorage(backend, "")
		if err != nil {
			t.Fatalf("NewBackendStorage failed: %v", err)
		}
		if s.prefix != "fido2/authenticator/" {
			t.Errorf("expected default prefix, got '%s'", s.prefix)
		}
	})

	t.Run("adds trailing slash to prefix", func(t *testing.T) {
		backend := storage.NewMemory()
		defer func() { _ = backend.Close() }()

		s, err := NewBackendStorage(backend, "test")
		if err != nil {
			t.Fatalf("NewBackendStorage failed: %v", err)
		}
		if s.prefix != "test/" {
			t.Errorf("expected 'test/', got '%s'", s.prefix)
		}
	})

	t.Run("rejects nil backend", func(t *testing.T) {
		_, err := NewBackendStorage(nil, "test/")
		if err != ErrNilStorage {
			t.Errorf("expected ErrNilStorage, got %v", err)
		}
	})
}

func TestBackendStorage_Store(t *testing.T) {
	t.Run("stores credential successfully", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		cred := createTestCredential(t, []byte{1, 2, 3, 4}, "example.com", true)

		err := s.Store(cred)
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		count, err := s.Count()
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count != 1 {
			t.Errorf("expected count 1, got %d", count)
		}
	})

	t.Run("rejects nil credential", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		err := s.Store(nil)
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("rejects empty credential ID", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		cred := &StoredCredential{
			CredentialID: []byte{},
			RPID:         "example.com",
		}

		err := s.Store(cred)
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		cred := createTestCredential(t, []byte{1, 2, 3, 4}, "example.com", true)

		err := s.Store(cred)
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})

	t.Run("overwrites existing credential with same ID", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		cred1 := createTestCredential(t, []byte{1, 2, 3, 4}, "example1.com", true)
		cred2 := createTestCredential(t, []byte{1, 2, 3, 4}, "example2.com", false)

		if err := s.Store(cred1); err != nil {
			t.Fatalf("Store cred1 failed: %v", err)
		}
		if err := s.Store(cred2); err != nil {
			t.Fatalf("Store cred2 failed: %v", err)
		}

		loaded, err := s.Load([]byte{1, 2, 3, 4})
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		if loaded.RPID != "example2.com" {
			t.Errorf("expected RPID example2.com, got %s", loaded.RPID)
		}
	})
}

func TestBackendStorage_Load(t *testing.T) {
	t.Run("loads credential successfully", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		credID := []byte{5, 6, 7, 8}
		cred := createTestCredential(t, credID, "example.com", true)
		_ = s.Store(cred)

		loaded, err := s.Load(credID)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		if !bytes.Equal(loaded.CredentialID, credID) {
			t.Error("credential ID mismatch")
		}
		if loaded.RPID != "example.com" {
			t.Errorf("expected RPID example.com, got %s", loaded.RPID)
		}
	})

	t.Run("returns ErrCredentialNotFound for missing credential", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		_, err := s.Load([]byte{99, 99, 99})
		if err != ErrCredentialNotFound {
			t.Errorf("expected ErrCredentialNotFound, got %v", err)
		}
	})

	t.Run("rejects empty credential ID", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		_, err := s.Load([]byte{})
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("rejects nil credential ID", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		_, err := s.Load(nil)
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		_, err := s.Load([]byte{1, 2, 3, 4})
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestBackendStorage_LoadByRPID(t *testing.T) {
	t.Run("loads credentials for RPID", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		// Store credentials for different RPs
		_ = s.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = s.Store(createTestCredential(t, []byte{2}, "example.com", false))
		_ = s.Store(createTestCredential(t, []byte{3}, "other.com", true))

		creds, err := s.LoadByRPID("example.com")
		if err != nil {
			t.Fatalf("LoadByRPID failed: %v", err)
		}
		if len(creds) != 2 {
			t.Errorf("expected 2 credentials, got %d", len(creds))
		}
	})

	t.Run("returns empty slice for unknown RPID", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		_ = s.Store(createTestCredential(t, []byte{1}, "example.com", true))

		creds, err := s.LoadByRPID("unknown.com")
		if err != nil {
			t.Fatalf("LoadByRPID failed: %v", err)
		}
		if len(creds) != 0 {
			t.Errorf("expected 0 credentials, got %d", len(creds))
		}
	})

	t.Run("rejects empty RPID", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		_, err := s.LoadByRPID("")
		if err != ErrInvalidRPIDEmpty {
			t.Errorf("expected ErrInvalidRPIDEmpty, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		_, err := s.LoadByRPID("example.com")
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestBackendStorage_Delete(t *testing.T) {
	t.Run("deletes credential successfully", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		credID := []byte{1, 2, 3, 4}
		_ = s.Store(createTestCredential(t, credID, "example.com", true))

		err := s.Delete(credID)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = s.Load(credID)
		if err != ErrCredentialNotFound {
			t.Error("credential should not exist after deletion")
		}
	})

	t.Run("returns ErrCredentialNotFound for missing credential", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		err := s.Delete([]byte{99, 99, 99})
		if err != ErrCredentialNotFound {
			t.Errorf("expected ErrCredentialNotFound, got %v", err)
		}
	})

	t.Run("rejects empty credential ID", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		err := s.Delete([]byte{})
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		err := s.Delete([]byte{1, 2, 3, 4})
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestBackendStorage_Count(t *testing.T) {
	t.Run("returns correct count", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		count, err := s.Count()
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0, got %d", count)
		}

		_ = s.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = s.Store(createTestCredential(t, []byte{2}, "example.com", false))

		count, err = s.Count()
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2, got %d", count)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		_, err := s.Count()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestBackendStorage_CountDiscoverable(t *testing.T) {
	t.Run("returns correct discoverable count", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		_ = s.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = s.Store(createTestCredential(t, []byte{2}, "example.com", false))
		_ = s.Store(createTestCredential(t, []byte{3}, "example.com", true))

		count, err := s.CountDiscoverable()
		if err != nil {
			t.Fatalf("CountDiscoverable failed: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 discoverable, got %d", count)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		_, err := s.CountDiscoverable()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestBackendStorage_SaveState(t *testing.T) {
	t.Run("saves state successfully", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		state := createTestStateForBackend(t)

		err := s.SaveState(state)
		if err != nil {
			t.Fatalf("SaveState failed: %v", err)
		}

		// Verify it was stored
		loaded, err := s.LoadState()
		if err != nil {
			t.Fatalf("LoadState failed: %v", err)
		}
		if loaded == nil {
			t.Error("loaded state should not be nil")
		}
	})

	t.Run("rejects nil state", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		err := s.SaveState(nil)
		if err != ErrInvalidParameter {
			t.Errorf("expected ErrInvalidParameter, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		state := createTestStateForBackend(t)

		err := s.SaveState(state)
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestBackendStorage_LoadState(t *testing.T) {
	t.Run("loads state successfully", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		state := createTestStateForBackend(t)
		state.AAGUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		state.PINSet = true
		state.PINHash = []byte{1, 2, 3, 4}
		state.SetPINRetries(5)
		_ = s.SaveState(state)

		loaded, err := s.LoadState()
		if err != nil {
			t.Fatalf("LoadState failed: %v", err)
		}
		if loaded.AAGUID != state.AAGUID {
			t.Error("AAGUID mismatch")
		}
		if loaded.PINSet != true {
			t.Error("PINSet mismatch")
		}
		if !bytes.Equal(loaded.PINHash, state.PINHash) {
			t.Error("PINHash mismatch")
		}
		if loaded.PINRetries() != 5 {
			t.Errorf("expected PIN retries 5, got %d", loaded.PINRetries())
		}
	})

	t.Run("returns ErrStateNotFound when no state saved", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		_, err := s.LoadState()
		if err != ErrStateNotFound {
			t.Errorf("expected ErrStateNotFound, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		_, err := s.LoadState()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})

	t.Run("preserves attestation key", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		state := createTestStateForBackend(t)
		_ = s.SaveState(state)

		loaded, err := s.LoadState()
		if err != nil {
			t.Fatalf("LoadState failed: %v", err)
		}
		if loaded.AttestationKey == nil {
			t.Error("attestation key should be preserved")
		}
		// Verify it's a valid key
		if loaded.AttestationKey.X == nil {
			t.Error("attestation key should have valid public key")
		}
	})
}

func TestBackendStorage_Close(t *testing.T) {
	t.Run("closes successfully", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Store(createTestCredential(t, []byte{1}, "example.com", true))

		err := s.Close()
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		if !s.closed {
			t.Error("storage should be marked closed")
		}
	})

	t.Run("is idempotent", func(t *testing.T) {
		s := createBackendStorage(t)

		err1 := s.Close()
		err2 := s.Close()
		err3 := s.Close()

		if err1 != nil || err2 != nil || err3 != nil {
			t.Error("Close should be idempotent and return nil")
		}
	})

	t.Run("does not close underlying backend", func(t *testing.T) {
		backend := storage.NewMemory()

		s, _ := NewBackendStorage(backend, "test/")
		_ = s.Store(createTestCredential(t, []byte{1}, "example.com", true))

		// Close the BackendStorage
		_ = s.Close()

		// The underlying backend should still work
		err := backend.Put("test-key", []byte("test-value"), nil)
		if err != nil {
			t.Errorf("underlying backend should still work after BackendStorage.Close: %v", err)
		}

		_ = backend.Close()
	})
}

func TestBackendStorage_CredentialKey(t *testing.T) {
	backend := storage.NewMemory()
	defer func() { _ = backend.Close() }()

	s, _ := NewBackendStorage(backend, "myapp/fido2/")

	credID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	key := s.credentialKey(credID)

	expected := "myapp/fido2/credentials/deadbeef"
	if key != expected {
		t.Errorf("expected key '%s', got '%s'", expected, key)
	}
}

func TestBackendStorage_Persistence(t *testing.T) {
	t.Run("credentials persist across storage instances", func(t *testing.T) {
		// Use the same backend for multiple storage instances
		backend := storage.NewMemory()
		defer func() { _ = backend.Close() }()

		// First instance stores credentials
		s1, _ := NewBackendStorage(backend, "test/")
		cred := createTestCredential(t, []byte{1, 2, 3, 4}, "example.com", true)
		cred.SignCount = 42
		cred.UserName = "persistent-user"
		_ = s1.Store(cred)
		_ = s1.Close()

		// Second instance should see the credentials
		s2, _ := NewBackendStorage(backend, "test/")
		defer func() { _ = s2.Close() }()

		loaded, err := s2.Load([]byte{1, 2, 3, 4})
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		if loaded.SignCount != 42 {
			t.Errorf("expected SignCount 42, got %d", loaded.SignCount)
		}
		if loaded.UserName != "persistent-user" {
			t.Errorf("expected UserName 'persistent-user', got '%s'", loaded.UserName)
		}
	})

	t.Run("state persists across storage instances", func(t *testing.T) {
		backend := storage.NewMemory()
		defer func() { _ = backend.Close() }()

		// First instance saves state
		s1, _ := NewBackendStorage(backend, "test/")
		state := createTestStateForBackend(t)
		state.AAGUID = [16]byte{99, 99, 99}
		state.PINSet = true
		state.SetPINRetries(3)
		_ = s1.SaveState(state)
		_ = s1.Close()

		// Second instance should see the state
		s2, _ := NewBackendStorage(backend, "test/")
		defer func() { _ = s2.Close() }()

		loaded, err := s2.LoadState()
		if err != nil {
			t.Fatalf("LoadState failed: %v", err)
		}
		if loaded.AAGUID != state.AAGUID {
			t.Error("AAGUID mismatch")
		}
		if loaded.PINSet != true {
			t.Error("PINSet mismatch")
		}
		if loaded.PINRetries() != 3 {
			t.Errorf("expected PIN retries 3, got %d", loaded.PINRetries())
		}
	})
}

func TestBackendStorage_NamespaceIsolation(t *testing.T) {
	t.Run("different prefixes isolate data", func(t *testing.T) {
		backend := storage.NewMemory()
		defer func() { _ = backend.Close() }()

		s1, _ := NewBackendStorage(backend, "app1/")
		s2, _ := NewBackendStorage(backend, "app2/")
		defer func() { _ = s1.Close() }()
		defer func() { _ = s2.Close() }()

		// Store in first namespace
		_ = s1.Store(createTestCredential(t, []byte{1}, "example.com", true))

		// Second namespace should be empty
		count, _ := s2.Count()
		if count != 0 {
			t.Errorf("expected 0 credentials in s2, got %d", count)
		}

		// First namespace should have the credential
		count, _ = s1.Count()
		if count != 1 {
			t.Errorf("expected 1 credential in s1, got %d", count)
		}
	})
}

func TestBackendStorage_JSONSerialization(t *testing.T) {
	t.Run("preserves all credential fields through serialization", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		original := &StoredCredential{
			CredentialID:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
			RPID:            "example.com",
			RPName:          "Example Corp",
			UserID:          []byte{9, 10, 11, 12},
			UserName:        "user@example.com",
			UserDisplayName: "Test User",
			PrivateKey:      []byte{13, 14, 15, 16},
			PublicKeyCOSE:   []byte{17, 18, 19, 20},
			Algorithm:       COSEAlgES256,
			SignCount:       999,
			Discoverable:    true,
			HMACSecretKey:   make([]byte, 32),
			CreatedAt:       time.Now().Unix(),
		}

		if err := s.Store(original); err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		loaded, err := s.Load(original.CredentialID)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		// Verify all fields
		if !bytes.Equal(loaded.CredentialID, original.CredentialID) {
			t.Error("CredentialID mismatch")
		}
		if loaded.RPID != original.RPID {
			t.Error("RPID mismatch")
		}
		if loaded.RPName != original.RPName {
			t.Error("RPName mismatch")
		}
		if !bytes.Equal(loaded.UserID, original.UserID) {
			t.Error("UserID mismatch")
		}
		if loaded.UserName != original.UserName {
			t.Error("UserName mismatch")
		}
		if loaded.UserDisplayName != original.UserDisplayName {
			t.Error("UserDisplayName mismatch")
		}
		if !bytes.Equal(loaded.PrivateKey, original.PrivateKey) {
			t.Error("PrivateKey mismatch")
		}
		if !bytes.Equal(loaded.PublicKeyCOSE, original.PublicKeyCOSE) {
			t.Error("PublicKeyCOSE mismatch")
		}
		if loaded.Algorithm != original.Algorithm {
			t.Error("Algorithm mismatch")
		}
		if loaded.SignCount != original.SignCount {
			t.Error("SignCount mismatch")
		}
		if loaded.Discoverable != original.Discoverable {
			t.Error("Discoverable mismatch")
		}
		if !bytes.Equal(loaded.HMACSecretKey, original.HMACSecretKey) {
			t.Error("HMACSecretKey mismatch")
		}
		if loaded.CreatedAt != original.CreatedAt {
			t.Error("CreatedAt mismatch")
		}
	})
}

// TestBackendStorage_Clear tests the Clear method.
func TestBackendStorage_Clear(t *testing.T) {
	t.Run("clears all credentials successfully", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		// Store multiple credentials
		_ = s.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = s.Store(createTestCredential(t, []byte{2}, "example.com", false))
		_ = s.Store(createTestCredential(t, []byte{3}, "other.com", true))

		// Verify credentials exist
		count, err := s.Count()
		require.NoError(t, err)
		require.Equal(t, 3, count)

		// Clear all credentials
		err = s.Clear()
		require.NoError(t, err)

		// Verify all credentials are deleted
		count, err = s.Count()
		require.NoError(t, err)
		require.Equal(t, 0, count)
	})

	t.Run("clears empty storage without error", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		// Clear empty storage should succeed
		err := s.Clear()
		require.NoError(t, err)

		// Verify storage is still empty
		count, err := s.Count()
		require.NoError(t, err)
		require.Equal(t, 0, count)
	})

	t.Run("does not clear state", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		// Save state
		state := createTestStateForBackend(t)
		state.PINSet = true
		err := s.SaveState(state)
		require.NoError(t, err)

		// Store credentials
		_ = s.Store(createTestCredential(t, []byte{1}, "example.com", true))

		// Clear credentials
		err = s.Clear()
		require.NoError(t, err)

		// Verify state is still accessible
		loadedState, err := s.LoadState()
		require.NoError(t, err)
		require.True(t, loadedState.PINSet)
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		err := s.Clear()
		require.ErrorIs(t, err, ErrStorageClosed)
	})
}

// TestBackendStorage_ListAll tests the ListAll method.
func TestBackendStorage_ListAll(t *testing.T) {
	t.Run("lists all credential IDs successfully", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		// Store multiple credentials
		credID1 := []byte{0x01, 0x02, 0x03, 0x04}
		credID2 := []byte{0xAB, 0xCD, 0xEF, 0x01}
		credID3 := []byte{0xDE, 0xAD, 0xBE, 0xEF}

		_ = s.Store(createTestCredential(t, credID1, "example.com", true))
		_ = s.Store(createTestCredential(t, credID2, "example.com", false))
		_ = s.Store(createTestCredential(t, credID3, "other.com", true))

		// List all credential IDs
		credIDs, err := s.ListAll()
		require.NoError(t, err)
		require.Len(t, credIDs, 3)

		// Verify all expected credential IDs are in the result
		credIDMap := make(map[string]bool)
		for _, id := range credIDs {
			credIDMap[string(id)] = true
		}

		require.True(t, credIDMap[string(credID1)], "credID1 should be in the list")
		require.True(t, credIDMap[string(credID2)], "credID2 should be in the list")
		require.True(t, credIDMap[string(credID3)], "credID3 should be in the list")
	})

	t.Run("returns empty slice for empty storage", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		credIDs, err := s.ListAll()
		require.NoError(t, err)
		require.Empty(t, credIDs)
	})

	t.Run("credential IDs can be used to load credentials", func(t *testing.T) {
		s := createBackendStorage(t)
		defer func() { _ = s.Close() }()

		// Store a credential
		origCredID := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		origCred := createTestCredential(t, origCredID, "example.com", true)
		origCred.UserName = "test-user"
		_ = s.Store(origCred)

		// List all credential IDs
		credIDs, err := s.ListAll()
		require.NoError(t, err)
		require.Len(t, credIDs, 1)

		// Load credential using the listed ID
		loaded, err := s.Load(credIDs[0])
		require.NoError(t, err)
		require.Equal(t, "test-user", loaded.UserName)
		require.Equal(t, "example.com", loaded.RPID)
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		s := createBackendStorage(t)
		_ = s.Close()

		_, err := s.ListAll()
		require.ErrorIs(t, err, ErrStorageClosed)
	})
}

// TestWrapStorageError tests the wrapStorageError helper function.
func TestWrapStorageError(t *testing.T) {
	t.Run("returns nil for nil error", func(t *testing.T) {
		err := wrapStorageError(nil)
		require.Nil(t, err)
	})

	t.Run("wraps error with ErrStorageError", func(t *testing.T) {
		originalErr := errors.New("underlying storage failure")
		wrappedErr := wrapStorageError(originalErr)

		require.Error(t, wrappedErr)
		require.ErrorIs(t, wrappedErr, ErrStorageError)
	})

	t.Run("preserves original error information", func(t *testing.T) {
		originalErr := errors.New("disk full")
		wrappedErr := wrapStorageError(originalErr)

		// The wrapped error should contain the original error
		require.ErrorIs(t, wrappedErr, originalErr)
	})

	t.Run("wraps typed errors", func(t *testing.T) {
		// Create a custom error type
		customErr := &customTestError{msg: "custom error"}
		wrappedErr := wrapStorageError(customErr)

		require.Error(t, wrappedErr)
		require.ErrorIs(t, wrappedErr, ErrStorageError)
		require.ErrorIs(t, wrappedErr, customErr)
	})
}

// customTestError is a custom error type for testing.
type customTestError struct {
	msg string
}

func (e *customTestError) Error() string {
	return e.msg
}

// Helper functions

func createBackendStorage(t *testing.T) *BackendStorage {
	t.Helper()
	backend := storage.NewMemory()
	s, err := NewBackendStorage(backend, "test/")
	if err != nil {
		t.Fatalf("failed to create BackendStorage: %v", err)
	}
	return s
}

func createTestStateForBackend(t *testing.T) *AuthenticatorState {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attestation key: %v", err)
	}

	state := NewAuthenticatorState()
	state.AAGUID = DefaultAAGUID
	state.AttestationKey = key

	return state
}
