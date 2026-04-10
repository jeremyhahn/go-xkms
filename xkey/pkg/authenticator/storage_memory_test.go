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

package authenticator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"
)

func TestNewMemoryStorage(t *testing.T) {
	storage := NewMemoryStorage()
	if storage == nil {
		t.Fatal("NewMemoryStorage returned nil")
	}
	if storage.credentials == nil {
		t.Error("credentials map should be initialized")
	}
	if storage.closed {
		t.Error("storage should not be closed on creation")
	}
}

func TestMemoryStorage_Store(t *testing.T) {
	t.Run("stores credential successfully", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		cred := createTestCredential(t, []byte{1, 2, 3, 4}, "example.com", true)

		err := storage.Store(cred)
		if err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		count, err := storage.Count()
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count != 1 {
			t.Errorf("expected count 1, got %d", count)
		}
	})

	t.Run("rejects nil credential", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		err := storage.Store(nil)
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("rejects empty credential ID", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		cred := &StoredCredential{
			CredentialID: []byte{},
			RPID:         "example.com",
		}

		err := storage.Store(cred)
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		cred := createTestCredential(t, []byte{1, 2, 3, 4}, "example.com", true)

		err := storage.Store(cred)
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})

	t.Run("overwrites existing credential with same ID", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		cred1 := createTestCredential(t, []byte{1, 2, 3, 4}, "example1.com", true)
		cred2 := createTestCredential(t, []byte{1, 2, 3, 4}, "example2.com", false)

		if err := storage.Store(cred1); err != nil {
			t.Fatalf("Store cred1 failed: %v", err)
		}
		if err := storage.Store(cred2); err != nil {
			t.Fatalf("Store cred2 failed: %v", err)
		}

		loaded, err := storage.Load([]byte{1, 2, 3, 4})
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		if loaded.RPID != "example2.com" {
			t.Errorf("expected RPID example2.com, got %s", loaded.RPID)
		}
	})
}

func TestMemoryStorage_Load(t *testing.T) {
	t.Run("loads credential successfully", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		credID := []byte{5, 6, 7, 8}
		cred := createTestCredential(t, credID, "example.com", true)
		_ = storage.Store(cred)

		loaded, err := storage.Load(credID)
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

	t.Run("returns copy not reference", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		credID := []byte{1, 2, 3, 4}
		cred := createTestCredential(t, credID, "example.com", true)
		_ = storage.Store(cred)

		loaded1, _ := storage.Load(credID)
		loaded1.RPID = "modified.com"

		loaded2, _ := storage.Load(credID)
		if loaded2.RPID != "example.com" {
			t.Error("modifying loaded credential should not affect stored credential")
		}
	})

	t.Run("returns ErrCredentialNotFound for missing credential", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_, err := storage.Load([]byte{99, 99, 99})
		if err != ErrCredentialNotFound {
			t.Errorf("expected ErrCredentialNotFound, got %v", err)
		}
	})

	t.Run("rejects empty credential ID", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_, err := storage.Load([]byte{})
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("rejects nil credential ID", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_, err := storage.Load(nil)
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		_, err := storage.Load([]byte{1, 2, 3, 4})
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestMemoryStorage_LoadByRPID(t *testing.T) {
	t.Run("loads credentials for RPID", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		// Store credentials for different RPs
		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = storage.Store(createTestCredential(t, []byte{2}, "example.com", false))
		_ = storage.Store(createTestCredential(t, []byte{3}, "other.com", true))

		creds, err := storage.LoadByRPID("example.com")
		if err != nil {
			t.Fatalf("LoadByRPID failed: %v", err)
		}
		if len(creds) != 2 {
			t.Errorf("expected 2 credentials, got %d", len(creds))
		}
	})

	t.Run("returns empty slice for unknown RPID", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", true))

		creds, err := storage.LoadByRPID("unknown.com")
		if err != nil {
			t.Fatalf("LoadByRPID failed: %v", err)
		}
		if len(creds) != 0 {
			t.Errorf("expected 0 credentials, got %d", len(creds))
		}
	})

	t.Run("rejects empty RPID", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_, err := storage.LoadByRPID("")
		if err != ErrInvalidRPIDEmpty {
			t.Errorf("expected ErrInvalidRPIDEmpty, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		_, err := storage.LoadByRPID("example.com")
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestMemoryStorage_Delete(t *testing.T) {
	t.Run("deletes credential successfully", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		credID := []byte{1, 2, 3, 4}
		_ = storage.Store(createTestCredential(t, credID, "example.com", true))

		err := storage.Delete(credID)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = storage.Load(credID)
		if err != ErrCredentialNotFound {
			t.Error("credential should not exist after deletion")
		}
	})

	t.Run("returns ErrCredentialNotFound for missing credential", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		err := storage.Delete([]byte{99, 99, 99})
		if err != ErrCredentialNotFound {
			t.Errorf("expected ErrCredentialNotFound, got %v", err)
		}
	})

	t.Run("rejects empty credential ID", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		err := storage.Delete([]byte{})
		if err != ErrInvalidCredentialID {
			t.Errorf("expected ErrInvalidCredentialID, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		err := storage.Delete([]byte{1, 2, 3, 4})
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestMemoryStorage_Count(t *testing.T) {
	t.Run("returns correct count", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		count, err := storage.Count()
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0, got %d", count)
		}

		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = storage.Store(createTestCredential(t, []byte{2}, "example.com", false))

		count, err = storage.Count()
		if err != nil {
			t.Fatalf("Count failed: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2, got %d", count)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		_, err := storage.Count()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestMemoryStorage_CountDiscoverable(t *testing.T) {
	t.Run("returns correct discoverable count", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = storage.Store(createTestCredential(t, []byte{2}, "example.com", false))
		_ = storage.Store(createTestCredential(t, []byte{3}, "example.com", true))

		count, err := storage.CountDiscoverable()
		if err != nil {
			t.Fatalf("CountDiscoverable failed: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 discoverable, got %d", count)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		_, err := storage.CountDiscoverable()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestMemoryStorage_EnumerateDiscoverable(t *testing.T) {
	t.Run("returns all discoverable credentials", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = storage.Store(createTestCredential(t, []byte{2}, "example.com", false))
		_ = storage.Store(createTestCredential(t, []byte{3}, "other.com", true))
		_ = storage.Store(createTestCredential(t, []byte{4}, "other.com", false))

		creds, err := storage.EnumerateDiscoverable()
		if err != nil {
			t.Fatalf("EnumerateDiscoverable failed: %v", err)
		}
		if len(creds) != 2 {
			t.Errorf("expected 2 discoverable credentials, got %d", len(creds))
		}

		// Verify all returned credentials are discoverable
		for _, cred := range creds {
			if !cred.Discoverable {
				t.Error("EnumerateDiscoverable returned non-discoverable credential")
			}
		}
	})

	t.Run("returns empty slice when no discoverable credentials", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", false))
		_ = storage.Store(createTestCredential(t, []byte{2}, "example.com", false))

		creds, err := storage.EnumerateDiscoverable()
		if err != nil {
			t.Fatalf("EnumerateDiscoverable failed: %v", err)
		}
		if len(creds) != 0 {
			t.Errorf("expected 0 credentials, got %d", len(creds))
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		_, err := storage.EnumerateDiscoverable()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestMemoryStorage_Clear(t *testing.T) {
	t.Run("clears all credentials", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", true))
		_ = storage.Store(createTestCredential(t, []byte{2}, "example.com", false))
		_ = storage.Store(createTestCredential(t, []byte{3}, "other.com", true))

		count, _ := storage.Count()
		if count != 3 {
			t.Fatalf("expected 3 credentials before clear, got %d", count)
		}

		err := storage.Clear()
		if err != nil {
			t.Fatalf("Clear failed: %v", err)
		}

		count, _ = storage.Count()
		if count != 0 {
			t.Errorf("expected 0 credentials after clear, got %d", count)
		}
	})

	t.Run("preserves state after clear", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		state := createTestState(t)
		state.PINSet = true
		_ = storage.SaveState(state)

		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", true))

		err := storage.Clear()
		if err != nil {
			t.Fatalf("Clear failed: %v", err)
		}

		// State should still be accessible
		loadedState, err := storage.LoadState()
		if err != nil {
			t.Fatalf("LoadState after clear failed: %v", err)
		}
		if !loadedState.PINSet {
			t.Error("state should be preserved after Clear")
		}
	})

	t.Run("works on empty storage", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		err := storage.Clear()
		if err != nil {
			t.Fatalf("Clear on empty storage failed: %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		err := storage.Clear()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestMemoryStorage_ListAll(t *testing.T) {
	t.Run("returns all credential IDs", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_ = storage.Store(createTestCredential(t, []byte{1, 2, 3}, "example.com", true))
		_ = storage.Store(createTestCredential(t, []byte{4, 5, 6}, "example.com", false))
		_ = storage.Store(createTestCredential(t, []byte{7, 8, 9}, "other.com", true))

		ids, err := storage.ListAll()
		if err != nil {
			t.Fatalf("ListAll failed: %v", err)
		}
		if len(ids) != 3 {
			t.Errorf("expected 3 IDs, got %d", len(ids))
		}

		// Verify all expected IDs are present
		expectedIDs := [][]byte{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}
		for _, expected := range expectedIDs {
			found := false
			for _, id := range ids {
				if bytes.Equal(id, expected) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected ID %v not found in ListAll result", expected)
			}
		}
	})

	t.Run("returns empty slice for empty storage", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		ids, err := storage.ListAll()
		if err != nil {
			t.Fatalf("ListAll failed: %v", err)
		}
		if len(ids) != 0 {
			t.Errorf("expected 0 IDs, got %d", len(ids))
		}
	})

	t.Run("returns copies of credential IDs", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_ = storage.Store(createTestCredential(t, []byte{1, 2, 3, 4}, "example.com", true))

		ids1, _ := storage.ListAll()
		ids1[0][0] = 99 // Modify the returned ID

		ids2, _ := storage.ListAll()
		if ids2[0][0] == 99 {
			t.Error("ListAll should return copies, not references")
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		_, err := storage.ListAll()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})
}

func TestMemoryStorage_SaveState(t *testing.T) {
	t.Run("saves state successfully", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		state := createTestState(t)

		err := storage.SaveState(state)
		if err != nil {
			t.Fatalf("SaveState failed: %v", err)
		}

		if storage.state == nil {
			t.Error("state should be saved")
		}
	})

	t.Run("rejects nil state", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		err := storage.SaveState(nil)
		if err != ErrInvalidParameter {
			t.Errorf("expected ErrInvalidParameter, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		state := createTestState(t)

		err := storage.SaveState(state)
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})

	t.Run("stores copy not reference", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		state := createTestState(t)
		originalPINSet := state.PINSet
		_ = storage.SaveState(state)

		// Modify original
		state.PINSet = !originalPINSet

		// Load and verify
		loaded, _ := storage.LoadState()
		if loaded.PINSet != originalPINSet {
			t.Error("modifying original state should not affect stored state")
		}
	})
}

func TestMemoryStorage_LoadState(t *testing.T) {
	t.Run("loads state successfully", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		state := createTestState(t)
		state.AAGUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		state.PINSet = true
		state.SetPINRetries(5)
		_ = storage.SaveState(state)

		loaded, err := storage.LoadState()
		if err != nil {
			t.Fatalf("LoadState failed: %v", err)
		}
		if loaded.AAGUID != state.AAGUID {
			t.Error("AAGUID mismatch")
		}
		if loaded.PINSet != true {
			t.Error("PINSet mismatch")
		}
		if loaded.PINRetries() != 5 {
			t.Errorf("expected PIN retries 5, got %d", loaded.PINRetries())
		}
	})

	t.Run("returns ErrStateNotFound when no state saved", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		_, err := storage.LoadState()
		if err != ErrStateNotFound {
			t.Errorf("expected ErrStateNotFound, got %v", err)
		}
	})

	t.Run("fails when storage is closed", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Close()

		_, err := storage.LoadState()
		if err != ErrStorageClosed {
			t.Errorf("expected ErrStorageClosed, got %v", err)
		}
	})

	t.Run("returns copy not reference", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		state := createTestState(t)
		state.PINSet = true
		_ = storage.SaveState(state)

		loaded1, _ := storage.LoadState()
		loaded1.PINSet = false

		loaded2, _ := storage.LoadState()
		if loaded2.PINSet != true {
			t.Error("modifying loaded state should not affect stored state")
		}
	})

	t.Run("preserves attestation key", func(t *testing.T) {
		storage := NewMemoryStorage()
		defer func() { _ = storage.Close() }()

		state := createTestState(t)
		_ = storage.SaveState(state)

		loaded, err := storage.LoadState()
		if err != nil {
			t.Fatalf("LoadState failed: %v", err)
		}
		if loaded.AttestationKey == nil {
			t.Error("attestation key should be preserved")
		}
		// Verify it's a valid key by using it
		if loaded.AttestationKey.X == nil {
			t.Error("attestation key should have valid public key")
		}
	})
}

func TestMemoryStorage_Close(t *testing.T) {
	t.Run("closes successfully", func(t *testing.T) {
		storage := NewMemoryStorage()
		_ = storage.Store(createTestCredential(t, []byte{1}, "example.com", true))

		err := storage.Close()
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		if !storage.closed {
			t.Error("storage should be marked closed")
		}
		if storage.credentials != nil {
			t.Error("credentials should be cleared")
		}
	})

	t.Run("is idempotent", func(t *testing.T) {
		storage := NewMemoryStorage()

		err1 := storage.Close()
		err2 := storage.Close()
		err3 := storage.Close()

		if err1 != nil || err2 != nil || err3 != nil {
			t.Error("Close should be idempotent and return nil")
		}
	})
}

func TestMemoryStorage_CopyCredential(t *testing.T) {
	t.Run("creates deep copy of all fields", func(t *testing.T) {
		storage := NewMemoryStorage()

		original := &StoredCredential{
			CredentialID:    []byte{1, 2, 3, 4},
			RPID:            "example.com",
			RPName:          "Example",
			UserID:          []byte{5, 6, 7, 8},
			UserName:        "user@example.com",
			UserDisplayName: "Test User",
			PrivateKey:      []byte{9, 10, 11, 12},
			PublicKeyCOSE:   []byte{13, 14, 15, 16},
			Algorithm:       COSEAlgES256,
			SignCount:       42,
			Discoverable:    true,
			HMACSecretKey:   []byte{17, 18, 19, 20},
			CreatedAt:       time.Now().Unix(),
		}

		copied := storage.copyCredential(original)

		// Verify all fields are copied
		if !bytes.Equal(copied.CredentialID, original.CredentialID) {
			t.Error("CredentialID not copied")
		}
		if !bytes.Equal(copied.UserID, original.UserID) {
			t.Error("UserID not copied")
		}
		if !bytes.Equal(copied.PrivateKey, original.PrivateKey) {
			t.Error("PrivateKey not copied")
		}
		if !bytes.Equal(copied.PublicKeyCOSE, original.PublicKeyCOSE) {
			t.Error("PublicKeyCOSE not copied")
		}
		if !bytes.Equal(copied.HMACSecretKey, original.HMACSecretKey) {
			t.Error("HMACSecretKey not copied")
		}

		// Modify original and verify copy is unchanged
		original.CredentialID[0] = 99
		original.RPID = "modified.com"

		if copied.CredentialID[0] == 99 {
			t.Error("copy should be independent of original (CredentialID)")
		}
		if copied.RPID == "modified.com" {
			t.Error("copy should be independent of original (RPID)")
		}
	})

	t.Run("handles nil credential", func(t *testing.T) {
		storage := NewMemoryStorage()
		copied := storage.copyCredential(nil)
		if copied != nil {
			t.Error("copying nil should return nil")
		}
	})

	t.Run("handles empty byte slices", func(t *testing.T) {
		storage := NewMemoryStorage()

		original := &StoredCredential{
			CredentialID: []byte{1},
			RPID:         "example.com",
		}

		copied := storage.copyCredential(original)
		if copied.UserID != nil {
			t.Error("empty UserID should remain nil")
		}
		if copied.PrivateKey != nil {
			t.Error("empty PrivateKey should remain nil")
		}
	})
}

func TestCopyBytes(t *testing.T) {
	t.Run("returns nil for nil input", func(t *testing.T) {
		result := copyBytes(nil)
		if result != nil {
			t.Error("copyBytes(nil) should return nil")
		}
	})

	t.Run("returns nil for empty slice", func(t *testing.T) {
		result := copyBytes([]byte{})
		if result != nil {
			t.Error("copyBytes(empty) should return nil")
		}
	})

	t.Run("creates independent copy of non-empty slice", func(t *testing.T) {
		original := []byte{1, 2, 3, 4, 5}
		copied := copyBytes(original)

		if !bytes.Equal(copied, original) {
			t.Error("copied bytes should match original")
		}

		// Modify original and verify copy is unchanged
		original[0] = 99
		if copied[0] == 99 {
			t.Error("copy should be independent of original")
		}
	})

	t.Run("preserves exact length", func(t *testing.T) {
		original := []byte{10, 20, 30}
		copied := copyBytes(original)

		if len(copied) != len(original) {
			t.Errorf("expected length %d, got %d", len(original), len(copied))
		}
	})
}

func TestCopyState(t *testing.T) {
	t.Run("returns nil for nil state", func(t *testing.T) {
		storage := NewMemoryStorage()
		result := storage.copyState(nil)
		if result != nil {
			t.Error("copyState(nil) should return nil")
		}
	})

	t.Run("copies basic fields", func(t *testing.T) {
		storage := NewMemoryStorage()
		original := createTestState(t)
		original.AAGUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		original.PINSet = true
		original.SetPINRetries(5)
		original.SetUVRetries(2)
		original.PINHash = []byte{10, 20, 30, 40}
		original.AttestationCert = []byte{50, 60, 70, 80}

		copied := storage.copyState(original)

		if copied.AAGUID != original.AAGUID {
			t.Error("AAGUID not copied")
		}
		if copied.PINSet != original.PINSet {
			t.Error("PINSet not copied")
		}
		if copied.PINRetries() != 5 {
			t.Errorf("PINRetries not copied: expected 5, got %d", copied.PINRetries())
		}
		if copied.UVRetries() != 2 {
			t.Errorf("UVRetries not copied: expected 2, got %d", copied.UVRetries())
		}
		if !bytes.Equal(copied.PINHash, original.PINHash) {
			t.Error("PINHash not copied")
		}
		if !bytes.Equal(copied.AttestationCert, original.AttestationCert) {
			t.Error("AttestationCert not copied")
		}
	})

	t.Run("creates deep copy of byte slices", func(t *testing.T) {
		storage := NewMemoryStorage()
		original := createTestState(t)
		original.PINHash = []byte{1, 2, 3, 4}
		original.AttestationCert = []byte{5, 6, 7, 8}

		copied := storage.copyState(original)

		// Modify original
		original.PINHash[0] = 99
		original.AttestationCert[0] = 99

		if copied.PINHash[0] == 99 {
			t.Error("PINHash should be independent copy")
		}
		if copied.AttestationCert[0] == 99 {
			t.Error("AttestationCert should be independent copy")
		}
	})

	t.Run("copies attestation key", func(t *testing.T) {
		storage := NewMemoryStorage()
		original := createTestState(t)

		copied := storage.copyState(original)

		if copied.AttestationKey == nil {
			t.Error("AttestationKey should be copied")
		}
		// Verify it's a valid copy by checking the public key coordinates
		if copied.AttestationKey.X.Cmp(original.AttestationKey.X) != 0 {
			t.Error("AttestationKey X coordinate mismatch")
		}
		if copied.AttestationKey.Y.Cmp(original.AttestationKey.Y) != 0 {
			t.Error("AttestationKey Y coordinate mismatch")
		}
	})

	t.Run("handles state without attestation key", func(t *testing.T) {
		storage := NewMemoryStorage()
		original := NewAuthenticatorState()
		original.PINSet = true

		copied := storage.copyState(original)

		if copied.AttestationKey != nil {
			t.Error("AttestationKey should be nil when original has no key")
		}
		if !copied.PINSet {
			t.Error("PINSet should be copied")
		}
	})

	t.Run("handles empty byte slices", func(t *testing.T) {
		storage := NewMemoryStorage()
		original := NewAuthenticatorState()

		copied := storage.copyState(original)

		if copied.PINHash != nil {
			t.Error("empty PINHash should remain nil")
		}
		if copied.AttestationCert != nil {
			t.Error("empty AttestationCert should remain nil")
		}
	})
}

func TestStateToSerializable(t *testing.T) {
	t.Run("converts state successfully", func(t *testing.T) {
		state := createTestState(t)
		state.AAGUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		state.PINHash = []byte{1, 2, 3, 4}
		state.PINSet = true
		state.SetPINRetries(5)
		state.SetUVRetries(2)
		state.AttestationCert = []byte{5, 6, 7, 8}

		serializable, err := stateToSerializable(state)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		if serializable.AAGUID != state.AAGUID {
			t.Error("AAGUID mismatch")
		}
		if !bytes.Equal(serializable.PINHash, state.PINHash) {
			t.Error("PINHash mismatch")
		}
		if serializable.PINSet != state.PINSet {
			t.Error("PINSet mismatch")
		}
		if serializable.PINRetries != 5 {
			t.Error("PINRetries mismatch")
		}
		if serializable.UVRetries != 2 {
			t.Error("UVRetries mismatch")
		}
		if len(serializable.AttestationKeyPKCS8) == 0 {
			t.Error("AttestationKeyPKCS8 should be populated")
		}
		if !bytes.Equal(serializable.AttestationCert, state.AttestationCert) {
			t.Error("AttestationCert mismatch")
		}
	})

	t.Run("rejects nil state", func(t *testing.T) {
		_, err := stateToSerializable(nil)
		if err != ErrInvalidParameter {
			t.Errorf("expected ErrInvalidParameter, got %v", err)
		}
	})

	t.Run("handles state without attestation key", func(t *testing.T) {
		state := NewAuthenticatorState()

		serializable, err := stateToSerializable(state)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		if serializable.AttestationKeyPKCS8 != nil {
			t.Error("AttestationKeyPKCS8 should be nil for state without key")
		}
	})

	t.Run("serializes SO PIN manager fields", func(t *testing.T) {
		state := createTestState(t)
		state.SOPINManager = NewSOPINManager()
		state.SOPINManager.IsSet = true
		state.SOPINManager.SetRetries(7)
		state.SOPINManager.Iterations = 4
		state.SOPINManager.Memory = 65536
		state.SOPINManager.Parallelism = 2
		state.SOPINManager.Salt = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		serializable, err := stateToSerializable(state)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		if !serializable.SOPINSet {
			t.Error("SOPINSet should be true")
		}
		if serializable.SOPINRetries != 7 {
			t.Errorf("SOPINRetries mismatch: expected 7, got %d", serializable.SOPINRetries)
		}
		if serializable.SOPINIterations != 4 {
			t.Errorf("SOPINIterations mismatch: expected 4, got %d", serializable.SOPINIterations)
		}
		if serializable.SOPINMemory != 65536 {
			t.Errorf("SOPINMemory mismatch: expected 65536, got %d", serializable.SOPINMemory)
		}
		if serializable.SOPINParallelism != 2 {
			t.Errorf("SOPINParallelism mismatch: expected 2, got %d", serializable.SOPINParallelism)
		}
		if !bytes.Equal(serializable.SOPINSalt, state.SOPINManager.Salt) {
			t.Error("SOPINSalt mismatch")
		}
	})

	t.Run("serializes wrapped key fields", func(t *testing.T) {
		state := createTestState(t)
		state.WrappedAK = []byte{1, 2, 3, 4}
		state.WrappedCMKUser = []byte{5, 6, 7, 8}
		state.WrappedCMKSO = []byte{9, 10, 11, 12}
		state.WrappedAttestUser = []byte{13, 14, 15, 16}
		state.WrappedAttestSO = []byte{17, 18, 19, 20}
		state.AttestedConfigHash = []byte{21, 22, 23, 24}

		serializable, err := stateToSerializable(state)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		if !bytes.Equal(serializable.WrappedAK, state.WrappedAK) {
			t.Error("WrappedAK mismatch")
		}
		if !bytes.Equal(serializable.WrappedCMKUser, state.WrappedCMKUser) {
			t.Error("WrappedCMKUser mismatch")
		}
		if !bytes.Equal(serializable.WrappedCMKSO, state.WrappedCMKSO) {
			t.Error("WrappedCMKSO mismatch")
		}
		if !bytes.Equal(serializable.WrappedAttestUser, state.WrappedAttestUser) {
			t.Error("WrappedAttestUser mismatch")
		}
		if !bytes.Equal(serializable.WrappedAttestSO, state.WrappedAttestSO) {
			t.Error("WrappedAttestSO mismatch")
		}
		if !bytes.Equal(serializable.AttestedConfigHash, state.AttestedConfigHash) {
			t.Error("AttestedConfigHash mismatch")
		}
	})

	t.Run("skips attestation key serialization when WrappedAttestSO is set", func(t *testing.T) {
		state := createTestState(t)
		state.WrappedAttestSO = []byte{1, 2, 3, 4, 5, 6, 7, 8}

		serializable, err := stateToSerializable(state)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		// AttestationKeyPKCS8 should be empty when WrappedAttestSO is set
		if len(serializable.AttestationKeyPKCS8) != 0 {
			t.Error("AttestationKeyPKCS8 should be empty when WrappedAttestSO is set")
		}
		if !bytes.Equal(serializable.WrappedAttestSO, state.WrappedAttestSO) {
			t.Error("WrappedAttestSO should be copied")
		}
	})

	t.Run("handles nil SO PIN manager", func(t *testing.T) {
		state := createTestState(t)
		state.SOPINManager = nil

		serializable, err := stateToSerializable(state)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		if serializable.SOPINSet {
			t.Error("SOPINSet should be false for nil SOPINManager")
		}
		if serializable.SOPINSalt != nil {
			t.Error("SOPINSalt should be nil for nil SOPINManager")
		}
	})

	t.Run("creates independent copies of byte slices", func(t *testing.T) {
		state := createTestState(t)
		state.PINHash = []byte{1, 2, 3, 4}
		state.AttestationCert = []byte{5, 6, 7, 8}
		state.WrappedAK = []byte{9, 10, 11, 12}

		serializable, err := stateToSerializable(state)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		// Modify original
		state.PINHash[0] = 99
		state.AttestationCert[0] = 99
		state.WrappedAK[0] = 99

		if serializable.PINHash[0] == 99 {
			t.Error("PINHash should be independent copy")
		}
		if serializable.AttestationCert[0] == 99 {
			t.Error("AttestationCert should be independent copy")
		}
		if serializable.WrappedAK[0] == 99 {
			t.Error("WrappedAK should be independent copy")
		}
	})
}

func TestSerializableToState(t *testing.T) {
	t.Run("converts serializable successfully", func(t *testing.T) {
		// First convert a state to serializable
		original := createTestState(t)
		original.PINHash = []byte{1, 2, 3, 4}
		original.PINSet = true
		original.SetPINRetries(5)
		original.SetUVRetries(2)
		original.AttestationCert = []byte{5, 6, 7, 8}

		serializable, _ := stateToSerializable(original)

		// Then convert back
		state, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		if state.AAGUID != original.AAGUID {
			t.Error("AAGUID mismatch")
		}
		if !bytes.Equal(state.PINHash, original.PINHash) {
			t.Error("PINHash mismatch")
		}
		if state.PINSet != original.PINSet {
			t.Error("PINSet mismatch")
		}
		if state.PINRetries() != 5 {
			t.Error("PINRetries mismatch")
		}
		if state.UVRetries() != 2 {
			t.Error("UVRetries mismatch")
		}
		if state.AttestationKey == nil {
			t.Error("AttestationKey should be restored")
		}
		if !bytes.Equal(state.AttestationCert, original.AttestationCert) {
			t.Error("AttestationCert mismatch")
		}
	})

	t.Run("rejects nil serializable", func(t *testing.T) {
		_, err := serializableToState(nil)
		if err != ErrInvalidParameter {
			t.Errorf("expected ErrInvalidParameter, got %v", err)
		}
	})

	t.Run("returns error for invalid PKCS8 key", func(t *testing.T) {
		serializable := &SerializableState{
			AttestationKeyPKCS8: []byte{1, 2, 3, 4}, // Invalid PKCS8 data
		}

		_, err := serializableToState(serializable)
		if err != ErrDeserializationFailed {
			t.Errorf("expected ErrDeserializationFailed, got %v", err)
		}
	})

	t.Run("returns error for non-ECDSA key", func(t *testing.T) {
		// Generate an RSA key and serialize it as PKCS8
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("failed to marshal RSA key: %v", err)
		}

		serializable := &SerializableState{
			AttestationKeyPKCS8: pkcs8Bytes,
		}

		_, err = serializableToState(serializable)
		if err != ErrDeserializationFailed {
			t.Errorf("expected ErrDeserializationFailed for non-ECDSA key, got %v", err)
		}
	})

	t.Run("deserializes SO PIN manager fields", func(t *testing.T) {
		serializable := &SerializableState{
			SOPINSet:         true,
			SOPINRetries:     7,
			SOPINIterations:  4,
			SOPINMemory:      65536,
			SOPINParallelism: 2,
			SOPINSalt:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		}

		state, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		if state.SOPINManager == nil {
			t.Fatal("SOPINManager should be created")
		}
		if !state.SOPINManager.IsSet {
			t.Error("IsSet should be true")
		}
		if state.SOPINManager.Retries() != 7 {
			t.Errorf("Retries mismatch: expected 7, got %d", state.SOPINManager.Retries())
		}
		if state.SOPINManager.Iterations != 4 {
			t.Errorf("Iterations mismatch: expected 4, got %d", state.SOPINManager.Iterations)
		}
		if state.SOPINManager.Memory != 65536 {
			t.Errorf("Memory mismatch: expected 65536, got %d", state.SOPINManager.Memory)
		}
		if state.SOPINManager.Parallelism != 2 {
			t.Errorf("Parallelism mismatch: expected 2, got %d", state.SOPINManager.Parallelism)
		}
		if !bytes.Equal(state.SOPINManager.Salt, serializable.SOPINSalt) {
			t.Error("Salt mismatch")
		}
	})

	t.Run("creates SO PIN manager when salt is present but SOPINSet is false", func(t *testing.T) {
		serializable := &SerializableState{
			SOPINSet:  false,
			SOPINSalt: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		}

		state, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		if state.SOPINManager == nil {
			t.Error("SOPINManager should be created when salt is present")
		}
	})

	t.Run("deserializes wrapped key fields", func(t *testing.T) {
		serializable := &SerializableState{
			WrappedAK:          []byte{1, 2, 3, 4},
			WrappedCMKUser:     []byte{5, 6, 7, 8},
			WrappedCMKSO:       []byte{9, 10, 11, 12},
			WrappedAttestUser:  []byte{13, 14, 15, 16},
			WrappedAttestSO:    []byte{17, 18, 19, 20},
			AttestedConfigHash: []byte{21, 22, 23, 24},
		}

		state, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		if !bytes.Equal(state.WrappedAK, serializable.WrappedAK) {
			t.Error("WrappedAK mismatch")
		}
		if !bytes.Equal(state.WrappedCMKUser, serializable.WrappedCMKUser) {
			t.Error("WrappedCMKUser mismatch")
		}
		if !bytes.Equal(state.WrappedCMKSO, serializable.WrappedCMKSO) {
			t.Error("WrappedCMKSO mismatch")
		}
		if !bytes.Equal(state.WrappedAttestUser, serializable.WrappedAttestUser) {
			t.Error("WrappedAttestUser mismatch")
		}
		if !bytes.Equal(state.WrappedAttestSO, serializable.WrappedAttestSO) {
			t.Error("WrappedAttestSO mismatch")
		}
		if !bytes.Equal(state.AttestedConfigHash, serializable.AttestedConfigHash) {
			t.Error("AttestedConfigHash mismatch")
		}
	})

	t.Run("skips attestation key deserialization when WrappedAttestSO is set", func(t *testing.T) {
		// Create a valid ECDSA key in PKCS8 format
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("failed to marshal key: %v", err)
		}

		serializable := &SerializableState{
			AttestationKeyPKCS8: pkcs8Bytes,
			WrappedAttestSO:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
		}

		state, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		// AttestationKey should be nil because WrappedAttestSO is set
		if state.AttestationKey != nil {
			t.Error("AttestationKey should be nil when WrappedAttestSO is set")
		}
		if !bytes.Equal(state.WrappedAttestSO, serializable.WrappedAttestSO) {
			t.Error("WrappedAttestSO should be copied")
		}
	})

	t.Run("creates independent copies of byte slices", func(t *testing.T) {
		serializable := &SerializableState{
			PINHash:         []byte{1, 2, 3, 4},
			AttestationCert: []byte{5, 6, 7, 8},
			WrappedAK:       []byte{9, 10, 11, 12},
		}

		state, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		// Modify serializable
		serializable.PINHash[0] = 99
		serializable.AttestationCert[0] = 99
		serializable.WrappedAK[0] = 99

		if state.PINHash[0] == 99 {
			t.Error("PINHash should be independent copy")
		}
		if state.AttestationCert[0] == 99 {
			t.Error("AttestationCert should be independent copy")
		}
		if state.WrappedAK[0] == 99 {
			t.Error("WrappedAK should be independent copy")
		}
	})

	t.Run("uses default values for zero Argon2id parameters", func(t *testing.T) {
		serializable := &SerializableState{
			SOPINSet:         true,
			SOPINSalt:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			SOPINIterations:  0, // Zero should keep default
			SOPINMemory:      0, // Zero should keep default
			SOPINParallelism: 0, // Zero should keep default
		}

		state, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		// Defaults from NewSOPINManager should be preserved
		if state.SOPINManager.Iterations == 0 {
			t.Error("Iterations should use default, not zero")
		}
		if state.SOPINManager.Memory == 0 {
			t.Error("Memory should use default, not zero")
		}
		if state.SOPINManager.Parallelism == 0 {
			t.Error("Parallelism should use default, not zero")
		}
	})

	t.Run("handles state without SO PIN manager", func(t *testing.T) {
		serializable := &SerializableState{
			SOPINSet:  false,
			SOPINSalt: nil,
		}

		state, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		if state.SOPINManager != nil {
			t.Error("SOPINManager should be nil when not set")
		}
	})
}

func TestSerializationRoundTrip(t *testing.T) {
	t.Run("full state round trip with SO PIN", func(t *testing.T) {
		original := createTestState(t)
		original.AAGUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		original.PINHash = []byte{10, 20, 30, 40}
		original.PINSet = true
		original.SetPINRetries(5)
		original.SetUVRetries(2)
		original.AttestationCert = []byte{50, 60, 70, 80}

		// Set up SO PIN manager
		original.SOPINManager = NewSOPINManager()
		original.SOPINManager.IsSet = true
		original.SOPINManager.SetRetries(7)
		original.SOPINManager.Iterations = 4
		original.SOPINManager.Memory = 65536
		original.SOPINManager.Parallelism = 2
		original.SOPINManager.Salt = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		// Serialize
		serializable, err := stateToSerializable(original)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		// Deserialize
		restored, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		// Verify all fields
		if restored.AAGUID != original.AAGUID {
			t.Error("AAGUID round trip failed")
		}
		if !bytes.Equal(restored.PINHash, original.PINHash) {
			t.Error("PINHash round trip failed")
		}
		if restored.PINSet != original.PINSet {
			t.Error("PINSet round trip failed")
		}
		if restored.PINRetries() != original.PINRetries() {
			t.Error("PINRetries round trip failed")
		}
		if restored.UVRetries() != original.UVRetries() {
			t.Error("UVRetries round trip failed")
		}
		if !bytes.Equal(restored.AttestationCert, original.AttestationCert) {
			t.Error("AttestationCert round trip failed")
		}

		// Verify SO PIN manager
		if restored.SOPINManager == nil {
			t.Fatal("SOPINManager round trip failed - nil")
		}
		if restored.SOPINManager.IsSet != original.SOPINManager.IsSet {
			t.Error("SOPINManager.IsSet round trip failed")
		}
		if restored.SOPINManager.Retries() != original.SOPINManager.Retries() {
			t.Error("SOPINManager.Retries round trip failed")
		}
		if restored.SOPINManager.Iterations != original.SOPINManager.Iterations {
			t.Error("SOPINManager.Iterations round trip failed")
		}
		if restored.SOPINManager.Memory != original.SOPINManager.Memory {
			t.Error("SOPINManager.Memory round trip failed")
		}
		if restored.SOPINManager.Parallelism != original.SOPINManager.Parallelism {
			t.Error("SOPINManager.Parallelism round trip failed")
		}
		if !bytes.Equal(restored.SOPINManager.Salt, original.SOPINManager.Salt) {
			t.Error("SOPINManager.Salt round trip failed")
		}

		// Verify attestation key
		if restored.AttestationKey == nil {
			t.Error("AttestationKey round trip failed - nil")
		} else {
			if restored.AttestationKey.X.Cmp(original.AttestationKey.X) != 0 {
				t.Error("AttestationKey.X round trip failed")
			}
			if restored.AttestationKey.Y.Cmp(original.AttestationKey.Y) != 0 {
				t.Error("AttestationKey.Y round trip failed")
			}
		}
	})

	t.Run("full state round trip with wrapped keys", func(t *testing.T) {
		original := NewAuthenticatorState()
		original.AAGUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		original.PINHash = []byte{10, 20, 30, 40}
		original.PINSet = true
		original.AttestationCert = []byte{50, 60, 70, 80}

		// Set wrapped keys (simulating SO PIN protected state)
		original.WrappedAK = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		original.WrappedCMKUser = []byte{21, 22, 23, 24, 25, 26, 27, 28}
		original.WrappedCMKSO = []byte{31, 32, 33, 34, 35, 36, 37, 38}
		original.WrappedAttestUser = []byte{41, 42, 43, 44, 45, 46, 47, 48}
		original.WrappedAttestSO = []byte{51, 52, 53, 54, 55, 56, 57, 58}
		original.AttestedConfigHash = []byte{61, 62, 63, 64}

		// Serialize
		serializable, err := stateToSerializable(original)
		if err != nil {
			t.Fatalf("stateToSerializable failed: %v", err)
		}

		// Deserialize
		restored, err := serializableToState(serializable)
		if err != nil {
			t.Fatalf("serializableToState failed: %v", err)
		}

		// Verify wrapped keys
		if !bytes.Equal(restored.WrappedAK, original.WrappedAK) {
			t.Error("WrappedAK round trip failed")
		}
		if !bytes.Equal(restored.WrappedCMKUser, original.WrappedCMKUser) {
			t.Error("WrappedCMKUser round trip failed")
		}
		if !bytes.Equal(restored.WrappedCMKSO, original.WrappedCMKSO) {
			t.Error("WrappedCMKSO round trip failed")
		}
		if !bytes.Equal(restored.WrappedAttestUser, original.WrappedAttestUser) {
			t.Error("WrappedAttestUser round trip failed")
		}
		if !bytes.Equal(restored.WrappedAttestSO, original.WrappedAttestSO) {
			t.Error("WrappedAttestSO round trip failed")
		}
		if !bytes.Equal(restored.AttestedConfigHash, original.AttestedConfigHash) {
			t.Error("AttestedConfigHash round trip failed")
		}
	})
}

// Helper functions

func createTestCredential(t *testing.T, id []byte, rpID string, discoverable bool) *StoredCredential {
	t.Helper()
	return &StoredCredential{
		CredentialID:    id,
		RPID:            rpID,
		RPName:          "Test RP",
		UserID:          []byte("user-123"),
		UserName:        "testuser",
		UserDisplayName: "Test User",
		PrivateKey:      []byte{1, 2, 3, 4, 5, 6, 7, 8},
		PublicKeyCOSE:   []byte{9, 10, 11, 12, 13, 14, 15, 16},
		Algorithm:       COSEAlgES256,
		SignCount:       0,
		Discoverable:    discoverable,
		HMACSecretKey:   make([]byte, 32),
		CreatedAt:       time.Now().Unix(),
	}
}

func createTestState(t *testing.T) *AuthenticatorState {
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
