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
