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

package webauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func TestBackendUserStore_CreateGetSaveDelete(t *testing.T) {
	ctx := context.Background()
	store := NewBackendUserStore(storage.NewMemory())

	u, err := store.Create(ctx, "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Duplicate create is rejected.
	if _, err := store.Create(ctx, "alice@example.com", "Alice"); !errors.Is(err, ErrUserAlreadyExists) {
		t.Fatalf("duplicate Create = %v, want ErrUserAlreadyExists", err)
	}

	// GetByID + GetByEmail resolve to the same user.
	byID, err := store.GetByID(ctx, u.WebAuthnID())
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	byEmail, err := store.GetByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if !bytes.Equal(byID.WebAuthnID(), byEmail.WebAuthnID()) {
		t.Fatalf("GetByID/GetByEmail mismatch")
	}
	if byID.Email() != "alice@example.com" {
		t.Fatalf("Email = %q, want alice@example.com", byID.Email())
	}

	// Save persists credential + session changes.
	du := byID.(*DefaultUser)
	du.SetSessionData([]byte("session-blob"))
	du.AddCredential(&Credential{ID: []byte{1, 2, 3}, UserID: du.WebAuthnID()})
	if err := store.Save(ctx, du); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := store.GetByID(ctx, u.WebAuthnID())
	if err != nil {
		t.Fatalf("GetByID after Save: %v", err)
	}
	rdu := reloaded.(*DefaultUser)
	if string(rdu.SessionData()) != "session-blob" {
		t.Fatalf("SessionData = %q, want session-blob", rdu.SessionData())
	}
	if len(rdu.Credentials()) != 1 {
		t.Fatalf("Credentials = %d, want 1", len(rdu.Credentials()))
	}

	// Delete removes both the user and its email index.
	if err := store.Delete(ctx, u.WebAuthnID()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.GetByID(ctx, u.WebAuthnID()); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByID after Delete = %v, want ErrUserNotFound", err)
	}
	if _, err := store.GetByEmail(ctx, "alice@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByEmail after Delete = %v, want ErrUserNotFound", err)
	}
}

// TestBackendUserStore_SurvivesNewInstance is the durability guard: a user
// created via one store is visible to a fresh store over the same backend
// (modeling a restart). Memory stores lost this on restart.
func TestBackendUserStore_SurvivesNewInstance(t *testing.T) {
	ctx := context.Background()
	backend := storage.NewMemory()

	u, err := NewBackendUserStore(backend).Create(ctx, "bob@example.com", "Bob")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := NewBackendUserStore(backend).GetByID(ctx, u.WebAuthnID())
	if err != nil {
		t.Fatalf("GetByID on fresh store: %v", err)
	}
	if got.Email() != "bob@example.com" {
		t.Fatalf("user did not survive a fresh store instance")
	}
}

func TestBackendUserStore_GetMissing(t *testing.T) {
	ctx := context.Background()
	store := NewBackendUserStore(storage.NewMemory())
	if _, err := store.GetByID(ctx, []byte("nope")); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByID(missing) = %v, want ErrUserNotFound", err)
	}
	if _, err := store.GetByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByEmail(missing) = %v, want ErrUserNotFound", err)
	}
	if err := store.Delete(ctx, []byte("nope")); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("Delete(missing) = %v, want ErrUserNotFound", err)
	}
}

func TestBackendCredentialStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewBackendCredentialStore(storage.NewMemory())
	userID := []byte{9, 9, 9}
	c1 := &Credential{ID: []byte{1}, UserID: userID}
	c2 := &Credential{ID: []byte{2}, UserID: userID}

	if err := store.Save(ctx, c1); err != nil {
		t.Fatalf("Save c1: %v", err)
	}
	if err := store.Save(ctx, c2); err != nil {
		t.Fatalf("Save c2: %v", err)
	}

	got, err := store.GetByCredentialID(ctx, []byte{1})
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if !bytes.Equal(got.ID, []byte{1}) {
		t.Fatalf("GetByCredentialID returned wrong cred")
	}

	creds, err := store.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("GetByUserID = %d creds, want 2", len(creds))
	}

	// Update requires the credential to exist.
	if err := store.Update(ctx, &Credential{ID: []byte{42}, UserID: userID}); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("Update(missing) = %v, want ErrCredentialNotFound", err)
	}
	if err := store.Update(ctx, c1); err != nil {
		t.Fatalf("Update(existing): %v", err)
	}

	// Delete one, then DeleteByUserID the rest.
	if err := store.Delete(ctx, []byte{1}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.GetByCredentialID(ctx, []byte{1}); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("GetByCredentialID after Delete = %v, want ErrCredentialNotFound", err)
	}
	if err := store.DeleteByUserID(ctx, userID); err != nil {
		t.Fatalf("DeleteByUserID: %v", err)
	}
	remaining, err := store.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByUserID after DeleteByUserID: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("GetByUserID after DeleteByUserID = %d, want 0", len(remaining))
	}
}
