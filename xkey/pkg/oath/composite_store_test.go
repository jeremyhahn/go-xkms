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

package oath

import (
	"errors"
	"testing"
)

func newCompositeTestCredential(id, name, backendID string) *Credential {
	cred := createTestCredential(id, name)
	cred.BackendID = backendID
	return cred
}

func setupCompositeStore() (*CompositeStore, *MemoryStore, *MemoryStore) {
	storeA := NewMemoryStore()
	storeB := NewMemoryStore()
	cs := NewCompositeStore("backend-a")
	cs.Register("backend-a", storeA)
	cs.Register("backend-b", storeB)
	return cs, storeA, storeB
}

func TestCompositeStore_Add_RoutesToBackendID(t *testing.T) {
	cs, storeA, storeB := setupCompositeStore()

	credA := newCompositeTestCredential("cred-a", "CredA", "backend-a")
	if err := cs.Add(credA); err != nil {
		t.Fatalf("Add to backend-a: %v", err)
	}

	credB := newCompositeTestCredential("cred-b", "CredB", "backend-b")
	if err := cs.Add(credB); err != nil {
		t.Fatalf("Add to backend-b: %v", err)
	}

	// Verify credential is in the correct underlying store.
	if _, err := storeA.Get("cred-a"); err != nil {
		t.Errorf("expected cred-a in storeA, got error: %v", err)
	}
	if _, err := storeA.Get("cred-b"); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("expected cred-b NOT in storeA, got: %v", err)
	}

	if _, err := storeB.Get("cred-b"); err != nil {
		t.Errorf("expected cred-b in storeB, got error: %v", err)
	}
	if _, err := storeB.Get("cred-a"); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("expected cred-a NOT in storeB, got: %v", err)
	}
}

func TestCompositeStore_Add_RoutesToBackendID_UnknownBackend(t *testing.T) {
	cs, _, _ := setupCompositeStore()

	cred := newCompositeTestCredential("cred-x", "CredX", "nonexistent")
	err := cs.Add(cred)
	if !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("expected ErrStoreNotFound, got: %v", err)
	}
}

func TestCompositeStore_Add_UsesDefault(t *testing.T) {
	cs, storeA, _ := setupCompositeStore()

	cred := createTestCredential("cred-default", "CredDefault")
	// BackendID is intentionally empty.
	if cred.BackendID != "" {
		t.Fatal("test setup: BackendID should be empty")
	}

	if err := cs.Add(cred); err != nil {
		t.Fatalf("Add with empty BackendID: %v", err)
	}

	// Should be in default store (backend-a).
	got, err := storeA.Get("cred-default")
	if err != nil {
		t.Fatalf("expected cred in default store: %v", err)
	}

	// BackendID must be populated after Add.
	if got.BackendID != "backend-a" {
		t.Errorf("expected BackendID 'backend-a', got %q", got.BackendID)
	}
}

func TestCompositeStore_Add_UsesDefault_NoDefaultRegistered(t *testing.T) {
	cs := NewCompositeStore("missing-default")
	cred := createTestCredential("cred-x", "CredX")
	err := cs.Add(cred)
	if !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("expected ErrStoreNotFound, got: %v", err)
	}
}

func TestCompositeStore_Get_SearchesAllStores(t *testing.T) {
	cs, _, storeB := setupCompositeStore()

	// Add credential only to storeB directly.
	cred := newCompositeTestCredential("cred-b-only", "CredBOnly", "backend-b")
	if err := storeB.Add(cred); err != nil {
		t.Fatalf("storeB.Add: %v", err)
	}

	// CompositeStore.Get should find it even though it's not in storeA.
	got, err := cs.Get("cred-b-only")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "cred-b-only" {
		t.Errorf("expected ID 'cred-b-only', got %q", got.ID)
	}
	if got.BackendID != "backend-b" {
		t.Errorf("expected BackendID 'backend-b', got %q", got.BackendID)
	}
}

func TestCompositeStore_Get_PopulatesBackendID(t *testing.T) {
	cs, storeA, _ := setupCompositeStore()

	// Add a credential with empty BackendID directly to storeA.
	cred := createTestCredential("bare-cred", "BareCred")
	if err := storeA.Add(cred); err != nil {
		t.Fatalf("storeA.Add: %v", err)
	}

	got, err := cs.Get("bare-cred")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.BackendID == "" {
		t.Error("expected BackendID to be populated, got empty string")
	}
}

func TestCompositeStore_Get_NotFound(t *testing.T) {
	cs, _, _ := setupCompositeStore()

	_, err := cs.Get("nonexistent")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestCompositeStore_List_MergesAllStores(t *testing.T) {
	cs, storeA, storeB := setupCompositeStore()

	credA := newCompositeTestCredential("cred-a1", "Alpha", "backend-a")
	credB := newCompositeTestCredential("cred-b1", "Beta", "backend-b")
	credC := newCompositeTestCredential("cred-a2", "Charlie", "backend-a")

	if err := storeA.Add(credA); err != nil {
		t.Fatal(err)
	}
	if err := storeB.Add(credB); err != nil {
		t.Fatal(err)
	}
	if err := storeA.Add(credC); err != nil {
		t.Fatal(err)
	}

	creds, err := cs.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(creds) != 3 {
		t.Fatalf("expected 3 credentials, got %d", len(creds))
	}

	// Verify sorted by name.
	expected := []string{"Alpha", "Beta", "Charlie"}
	for i, name := range expected {
		if creds[i].Name != name {
			t.Errorf("index %d: expected name %q, got %q", i, name, creds[i].Name)
		}
	}
}

func TestCompositeStore_List_SetsBackendID(t *testing.T) {
	cs, storeA, storeB := setupCompositeStore()

	// Add credentials without BackendID directly to underlying stores.
	credA := createTestCredential("cred-list-a", "ListA")
	credB := createTestCredential("cred-list-b", "ListB")

	if err := storeA.Add(credA); err != nil {
		t.Fatal(err)
	}
	if err := storeB.Add(credB); err != nil {
		t.Fatal(err)
	}

	creds, err := cs.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	for _, cred := range creds {
		if cred.BackendID == "" {
			t.Errorf("credential %q has empty BackendID", cred.ID)
		}
	}
}

func TestCompositeStore_List_EmptyStores(t *testing.T) {
	cs, _, _ := setupCompositeStore()

	creds, err := cs.List()
	if err != nil {
		t.Fatalf("List on empty stores: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}
}

func TestCompositeStore_Update_RoutesByBackendID(t *testing.T) {
	cs, _, storeB := setupCompositeStore()

	cred := newCompositeTestCredential("cred-upd", "CredUpdate", "backend-b")
	if err := storeB.Add(cred); err != nil {
		t.Fatal(err)
	}

	// Update through composite store.
	cred.Issuer = "UpdatedIssuer"
	if err := cs.Update(cred); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := storeB.Get("cred-upd")
	if err != nil {
		t.Fatalf("storeB.Get after update: %v", err)
	}
	if got.Issuer != "UpdatedIssuer" {
		t.Errorf("expected Issuer 'UpdatedIssuer', got %q", got.Issuer)
	}
}

func TestCompositeStore_Update_EmptyBackendID_FindsOwner(t *testing.T) {
	cs, _, storeB := setupCompositeStore()

	cred := newCompositeTestCredential("cred-upd2", "CredUpdate2", "backend-b")
	if err := storeB.Add(cred); err != nil {
		t.Fatal(err)
	}

	// Clear BackendID to force owner lookup.
	cred.BackendID = ""
	cred.Issuer = "FoundIssuer"
	if err := cs.Update(cred); err != nil {
		t.Fatalf("Update with empty BackendID: %v", err)
	}

	got, err := storeB.Get("cred-upd2")
	if err != nil {
		t.Fatalf("storeB.Get: %v", err)
	}
	if got.Issuer != "FoundIssuer" {
		t.Errorf("expected Issuer 'FoundIssuer', got %q", got.Issuer)
	}
}

func TestCompositeStore_Update_UnknownBackend(t *testing.T) {
	cs, _, _ := setupCompositeStore()

	cred := newCompositeTestCredential("cred-x", "CredX", "nonexistent")
	err := cs.Update(cred)
	if !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("expected ErrStoreNotFound, got: %v", err)
	}
}

func TestCompositeStore_Update_NotFound(t *testing.T) {
	cs, _, _ := setupCompositeStore()

	cred := createTestCredential("cred-missing", "Missing")
	// BackendID empty, findOwner will search and find nothing.
	err := cs.Update(cred)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestCompositeStore_Delete_SearchesAllStores(t *testing.T) {
	cs, _, storeB := setupCompositeStore()

	cred := newCompositeTestCredential("cred-del", "CredDelete", "backend-b")
	if err := storeB.Add(cred); err != nil {
		t.Fatal(err)
	}

	// Delete through composite store (will search storeA first, miss, then find in storeB).
	if err := cs.Delete("cred-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify gone from storeB.
	_, err := storeB.Get("cred-del")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("expected ErrCredentialNotFound after delete, got: %v", err)
	}
}

func TestCompositeStore_Delete_NotFound(t *testing.T) {
	cs, _, _ := setupCompositeStore()

	err := cs.Delete("nonexistent")
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestCompositeStore_Close_ClosesAll(t *testing.T) {
	cs, storeA, storeB := setupCompositeStore()

	// Add a credential to each store to verify they work before close.
	credA := newCompositeTestCredential("cred-close-a", "CloseA", "backend-a")
	credB := newCompositeTestCredential("cred-close-b", "CloseB", "backend-b")
	if err := storeA.Add(credA); err != nil {
		t.Fatal(err)
	}
	if err := storeB.Add(credB); err != nil {
		t.Fatal(err)
	}

	if err := cs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Both underlying stores should be closed.
	if err := storeA.Add(createTestCredential("post-close", "PostClose")); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("storeA should be closed, got: %v", err)
	}
	if err := storeB.Add(createTestCredential("post-close2", "PostClose2")); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("storeB should be closed, got: %v", err)
	}
}

func TestCompositeStore_Register_Unregister(t *testing.T) {
	cs := NewCompositeStore("store-1")

	store1 := NewMemoryStore()
	store2 := NewMemoryStore()

	cs.Register("store-1", store1)
	cs.Register("store-2", store2)

	// Add to store-2 through composite.
	cred := newCompositeTestCredential("reg-cred", "RegCred", "store-2")
	if err := cs.Add(cred); err != nil {
		t.Fatalf("Add before unregister: %v", err)
	}

	// Unregister store-2.
	cs.Unregister("store-2")

	// Adding to store-2 should fail.
	cred2 := newCompositeTestCredential("reg-cred2", "RegCred2", "store-2")
	err := cs.Add(cred2)
	if !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("expected ErrStoreNotFound after unregister, got: %v", err)
	}

	// store-1 should still work.
	cred3 := newCompositeTestCredential("reg-cred3", "RegCred3", "store-1")
	if err := cs.Add(cred3); err != nil {
		t.Fatalf("Add to store-1 after unregistering store-2: %v", err)
	}
}

func TestCompositeStore_SetDefault(t *testing.T) {
	cs, _, storeB := setupCompositeStore()

	// Default is "backend-a"; change it to "backend-b".
	cs.SetDefault("backend-b")

	cred := createTestCredential("cred-new-default", "CredNewDefault")
	if err := cs.Add(cred); err != nil {
		t.Fatalf("Add after SetDefault: %v", err)
	}

	got, err := storeB.Get("cred-new-default")
	if err != nil {
		t.Fatalf("expected credential in storeB after SetDefault: %v", err)
	}
	if got.BackendID != "backend-b" {
		t.Errorf("expected BackendID 'backend-b', got %q", got.BackendID)
	}
}

func TestCompositeStore_NewCompositeStore(t *testing.T) {
	cs := NewCompositeStore("default")
	if cs == nil {
		t.Fatal("expected non-nil CompositeStore")
	}
	if cs.defaultStore != "default" {
		t.Errorf("expected default store 'default', got %q", cs.defaultStore)
	}
	if len(cs.stores) != 0 {
		t.Errorf("expected empty stores map, got %d entries", len(cs.stores))
	}
}
