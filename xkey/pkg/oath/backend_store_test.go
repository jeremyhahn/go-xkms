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
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func newTestBackendStore(t *testing.T) *BackendStore {
	t.Helper()
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "oath/")
	if err != nil {
		t.Fatalf("failed to create backend store: %v", err)
	}
	return store
}

// NewBackendStore tests

func TestBackendStore_NewBackendStore_Success(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "oath/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.prefix != "oath/" {
		t.Errorf("expected prefix %q, got %q", "oath/", store.prefix)
	}
}

func TestBackendStore_NewBackendStore_EmptyPrefix(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.prefix != "" {
		t.Errorf("expected empty prefix, got %q", store.prefix)
	}
}

func TestBackendStore_NewBackendStore_NilBackend(t *testing.T) {
	_, err := NewBackendStore(nil, "oath/")
	if err == nil {
		t.Fatal("expected error for nil backend")
	}
	if err != ErrNilBackend {
		t.Errorf("expected ErrNilBackend, got %v", err)
	}
}

// Add tests

func TestBackendStore_Add_Success(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	err := store.Add(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it was stored
	retrieved, err := store.Get("test1")
	if err != nil {
		t.Fatalf("failed to retrieve added credential: %v", err)
	}
	if retrieved.ID != cred.ID {
		t.Errorf("expected ID %q, got %q", cred.ID, retrieved.ID)
	}
	if retrieved.Name != cred.Name {
		t.Errorf("expected Name %q, got %q", cred.Name, retrieved.Name)
	}
	if retrieved.Secret != cred.Secret {
		t.Errorf("expected Secret %q, got %q", cred.Secret, retrieved.Secret)
	}
}

func TestBackendStore_Add_DuplicateID(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	err := store.Add(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Attempt to add with same ID
	cred2 := createTestCredential("test1", "Different Name")
	err = store.Add(cred2)
	if err == nil {
		t.Fatal("expected error for duplicate ID")
	}
	if err != ErrDuplicateCredential {
		t.Errorf("expected ErrDuplicateCredential, got %v", err)
	}
}

func TestBackendStore_Add_DuplicateName(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred1 := createTestCredential("test1", "Test Credential")
	err := store.Add(cred1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Attempt to add with different ID but same name
	cred2 := createTestCredential("test2", "Test Credential")
	err = store.Add(cred2)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if err != ErrDuplicateCredential {
		t.Errorf("expected ErrDuplicateCredential, got %v", err)
	}
}

func TestBackendStore_Add_DuplicateNameCaseInsensitive(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred1 := createTestCredential("test1", "Test Credential")
	err := store.Add(cred1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Attempt to add with same name in different case
	cred2 := createTestCredential("test2", "TEST CREDENTIAL")
	err = store.Add(cred2)
	if err == nil {
		t.Fatal("expected error for duplicate name (case-insensitive)")
	}
	if err != ErrDuplicateCredential {
		t.Errorf("expected ErrDuplicateCredential, got %v", err)
	}
}

func TestBackendStore_Add_InvalidCredential_EmptyName(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := &Credential{
		ID:     "test1",
		Name:   "", // Invalid
		Secret: "JBSWY3DPEHPK3PXP",
		Type:   TypeTOTP,
	}

	err := store.Add(cred)
	if err == nil {
		t.Fatal("expected error for invalid credential")
	}
}

func TestBackendStore_Add_InvalidCredential_EmptySecret(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := &Credential{
		ID:        "test1",
		Name:      "Test",
		Secret:    "", // Invalid
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	err := store.Add(cred)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestBackendStore_Add_Closed(t *testing.T) {
	store := newTestBackendStore(t)
	store.Close()

	cred := createTestCredential("test1", "Test Credential")
	err := store.Add(cred)
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrBackendStoreClosed {
		t.Errorf("expected ErrBackendStoreClosed, got %v", err)
	}
}

// Get tests

func TestBackendStore_Get_ByID(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	retrieved, err := store.Get("test1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved.ID != "test1" {
		t.Errorf("expected ID %q, got %q", "test1", retrieved.ID)
	}
	if retrieved.Name != "Test Credential" {
		t.Errorf("expected Name %q, got %q", "Test Credential", retrieved.Name)
	}
}

func TestBackendStore_Get_ByName_CaseInsensitive(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Get by name (lowercase)
	retrieved, err := store.Get("test credential")
	if err != nil {
		t.Fatalf("unexpected error getting by lowercase name: %v", err)
	}
	if retrieved.ID != "test1" {
		t.Errorf("expected ID %q, got %q", "test1", retrieved.ID)
	}

	// Get by name (uppercase)
	retrieved, err = store.Get("TEST CREDENTIAL")
	if err != nil {
		t.Fatalf("unexpected error getting by uppercase name: %v", err)
	}
	if retrieved.ID != "test1" {
		t.Errorf("expected ID %q, got %q", "test1", retrieved.ID)
	}
}

func TestBackendStore_Get_ByID_CaseInsensitive(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Get by case-insensitive ID match (falls through to scan)
	retrieved, err := store.Get("TEST1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved.ID != "test1" {
		t.Errorf("expected ID %q, got %q", "test1", retrieved.ID)
	}
}

func TestBackendStore_Get_NotFound(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	_, err := store.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestBackendStore_Get_Closed(t *testing.T) {
	store := newTestBackendStore(t)
	store.Close()

	_, err := store.Get("test1")
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrBackendStoreClosed {
		t.Errorf("expected ErrBackendStoreClosed, got %v", err)
	}
}

// List tests

func TestBackendStore_List_Empty(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}
}

func TestBackendStore_List_SortedByName(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	store.Add(createTestCredential("test1", "Zebra"))
	store.Add(createTestCredential("test2", "Apple"))
	store.Add(createTestCredential("test3", "Mango"))

	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 items, got %d", len(list))
	}

	if list[0].Name != "Apple" {
		t.Errorf("expected first item %q, got %q", "Apple", list[0].Name)
	}
	if list[1].Name != "Mango" {
		t.Errorf("expected second item %q, got %q", "Mango", list[1].Name)
	}
	if list[2].Name != "Zebra" {
		t.Errorf("expected third item %q, got %q", "Zebra", list[2].Name)
	}
}

func TestBackendStore_List_PreservesAllFields(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 item, got %d", len(list))
	}

	retrieved := list[0]
	if retrieved.ID != cred.ID {
		t.Errorf("ID mismatch: expected %q, got %q", cred.ID, retrieved.ID)
	}
	if retrieved.Issuer != cred.Issuer {
		t.Errorf("Issuer mismatch: expected %q, got %q", cred.Issuer, retrieved.Issuer)
	}
	if retrieved.Secret != cred.Secret {
		t.Errorf("Secret mismatch: expected %q, got %q", cred.Secret, retrieved.Secret)
	}
	if retrieved.Type != cred.Type {
		t.Errorf("Type mismatch: expected %q, got %q", cred.Type, retrieved.Type)
	}
	if retrieved.Algorithm != cred.Algorithm {
		t.Errorf("Algorithm mismatch: expected %q, got %q", cred.Algorithm, retrieved.Algorithm)
	}
	if retrieved.Digits != cred.Digits {
		t.Errorf("Digits mismatch: expected %d, got %d", cred.Digits, retrieved.Digits)
	}
	if retrieved.Period != cred.Period {
		t.Errorf("Period mismatch: expected %d, got %d", cred.Period, retrieved.Period)
	}
}

func TestBackendStore_List_Closed(t *testing.T) {
	store := newTestBackendStore(t)
	store.Close()

	_, err := store.List()
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrBackendStoreClosed {
		t.Errorf("expected ErrBackendStoreClosed, got %v", err)
	}
}

// Update tests

func TestBackendStore_Update_Success(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Update the credential
	cred.Name = "Updated Credential"
	err := store.Update(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the update persisted
	retrieved, err := store.Get("test1")
	if err != nil {
		t.Fatalf("failed to retrieve: %v", err)
	}
	if retrieved.Name != "Updated Credential" {
		t.Errorf("expected updated name %q, got %q", "Updated Credential", retrieved.Name)
	}
}

func TestBackendStore_Update_Counter(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := &Credential{
		ID:        "hotp1",
		Name:      "HOTP Credential",
		Issuer:    "TestIssuer",
		Secret:    "JBSWY3DPEHPK3PXP",
		Type:      TypeHOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
		Counter:   0,
		CreatedAt: time.Now(),
	}
	store.Add(cred)

	// Simulate counter increment
	cred.Counter = 5
	err := store.Update(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	retrieved, err := store.Get("hotp1")
	if err != nil {
		t.Fatalf("failed to retrieve: %v", err)
	}
	if retrieved.Counter != 5 {
		t.Errorf("expected counter 5, got %d", retrieved.Counter)
	}
}

func TestBackendStore_Update_NotFound(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	err := store.Update(cred)
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestBackendStore_Update_InvalidCredential(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Make credential invalid
	cred.Name = ""
	err := store.Update(cred)
	if err == nil {
		t.Fatal("expected error for invalid credential")
	}
}

func TestBackendStore_Update_Closed(t *testing.T) {
	store := newTestBackendStore(t)
	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)
	store.Close()

	err := store.Update(cred)
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrBackendStoreClosed {
		t.Errorf("expected ErrBackendStoreClosed, got %v", err)
	}
}

// Delete tests

func TestBackendStore_Delete_ByID(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	err := store.Delete("test1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deleted
	_, err = store.Get("test1")
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound after delete, got %v", err)
	}
}

func TestBackendStore_Delete_ByName(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Delete by name (case-insensitive)
	err := store.Delete("test credential")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deleted
	_, err = store.Get("test1")
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound after delete, got %v", err)
	}
}

func TestBackendStore_Delete_ByID_CaseInsensitive(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Delete by case-insensitive ID (falls through to scan)
	err := store.Delete("TEST1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deleted
	_, err = store.Get("test1")
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound after delete, got %v", err)
	}
}

func TestBackendStore_Delete_NotFound(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	err := store.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestBackendStore_Delete_Closed(t *testing.T) {
	store := newTestBackendStore(t)
	store.Close()

	err := store.Delete("test1")
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrBackendStoreClosed {
		t.Errorf("expected ErrBackendStoreClosed, got %v", err)
	}
}

func TestBackendStore_Delete_VerifiesListAfter(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	store.Add(createTestCredential("test1", "First"))
	store.Add(createTestCredential("test2", "Second"))
	store.Add(createTestCredential("test3", "Third"))

	// Delete middle item
	err := store.Delete("test2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 items after delete, got %d", len(list))
	}

	// Verify remaining items are correct and sorted
	if list[0].Name != "First" {
		t.Errorf("expected first item %q, got %q", "First", list[0].Name)
	}
	if list[1].Name != "Third" {
		t.Errorf("expected second item %q, got %q", "Third", list[1].Name)
	}
}

// Close tests

func TestBackendStore_Close_Success(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBackendStore_Close_Idempotent(t *testing.T) {
	store := newTestBackendStore(t)

	err := store.Close()
	if err != nil {
		t.Fatalf("unexpected error on first close: %v", err)
	}

	err = store.Close()
	if err != nil {
		t.Fatalf("unexpected error on second close: %v", err)
	}
}

func TestBackendStore_Close_DoesNotCloseBackend(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "oath/")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Add a credential
	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Close the store
	store.Close()

	// Backend should still be usable by other consumers
	_, err = backend.Get(context.Background(), "oath/test1.json")
	if err != nil {
		t.Fatalf("backend should still be functional after store close: %v", err)
	}
}

// Interface compliance test

func TestBackendStore_ImplementsStoreInterface(t *testing.T) {
	store := newTestBackendStore(t)
	var _ Store = store
	testStoreInterface(t, store)
}

// Concurrency test

func TestBackendStore_Concurrency(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cred := createTestCredential(
				strings.ReplaceAll("test-concurrent-#", "#", string(rune('0'+id%10))),
				strings.ReplaceAll("Concurrent #", "#", string(rune('0'+id%10))),
			)
			cred.ID = cred.ID + string(rune('a'+id%26))
			cred.Name = cred.Name + string(rune('a'+id%26))
			store.Add(cred)
		}(i)
	}
	wg.Wait()

	// List should succeed without race conditions
	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) == 0 {
		t.Error("expected some credentials after concurrent adds")
	}
}

// Error sentinel tests

func TestBackendStore_ErrorMessages(t *testing.T) {
	errors := []error{
		ErrNilBackend,
		ErrBackendStoreClosed,
		ErrDuplicateCredential,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("expected non-empty error message for %v", err)
		}
		if !strings.HasPrefix(err.Error(), "oath:") {
			t.Errorf("expected error to start with 'oath:', got %q", err.Error())
		}
	}
}

// Multiple credentials workflow test

func TestBackendStore_Workflow(t *testing.T) {
	store := newTestBackendStore(t)
	defer store.Close()

	// Start empty
	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty store, got %d items", len(list))
	}

	// Add several credentials
	cred1 := createTestCredential("github", "GitHub")
	cred2 := createTestCredential("aws", "AWS")
	cred3 := createTestCredential("google", "Google")

	for _, cred := range []*Credential{cred1, cred2, cred3} {
		if err := store.Add(cred); err != nil {
			t.Fatalf("failed to add %s: %v", cred.Name, err)
		}
	}

	// Verify list
	list, err = store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 items, got %d", len(list))
	}

	// Update one
	cred2.Name = "Amazon Web Services"
	if err := store.Update(cred2); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	// Verify update by getting it back
	retrieved, err := store.Get("aws")
	if err != nil {
		t.Fatalf("failed to get: %v", err)
	}
	if retrieved.Name != "Amazon Web Services" {
		t.Errorf("expected updated name %q, got %q", "Amazon Web Services", retrieved.Name)
	}

	// Delete one by name
	if err := store.Delete("GitHub"); err != nil {
		t.Fatalf("failed to delete: %v", err)
	}

	// Verify deletion
	list, err = store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 items after delete, got %d", len(list))
	}

	// Verify ordering after update and delete
	if list[0].Name != "Amazon Web Services" {
		t.Errorf("expected first item %q, got %q", "Amazon Web Services", list[0].Name)
	}
	if list[1].Name != "Google" {
		t.Errorf("expected second item %q, got %q", "Google", list[1].Name)
	}
}

// Key format verification

func TestBackendStore_KeyFormat(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "oath/")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	cred := createTestCredential("my-service", "My Service")
	store.Add(cred)

	// Verify the key format in the backend directly
	exists, err := backend.Exists(context.Background(), "oath/my-service.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected credential to be stored at 'oath/my-service.json'")
	}
}

func TestBackendStore_KeyFormat_NoPrefix(t *testing.T) {
	backend := storage.NewMemory()
	store, err := NewBackendStore(backend, "")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	cred := createTestCredential("my-service", "My Service")
	store.Add(cred)

	// Verify the key format with empty prefix
	exists, err := backend.Exists(context.Background(), "my-service.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected credential to be stored at 'my-service.json'")
	}
}
