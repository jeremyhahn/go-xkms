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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func createTestCredential(id, name string) *Credential {
	return &Credential{
		ID:          id,
		Name:        name,
		Issuer:      "TestIssuer",
		AccountName: name + "@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        TypeTOTP,
		Algorithm:   AlgorithmSHA1,
		Digits:      6,
		Period:      30,
		CreatedAt:   time.Now(),
	}
}

// MemoryStore Tests

func TestMemoryStore_NewMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestMemoryStore_Add_Success(t *testing.T) {
	store := NewMemoryStore()
	cred := createTestCredential("test1", "Test Credential")

	err := store.Add(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it was added
	retrieved, err := store.Get("test1")
	if err != nil {
		t.Fatalf("failed to retrieve added credential: %v", err)
	}
	if retrieved.ID != cred.ID {
		t.Errorf("expected ID %q, got %q", cred.ID, retrieved.ID)
	}
}

func TestMemoryStore_Add_Duplicate(t *testing.T) {
	store := NewMemoryStore()
	cred := createTestCredential("test1", "Test Credential")

	err := store.Add(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try to add again
	err = store.Add(cred)
	if err == nil {
		t.Fatal("expected error for duplicate credential")
	}
	if err != ErrCredentialExists {
		t.Errorf("expected ErrCredentialExists, got %v", err)
	}
}

func TestMemoryStore_Add_InvalidCredential(t *testing.T) {
	store := NewMemoryStore()
	cred := &Credential{
		ID:     "test1",
		Name:   "", // Invalid: empty name
		Secret: "JBSWY3DPEHPK3PXP",
		Type:   TypeTOTP,
	}

	err := store.Add(cred)
	if err == nil {
		t.Fatal("expected error for invalid credential")
	}
}

func TestMemoryStore_Add_Closed(t *testing.T) {
	store := NewMemoryStore()
	store.Close()

	cred := createTestCredential("test1", "Test Credential")
	err := store.Add(cred)
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestMemoryStore_Get_Success(t *testing.T) {
	store := NewMemoryStore()
	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Get by ID
	retrieved, err := store.Get("test1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved.ID != cred.ID {
		t.Errorf("expected ID %q, got %q", cred.ID, retrieved.ID)
	}

	// Get by name (case-insensitive)
	retrieved, err = store.Get("test credential")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved.ID != cred.ID {
		t.Errorf("expected ID %q, got %q", cred.ID, retrieved.ID)
	}
}

func TestMemoryStore_Get_NotFound(t *testing.T) {
	store := NewMemoryStore()

	_, err := store.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestMemoryStore_Get_Closed(t *testing.T) {
	store := NewMemoryStore()
	store.Close()

	_, err := store.Get("test1")
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestMemoryStore_List_Success(t *testing.T) {
	store := NewMemoryStore()

	// Empty store
	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}

	// Add credentials
	store.Add(createTestCredential("test1", "Zebra"))
	store.Add(createTestCredential("test2", "Apple"))
	store.Add(createTestCredential("test3", "Mango"))

	list, err = store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 items, got %d", len(list))
	}

	// Verify sorted by name
	if list[0].Name != "Apple" {
		t.Errorf("expected first item to be 'Apple', got %q", list[0].Name)
	}
	if list[1].Name != "Mango" {
		t.Errorf("expected second item to be 'Mango', got %q", list[1].Name)
	}
	if list[2].Name != "Zebra" {
		t.Errorf("expected third item to be 'Zebra', got %q", list[2].Name)
	}
}

func TestMemoryStore_List_Closed(t *testing.T) {
	store := NewMemoryStore()
	store.Close()

	_, err := store.List()
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestMemoryStore_Update_Success(t *testing.T) {
	store := NewMemoryStore()
	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Update credential
	cred.Name = "Updated Credential"
	err := store.Update(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify update
	retrieved, err := store.Get("test1")
	if err != nil {
		t.Fatalf("failed to retrieve: %v", err)
	}
	if retrieved.Name != "Updated Credential" {
		t.Errorf("expected updated name, got %q", retrieved.Name)
	}
}

func TestMemoryStore_Update_NotFound(t *testing.T) {
	store := NewMemoryStore()
	cred := createTestCredential("test1", "Test Credential")

	err := store.Update(cred)
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestMemoryStore_Update_Closed(t *testing.T) {
	store := NewMemoryStore()
	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)
	store.Close()

	err := store.Update(cred)
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestMemoryStore_Delete_Success(t *testing.T) {
	store := NewMemoryStore()
	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Delete by ID
	err := store.Delete("test1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deleted
	_, err = store.Get("test1")
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestMemoryStore_Delete_ByName(t *testing.T) {
	store := NewMemoryStore()
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
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestMemoryStore_Delete_NotFound(t *testing.T) {
	store := NewMemoryStore()

	err := store.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestMemoryStore_Delete_Closed(t *testing.T) {
	store := NewMemoryStore()
	store.Close()

	err := store.Delete("test1")
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestMemoryStore_Close(t *testing.T) {
	store := NewMemoryStore()

	err := store.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Close again should be idempotent
	err = store.Close()
	if err != nil {
		t.Fatalf("unexpected error on second close: %v", err)
	}
}

func TestMemoryStore_Concurrency(t *testing.T) {
	store := NewMemoryStore()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
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

	// Should be able to list without race conditions
	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) == 0 {
		t.Error("expected some credentials after concurrent adds")
	}
}

// FileStore Tests

func TestFileStore_NewFileStore_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	store.Close()
}

func TestFileStore_NewFileStore_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "nested", "credentials.json")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	store.Close()

	// Verify directory was created
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("expected directory to be created")
	}
}

func TestFileStore_NewFileStore_LoadsExisting(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	// Create store and add credential
	store1, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cred := createTestCredential("test1", "Test Credential")
	store1.Add(cred)
	store1.Close()

	// Open again and verify credential exists
	store2, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer store2.Close()

	retrieved, err := store2.Get("test1")
	if err != nil {
		t.Fatalf("failed to retrieve: %v", err)
	}
	if retrieved.ID != cred.ID {
		t.Errorf("expected ID %q, got %q", cred.ID, retrieved.ID)
	}
}

func TestFileStore_Add_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	err := store.Add(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected credentials file to be created")
	}
}

func TestFileStore_Add_Duplicate(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	err := store.Add(cred)
	if err == nil {
		t.Fatal("expected error for duplicate credential")
	}
	if err != ErrCredentialExists {
		t.Errorf("expected ErrCredentialExists, got %v", err)
	}
}

func TestFileStore_Add_DuplicateName(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	cred1 := createTestCredential("test1", "Test Credential")
	store.Add(cred1)

	// Try to add with different ID but same name
	cred2 := createTestCredential("test2", "Test Credential")
	err := store.Add(cred2)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if err != ErrCredentialExists {
		t.Errorf("expected ErrCredentialExists, got %v", err)
	}
}

func TestFileStore_Add_Closed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	store.Close()

	cred := createTestCredential("test1", "Test Credential")
	err := store.Add(cred)
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestFileStore_Get_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Get by ID
	retrieved, err := store.Get("test1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved.ID != cred.ID {
		t.Errorf("expected ID %q, got %q", cred.ID, retrieved.ID)
	}

	// Get by name (case-insensitive)
	retrieved, err = store.Get("TEST CREDENTIAL")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved.ID != cred.ID {
		t.Errorf("expected ID %q, got %q", cred.ID, retrieved.ID)
	}
}

func TestFileStore_Get_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	_, err := store.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestFileStore_Get_Closed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	store.Close()

	_, err := store.Get("test1")
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestFileStore_List_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	// Empty store
	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}

	// Add credentials
	store.Add(createTestCredential("test1", "Zebra"))
	store.Add(createTestCredential("test2", "Apple"))

	list, err = store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 items, got %d", len(list))
	}

	// Verify sorted by name
	if list[0].Name != "Apple" {
		t.Errorf("expected first item to be 'Apple', got %q", list[0].Name)
	}
	if list[1].Name != "Zebra" {
		t.Errorf("expected second item to be 'Zebra', got %q", list[1].Name)
	}
}

func TestFileStore_List_Closed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	store.Close()

	_, err := store.List()
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestFileStore_Update_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Update credential
	cred.Name = "Updated Credential"
	err := store.Update(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify update persisted
	retrieved, err := store.Get("test1")
	if err != nil {
		t.Fatalf("failed to retrieve: %v", err)
	}
	if retrieved.Name != "Updated Credential" {
		t.Errorf("expected updated name, got %q", retrieved.Name)
	}
}

func TestFileStore_Update_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
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

func TestFileStore_Update_Closed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)
	store.Close()

	err := store.Update(cred)
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestFileStore_Update_InvalidCredential(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Try to update with invalid credential
	cred.Name = "" // Invalid
	err := store.Update(cred)
	if err == nil {
		t.Fatal("expected error for invalid credential")
	}
}

func TestFileStore_Delete_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
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
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestFileStore_Delete_ByName(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	err := store.Delete("test credential")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deleted
	_, err = store.Get("test1")
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestFileStore_Delete_ByID_CaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	cred := createTestCredential("test1", "Test Credential")
	store.Add(cred)

	// Delete by lowercase ID match
	err := store.Delete("TEST1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify deleted
	_, err = store.Get("test1")
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestFileStore_Delete_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	defer store.Close()

	err := store.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
	if err != ErrCredentialNotFound {
		t.Errorf("expected ErrCredentialNotFound, got %v", err)
	}
}

func TestFileStore_Delete_Closed(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
	store.Close()

	err := store.Delete("test1")
	if err == nil {
		t.Fatal("expected error for closed store")
	}
	if err != ErrStoreClosed {
		t.Errorf("expected ErrStoreClosed, got %v", err)
	}
}

func TestFileStore_Close(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)

	err := store.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Close again should be idempotent
	err = store.Close()
	if err != nil {
		t.Fatalf("unexpected error on second close: %v", err)
	}
}

func TestFileStore_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	// Create store and add credentials
	store1, _ := NewFileStore(path)
	store1.Add(createTestCredential("test1", "First"))
	store1.Add(createTestCredential("test2", "Second"))
	store1.Close()

	// Open new store and verify
	store2, _ := NewFileStore(path)
	defer store2.Close()

	list, _ := store2.List()
	if len(list) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(list))
	}

	// Delete one and close
	store2.Delete("test1")
	store2.Close()

	// Open again and verify
	store3, _ := NewFileStore(path)
	defer store3.Close()

	list, _ = store3.List()
	if len(list) != 1 {
		t.Errorf("expected 1 credential, got %d", len(list))
	}
	if list[0].ID != "test2" {
		t.Errorf("expected ID 'test2', got %q", list[0].ID)
	}
}

func TestFileStore_Concurrency(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	store, _ := NewFileStore(path)
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

	// Should be able to list without race conditions
	list, err := store.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) == 0 {
		t.Error("expected some credentials after concurrent adds")
	}
}

func TestFileStore_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")

	// Write invalid JSON
	os.WriteFile(path, []byte("not valid json"), 0600)

	_, err := NewFileStore(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// Store interface tests (ensure both implementations satisfy the interface)

func TestStoreInterface_MemoryStore(t *testing.T) {
	var store Store = NewMemoryStore()
	testStoreInterface(t, store)
}

func TestStoreInterface_FileStore(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.json")
	fileStore, _ := NewFileStore(path)
	var store Store = fileStore
	testStoreInterface(t, store)
}

func testStoreInterface(t *testing.T, store Store) {
	t.Helper()
	defer store.Close()

	cred := createTestCredential("interface-test", "Interface Test")

	// Add
	if err := store.Add(cred); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Get
	retrieved, err := store.Get("interface-test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved.ID != cred.ID {
		t.Errorf("Get returned wrong credential")
	}

	// List
	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 item, got %d", len(list))
	}

	// Update
	cred.Name = "Updated"
	if err := store.Update(cred); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Delete
	if err := store.Delete("interface-test"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deleted
	list, _ = store.List()
	if len(list) != 0 {
		t.Errorf("expected 0 items after delete, got %d", len(list))
	}
}

func TestStoreErrors(t *testing.T) {
	// Verify error messages are meaningful
	errors := []error{
		ErrStoreNotInitialized,
		ErrStoreClosed,
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
