// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package profile

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// faultBackend wraps a real in-memory backend and lets a test force an error
// from a chosen method, exercising the store's storage-error branches.
type faultBackend struct {
	storage.Backend
	failExists bool
	failPut    bool
	failDelete bool
	failList   bool
}

func (f *faultBackend) Exists(ctx context.Context, key string) (bool, error) {
	if f.failExists {
		return false, errors.New("injected exists failure")
	}
	return f.Backend.Exists(ctx, key)
}

func (f *faultBackend) Put(ctx context.Context, key string, value []byte) error {
	if f.failPut {
		return errors.New("injected put failure")
	}
	return f.Backend.Put(ctx, key, value)
}

func (f *faultBackend) Delete(ctx context.Context, key string) error {
	if f.failDelete {
		return errors.New("injected delete failure")
	}
	return f.Backend.Delete(ctx, key)
}

func (f *faultBackend) List(ctx context.Context, prefix string) ([]string, error) {
	if f.failList {
		return nil, errors.New("injected list failure")
	}
	return f.Backend.List(ctx, prefix)
}

func newFaultStore(t *testing.T) (*BackendStore, *faultBackend) {
	t.Helper()
	fb := &faultBackend{Backend: storage.New()}
	st, err := NewStore(fb)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return st, fb
}

// TestStore_Close_Idempotent verifies Close returns nil the first time and on
// every subsequent call, and that operations on a closed store are rejected.
func TestStore_Close_Idempotent(t *testing.T) {
	st := newStore(t)

	if err := st.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close is a no-op.
	if err := st.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestStore_ClosedRejections exercises the ErrStoreClosed guard on every
// mutating and reading entry point.
func TestStore_ClosedRejections(t *testing.T) {
	st := newStore(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	p := &Profile{Name: "n", Host: "h"}
	checks := map[string]error{
		"Add":          st.Add(p),
		"Update":       st.Update(p),
		"Delete":       st.Delete("n"),
		"MoveToFolder": st.MoveToFolder("n", "f"),
		"CreateFolder": st.CreateFolder("f"),
		"RemoveFolder": st.RemoveFolder("f"),
	}
	for name, err := range checks {
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("%s on closed store: expected ErrStoreClosed, got %v", name, err)
		}
	}

	if _, err := st.Get("n"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Get on closed store: expected ErrStoreClosed, got %v", err)
	}
	if _, err := st.List(); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("List on closed store: expected ErrStoreClosed, got %v", err)
	}
}

// TestStore_FolderEmptyPaths covers the ErrFolderEmpty guard on every folder
// operation that validates its path argument.
func TestStore_FolderEmptyPaths(t *testing.T) {
	st := newStore(t)

	if err := st.CreateFolder(""); !errors.Is(err, ErrFolderEmpty) {
		t.Fatalf("CreateFolder(\"\"): expected ErrFolderEmpty, got %v", err)
	}
	if err := st.RemoveFolder(""); !errors.Is(err, ErrFolderEmpty) {
		t.Fatalf("RemoveFolder(\"\"): expected ErrFolderEmpty, got %v", err)
	}
	if err := st.RenameFolder("", "x"); !errors.Is(err, ErrFolderEmpty) {
		t.Fatalf("RenameFolder(\"\", x): expected ErrFolderEmpty, got %v", err)
	}
	if err := st.RenameFolder("x", ""); !errors.Is(err, ErrFolderEmpty) {
		t.Fatalf("RenameFolder(x, \"\"): expected ErrFolderEmpty, got %v", err)
	}
	if err := st.DeleteFolder(""); !errors.Is(err, ErrFolderEmpty) {
		t.Fatalf("DeleteFolder(\"\"): expected ErrFolderEmpty, got %v", err)
	}
}

// TestStore_RenameFolder_SameName rejects an identity rename.
func TestStore_RenameFolder_SameName(t *testing.T) {
	st := newStore(t)
	if err := st.RenameFolder("work", "work"); !errors.Is(err, ErrMoveToSameFolder) {
		t.Fatalf("expected ErrMoveToSameFolder, got %v", err)
	}
}

// TestStore_RemoveFolder_Missing is idempotent: removing an absent marker
// swallows storage.ErrNotFound and returns nil.
func TestStore_RemoveFolder_Missing(t *testing.T) {
	st := newStore(t)
	if err := st.RemoveFolder("never/created"); err != nil {
		t.Fatalf("RemoveFolder(missing): expected nil, got %v", err)
	}
}

// TestStore_Update_NotFound covers updating a profile that was never stored.
func TestStore_Update_NotFound(t *testing.T) {
	st := newStore(t)
	p := &Profile{Name: "ghost", Host: "h"}
	p.ID = generateID(p.Name, p.FolderPath)
	if err := st.Update(p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update(missing): expected ErrNotFound, got %v", err)
	}
}

// TestStore_Update_Invalid covers validation rejection before any storage read.
func TestStore_Update_Invalid(t *testing.T) {
	st := newStore(t)
	if err := st.Update(&Profile{Name: "", Host: "h"}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Update(invalid name): expected ErrInvalidName, got %v", err)
	}
	if err := st.Update(&Profile{Name: "n", Host: ""}); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("Update(invalid host): expected ErrInvalidHost, got %v", err)
	}
}

// TestStore_Delete_NotFound covers deleting an absent profile.
func TestStore_Delete_NotFound(t *testing.T) {
	st := newStore(t)
	if err := st.Delete("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(missing): expected ErrNotFound, got %v", err)
	}
}

// TestStore_MoveToFolder covers the happy path, the same-folder rejection, and
// the missing-entry rejection.
func TestStore_MoveToFolder(t *testing.T) {
	st := newStore(t)
	if err := st.Add(&Profile{Name: "box", FolderPath: "a", Host: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	entry, err := st.Get("box")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Same folder is a no-op rejection.
	if err := st.MoveToFolder(entry.ID, "a"); !errors.Is(err, ErrMoveToSameFolder) {
		t.Fatalf("MoveToFolder(same): expected ErrMoveToSameFolder, got %v", err)
	}

	// Real move regenerates the ID under the new folder.
	if err := st.MoveToFolder(entry.ID, "b"); err != nil {
		t.Fatalf("MoveToFolder(a->b): %v", err)
	}
	moved, err := st.Get("box")
	if err != nil {
		t.Fatalf("Get after move: %v", err)
	}
	if moved.FolderPath != "b" {
		t.Fatalf("expected folder b, got %q", moved.FolderPath)
	}

	// Moving a missing entry fails.
	if err := st.MoveToFolder("does-not-exist", "c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MoveToFolder(missing): expected ErrNotFound, got %v", err)
	}
}

// TestStore_FolderLifecycle exercises CreateFolder markers surfacing through
// ListFolders, RenameFolder migrating entries + markers, and DeleteFolder
// removing entries and markers together.
func TestStore_FolderLifecycle(t *testing.T) {
	st := newStore(t)

	// An empty folder is visible purely via its marker.
	if err := st.CreateFolder("team/empty"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if err := st.Add(&Profile{Name: "svc", FolderPath: "team/prod", Host: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	folders, err := st.ListFolders()
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	if !contains(folders, "team/empty") || !contains(folders, "team/prod") || !contains(folders, "team") {
		t.Fatalf("ListFolders missing expected entries: %v", folders)
	}

	// Rename the whole subtree.
	if err := st.RenameFolder("team", "org"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}
	moved, err := st.Get("svc")
	if err != nil {
		t.Fatalf("Get after rename: %v", err)
	}
	if moved.FolderPath != "org/prod" {
		t.Fatalf("expected org/prod after rename, got %q", moved.FolderPath)
	}
	folders, _ = st.ListFolders()
	if contains(folders, "team") {
		t.Fatalf("old folder still present after rename: %v", folders)
	}

	// Delete the subtree: entries and markers both gone.
	if err := st.DeleteFolder("org"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if _, err := st.Get("svc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("entry survived DeleteFolder: %v", err)
	}
	folders, _ = st.ListFolders()
	if contains(folders, "org") || contains(folders, "org/prod") {
		t.Fatalf("markers survived DeleteFolder: %v", folders)
	}
}

// TestStore_Search_EmptyReturnsAll covers the empty-query short-circuit.
func TestStore_Search_EmptyReturnsAll(t *testing.T) {
	st := newStore(t)
	if err := st.Add(&Profile{Name: "one", Host: "h1"}); err != nil {
		t.Fatalf("Add one: %v", err)
	}
	if err := st.Add(&Profile{Name: "two", Host: "h2"}); err != nil {
		t.Fatalf("Add two: %v", err)
	}
	all, err := st.Search("   ")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("empty query should return all, got %d", len(all))
	}
}

// TestStore_ListByFolderDirect distinguishes direct children from descendants.
func TestStore_ListByFolderDirect(t *testing.T) {
	st := newStore(t)
	if err := st.Add(&Profile{Name: "direct", FolderPath: "root", Host: "h"}); err != nil {
		t.Fatalf("Add direct: %v", err)
	}
	if err := st.Add(&Profile{Name: "nested", FolderPath: "root/sub", Host: "h"}); err != nil {
		t.Fatalf("Add nested: %v", err)
	}

	direct, err := st.ListByFolderDirect("root")
	if err != nil {
		t.Fatalf("ListByFolderDirect: %v", err)
	}
	if len(direct) != 1 || direct[0].Name != "direct" {
		t.Fatalf("expected only the direct child, got %+v", direct)
	}

	sub, err := st.ListByFolder("root")
	if err != nil {
		t.Fatalf("ListByFolder: %v", err)
	}
	if len(sub) != 2 {
		t.Fatalf("ListByFolder(root) should include descendants, got %d", len(sub))
	}
}

// TestStore_GetByName_HashedID covers the hashed-ID lookup branch in
// getUnlocked: a root-folder profile fetched by its Name resolves via
// generateID(name, "") rather than the name scan.
func TestStore_GetByName_HashedID(t *testing.T) {
	st := newStore(t)
	if err := st.Add(&Profile{Name: "rootbox", Host: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := st.Get("rootbox")
	if err != nil {
		t.Fatalf("Get by name: %v", err)
	}
	if got.Host != "h" {
		t.Fatalf("unexpected profile: %+v", got)
	}
}

// TestStore_CorruptData covers the unmarshalProfile error path: a value that is
// not valid JSON at a profile key surfaces ErrUnmarshalFailed on a direct Get,
// and is skipped by List.
func TestStore_CorruptData(t *testing.T) {
	st, fb := newFaultStore(t)
	// Write invalid JSON directly at a profile storage key.
	id := generateID("broken", "")
	key := st.storageKey(id)
	if err := fb.Backend.Put(context.Background(), key, []byte("{not json")); err != nil {
		t.Fatalf("seed corrupt data: %v", err)
	}

	if _, err := st.Get(id); !errors.Is(err, ErrUnmarshalFailed) {
		t.Fatalf("Get(corrupt): expected ErrUnmarshalFailed, got %v", err)
	}
	// List silently skips the unparseable entry.
	all, err := st.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("List should skip corrupt entry, got %d", len(all))
	}
}

// TestStore_StorageErrors covers the injected storage-failure branches on the
// mutating paths.
func TestStore_StorageErrors(t *testing.T) {
	st, fb := newFaultStore(t)

	// Add: Exists probe failure wraps ErrExists.
	fb.failExists = true
	if err := st.Add(&Profile{Name: "n", Host: "h"}); !errors.Is(err, ErrExists) {
		t.Fatalf("Add with Exists failure: expected ErrExists, got %v", err)
	}
	fb.failExists = false

	// Add succeeds so later operations have something to act on.
	if err := st.Add(&Profile{Name: "n", FolderPath: "a", Host: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	entry, err := st.Get("n")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// MoveToFolder: Delete of the old key failure wraps ErrNotFound.
	fb.failDelete = true
	if err := st.MoveToFolder(entry.ID, "b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MoveToFolder with Delete failure: expected ErrNotFound, got %v", err)
	}
	fb.failDelete = false

	// List failure surfaces as ErrNotFound through listUnlocked.
	fb.failList = true
	if _, err := st.List(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("List with backend failure: expected ErrNotFound, got %v", err)
	}
	fb.failList = false
}

// TestStore_Update_Rename covers the ID-regeneration branch: renaming a
// profile deletes the old key and writes the new one.
func TestStore_Update_Rename(t *testing.T) {
	st := newStore(t)
	if err := st.Add(&Profile{Name: "old", FolderPath: "f", Host: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	entry, err := st.Get("old")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	oldID := entry.ID
	entry.Name = "renamed"
	if err := st.Update(entry); err != nil {
		t.Fatalf("Update(rename): %v", err)
	}
	if entry.ID == oldID {
		t.Fatalf("ID should regenerate on rename")
	}
	if _, err := st.Get("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old name still resolves: %v", err)
	}
	if _, err := st.Get("renamed"); err != nil {
		t.Fatalf("Get(renamed): %v", err)
	}
}

// TestStore_Update_RenameDeleteError covers the Delete-failure branch during an
// Update that regenerates the ID.
func TestStore_Update_RenameDeleteError(t *testing.T) {
	st, fb := newFaultStore(t)
	if err := st.Add(&Profile{Name: "orig", FolderPath: "f", Host: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	entry, err := st.Get("orig")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	entry.Name = "moved"
	fb.failDelete = true
	if err := st.Update(entry); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update(rename) with Delete failure: expected ErrNotFound, got %v", err)
	}
}

// TestStore_PutErrors covers the Put-failure branches on Add and CreateFolder.
func TestStore_PutErrors(t *testing.T) {
	st, fb := newFaultStore(t)
	fb.failPut = true
	if err := st.Add(&Profile{Name: "n", Host: "h"}); err == nil {
		t.Fatalf("Add with Put failure: expected error")
	}
	if err := st.CreateFolder("f"); err == nil {
		t.Fatalf("CreateFolder with Put failure: expected error")
	}
}

// TestStore_RenameFolder_PropagatesRemoveFolderError verifies that a storage
// failure while migrating a folder marker during RenameFolder is reported to
// the caller rather than silently discarded (#701): before, a failed
// RemoveFolder left both the old and the new marker behind (RenameFolder
// still called CreateFolder next and returned nil), which is exactly the
// inconsistent state propagating the error prevents.
func TestStore_RenameFolder_PropagatesRemoveFolderError(t *testing.T) {
	st, fb := newFaultStore(t)
	if err := st.CreateFolder("work/prod"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	fb.failDelete = true
	if err := st.RenameFolder("work/prod", "work/production"); err == nil {
		t.Fatal("expected RenameFolder to propagate the RemoveFolder failure, got nil")
	}
}

// TestStore_DeleteFolder_PropagatesRemoveFolderError is the DeleteFolder
// counterpart: a storage failure removing a folder marker must not be
// swallowed into a reported success.
func TestStore_DeleteFolder_PropagatesRemoveFolderError(t *testing.T) {
	st, fb := newFaultStore(t)
	if err := st.CreateFolder("work/prod"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	fb.failDelete = true
	if err := st.DeleteFolder("work/prod"); err == nil {
		t.Fatal("expected DeleteFolder to propagate the RemoveFolder failure, got nil")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// ensure the storage package import is exercised even if the helper changes.
var _ = storage.New
