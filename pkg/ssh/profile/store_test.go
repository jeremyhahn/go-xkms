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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func newStore(t *testing.T) *DAOStore {
	t.Helper()
	st, err := NewStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return st
}

func TestStore_CRUD(t *testing.T) {
	st := newStore(t)

	if err := st.Add(&Profile{Name: "prod-web", FolderPath: "work/prod", Host: "web1.example.com", Port: 2222, User: "deploy"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Duplicate in same folder rejected.
	if err := st.Add(&Profile{Name: "prod-web", FolderPath: "work/prod", Host: "x"}); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	// Validation.
	if err := st.Add(&Profile{Name: "", Host: "h"}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("expected ErrInvalidName, got %v", err)
	}
	if err := st.Add(&Profile{Name: "n", Host: ""}); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("expected ErrInvalidHost, got %v", err)
	}

	got, err := st.Get("prod-web")
	if err != nil {
		t.Fatalf("Get by name: %v", err)
	}
	if got.Host != "web1.example.com" || got.EffectivePort() != 2222 || got.User != "deploy" {
		t.Fatalf("unexpected profile: %+v", got)
	}
	if _, err := st.Get(got.ID); err != nil {
		t.Fatalf("Get by ID: %v", err)
	}

	got.User = "root"
	if err := st.Update(got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	reread, _ := st.Get("prod-web")
	if reread.User != "root" {
		t.Fatalf("update not persisted: %+v", reread)
	}

	// Rename regenerates the ID; the old name no longer resolves.
	oldID := reread.ID
	reread.Name = "prod-api"
	if err := st.Update(reread); err != nil {
		t.Fatalf("Update(rename): %v", err)
	}
	if reread.ID == oldID {
		t.Fatalf("ID should regenerate on rename")
	}
	if _, err := st.Get("prod-web"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old name still resolves: %v", err)
	}

	if err := st.Delete("prod-api"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get("prod-api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := st.Delete("prod-api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(missing): expected ErrNotFound, got %v", err)
	}
	if err := st.Update(reread); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update(missing): expected ErrNotFound, got %v", err)
	}
}

// TestStore_KeySourceLocalRoundTrip verifies KeySource and SSHConfigAlias
// survive an Add/Get/Update round trip, so a "local" (ssh-agent/~/.ssh)
// profile keeps pointing at its ssh_config alias across restarts.
func TestStore_KeySourceLocalRoundTrip(t *testing.T) {
	st := newStore(t)

	if err := st.Add(&Profile{
		Name: "bastion", Host: "bastion.example.com",
		KeySource: "local", SSHConfigAlias: "bastion-alias",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := st.Get("bastion")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.KeySource != "local" || got.SSHConfigAlias != "bastion-alias" {
		t.Fatalf("unexpected local-key fields: %+v", got)
	}

	got.SSHConfigAlias = "renamed-alias"
	if err := st.Update(got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	reread, err := st.Get("bastion")
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if reread.SSHConfigAlias != "renamed-alias" {
		t.Fatalf("update not persisted: %+v", reread)
	}

	// A managed (default) profile leaves both fields empty.
	if err := st.Add(&Profile{Name: "managed", Host: "h"}); err != nil {
		t.Fatalf("Add managed: %v", err)
	}
	managed, err := st.Get("managed")
	if err != nil {
		t.Fatalf("Get managed: %v", err)
	}
	if managed.KeySource != "" || managed.SSHConfigAlias != "" {
		t.Fatalf("expected empty local-key fields on a managed profile: %+v", managed)
	}
}

func TestStore_EffectivePortDefault(t *testing.T) {
	st := newStore(t)
	if err := st.Add(&Profile{Name: "p", Host: "h"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	p, _ := st.Get("p")
	if p.EffectivePort() != 22 {
		t.Fatalf("expected default port 22, got %d", p.EffectivePort())
	}
}

func TestStore_Folders(t *testing.T) {
	st := newStore(t)
	seed := []*Profile{
		{Name: "a", FolderPath: "work", Host: "a"},
		{Name: "b", FolderPath: "work/prod", Host: "b"},
		{Name: "c", FolderPath: "work/prod/db", Host: "c"},
		{Name: "d", FolderPath: "personal/home", Host: "d"},
	}
	for _, p := range seed {
		if err := st.Add(p); err != nil {
			t.Fatalf("Add %s: %v", p.Name, err)
		}
	}
	// Empty marker folder persists.
	if err := st.CreateFolder("work/prod/empty"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// Ancestors of a profile's folder ("personal") are listed too.
	folders, err := st.ListFolders()
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	want := map[string]bool{"work": true, "work/prod": true, "work/prod/db": true, "personal": true, "personal/home": true, "work/prod/empty": true}
	for _, f := range folders {
		delete(want, f)
	}
	if len(want) != 0 {
		t.Fatalf("ListFolders missing %v (got %v)", want, folders)
	}

	// ListByFolder includes subfolders; Direct does not.
	sub, _ := st.ListByFolder("work")
	if len(sub) != 3 {
		t.Fatalf("ListByFolder(work) expected 3, got %d", len(sub))
	}
	direct, _ := st.ListByFolderDirect("work")
	if len(direct) != 1 || direct[0].Name != "a" {
		t.Fatalf("ListByFolderDirect(work) expected [a], got %+v", direct)
	}

	// Move.
	if err := st.MoveToFolder("d", "personal/home"); !errors.Is(err, ErrMoveToSameFolder) {
		t.Fatalf("MoveToFolder(same): expected ErrMoveToSameFolder, got %v", err)
	}
	if err := st.MoveToFolder("d", "archived"); err != nil {
		t.Fatalf("MoveToFolder: %v", err)
	}
	moved, _ := st.Get("d")
	if moved.FolderPath != "archived" {
		t.Fatalf("move failed: %+v", moved)
	}
	if err := st.MoveToFolder("does-not-exist", "c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MoveToFolder(missing): expected ErrNotFound, got %v", err)
	}

	// Rename subtree: entries and markers both move.
	if err := st.RenameFolder("work/prod", "work/production"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}
	renamed, err := st.ListByFolder("work/production")
	if err != nil {
		t.Fatalf("ListByFolder after rename: %v", err)
	}
	if len(renamed) != 2 {
		t.Fatalf("rename subtree expected 2 entries, got %d", len(renamed))
	}
	for _, p := range renamed {
		if p.FolderPath != "work/production" && p.FolderPath != "work/production/db" {
			t.Fatalf("entry not renamed: %+v", p)
		}
	}
	folders, _ = st.ListFolders()
	if contains(folders, "work/prod") || contains(folders, "work/prod/empty") || !contains(folders, "work/production/empty") {
		t.Fatalf("markers not renamed: %v", folders)
	}

	// Delete folder subtree: entries and markers both gone.
	if err := st.DeleteFolder("work/production"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	left, _ := st.ListByFolder("work/production")
	if len(left) != 0 {
		t.Fatalf("DeleteFolder left %d entries", len(left))
	}
	folders, _ = st.ListFolders()
	if contains(folders, "work/production") || contains(folders, "work/production/empty") {
		t.Fatalf("markers survived DeleteFolder: %v", folders)
	}
}

func TestStore_Search(t *testing.T) {
	st := newStore(t)
	_ = st.Add(&Profile{Name: "bastion", FolderPath: "work", Host: "jump.example.com", User: "admin"})
	_ = st.Add(&Profile{Name: "home-nas", FolderPath: "personal", Host: "nas.local", User: "pi"})

	res, err := st.Search("example")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 || res[0].Name != "bastion" {
		t.Fatalf("Search(example) = %+v", res)
	}
	if all, _ := st.Search("   "); len(all) != 2 {
		t.Fatalf("empty search should return all, got %d", len(all))
	}
}

func TestNewStore_NilBackend(t *testing.T) {
	if _, err := NewStore(nil); !errors.Is(err, ErrNilDAOFactory) {
		t.Fatalf("expected ErrNilDAOFactory, got %v", err)
	}
}
