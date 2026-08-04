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

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func newStore(t *testing.T) *BackendStore {
	t.Helper()
	st, err := NewStore(storage.New())
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

	if err := st.Delete("prod-web"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get("prod-web"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
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
		{Name: "d", FolderPath: "personal", Host: "d"},
	}
	for _, p := range seed {
		if err := st.Add(p); err != nil {
			t.Fatalf("Add %s: %v", p.Name, err)
		}
	}
	// Empty marker folder persists.
	if err := st.CreateFolder("work/empty"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	folders, err := st.ListFolders()
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	want := map[string]bool{"work": true, "work/prod": true, "work/prod/db": true, "personal": true, "work/empty": true}
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
	if err := st.MoveToFolder("d", "archived"); err != nil {
		t.Fatalf("MoveToFolder: %v", err)
	}
	moved, _ := st.Get("d")
	if moved.FolderPath != "archived" {
		t.Fatalf("move failed: %+v", moved)
	}

	// Rename subtree.
	if err := st.RenameFolder("work/prod", "work/production"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}
	if _, err := st.ListByFolder("work/production"); err != nil {
		t.Fatalf("ListByFolder after rename: %v", err)
	}
	renamed, _ := st.ListByFolder("work/production")
	if len(renamed) != 2 {
		t.Fatalf("rename subtree expected 2 entries, got %d", len(renamed))
	}
	for _, p := range renamed {
		if p.FolderPath != "work/production" && p.FolderPath != "work/production/db" {
			t.Fatalf("entry not renamed: %+v", p)
		}
	}

	// Delete folder subtree.
	if err := st.DeleteFolder("work/production"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	left, _ := st.ListByFolder("work/production")
	if len(left) != 0 {
		t.Fatalf("DeleteFolder left %d entries", len(left))
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
	if all, _ := st.Search(""); len(all) != 2 {
		t.Fatalf("empty search should return all, got %d", len(all))
	}
}

func TestNewStore_NilBackend(t *testing.T) {
	if _, err := NewStore(nil); !errors.Is(err, ErrNilBackend) {
		t.Fatalf("expected ErrNilBackend, got %v", err)
	}
}
