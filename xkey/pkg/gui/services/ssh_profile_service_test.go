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

package services

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ctxKeyTest is a unique context key type for SetContext round-trip tests.
type ctxKeyTest struct{}

func newProfileService(t *testing.T) *SSHProfileService {
	t.Helper()
	store, err := sshclient.NewProfileStore(sshDAOs(t, storage.New()))
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	return NewSSHProfileService(store)
}

func TestSSHProfileService_CRUDAndFolders(t *testing.T) {
	svc := newProfileService(t)

	if _, err := svc.AddProfile(SSHProfileParams{
		Name: "prod-web", FolderPath: "work/prod", Host: "web1.example.com", Port: 2222, User: "deploy",
		KeyScope: "user", KeyOwner: "local", KeyName: "laptop",
	}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	if _, err := svc.AddProfile(SSHProfileParams{Name: "home", FolderPath: "personal", Host: "nas.local", User: "pi"}); err != nil {
		t.Fatalf("AddProfile 2: %v", err)
	}

	list, err := svc.ListProfiles()
	if err != nil || len(list) != 2 {
		t.Fatalf("ListProfiles = %v, %v", list, err)
	}

	got, err := svc.GetProfile("prod-web")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.Host != "web1.example.com" || got.Port != 2222 || got.KeyName != "laptop" {
		t.Fatalf("unexpected profile: %+v", got)
	}

	// Folder listing.
	folders, err := svc.ListFolders()
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	if len(folders) < 3 {
		t.Fatalf("expected work, work/prod, personal; got %v", folders)
	}
	inWork, _ := svc.ListProfilesByFolder("work")
	if len(inWork) != 1 || inWork[0].Name != "prod-web" {
		t.Fatalf("ListProfilesByFolder(work) = %+v", inWork)
	}

	// Update.
	got.User = "root"
	if err := svc.UpdateProfile(SSHProfileParams{
		ID: got.ID, Name: got.Name, FolderPath: got.FolderPath, Host: got.Host, Port: got.Port, User: "root",
	}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	reread, _ := svc.GetProfile("prod-web")
	if reread.User != "root" {
		t.Fatalf("update not persisted: %+v", reread)
	}

	// Move + rename + delete folder.
	if err := svc.MoveProfile("home", "archived"); err != nil {
		t.Fatalf("MoveProfile: %v", err)
	}
	if err := svc.RenameFolder("work/prod", "work/production"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}
	if err := svc.DeleteFolder("work/production"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	remaining, _ := svc.ListProfilesByFolder("work/production")
	if len(remaining) != 0 {
		t.Fatalf("DeleteFolder left %d entries", len(remaining))
	}

	// Delete remaining.
	if err := svc.DeleteProfile("home"); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
}

func TestSSHProfileService_StoreNotSet(t *testing.T) {
	svc := NewSSHProfileService(nil)
	if _, err := svc.ListProfiles(); err == nil {
		t.Fatal("expected ErrSSHProfileStoreNotSet")
	}
}

// TestSSHProfileService_StoreNotSet_AllMethods pins the nil-store guard on
// every exported method, not just ListProfiles: each must fail closed with
// ErrSSHProfileStoreNotSet rather than nil-dereferencing the store.
func TestSSHProfileService_StoreNotSet_AllMethods(t *testing.T) {
	svc := NewSSHProfileService(nil)

	if _, err := svc.ListProfilesByFolder("work"); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("ListProfilesByFolder err = %v", err)
	}
	if _, err := svc.ListFolders(); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("ListFolders err = %v", err)
	}
	if _, err := svc.GetProfile("x"); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("GetProfile err = %v", err)
	}
	if _, err := svc.AddProfile(SSHProfileParams{Name: "x"}); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("AddProfile err = %v", err)
	}
	if err := svc.UpdateProfile(SSHProfileParams{Name: "x"}); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("UpdateProfile err = %v", err)
	}
	if err := svc.DeleteProfile("x"); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("DeleteProfile err = %v", err)
	}
	if err := svc.MoveProfile("x", "folder"); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("MoveProfile err = %v", err)
	}
	if err := svc.RenameFolder("a", "b"); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("RenameFolder err = %v", err)
	}
	if err := svc.DeleteFolder("a"); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("DeleteFolder err = %v", err)
	}
	if _, err := svc.SearchProfiles("x"); err != ErrSSHProfileStoreNotSet {
		t.Fatalf("SearchProfiles err = %v", err)
	}
}

func TestSSHProfileService_SetContext(t *testing.T) {
	svc := NewSSHProfileService(nil)
	ctx := context.WithValue(context.Background(), ctxKeyTest{}, "v")
	svc.SetContext(ctx)
	if svc.ctx != ctx {
		t.Fatal("SetContext did not store the context")
	}
}

func TestSSHProfileService_SetStoreAndStore(t *testing.T) {
	svc := NewSSHProfileService(nil)
	if svc.Store() != nil {
		t.Fatal("expected nil store by default")
	}

	store, err := sshclient.NewProfileStore(sshDAOs(t, storage.New()))
	if err != nil {
		t.Fatalf("NewProfileStore: %v", err)
	}
	svc.SetStore(store)
	if svc.Store() != store {
		t.Fatal("SetStore/Store did not round-trip the same store")
	}
}

// TestSSHProfileService_CreateFolder covers both branches: refused without
// a store, and delegated to the store when one is wired.
func TestSSHProfileService_CreateFolder(t *testing.T) {
	nostore := NewSSHProfileService(nil)
	if err := nostore.CreateFolder("work"); err == nil {
		t.Fatal("expected ErrSSHProfileStoreNotSet")
	}

	svc := newProfileService(t)
	if err := svc.CreateFolder("work/prod"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	folders, err := svc.ListFolders()
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	found := false
	for _, f := range folders {
		if f == "work/prod" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListFolders = %v, want it to include the created folder", folders)
	}
}

// TestSSHProfileService_SearchProfiles covers both branches: refused
// without a store, and delegated to the store's search when one is wired.
func TestSSHProfileService_SearchProfiles(t *testing.T) {
	nostore := NewSSHProfileService(nil)
	if _, err := nostore.SearchProfiles("prod"); err == nil {
		t.Fatal("expected ErrSSHProfileStoreNotSet")
	}

	svc := newProfileService(t)
	if _, err := svc.AddProfile(SSHProfileParams{Name: "prod-web", Host: "web1.example.com", User: "deploy"}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	if _, err := svc.AddProfile(SSHProfileParams{Name: "home-nas", Host: "nas.local", User: "pi"}); err != nil {
		t.Fatalf("AddProfile 2: %v", err)
	}

	results, err := svc.SearchProfiles("prod")
	if err != nil {
		t.Fatalf("SearchProfiles: %v", err)
	}
	if len(results) != 1 || results[0].Name != "prod-web" {
		t.Fatalf("SearchProfiles(\"prod\") = %+v, want exactly the prod-web profile", results)
	}
}

// TestSSHProfileService_LocalKeySourceRoundTrip verifies KeySource and
// SSHConfigAlias survive an AddProfile/GetProfile/UpdateProfile round trip
// through the SDK Profile mapping, so a "local" (ssh-agent/~/.ssh) profile
// keeps its ssh_config alias across restarts.
func TestSSHProfileService_LocalKeySourceRoundTrip(t *testing.T) {
	svc := newProfileService(t)

	if _, err := svc.AddProfile(SSHProfileParams{
		Name: "bastion", Host: "bastion.example.com",
		KeySource: "local", SSHConfigAlias: "bastion-alias",
	}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	got, err := svc.GetProfile("bastion")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.KeySource != "local" || got.SSHConfigAlias != "bastion-alias" {
		t.Fatalf("unexpected local-key fields: %+v", got)
	}

	if err := svc.UpdateProfile(SSHProfileParams{
		ID: got.ID, Name: got.Name, FolderPath: got.FolderPath, Host: got.Host,
		KeySource: "local", SSHConfigAlias: "renamed-alias",
	}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	reread, err := svc.GetProfile("bastion")
	if err != nil {
		t.Fatalf("GetProfile after update: %v", err)
	}
	if reread.SSHConfigAlias != "renamed-alias" {
		t.Fatalf("update not persisted: %+v", reread)
	}
}
