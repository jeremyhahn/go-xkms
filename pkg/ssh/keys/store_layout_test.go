// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package keys_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// newLayoutStore returns a DAOStore over a fresh in-memory DAO factory, and
// the factory so a test can inspect the stored records.
func newLayoutStore(t *testing.T) (*keys.DAOStore, *qrdbsdk.DAOFactory) {
	t.Helper()
	daos := testutil.NewMemoryDAOFactory()
	store, err := keys.NewDAOStore(daos)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store, daos
}

// putKey generates a software ed25519 key at (sc, owner, name) and stores it.
func putKey(t *testing.T, store keys.Store, sc scope.Scope, owner, name string) error {
	t.Helper()
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer k.Destroy()
	k.Scope, k.Owner, k.Name = sc, owner, name
	return store.Put(context.Background(), k)
}

// storedPaths returns the path of every record of kind in the platform
// partition of daos.
func storedPaths(t *testing.T, daos *qrdbsdk.DAOFactory, kind scope.Kind) []string {
	t.Helper()
	table, err := records.New[json.RawMessage](daos, kind)
	if err != nil {
		t.Fatalf("records.New: %v", err)
	}
	all, err := table.List(context.Background(), "", "")
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	paths := make([]string, 0, len(all))
	for _, e := range all {
		paths = append(paths, e.Path)
	}
	return paths
}

func TestDAOStore_WritesScopeLayoutPath(t *testing.T) {
	tests := []struct {
		scope scope.Scope
		owner string
		want  string
	}{
		{scope.Tenant, "acme", "system/ssh/shared/keys/deploy"},
		{scope.User, "alice", "system/ssh/users/alice/keys/deploy"},
		{scope.Service, "ci", "system/ssh/services/ci/keys/deploy"},
	}
	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			store, daos := newLayoutStore(t)
			if err := putKey(t, store, tt.scope, tt.owner, "deploy"); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got := storedPaths(t, daos, scope.KindKeys)
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("stored paths = %v, want [%s]", got, tt.want)
			}
			k, err := store.Get(context.Background(), tt.scope, tt.owner, "deploy")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer k.Destroy()
			if k.Scope != tt.scope || k.Owner != tt.owner || k.Name != "deploy" {
				t.Fatalf("round trip = %s/%s/%s", k.Scope, k.Owner, k.Name)
			}
		})
	}
}

// TestDAOStore_PartitionsAreDisjoint proves a tenant partition neither
// sees nor alters the platform partition's keys.
func TestDAOStore_PartitionsAreDisjoint(t *testing.T) {
	ctx := context.Background()
	store, daos := newLayoutStore(t)
	acme, err := store.Partition("acme")
	if err != nil {
		t.Fatalf("Partition: %v", err)
	}
	if err := putKey(t, store, scope.User, "alice", "deploy"); err != nil {
		t.Fatalf("Put platform: %v", err)
	}
	var nf *keys.KeyNotFoundError
	if _, err := acme.Get(ctx, scope.User, "alice", "deploy"); !errors.As(err, &nf) {
		t.Fatalf("Get through tenant partition: want *KeyNotFoundError, got %T: %v", err, err)
	}
	if err := putKey(t, acme, scope.User, "alice", "deploy"); err != nil {
		t.Fatalf("Put tenant: %v", err)
	}
	if got, err := acme.List(ctx, "", ""); err != nil || len(got) != 1 {
		t.Fatalf("tenant List = %d keys, err %v; want 1", len(got), err)
	}
	if got := storedPaths(t, daos, scope.KindKeys); len(got) != 1 {
		t.Fatalf("platform partition holds %v, want its one key", got)
	}
	if _, err := store.Partition("bad/tenant"); err == nil {
		t.Fatal("Partition(bad/tenant) succeeded")
	}
}

// TestDAOStore_TenantOwnerIsAuthoritative proves a tenant-scoped key,
// whose path carries no owner, is never aliased by another owner: it
// answers as missing, survives Delete, refuses overwrite and is filtered
// from the other owner's listing.
func TestDAOStore_TenantOwnerIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	store, daos := newLayoutStore(t)
	if err := putKey(t, store, scope.Tenant, "acme", "deploy"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var nf *keys.KeyNotFoundError
	if _, err := store.Get(ctx, scope.Tenant, "globex", "deploy"); !errors.As(err, &nf) {
		t.Fatalf("Get as other owner: want *KeyNotFoundError, got %T: %v", err, err)
	}
	if nf.ID != "tenant/globex/deploy" {
		t.Fatalf("KeyNotFoundError.ID = %q", nf.ID)
	}
	if err := store.Delete(ctx, scope.Tenant, "globex", "deploy"); !errors.As(err, &nf) {
		t.Fatalf("Delete as other owner: want *KeyNotFoundError, got %T: %v", err, err)
	}
	if got := storedPaths(t, daos, scope.KindKeys); len(got) != 1 {
		t.Fatalf("Delete as other owner removed the key: %v", got)
	}

	var conflict *keys.OwnerConflictError
	err := putKey(t, store, scope.Tenant, "globex", "deploy")
	if !errors.As(err, &conflict) {
		t.Fatalf("Put as other owner: want *OwnerConflictError, got %T: %v", err, err)
	}
	if conflict.Error() != "ssh/keys: key held by another owner: tenant/globex/deploy" {
		t.Fatalf("Error() = %q", conflict.Error())
	}
	k, err := store.Get(ctx, scope.Tenant, "acme", "deploy")
	if err != nil {
		t.Fatalf("Get as owner after refused overwrite: %v", err)
	}
	k.Destroy()

	other, err := store.List(ctx, scope.Tenant, "globex")
	if err != nil || len(other) != 0 {
		t.Fatalf("List other owner = %d keys, err %v; want none", len(other), err)
	}
	own, err := store.List(ctx, scope.Tenant, "acme")
	if err != nil || len(own) != 1 {
		t.Fatalf("List owner = %d keys, err %v; want 1", len(own), err)
	}

	// The owner itself may overwrite and delete.
	if err := putKey(t, store, scope.Tenant, "acme", "deploy"); err != nil {
		t.Fatalf("Put overwrite as owner: %v", err)
	}
	if err := store.Delete(ctx, scope.Tenant, "acme", "deploy"); err != nil {
		t.Fatalf("Delete as owner: %v", err)
	}
	if _, err := store.Get(ctx, scope.Tenant, "acme", "deploy"); !errors.As(err, &nf) {
		t.Fatalf("Get after delete: want *KeyNotFoundError, got %T: %v", err, err)
	}
}

// TestDAOStore_List_FiltersByKind proves a listing keeps only key records:
// a known_hosts pin and an authorized_keys entry under the same scope, owner
// and name never leak in.
func TestDAOStore_List_FiltersByKind(t *testing.T) {
	ctx := context.Background()
	store, daos := newLayoutStore(t)
	if err := putKey(t, store, scope.User, "alice", "laptop"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for _, kind := range []scope.Kind{scope.KindKnownHosts, scope.KindAuthorizedKeys} {
		table, err := records.New[json.RawMessage](daos, kind)
		if err != nil {
			t.Fatalf("records.New(%s): %v", kind, err)
		}
		if _, err := table.Put(ctx, scope.User, "alice", "laptop", json.RawMessage(`{"line":"x"}`)); err != nil {
			t.Fatalf("put %s: %v", kind, err)
		}
	}
	for _, f := range []struct {
		scope scope.Scope
		owner string
	}{{"", ""}, {scope.User, ""}, {scope.User, "alice"}} {
		got, err := store.List(ctx, f.scope, f.owner)
		if err != nil {
			t.Fatalf("List(%q, %q): %v", f.scope, f.owner, err)
		}
		if len(got) != 1 || got[0].Name != "laptop" {
			t.Fatalf("List(%q, %q) = %d keys, want only laptop", f.scope, f.owner, len(got))
		}
	}
}

func TestDAOStore_Put_StorageErrors(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer k.Destroy()
	k.Scope, k.Owner, k.Name = scope.Tenant, "acme", "deploy"

	var se *keys.StorageError
	if err := storeOver(t, keysFailingBackend{}).Put(context.Background(), k); !errors.As(err, &se) || se.Op != "put" {
		t.Fatalf("Put over failing backend: want *StorageError{put}, got %T: %v", err, err)
	}
	corrupt := corruptStore(t)
	if err := corrupt.Put(context.Background(), k); !errors.As(err, &se) {
		t.Fatalf("Put over corrupt record: want *StorageError, got %T: %v", err, err)
	}
	if err := corrupt.Delete(context.Background(), scope.Tenant, "acme", "deploy"); !errors.As(err, &se) {
		t.Fatalf("Delete over corrupt record: want *StorageError, got %T: %v", err, err)
	}
}
