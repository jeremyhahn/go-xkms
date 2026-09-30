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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newLayoutStore returns a BackendStore over a fresh in-memory backend,
// and the backend so a test can inspect the raw storage keys.
func newLayoutStore(t *testing.T) (*keys.BackendStore, storage.Backend) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := keys.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store, backend
}

// putKey generates a software ed25519 key at (sc, owner, name) and stores it.
func putKey(t *testing.T, store keys.Store, sc scope.Scope, owner, name string) error {
	t.Helper()
	k, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer k.Destroy()
	k.Scope, k.Owner, k.Name = sc, owner, name
	return store.Put(context.Background(), k)
}

// storedKeys returns every raw key in backend.
func storedKeys(t *testing.T, backend storage.Backend) []string {
	t.Helper()
	all, err := backend.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list backend: %v", err)
	}
	return all
}

func TestBackendStore_WritesScopeLayoutPath(t *testing.T) {
	tests := []struct {
		scope scope.Scope
		owner string
		want  string
	}{
		{scope.Tenant, "acme", "ssh/shared/keys/deploy"},
		{scope.User, "alice", "ssh/users/alice/keys/deploy"},
		{scope.Service, "ci", "ssh/services/ci/keys/deploy"},
	}
	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			store, backend := newLayoutStore(t)
			if err := putKey(t, store, tt.scope, tt.owner, "deploy"); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got := storedKeys(t, backend)
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("stored keys = %v, want [%s]", got, tt.want)
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

// TestBackendStore_TenantOwnerIsAuthoritative proves a tenant-scoped key,
// whose path carries no owner, is never aliased by another owner: it
// answers as missing, survives Delete, refuses overwrite and is filtered
// from the other owner's listing.
func TestBackendStore_TenantOwnerIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	store, backend := newLayoutStore(t)
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
	if got := storedKeys(t, backend); len(got) != 1 {
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

// TestBackendStore_List_FiltersByKind proves a listing keeps only key
// records: a known_hosts pin and an authorized_keys entry under the same
// scope and owner, and other SSH features sharing the view, never leak in.
func TestBackendStore_List_FiltersByKind(t *testing.T) {
	ctx := context.Background()
	store, backend := newLayoutStore(t)
	if err := putKey(t, store, scope.User, "alice", "laptop"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for _, foreign := range []string{
		"ssh/users/alice/known_hosts/laptop",
		"ssh/users/alice/authorized_keys/laptop",
		"ssh/sessions/laptop",
	} {
		if err := backend.Put(ctx, foreign, []byte("{not a key envelope")); err != nil {
			t.Fatalf("put %s: %v", foreign, err)
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

func TestBackendStore_Put_OwnerCheckStorageErrors(t *testing.T) {
	k, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer k.Destroy()
	k.Scope, k.Owner, k.Name = scope.Tenant, "acme", "deploy"

	failing, err := keys.NewBackendStore(keysFailingBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	var se *keys.StorageError
	if err := failing.Put(context.Background(), k); !errors.As(err, &se) || se.Op != "get" {
		t.Fatalf("Put over failing backend: want *StorageError{get}, got %T: %v", err, err)
	}

	corrupt, err := keys.NewBackendStore(keysCorruptBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	var ser *keys.SerializationError
	if err := corrupt.Put(context.Background(), k); !errors.As(err, &ser) {
		t.Fatalf("Put over corrupt record: want *SerializationError, got %T: %v", err, err)
	}
	if err := corrupt.Delete(context.Background(), scope.Tenant, "acme", "deploy"); !errors.As(err, &ser) {
		t.Fatalf("Delete over corrupt record: want *SerializationError, got %T: %v", err, err)
	}
}
