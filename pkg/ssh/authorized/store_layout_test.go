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

package authorized_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// addEntry stores a fresh ed25519 entry at (sc, owner, name).
func addEntry(t *testing.T, store authorized.Store, sc scope.Scope, owner, name string) error {
	t.Helper()
	k := generateKey(t, keys.AlgorithmEd25519)
	defer k.Destroy()
	return store.Add(context.Background(), sc, owner, name, &authorized.Entry{Key: k, Comment: name})
}

func TestStore_WritesScopeLayoutPath(t *testing.T) {
	tests := []struct {
		scope scope.Scope
		owner string
		want  string
	}{
		{scope.Tenant, "acme", "ssh/shared/authorized_keys/ops"},
		{scope.User, "alice", "ssh/users/alice/authorized_keys/ops"},
		{scope.Service, "ci", "ssh/services/ci/authorized_keys/ops"},
	}
	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			ctx := context.Background()
			store, backend := newStore(t)
			if err := addEntry(t, store, tt.scope, tt.owner, "ops"); err != nil {
				t.Fatalf("Add: %v", err)
			}
			got, err := backend.List(ctx, "")
			if err != nil {
				t.Fatalf("list backend: %v", err)
			}
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("stored keys = %v, want [%s]", got, tt.want)
			}
			rec, err := store.Get(ctx, tt.scope, tt.owner, "ops")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if rec.Scope != tt.scope || rec.Owner != tt.owner || rec.Name != "ops" {
				t.Fatalf("round trip = %s/%s/%s", rec.Scope, rec.Owner, rec.Name)
			}
		})
	}
}

// TestStore_TenantOwnerIsAuthoritative proves a tenant-scoped entry, whose
// path carries no owner, is never aliased by another owner.
func TestStore_TenantOwnerIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	store, backend := newStore(t)
	if err := addEntry(t, store, scope.Tenant, "acme", "ops"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var nf *authorized.NotFoundError
	if _, err := store.Get(ctx, scope.Tenant, "globex", "ops"); !errors.As(err, &nf) {
		t.Fatalf("Get as other owner: want *NotFoundError, got %T: %v", err, err)
	}
	if err := store.Remove(ctx, scope.Tenant, "globex", "ops"); !errors.As(err, &nf) {
		t.Fatalf("Remove as other owner: want *NotFoundError, got %T: %v", err, err)
	}
	if got, err := backend.List(ctx, ""); err != nil || len(got) != 1 {
		t.Fatalf("Remove as other owner removed the entry: %v, %v", got, err)
	}

	var dup *authorized.DuplicateError
	if err := addEntry(t, store, scope.Tenant, "globex", "ops"); !errors.As(err, &dup) {
		t.Fatalf("Add as other owner: want *DuplicateError, got %T: %v", err, err)
	}
	rec, err := store.Get(ctx, scope.Tenant, "acme", "ops")
	if err != nil || rec.Owner != "acme" {
		t.Fatalf("owner's entry after refused Add: %v, %v", rec, err)
	}

	if recs, err := store.List(ctx, scope.Tenant, "globex"); err != nil || len(recs) != 0 {
		t.Fatalf("List other owner = %d entries, err %v; want none", len(recs), err)
	}
	if recs, err := store.List(ctx, scope.Tenant, "acme"); err != nil || len(recs) != 1 {
		t.Fatalf("List owner = %d entries, err %v; want 1", len(recs), err)
	}
	if err := store.Remove(ctx, scope.Tenant, "acme", "ops"); err != nil {
		t.Fatalf("Remove as owner: %v", err)
	}
}

// TestStore_List_FiltersByKind proves a listing keeps only authorized_keys
// entries: a key and a known_hosts pin under the same scope and owner never
// leak in.
func TestStore_List_FiltersByKind(t *testing.T) {
	ctx := context.Background()
	store, backend := newStore(t)
	if err := addEntry(t, store, scope.Service, "ci", "deploy"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	for _, foreign := range []string{
		"ssh/services/ci/keys/deploy",
		"ssh/services/ci/known_hosts/deploy",
		"ssh/sessions/deploy",
	} {
		if err := backend.Put(ctx, foreign, []byte("{not an entry envelope")); err != nil {
			t.Fatalf("put %s: %v", foreign, err)
		}
	}
	for _, f := range []struct {
		scope scope.Scope
		owner string
	}{{"", ""}, {scope.Service, ""}, {scope.Service, "ci"}} {
		recs, err := store.List(ctx, f.scope, f.owner)
		if err != nil {
			t.Fatalf("List(%q, %q): %v", f.scope, f.owner, err)
		}
		if len(recs) != 1 || recs[0].Name != "deploy" {
			t.Fatalf("List(%q, %q) = %d entries, want only deploy", f.scope, f.owner, len(recs))
		}
	}
}

func TestStore_Remove_TenantStorageErrors(t *testing.T) {
	failing, err := authorized.NewBackendStore(failingBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	var se *authorized.StorageError
	if err := failing.Remove(context.Background(), scope.Tenant, "acme", "ops"); !errors.As(err, &se) || se.Op != "get" {
		t.Fatalf("Remove over failing backend: want *StorageError{get}, got %T: %v", err, err)
	}
	corrupt, err := authorized.NewBackendStore(corruptBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	var ser *authorized.SerializationError
	if err := corrupt.Remove(context.Background(), scope.Tenant, "acme", "ops"); !errors.As(err, &ser) {
		t.Fatalf("Remove over corrupt record: want *SerializationError, got %T: %v", err, err)
	}
}
