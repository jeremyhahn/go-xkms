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

package known_hosts_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// newLayoutStore returns a DAOStore over a fresh in-memory DAO factory, and
// the factory so a test can inspect the stored records.
func newLayoutStore(t *testing.T) (*known_hosts.DAOStore, *qrdbsdk.DAOFactory) {
	t.Helper()
	daos := testutil.NewMemoryDAOFactory()
	store, err := known_hosts.NewDAOStore(daos)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store, daos
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

// layoutPin returns a pin of pub for host at (sc, owner).
func layoutPin(pub ssh.PublicKey, sc scope.Scope, owner, host string) *known_hosts.Pin {
	return &known_hosts.Pin{
		Host:        host,
		Fingerprint: keys.Fingerprint(pub),
		Algorithm:   pub.Type(),
		PublicKey:   pub.Marshal(),
		Scope:       sc,
		Owner:       owner,
		AddedAt:     time.Now().UTC(),
		Source:      known_hosts.SourceManual,
	}
}

func TestKHStore_WritesScopeLayoutPath(t *testing.T) {
	tests := []struct {
		scope scope.Scope
		owner string
		want  string
	}{
		{scope.Tenant, "acme", "system/ssh/shared/known_hosts/bastion.example.com"},
		{scope.User, "alice", "system/ssh/users/alice/known_hosts/bastion.example.com"},
		{scope.Service, "ci", "system/ssh/services/ci/known_hosts/bastion.example.com"},
	}
	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			ctx := context.Background()
			store, daos := newLayoutStore(t)
			pub := newEd25519PublicKey(t)
			if err := store.Add(ctx, layoutPin(pub, tt.scope, tt.owner, "bastion.example.com")); err != nil {
				t.Fatalf("Add: %v", err)
			}
			got := storedPaths(t, daos, scope.KindKnownHosts)
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("stored paths = %v, want [%s]", got, tt.want)
			}
			if err := known_hosts.Verify(ctx, store, tt.scope, tt.owner, "bastion.example.com", pub); err != nil {
				t.Fatalf("Verify round trip: %v", err)
			}
		})
	}
}

// TestKHStore_PartitionsAreDisjoint proves a tenant partition neither sees
// nor alters the platform partition's pins.
func TestKHStore_PartitionsAreDisjoint(t *testing.T) {
	ctx := context.Background()
	store, daos := newLayoutStore(t)
	acme, err := store.Partition("acme")
	if err != nil {
		t.Fatalf("Partition: %v", err)
	}
	const host = "bastion.example.com"
	if err := store.Add(ctx, layoutPin(newEd25519PublicKey(t), scope.User, "alice", host)); err != nil {
		t.Fatalf("Add platform: %v", err)
	}
	var nf *known_hosts.NotFoundError
	if _, err := acme.Get(ctx, scope.User, "alice", host); !errors.As(err, &nf) {
		t.Fatalf("Get through tenant partition: want *NotFoundError, got %T: %v", err, err)
	}
	if err := acme.Add(ctx, layoutPin(newEd25519PublicKey(t), scope.User, "alice", host)); err != nil {
		t.Fatalf("Add tenant: %v", err)
	}
	if pins, err := acme.List(ctx, "", ""); err != nil || len(pins) != 1 {
		t.Fatalf("tenant List = %d pins, err %v; want 1", len(pins), err)
	}
	if got := storedPaths(t, daos, scope.KindKnownHosts); len(got) != 1 {
		t.Fatalf("platform partition holds %v, want its one pin", got)
	}
	if _, err := store.Partition("bad/tenant"); err == nil {
		t.Fatal("Partition(bad/tenant) succeeded")
	}
}

// TestKHStore_TenantOwnerIsAuthoritative proves a tenant-scoped pin, whose
// path carries no owner, is never aliased by another owner.
func TestKHStore_TenantOwnerIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	store, daos := newLayoutStore(t)
	pub := newEd25519PublicKey(t)
	const host = "bastion.example.com"
	if err := store.Add(ctx, layoutPin(pub, scope.Tenant, "acme", host)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var nf *known_hosts.NotFoundError
	if _, err := store.Get(ctx, scope.Tenant, "globex", host); !errors.As(err, &nf) {
		t.Fatalf("Get as other owner: want *NotFoundError, got %T: %v", err, err)
	}
	if err := known_hosts.Verify(ctx, store, scope.Tenant, "globex", host, pub); !errors.As(err, &nf) {
		t.Fatalf("Verify as other owner: want *NotFoundError, got %T: %v", err, err)
	}
	if err := store.Remove(ctx, scope.Tenant, "globex", host); !errors.As(err, &nf) {
		t.Fatalf("Remove as other owner: want *NotFoundError, got %T: %v", err, err)
	}
	if got := storedPaths(t, daos, scope.KindKnownHosts); len(got) != 1 {
		t.Fatalf("Remove as other owner removed the pin: %v", got)
	}

	var dup *known_hosts.DuplicateError
	if err := store.Add(ctx, layoutPin(newEd25519PublicKey(t), scope.Tenant, "globex", host)); !errors.As(err, &dup) {
		t.Fatalf("Add as other owner: want *DuplicateError, got %T: %v", err, err)
	}
	if err := known_hosts.Verify(ctx, store, scope.Tenant, "acme", host, pub); err != nil {
		t.Fatalf("owner's pin changed by refused Add: %v", err)
	}

	if pins, err := store.List(ctx, scope.Tenant, "globex"); err != nil || len(pins) != 0 {
		t.Fatalf("List other owner = %d pins, err %v; want none", len(pins), err)
	}
	if pins, err := store.List(ctx, scope.Tenant, "acme"); err != nil || len(pins) != 1 {
		t.Fatalf("List owner = %d pins, err %v; want 1", len(pins), err)
	}

	if err := store.Remove(ctx, scope.Tenant, "acme", host); err != nil {
		t.Fatalf("Remove as owner: %v", err)
	}
}

// TestKHStore_List_FiltersByKind proves a listing keeps only pins: a key
// and an authorized_keys entry under the same scope, owner and name never
// leak in.
func TestKHStore_List_FiltersByKind(t *testing.T) {
	ctx := context.Background()
	store, daos := newLayoutStore(t)
	if err := store.Add(ctx, layoutPin(newEd25519PublicKey(t), scope.User, "alice", "web")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	for _, kind := range []scope.Kind{scope.KindKeys, scope.KindAuthorizedKeys} {
		table, err := records.New[json.RawMessage](daos, kind)
		if err != nil {
			t.Fatalf("records.New(%s): %v", kind, err)
		}
		if _, err := table.Put(ctx, scope.User, "alice", "web", json.RawMessage(`{"line":"x"}`)); err != nil {
			t.Fatalf("put %s: %v", kind, err)
		}
	}
	for _, f := range []struct {
		scope scope.Scope
		owner string
	}{{"", ""}, {scope.User, ""}, {scope.User, "alice"}} {
		pins, err := store.List(ctx, f.scope, f.owner)
		if err != nil {
			t.Fatalf("List(%q, %q): %v", f.scope, f.owner, err)
		}
		if len(pins) != 1 || pins[0].Host != "web" {
			t.Fatalf("List(%q, %q) = %d pins, want only web", f.scope, f.owner, len(pins))
		}
	}
}

func TestKHStore_Remove_TenantStorageErrors(t *testing.T) {
	var se *known_hosts.StorageError
	if err := storeOver(t, khFailingBackend{}).Remove(context.Background(), scope.Tenant, "acme", "bastion.example.com"); !errors.As(err, &se) || se.Op != "delete" {
		t.Fatalf("Remove over failing backend: want *StorageError{delete}, got %T: %v", err, err)
	}
	if err := corruptStore(t).Remove(context.Background(), scope.Tenant, "acme", "bastion.example.com"); !errors.As(err, &se) {
		t.Fatalf("Remove over corrupt record: want *StorageError, got %T: %v", err, err)
	}
}
