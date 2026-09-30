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
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newLayoutStore returns a BackendStore over a fresh in-memory backend,
// and the backend so a test can inspect the raw storage keys.
func newLayoutStore(t *testing.T) (*known_hosts.BackendStore, storage.Backend) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	store, err := known_hosts.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store, backend
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
		{scope.Tenant, "acme", "ssh/shared/known_hosts/bastion.example.com"},
		{scope.User, "alice", "ssh/users/alice/known_hosts/bastion.example.com"},
		{scope.Service, "ci", "ssh/services/ci/known_hosts/bastion.example.com"},
	}
	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			ctx := context.Background()
			store, backend := newLayoutStore(t)
			pub := newEd25519PublicKey(t)
			if err := store.Add(ctx, layoutPin(pub, tt.scope, tt.owner, "bastion.example.com")); err != nil {
				t.Fatalf("Add: %v", err)
			}
			got, err := backend.List(ctx, "")
			if err != nil {
				t.Fatalf("list backend: %v", err)
			}
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("stored keys = %v, want [%s]", got, tt.want)
			}
			if err := known_hosts.Verify(ctx, store, tt.scope, tt.owner, "bastion.example.com", pub); err != nil {
				t.Fatalf("Verify round trip: %v", err)
			}
		})
	}
}

// TestKHStore_TenantOwnerIsAuthoritative proves a tenant-scoped pin, whose
// path carries no owner, is never aliased by another owner.
func TestKHStore_TenantOwnerIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	store, backend := newLayoutStore(t)
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
	if got, err := backend.List(ctx, ""); err != nil || len(got) != 1 {
		t.Fatalf("Remove as other owner removed the pin: %v, %v", got, err)
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
// and an authorized_keys entry under the same scope and owner never leak in.
func TestKHStore_List_FiltersByKind(t *testing.T) {
	ctx := context.Background()
	store, backend := newLayoutStore(t)
	if err := store.Add(ctx, layoutPin(newEd25519PublicKey(t), scope.User, "alice", "web")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	for _, foreign := range []string{
		"ssh/users/alice/keys/web",
		"ssh/users/alice/authorized_keys/web",
		"ssh/profiles/web",
	} {
		if err := backend.Put(ctx, foreign, []byte("{not a pin envelope")); err != nil {
			t.Fatalf("put %s: %v", foreign, err)
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
	failing, err := known_hosts.NewBackendStore(khFailingBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	var se *known_hosts.StorageError
	if err := failing.Remove(context.Background(), scope.Tenant, "acme", "web"); !errors.As(err, &se) || se.Op != "get" {
		t.Fatalf("Remove over failing backend: want *StorageError{get}, got %T: %v", err, err)
	}
	corrupt, err := known_hosts.NewBackendStore(khCorruptBackend{})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	var ser *known_hosts.SerializationError
	if err := corrupt.Remove(context.Background(), scope.Tenant, "acme", "web"); !errors.As(err, &ser) {
		t.Fatalf("Remove over corrupt record: want *SerializationError, got %T: %v", err, err)
	}
}
