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

package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newStores returns fresh Stores over an in-memory DAO factory.
func newStores(t *testing.T) *sdkssh.Stores {
	t.Helper()
	stores, err := sdkssh.NewStores(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewStores: %v", err)
	}
	return stores
}

// TestNewStores_NilDAOFactory rejects a nil factory with NilInputError.
func TestNewStores_NilDAOFactory(t *testing.T) {
	_, err := sdkssh.NewStores(nil)
	var nie *sdkssh.NilInputError
	if !errors.As(err, &nie) || nie.Field != "daos" {
		t.Fatalf("expected NilInputError{daos}, got %T: %v", err, err)
	}
}

// TestStores_PartitionIsolatesTenants proves a host-key pin written through
// one tenant's partition is invisible through another's and through the
// platform partition, while the partition that wrote it reads it back.
func TestStores_PartitionIsolatesTenants(t *testing.T) {
	ctx := context.Background()
	stores := newStores(t)
	acme, err := stores.Partition("acme")
	if err != nil {
		t.Fatalf("Partition(acme): %v", err)
	}
	globex, err := stores.Partition("globex")
	if err != nil {
		t.Fatalf("Partition(globex): %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hostKey, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	pin := pkgknownhosts.PinFromPublicKey("web1.example.com", "tenant", "acme", hostKey, "")
	if err := acme.KnownHosts.Add(ctx, pin); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if got, err := acme.KnownHosts.List(ctx, "tenant", "acme"); err != nil || len(got) != 1 {
		t.Fatalf("acme partition: want 1 pin, got %d (%v)", len(got), err)
	}
	if got, err := globex.KnownHosts.List(ctx, "tenant", "acme"); err != nil || len(got) != 0 {
		t.Fatalf("globex partition: want no pins, got %d (%v)", len(got), err)
	}
	if got, err := stores.KnownHosts.List(ctx, "tenant", "acme"); err != nil || len(got) != 0 {
		t.Fatalf("platform partition: want no pins, got %d (%v)", len(got), err)
	}
}

// TestStores_PartitionRejectsInvalidTenant refuses a tenant ID that cannot
// root a partition.
func TestStores_PartitionRejectsInvalidTenant(t *testing.T) {
	if _, err := newStores(t).Partition("../escape"); err == nil {
		t.Fatal("expected an error for an invalid tenant ID")
	}
}
