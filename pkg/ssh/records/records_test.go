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

package records

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// body is a record body that counts its wipes.
type body struct {
	Value string `json:"value"`
	wiped *int
}

func (b *body) Wipe() {
	if b.wiped != nil {
		*b.wiped++
	}
}

func newTable(t *testing.T) *Table[body] {
	t.Helper()
	table, err := New[body](testutil.NewMemoryDAOFactory(), scope.KindKeys)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return table
}

func TestTableRoundTrip(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)

	stored, err := table.Create(ctx, scope.User, "alice", "id1", body{Value: "v1"})
	if err != nil || !stored {
		t.Fatalf("Create = %v, %v; want stored", stored, err)
	}
	got, found, err := table.Get(ctx, scope.User, "alice", "id1")
	if err != nil || !found {
		t.Fatalf("Get = %v, %v", found, err)
	}
	if got.Body.Value != "v1" || got.Scope != scope.User || got.Owner != "alice" || got.Name != "id1" {
		t.Fatalf("Get = %+v", got)
	}
	if got.Path != "system/ssh/users/alice/keys/id1" || got.Partition != "system/" {
		t.Fatalf("Path = %q, Partition = %q", got.Path, got.Partition)
	}

	if ok, err := table.Put(ctx, scope.User, "alice", "id1", body{Value: "v2"}); err != nil || !ok {
		t.Fatalf("Put = %v, %v", ok, err)
	}
	got, _, err = table.Get(ctx, scope.User, "alice", "id1")
	if err != nil || got.Body.Value != "v2" {
		t.Fatalf("Get after Put = %+v, %v", got, err)
	}

	if ok, err := table.Delete(ctx, scope.User, "alice", "id1"); err != nil || !ok {
		t.Fatalf("Delete = %v, %v", ok, err)
	}
	if _, found, err := table.Get(ctx, scope.User, "alice", "id1"); err != nil || found {
		t.Fatalf("Get after Delete = %v, %v; want missing", found, err)
	}
	if ok, err := table.Delete(ctx, scope.User, "alice", "id1"); err != nil || ok {
		t.Fatalf("second Delete = %v, %v; want false", ok, err)
	}
}

func TestTableCreateRefusesExisting(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)
	if _, err := table.Create(ctx, scope.Tenant, "alice", "shared", body{Value: "a"}); err != nil {
		t.Fatal(err)
	}
	// A tenant-scoped path carries no owner, so it exists for every owner.
	stored, err := table.Create(ctx, scope.Tenant, "bob", "shared", body{Value: "b"})
	if err != nil || stored {
		t.Fatalf("Create over existing = %v, %v; want refused", stored, err)
	}
	got, _, err := table.Get(ctx, scope.Tenant, "alice", "shared")
	if err != nil || got.Body.Value != "a" {
		t.Fatalf("existing record changed: %+v, %v", got, err)
	}
}

func TestTableOtherOwnerAnswersAsMissing(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)
	if _, err := table.Put(ctx, scope.Tenant, "alice", "shared", body{Value: "a"}); err != nil {
		t.Fatal(err)
	}
	wiped := 0
	table.records = wipeCounting(table.records, &wiped)

	if _, found, err := table.Get(ctx, scope.Tenant, "bob", "shared"); err != nil || found {
		t.Fatalf("Get by other owner = %v, %v; want missing", found, err)
	}
	if ok, err := table.Put(ctx, scope.Tenant, "bob", "shared", body{Value: "b"}); err != nil || ok {
		t.Fatalf("Put by other owner = %v, %v; want refused", ok, err)
	}
	if ok, err := table.Delete(ctx, scope.Tenant, "bob", "shared"); err != nil || ok {
		t.Fatalf("Delete by other owner = %v, %v; want refused", ok, err)
	}
	if wiped != 3 {
		t.Fatalf("records read and withheld were wiped %d times, want 3", wiped)
	}
	got, found, err := table.Get(ctx, scope.Tenant, "alice", "shared")
	if err != nil || !found || got.Body.Value != "a" {
		t.Fatalf("owner's record = %+v, %v, %v", got, found, err)
	}
}

func TestTableListFiltersAndPartitions(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)
	acme, err := table.Partition("acme")
	if err != nil {
		t.Fatal(err)
	}
	puts := []struct {
		table *Table[body]
		sc    scope.Scope
		owner string
		name  string
	}{
		{table, scope.User, "alice", "b"},
		{table, scope.User, "alice", "a"},
		{table, scope.User, "bob", "c"},
		{table, scope.Tenant, "alice", "d"},
		{table, scope.Service, "svc", "e"},
		{acme, scope.User, "alice", "f"},
	}
	for _, p := range puts {
		if _, err := p.table.Put(ctx, p.sc, p.owner, p.name, body{Value: p.name}); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		table *Table[body]
		sc    scope.Scope
		owner string
		want  []string
	}{
		{"everything", table, "", "", []string{"e", "d", "a", "b", "c"}},
		{"scope ignores owner when empty", table, "", "bob", []string{"e", "d", "a", "b", "c"}},
		{"one scope", table, scope.User, "", []string{"a", "b", "c"}},
		{"one owner", table, scope.User, "alice", []string{"a", "b"}},
		{"tenant scope by owner", table, scope.Tenant, "bob", nil},
		{"other partition", acme, "", "", []string{"f"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.table.List(ctx, tc.sc, tc.owner)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(got))
			for _, e := range got {
				names = append(names, e.Name)
			}
			if len(names) != len(tc.want) {
				t.Fatalf("List = %v, want %v", names, tc.want)
			}
			for i := range names {
				if names[i] != tc.want[i] {
					t.Fatalf("List = %v, want %v", names, tc.want)
				}
			}
		})
	}
	if _, found, err := acme.Get(ctx, scope.User, "alice", "a"); err != nil || found {
		t.Fatalf("partition leaked a record: %v, %v", found, err)
	}
}

func TestTableInvalidInputs(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)

	var kindErr *scope.KindInvalidError
	if _, err := New[body](testutil.NewMemoryDAOFactory(), scope.Kind("bogus")); !errors.As(err, &kindErr) {
		t.Fatalf("New(bogus kind) = %v, want *KindInvalidError", err)
	}
	var storeErr *StoreError
	if _, err := New[body](nil, scope.KindKeys); !errors.As(err, &storeErr) || !errors.Is(err, dao.ErrNilFactory) {
		t.Fatalf("New(nil) = %v, want *StoreError wrapping ErrNilFactory", err)
	}
	if _, err := table.Partition("bad/tenant"); err == nil {
		t.Fatal("Partition(bad/tenant) succeeded")
	}
	var malformed *scope.KeyIDMalformedError
	if _, _, err := table.Get(ctx, scope.User, "", "x"); !errors.As(err, &malformed) {
		t.Fatalf("Get(empty owner) = %v, want *KeyIDMalformedError", err)
	}
	if _, err := table.Create(ctx, scope.User, "alice", "a/b", body{}); !errors.As(err, &malformed) {
		t.Fatalf("Create(name with /) = %v, want *KeyIDMalformedError", err)
	}
	if _, err := table.Put(ctx, scope.Scope("bogus"), "alice", "a", body{}); err == nil {
		t.Fatal("Put(bogus scope) succeeded")
	}
	if _, err := table.Delete(ctx, scope.User, "alice", ""); !errors.As(err, &malformed) {
		t.Fatalf("Delete(empty name) = %v, want *KeyIDMalformedError", err)
	}
	var scopeErr *scope.ScopeInvalidError
	if _, err := table.List(ctx, scope.Scope("bogus"), ""); !errors.As(err, &scopeErr) {
		t.Fatalf("List(bogus scope) = %v, want *ScopeInvalidError", err)
	}
	if _, err := table.List(ctx, scope.User, "a/b"); !errors.As(err, &malformed) {
		t.Fatalf("List(owner with /) = %v, want *KeyIDMalformedError", err)
	}
}

// TestTableOverKVAdapter runs the table over a storage.Backend adapted to a
// KVStore -- the store xkey serves its databases from -- which maintains no
// indexes, so List plans a full scan.
func TestTableOverKVAdapter(t *testing.T) {
	ctx := context.Background()
	kv, err := kvadapter.New(storage.New())
	if err != nil {
		t.Fatal(err)
	}
	table, err := New[body](dao.NewStoreFactory(kv), scope.KindKnownHosts)
	if err != nil {
		t.Fatal(err)
	}
	if stored, err := table.Create(ctx, scope.User, "alice", "host", body{Value: "v"}); err != nil || !stored {
		t.Fatalf("Create = %v, %v", stored, err)
	}
	if ok, err := table.Put(ctx, scope.User, "alice", "host", body{Value: "w"}); err != nil || !ok {
		t.Fatalf("Put = %v, %v", ok, err)
	}
	got, err := table.List(ctx, scope.User, "alice")
	if err != nil || len(got) != 1 || got[0].Body.Value != "w" {
		t.Fatalf("List = %+v, %v", got, err)
	}
	if ok, err := table.Delete(ctx, scope.User, "alice", "host"); err != nil || !ok {
		t.Fatalf("Delete = %v, %v", ok, err)
	}
}

func TestErrors(t *testing.T) {
	inner := errors.New("boom")
	storeErr := &StoreError{Op: "get", Path: "system/x", Err: inner}
	if !errors.Is(storeErr, inner) || storeErr.Error() != "ssh/records: get system/x: boom" {
		t.Fatalf("StoreError = %q", storeErr.Error())
	}
	conflict := &ConflictError{Op: "put", Path: "system/x"}
	if conflict.Error() == "" {
		t.Fatal("ConflictError has no message")
	}
}

// wipeCounting returns d with every body it decodes counting its wipes into
// n.
func wipeCounting(d qrdbsdk.GenericDAO[*Entity[body]], n *int) qrdbsdk.GenericDAO[*Entity[body]] {
	return &countingDAO{GenericDAO: d, n: n}
}

// countingDAO stamps the wipe counter on every record it reads.
type countingDAO struct {
	qrdbsdk.GenericDAO[*Entity[body]]
	n *int
}

func (d *countingDAO) GetByNaturalKey(ctx context.Context, value string) (*Entity[body], error) {
	e, err := d.GenericDAO.GetByNaturalKey(ctx, value)
	if e != nil {
		e.Body.wiped = d.n
	}
	return e, err
}
