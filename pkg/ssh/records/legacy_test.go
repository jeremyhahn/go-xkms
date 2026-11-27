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

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

func acceptAll(*Entity[body]) error { return nil }

func TestTableImportReadsBack(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)
	acme, err := table.Partition("acme")
	if err != nil {
		t.Fatalf("Partition: %v", err)
	}
	data := []byte(`{"v":2,"scope":"user","owner":"alice","name":"id","value":"secret"}`)

	if err := acme.Import(ctx, "ssh/users/alice/keys/id", data, acceptAll); err != nil {
		t.Fatalf("Import: %v", err)
	}
	// A second import of the same record overwrites it in place.
	if err := acme.Import(ctx, "ssh/users/alice/keys/id", data, acceptAll); err != nil {
		t.Fatalf("second Import: %v", err)
	}

	e, found, err := acme.Get(ctx, scope.User, "alice", "id")
	if err != nil || !found {
		t.Fatalf("Get = %v, %v", found, err)
	}
	if e.Body.Value != "secret" || e.Path != "acme/ssh/users/alice/keys/id" {
		t.Fatalf("imported entity = %+v", e)
	}
	if _, found, _ := table.Get(ctx, scope.User, "alice", "id"); found {
		t.Fatal("record imported into the acme partition is visible in the system partition")
	}
}

func TestTableImportNamesByHost(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)
	data := []byte(`{"scope":"tenant","owner":"alice","host":"example.com","value":"pin"}`)

	if err := table.Import(ctx, "ssh/shared/keys/example.com", data, acceptAll); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if _, found, err := table.Get(ctx, scope.Tenant, "alice", "example.com"); err != nil || !found {
		t.Fatalf("Get = %v, %v", found, err)
	}
}

func TestTableImportRejectsBadRecords(t *testing.T) {
	ctx := context.Background()
	rejected := errors.New("rejected")
	tests := []struct {
		name  string
		rel   string
		data  string
		check func(*Entity[body]) error
		want  any
	}{
		{"not json", "ssh/shared/keys/k", `{`, acceptAll, new(*LegacyRecordError)},
		{"bad body", "ssh/shared/keys/k", `{"scope":"tenant","owner":"alice","name":"k","value":7}`, acceptAll, new(*LegacyRecordError)},
		{"bad scope", "ssh/shared/keys/k", `{"scope":"galaxy","name":"k"}`, acceptAll, new(*LegacyRecordError)},
		{"other path", "ssh/shared/keys/k", `{"scope":"tenant","owner":"alice","name":"other"}`, acceptAll, new(*LegacyPathError)},
		{"check fails", "ssh/shared/keys/k", `{"scope":"tenant","owner":"alice","name":"k"}`,
			func(*Entity[body]) error { return rejected }, new(*LegacyRecordError)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := newTable(t)
			err := table.Import(ctx, tt.rel, []byte(tt.data), tt.check)
			if err == nil || !errors.As(err, tt.want) {
				t.Fatalf("Import error = %T %v, want %T", err, err, tt.want)
			}
			if _, found, _ := table.Get(ctx, scope.Tenant, "alice", "k"); found {
				t.Fatal("a rejected record was written")
			}
		})
	}
}

func TestTableImportOwnerConflict(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)
	if _, err := table.Create(ctx, scope.Tenant, "bob", "k", body{Value: "bob's"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	data := []byte(`{"scope":"tenant","owner":"alice","name":"k","value":"alice's"}`)

	var conflict *LegacyOwnerConflictError
	if err := table.Import(ctx, "ssh/shared/keys/k", data, acceptAll); !errors.As(err, &conflict) {
		t.Fatalf("Import error = %v, want *LegacyOwnerConflictError", err)
	}
	e, found, err := table.Get(ctx, scope.Tenant, "bob", "k")
	if err != nil || !found || e.Body.Value != "bob's" {
		t.Fatalf("bob's record = %+v, %v, %v", e, found, err)
	}
}

func TestTableImportWipesTheBody(t *testing.T) {
	ctx := context.Background()
	table := newTable(t)
	wiped := 0
	data := []byte(`{"scope":"tenant","owner":"alice","name":"k","value":"v"}`)
	check := func(e *Entity[body]) error {
		e.Body.wiped = &wiped
		return nil
	}
	if err := table.Import(ctx, "ssh/shared/keys/k", data, check); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if wiped != 1 {
		t.Fatalf("body wiped %d times, want 1", wiped)
	}
}

func TestLegacyErrors(t *testing.T) {
	inner := errors.New("boom")
	recordErr := &LegacyRecordError{Path: "ssh/shared/keys/k", Err: inner}
	if !errors.Is(recordErr, inner) || recordErr.Error() != "ssh/records: legacy record ssh/shared/keys/k: boom" {
		t.Fatalf("LegacyRecordError = %q", recordErr.Error())
	}
	pathErr := &LegacyPathError{Path: "ssh/shared/keys/k", Record: "ssh/shared/keys/j"}
	if pathErr.Error() != "ssh/records: legacy record ssh/shared/keys/k names the record ssh/shared/keys/j" {
		t.Fatalf("LegacyPathError = %q", pathErr.Error())
	}
	conflict := &LegacyOwnerConflictError{Path: "ssh/shared/keys/k"}
	if conflict.Error() != "ssh/records: legacy record ssh/shared/keys/k is held by another owner" {
		t.Fatalf("LegacyOwnerConflictError = %q", conflict.Error())
	}
}
