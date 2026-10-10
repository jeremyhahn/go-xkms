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

package authorized_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// TestStore_List_NamesRoundTripToGetAndRemove is the regression test for
// the bug where List discarded the stored name: every listed Record must
// carry the name it was filed under, and that name alone must be enough
// to Get and then Remove the entry. That is the user journey — list,
// then act on what you listed — that the old []*Entry return broke.
func TestStore_List_NamesRoundTripToGetAndRemove(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	names := []string{"laptop", "desktop", "phone", "backup-runner"}
	fingerprints := make(map[string]string, len(names))
	for _, name := range names {
		k := generateKey(t, keys.AlgorithmEd25519)
		defer k.Destroy()
		fingerprints[name] = k.Fingerprint
		entry := &authorized.Entry{Key: k, Comment: name + "@alice", Options: []string{"no-pty"}}
		if err := store.Add(ctx, scope.User, "alice", name, entry); err != nil {
			t.Fatalf("Add %s: %v", name, err)
		}
	}

	list, err := store.List(ctx, scope.User, "alice")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != len(names) {
		t.Fatalf("List returned %d records, want %d", len(list), len(names))
	}

	seen := make(map[string]bool, len(list))
	for i, rec := range list {
		if rec == nil || rec.Entry == nil {
			t.Fatalf("record %d is degenerate: %+v", i, rec)
		}
		if rec.Name == "" {
			t.Fatalf("record %d has empty Name — the stored name was discarded on read", i)
		}
		if _, ok := fingerprints[rec.Name]; !ok {
			t.Fatalf("record %d has unknown Name %q", i, rec.Name)
		}
		if seen[rec.Name] {
			t.Fatalf("record %d repeats Name %q", i, rec.Name)
		}
		seen[rec.Name] = true

		if rec.Scope != scope.User {
			t.Fatalf("record %q Scope = %q, want %q", rec.Name, rec.Scope, scope.User)
		}
		if rec.Owner != "alice" {
			t.Fatalf("record %q Owner = %q, want alice", rec.Name, rec.Owner)
		}
		if rec.AddedAt.IsZero() {
			t.Fatalf("record %q AddedAt is zero", rec.Name)
		}
		if got := rec.Entry.Key.Fingerprint; got != fingerprints[rec.Name] {
			t.Fatalf("record %q fingerprint = %s, want %s", rec.Name, got, fingerprints[rec.Name])
		}
	}

	// Feed each listed name straight back into Get and Remove — the
	// thing a caller could not do while List dropped the name.
	for _, rec := range list {
		got, gerr := store.Get(ctx, rec.Scope, rec.Owner, rec.Name)
		if gerr != nil {
			t.Fatalf("Get(%s/%s/%s) from listed record: %v", rec.Scope, rec.Owner, rec.Name, gerr)
		}
		if got.Name != rec.Name {
			t.Fatalf("Get returned Name %q, want %q", got.Name, rec.Name)
		}
		if got.Entry.Key.Fingerprint != rec.Entry.Key.Fingerprint {
			t.Fatalf("Get(%q) returned a different key than List", rec.Name)
		}
		if rerr := store.Remove(ctx, rec.Scope, rec.Owner, rec.Name); rerr != nil {
			t.Fatalf("Remove(%s/%s/%s) from listed record: %v", rec.Scope, rec.Owner, rec.Name, rerr)
		}
	}

	empty, err := store.List(ctx, scope.User, "alice")
	if err != nil {
		t.Fatalf("List after removals: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected every listed record to be removable, %d remain", len(empty))
	}
}

// TestStore_List_ScopeOwnerFiltering confirms the prefix filters still
// select correctly, and that each Record reports the coordinates it was
// actually stored under rather than the ones the caller asked for.
func TestStore_List_ScopeOwnerFiltering(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	type fixture struct {
		sc    scope.Scope
		owner string
		name  string
	}
	fixtures := []fixture{
		{scope.User, "alice", "laptop"},
		{scope.User, "alice", "phone"},
		{scope.User, "bob", "laptop"},
		{scope.Tenant, "acme", "shared"},
	}
	for _, f := range fixtures {
		k := generateKey(t, keys.AlgorithmEd25519)
		defer k.Destroy()
		if err := store.Add(ctx, f.sc, f.owner, f.name, &authorized.Entry{Key: k}); err != nil {
			t.Fatalf("Add %s/%s/%s: %v", f.sc, f.owner, f.name, err)
		}
	}

	cases := []struct {
		label string
		sc    scope.Scope
		owner string
		want  []string // "<scope>/<owner>/<name>"
	}{
		{"all scopes", scope.Scope(""), "", []string{
			"tenant/acme/shared", "user/alice/laptop", "user/alice/phone", "user/bob/laptop",
		}},
		{"user scope", scope.User, "", []string{
			"user/alice/laptop", "user/alice/phone", "user/bob/laptop",
		}},
		{"user/alice", scope.User, "alice", []string{
			"user/alice/laptop", "user/alice/phone",
		}},
		{"tenant/acme", scope.Tenant, "acme", []string{"tenant/acme/shared"}},
		{"unknown owner", scope.User, "carol", nil},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			list, err := store.List(ctx, tc.sc, tc.owner)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(list) != len(tc.want) {
				t.Fatalf("List returned %d records, want %d", len(list), len(tc.want))
			}
			got := make(map[string]bool, len(list))
			for _, rec := range list {
				got[string(rec.Scope)+"/"+rec.Owner+"/"+rec.Name] = true
			}
			for _, want := range tc.want {
				if !got[want] {
					t.Fatalf("List missing %q; got %v", want, got)
				}
			}
		})
	}
}

// plantedEnvelope is an authorized_keys record body written around the
// store, so a test can plant a record the store itself never writes.
type plantedEnvelope struct {
	AddedAt time.Time `json:"added"`
	Line    string    `json:"line"`
}

// storeWithPlanted returns a DAOStore whose user-scoped record alice/name
// holds env.
func storeWithPlanted(t *testing.T, name string, env plantedEnvelope) *authorized.DAOStore {
	t.Helper()
	daos := testutil.NewMemoryDAOFactory()
	table, err := records.New[plantedEnvelope](daos, scope.KindAuthorizedKeys)
	if err != nil {
		t.Fatalf("records.New: %v", err)
	}
	if _, err := table.Put(context.Background(), scope.User, "alice", name, env); err != nil {
		t.Fatalf("plant record: %v", err)
	}
	store, err := authorized.NewDAOStore(daos)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return store
}

// TestStore_StoredRecordMalformedLine is the bad-input companion: a record
// whose line is garbage must surface a *MalformedLineError from both Get and
// List, not a partially populated Record.
func TestStore_StoredRecordMalformedLine(t *testing.T) {
	store := storeWithPlanted(t, "corrupt-line", plantedEnvelope{
		AddedAt: time.Now().UTC(),
		Line:    "this is not an authorized_keys line",
	})
	ctx := context.Background()

	got, err := store.Get(ctx, scope.User, "alice", "corrupt-line")
	var malformed *authorized.MalformedLineError
	if !errors.As(err, &malformed) {
		t.Fatalf("Get: expected MalformedLineError, got %T: %v", err, err)
	}
	if got != nil {
		t.Fatalf("Get: expected nil record alongside error, got %+v", got)
	}

	list, err := store.List(ctx, scope.User, "alice")
	if !errors.As(err, &malformed) {
		t.Fatalf("List: expected MalformedLineError, got %T: %v", err, err)
	}
	if list != nil {
		t.Fatalf("List: expected nil slice alongside error, got %+v", list)
	}
}

// TestVerify_ReturnsNamedRecord asserts Verify identifies which stored
// entry granted access — previously impossible, since it returned a bare
// Entry.
func TestVerify_ReturnsNamedRecord(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()

	decoy := generateKey(t, keys.AlgorithmEd25519)
	defer decoy.Destroy()
	if err := store.Add(ctx, scope.User, "alice", "decoy", &authorized.Entry{Key: decoy}); err != nil {
		t.Fatalf("Add decoy: %v", err)
	}
	match := generateKey(t, keys.AlgorithmEd25519)
	defer match.Destroy()
	if err := store.Add(ctx, scope.User, "alice", "yubikey", &authorized.Entry{Key: match}); err != nil {
		t.Fatalf("Add match: %v", err)
	}

	rec, err := authorized.Verify(ctx, store, scope.User, "alice", match.PublicKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rec.Name != "yubikey" {
		t.Fatalf("Verify Name = %q, want yubikey", rec.Name)
	}
	if rec.Scope != scope.User || rec.Owner != "alice" {
		t.Fatalf("Verify coordinates = %s/%s, want user/alice", rec.Scope, rec.Owner)
	}

	// The name Verify reports is the one that revokes the access.
	if err := store.Remove(ctx, rec.Scope, rec.Owner, rec.Name); err != nil {
		t.Fatalf("Remove by verified name: %v", err)
	}
	if _, err := authorized.Verify(ctx, store, scope.User, "alice", match.PublicKey); err == nil {
		t.Fatal("expected Verify to fail after the named entry was removed")
	}
}
