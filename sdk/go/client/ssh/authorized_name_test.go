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

package ssh_test

import (
	"context"
	"errors"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// addAuthorized generates a key and pins its public half as an
// authorized entry under (scope, owner, name). It returns the emitted
// authorized_keys line.
func addAuthorized(t *testing.T, client sdkssh.Client, scope, owner, name string) string {
	t.Helper()
	ctx := context.Background()
	gen, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope:     scope,
		Owner:     owner,
		Name:      "key-" + name,
		Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate %s: %v", name, err)
	}
	auth := client.AuthorizedKeys()
	line, err := auth.Emit(ctx, sdkssh.EmitRequest{
		PublicKey: gen.PublicKey,
		Comment:   name + "@" + owner,
	})
	if err != nil {
		t.Fatalf("Emit %s: %v", name, err)
	}
	if err := auth.Add(ctx, sdkssh.AddAuthorizedKeyRequest{
		Scope: scope, Owner: owner, Name: name, Line: line,
	}); err != nil {
		t.Fatalf("Add %s: %v", name, err)
	}
	return line
}

// TestAuthorizedKeys_List_ReturnsUsableNames is the SDK-level regression
// test for the empty-name bug: ssh.authorizedKeys.list used to hand back
// entries with Name == "", so a client could not act on anything it
// listed. Every listed entry must now carry its stored name, scope and
// owner, and those must resolve through Get and Remove.
func TestAuthorizedKeys_List_ReturnsUsableNames(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()

	lines := map[string]string{}
	for _, name := range []string{"laptop", "desktop", "ci-runner"} {
		lines[name] = addAuthorized(t, client, "user", "alice", name)
	}

	auth := client.AuthorizedKeys()
	list, err := auth.List(ctx, sdkssh.ListAuthorizedKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != len(lines) {
		t.Fatalf("List returned %d entries, want %d", len(list), len(lines))
	}

	for i, e := range list {
		if e == nil {
			t.Fatalf("entry %d is nil", i)
		}
		if e.Name == "" {
			t.Fatalf("entry %d has empty Name — list results are unusable for Get/Remove", i)
		}
		want, ok := lines[e.Name]
		if !ok {
			t.Fatalf("entry %d has unexpected Name %q", i, e.Name)
		}
		if e.Scope != "user" || e.Owner != "alice" {
			t.Fatalf("entry %q coordinates = %s/%s, want user/alice", e.Name, e.Scope, e.Owner)
		}
		if e.Line != want {
			t.Fatalf("entry %q line = %q, want %q", e.Name, e.Line, want)
		}
	}

	// Round-trip every listed name through Get and Remove.
	for _, e := range list {
		got, gerr := auth.Get(ctx, e.Scope, e.Owner, e.Name)
		if gerr != nil {
			t.Fatalf("Get(%s/%s/%s): %v", e.Scope, e.Owner, e.Name, gerr)
		}
		if got.Name != e.Name || got.Line != e.Line {
			t.Fatalf("Get(%q) returned %+v, want name/line to match the listed entry", e.Name, got)
		}
		if rerr := auth.Remove(ctx, e.Scope, e.Owner, e.Name); rerr != nil {
			t.Fatalf("Remove(%s/%s/%s): %v", e.Scope, e.Owner, e.Name, rerr)
		}
	}

	remaining, err := auth.List(ctx, sdkssh.ListAuthorizedKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List after removals: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected all listed entries to be removable, %d remain", len(remaining))
	}
}

// TestAuthorizedKeys_List_CrossScope confirms an unscoped list reports
// each entry's own scope and owner rather than echoing the (empty)
// request fields.
func TestAuthorizedKeys_List_CrossScope(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()

	addAuthorized(t, client, "user", "alice", "laptop")
	addAuthorized(t, client, "tenant", "acme", "shared")

	list, err := client.AuthorizedKeys().List(ctx, sdkssh.ListAuthorizedKeysRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(list))
	}
	want := map[string]string{"user/alice": "laptop", "tenant/acme": "shared"}
	for _, e := range list {
		name, ok := want[e.Scope+"/"+e.Owner]
		if !ok {
			t.Fatalf("unexpected coordinates %s/%s", e.Scope, e.Owner)
		}
		if e.Name != name {
			t.Fatalf("%s/%s Name = %q, want %q", e.Scope, e.Owner, e.Name, name)
		}
	}
}

// TestAuthorizedKeys_List_InvalidScope is the bad-input companion: an
// unparseable scope must be rejected, not silently listed as empty.
func TestAuthorizedKeys_List_InvalidScope(t *testing.T) {
	client := newClient(t)

	list, err := client.AuthorizedKeys().List(context.Background(),
		sdkssh.ListAuthorizedKeysRequest{Scope: "not-a-scope", Owner: "alice"})
	var invalid *sdkssh.InvalidScopeError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected InvalidScopeError, got %T: %v", err, err)
	}
	if list != nil {
		t.Fatalf("expected nil list alongside error, got %+v", list)
	}
}

// TestAuthorizedKeys_Verify_ReportsStoredName asserts a successful Verify
// names the entry that granted access, so the caller can audit or revoke
// it. It used to return an entry with Name == "".
func TestAuthorizedKeys_Verify_ReportsStoredName(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()

	addAuthorized(t, client, "user", "alice", "decoy")
	line := addAuthorized(t, client, "user", "alice", "yubikey")

	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	auth := client.AuthorizedKeys()
	got, err := auth.Verify(ctx, "user", "alice", pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Name != "yubikey" {
		t.Fatalf("Verify Name = %q, want yubikey", got.Name)
	}
	if got.Scope != "user" || got.Owner != "alice" {
		t.Fatalf("Verify coordinates = %s/%s, want user/alice", got.Scope, got.Owner)
	}

	// Revoking by the reported name denies the key.
	if err := auth.Remove(ctx, got.Scope, got.Owner, got.Name); err != nil {
		t.Fatalf("Remove by verified name: %v", err)
	}
	if _, err := auth.Verify(ctx, "user", "alice", pub); err == nil {
		t.Fatal("expected Verify to fail after the named entry was removed")
	}
}
