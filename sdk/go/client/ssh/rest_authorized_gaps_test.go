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
	"errors"
	"testing"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestRESTAuthorizedKeys_GetListRemove covers the three REST
// AuthorizedKeysClient methods TestRESTAuthorizedKeys_EmitAddListVerify does
// not exercise: fetching a single entry, listing entries by scope/owner, and
// removing one — including the after-Remove Get returning *NotFoundError.
func TestRESTAuthorizedKeys_GetListRemove(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()

	ctx := context.Background()
	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "forauth-gaps", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	auth := client.AuthorizedKeys()
	line, err := auth.Emit(ctx, sdkssh.EmitRequest{PublicKey: genned.PublicKey, Comment: "alice@forauth-gaps"})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := auth.Add(ctx, sdkssh.AddAuthorizedKeyRequest{
		Scope: "user", Owner: "alice", Name: "forauth-gaps", Line: line,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := auth.Get(ctx, "user", "alice", "forauth-gaps")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "forauth-gaps" || got.Owner != "alice" {
		t.Fatalf("unexpected entry: %+v", got)
	}

	list, err := auth.List(ctx, sdkssh.ListAuthorizedKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, e := range list {
		if e.Name == "forauth-gaps" {
			found = true
		}
	}
	if !found {
		t.Fatalf("List did not include the added entry: %+v", list)
	}

	if err := auth.Remove(ctx, "user", "alice", "forauth-gaps"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	_, err = auth.Get(ctx, "user", "alice", "forauth-gaps")
	var nf *sdkssh.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError after Remove, got %T: %v", err, err)
	}
}
