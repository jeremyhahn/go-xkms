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

// TestEmbedded_InvalidScopeIsRejectedEverywhere pins that every embedded
// sub-client operation validates its Scope argument independently — each
// method parses req.Scope itself rather than sharing one guard, so a
// regression that drops the check on a single method (while every other
// method still validates) would otherwise go unnoticed.
package ssh_test

import (
	"context"
	"errors"
	"testing"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

func TestEmbedded_InvalidScopeIsRejectedEverywhere(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	const bogus = "bogus-scope"

	checks := map[string]func() error{
		"Keys.Import": func() error {
			_, err := client.Keys().Import(ctx, sdkssh.ImportRequest{Scope: bogus, PEM: []byte("x")}, nil)
			return err
		},
		"Keys.Get": func() error {
			_, err := client.Keys().Get(ctx, sdkssh.GetKeyRequest{Scope: bogus, Owner: "a", Name: "n"})
			return err
		},
		"Keys.List": func() error {
			_, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{Scope: bogus})
			return err
		},
		"Keys.Delete": func() error {
			return client.Keys().Delete(ctx, sdkssh.DeleteKeyRequest{Scope: bogus, Owner: "a", Name: "n"})
		},
		"Keys.ExportPublic": func() error {
			_, err := client.Keys().ExportPublic(ctx, sdkssh.ExportRequest{Scope: bogus, Owner: "a", Name: "n"})
			return err
		},
		"Keys.Signer": func() error {
			_, err := client.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: bogus, Owner: "a", Name: "n"})
			return err
		},
		"KnownHosts.Add": func() error {
			return client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{Scope: bogus, Host: "h", PublicKey: "ssh-ed25519 AAAA"})
		},
		"KnownHosts.List": func() error {
			_, err := client.KnownHosts().List(ctx, sdkssh.ListKnownHostsRequest{Scope: bogus})
			return err
		},
		"KnownHosts.Remove": func() error {
			return client.KnownHosts().Remove(ctx, sdkssh.RemoveKnownHostRequest{Scope: bogus, Host: "h"})
		},
		"KnownHosts.Verify": func() error {
			return client.KnownHosts().Verify(ctx, bogus, "a", "h", nil)
		},
		"AuthorizedKeys.Add": func() error {
			return client.AuthorizedKeys().Add(ctx, sdkssh.AddAuthorizedKeyRequest{Scope: bogus, Name: "n", Line: "ssh-ed25519 AAAA"})
		},
		"AuthorizedKeys.Get": func() error {
			_, err := client.AuthorizedKeys().Get(ctx, bogus, "a", "n")
			return err
		},
		"AuthorizedKeys.List": func() error {
			_, err := client.AuthorizedKeys().List(ctx, sdkssh.ListAuthorizedKeysRequest{Scope: bogus})
			return err
		},
		"AuthorizedKeys.Remove": func() error {
			return client.AuthorizedKeys().Remove(ctx, bogus, "a", "n")
		},
		"AuthorizedKeys.Verify": func() error {
			_, err := client.AuthorizedKeys().Verify(ctx, bogus, "a", nil)
			return err
		},
		"Session.Dial": func() error {
			_, err := client.Session().Dial(ctx, sdkssh.SessionDialRequest{KeyScope: bogus, Host: "h", User: "u"})
			return err
		},
		"Session.Dial/HostKeyScope": func() error {
			_, err := client.Session().Dial(ctx, sdkssh.SessionDialRequest{
				KeyScope: "user", HostKeyScope: bogus, Host: "h", User: "u", KeyOwner: "a", KeyName: "n",
			})
			return err
		},
	}

	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			err := check()
			var se *sdkssh.InvalidScopeError
			if !errors.As(err, &se) {
				t.Fatalf("%s: expected *InvalidScopeError, got %T: %v", name, err, err)
			}
		})
	}
}
