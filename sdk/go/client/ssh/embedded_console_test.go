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
	"net"
	"strconv"
	"testing"

	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// closedTCPAddr binds an ephemeral loopback port and immediately closes it,
// returning an address nothing is listening on so a dial attempt fails fast
// and deterministically (connection refused) instead of hanging.
func closedTCPAddr(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port
}

// TestEmbeddedClient_Console_KeyNotFound pins the error path: Console
// resolves the signer via Keys().Signer before ever attempting to dial, so
// a nonexistent key must fail with the store's own KeyNotFoundError rather
// than a network error.
func TestEmbeddedClient_Console_KeyNotFound(t *testing.T) {
	client := newClient(t)
	_, err := client.Console(context.Background(), sdkssh.ConsoleConnectRequest{
		KeyScope: "user",
		KeyOwner: "alice",
		KeyName:  "does-not-exist",
		Host:     "server.example.test",
		Port:     22,
		User:     "deploy",
	}, sdkssh.ConsoleConfig{})
	var nf *pkgkeys.KeyNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *pkgkeys.KeyNotFoundError, got %T: %v", err, err)
	}
}

// TestEmbeddedClient_Console_ReachesDialWithResolvedSigner pins that a
// resolvable key carries Console past signer resolution and into
// OpenConsole's dial: targeting a closed local port, the error observed
// must be a dial-stage failure, not the KeyNotFoundError the previous test
// pins — proving the resolved signer was actually handed to OpenConsole.
func TestEmbeddedClient_Console_ReachesDialWithResolvedSigner(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()

	if _, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "console-key",
		Algorithm: "ed25519",
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	host, port := closedTCPAddr(t)
	_, err := client.Console(ctx, sdkssh.ConsoleConnectRequest{
		KeyScope: "user",
		KeyOwner: "alice",
		KeyName:  "console-key",
		Host:     host,
		Port:     port,
		User:     "deploy",
	}, sdkssh.ConsoleConfig{})
	if err == nil {
		t.Fatal("expected a dial-stage error against a closed port")
	}
	var nf *pkgkeys.KeyNotFoundError
	if errors.As(err, &nf) {
		t.Fatalf("got a KeyNotFoundError; signer resolution should have succeeded: %v", err)
	}
}
