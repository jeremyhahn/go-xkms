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
	"net"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestEmbeddedSession_DialRunClose dials the embedded transport's Session
// sub-client against a real in-process SSH server, runs a command, and
// closes the session — covering embeddedSession.Run/Close and the success
// path through embeddedSessionClient.Dial that the missing-known-host test
// (TestSession_RejectsMissingKnownHost) does not reach.
func TestEmbeddedSession_DialRunClose(t *testing.T) {
	client := newClient(t)
	target := newTargetSSHServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	genned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "ssh", Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	host, port := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: authorizedKeyLine(target.signer.PublicKey()),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}

	sess, err := client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err != nil {
		if handshakeBlockedByFIPS(t, err) {
			return
		}
		t.Fatalf("Session.Dial: %v", err)
	}

	stdout, _, err := sess.Run(ctx, "echo hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(stdout), "echo hello") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestEmbeddedKnownHosts_Callback pins the KnownHostsClient.Callback
// forwarding: a callback built for a pinned host must accept the pinned key
// and reject a different one, and an invalid scope must yield a callback
// that always refuses.
func TestEmbeddedKnownHosts_Callback(t *testing.T) {
	client := newClient(t)
	target := newTargetSSHServer(t)
	ctx := context.Background()

	host, _ := target.hostPort()
	if err := client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: host,
		PublicKey: authorizedKeyLine(target.signer.PublicKey()),
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}

	cb := client.KnownHosts().Callback(ctx, "user", "alice")
	addr := &net.TCPAddr{}
	if err := cb(host, addr, target.signer.PublicKey()); err != nil {
		t.Fatalf("callback rejected the pinned host key: %v", err)
	}

	decoyPub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(decoyHostKeyLine(t)))
	if err != nil {
		t.Fatalf("parse decoy key: %v", err)
	}
	if err := cb(host, addr, decoyPub); err == nil {
		t.Fatal("callback accepted a host key that does not match the pin")
	}

	badCB := client.KnownHosts().Callback(ctx, "not-a-scope", "alice")
	if err := badCB(host, addr, target.signer.PublicKey()); err == nil {
		t.Fatal("callback built with an invalid scope must always refuse")
	}
}
