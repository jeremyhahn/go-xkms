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
	"strings"
	"testing"
	"time"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestRESTSessionDial_Success dials the REST client's Session sub-client
// against a real in-process SSH server: the private key never leaves the
// server side of the fixture (the embedded backend behind the httptest
// server) — the REST client only ever sees a forward-signing proxy — and
// the presented host key is verified against a pin added through the same
// REST client. This is also the code path QUIC uses (NewQUIC wraps
// restClient verbatim), so it is not duplicated in a QUIC-specific test.
func TestRESTSessionDial_Success(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()
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
	defer func() { _ = sess.Close() }()

	stdout, _, err := sess.Run(ctx, "echo hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(stdout), "echo hello") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
}

// TestRESTSessionDial_UnknownHostRefused asserts that dialing a target
// with no known_hosts pin fails closed with a typed error — never an
// InsecureIgnoreHostKey fallback.
func TestRESTSessionDial_UnknownHostRefused(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()
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

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail for an unpinned host")
	}
	if handshakeBlockedByFIPS(t, err) {
		return
	}
	var notFound *sdkssh.NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *NotFoundError in the chain, got %T: %v", err, err)
	}
}

// TestRESTSessionDial_HostKeyMismatchRefused asserts that a pin for the
// wrong host key refuses the connection with a typed *MismatchError —
// the MITM-indicating case.
func TestRESTSessionDial_HostKeyMismatchRefused(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()
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
		PublicKey: decoyHostKeyLine(t), // pins a key that does NOT match target.signer
	}); err != nil {
		t.Fatalf("KnownHosts.Add: %v", err)
	}

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail for a mismatched host key")
	}
	if handshakeBlockedByFIPS(t, err) {
		return
	}
	var mismatch *sdkssh.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *MismatchError in the chain, got %T: %v", err, err)
	}
}

// TestRESTSessionDial_SignerErrorPropagates deletes the authentication key
// after it is generated but before dialing, so resolving the remote-signer
// proxy (Keys().Signer, which fetches the public half from the server)
// fails; that failure must surface to the caller intact rather than being
// swallowed or silently downgraded to a different auth method.
func TestRESTSessionDial_SignerErrorPropagates(t *testing.T) {
	_, client, cleanup := newRESTFixture(t)
	defer cleanup()
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
	if err := client.Keys().Delete(ctx, sdkssh.DeleteKeyRequest{
		Scope: "user", Owner: "alice", Name: genned.Name,
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = client.Session().Dial(ctx, sdkssh.SessionDialRequest{
		KeyScope: "user", KeyOwner: "alice", KeyName: genned.Name,
		Host: host, Port: port, User: "testuser", TimeoutSeconds: 5,
	})
	if err == nil {
		t.Fatal("expected dial to fail when the signing key no longer exists")
	}
	var notFound *sdkssh.NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *NotFoundError in the chain, got %T: %v", err, err)
	}
}
