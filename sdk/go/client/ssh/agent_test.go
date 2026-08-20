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
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	gosshagent "golang.org/x/crypto/ssh/agent"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// These tests are hermetic: they speak the ssh-agent protocol in-process and
// shell out to nothing. The end-to-end consumer scenario -- a real `git commit
// -S` signed through the socket -- is an integration test, because it needs the
// host's git and ssh-keygen: test/integration/sshagent/git_signing_test.go.

// newAgentSigner generates a key through the SDK and returns its signer plus
// its authorized_keys line, exactly as a consumer would obtain them.
func newAgentSigner(t *testing.T, name string) (gossh.Signer, string) {
	t.Helper()
	client := newClient(t)
	ctx := context.Background()

	key, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      name,
		Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer, err := client.Keys().Signer(ctx, sdkssh.GetKeyRequest{
		Scope: "user",
		Owner: "alice",
		Name:  name,
	})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	return signer, key.PublicKey
}

// dialAgent connects to the session's socket and returns an agent client.
func dialAgent(t *testing.T, sess *sdkssh.AgentSession) gosshagent.ExtendedAgent {
	t.Helper()
	conn, err := net.Dial("unix", sess.SockPath)
	if err != nil {
		t.Fatalf("dial %s: %v", sess.SockPath, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return gosshagent.NewClient(conn)
}

// TestStartAgent_ServesTheKMSHeldKey is the hermetic core of go-xkms#52: a key
// generated through the SDK is reachable over an agent socket, and signatures
// produced there verify under it. This is what git, ssh-keygen -Y sign and age
// each do over the same protocol.
//
// It asserts the signature verifies rather than merely that one came back --
// an agent returning a well-formed but wrong signature is exactly the failure
// a consumer would ship without noticing.
func TestStartAgent_ServesTheKMSHeldKey(t *testing.T) {
	signer, pubLine := newAgentSigner(t, "commit-signing")

	sess, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{
		Signers: []gossh.Signer{signer},
	})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	defer sess.Stop()

	// The socket is usable the moment StartAgent returns -- no polling.
	client := dialAgent(t, sess)

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected exactly the served identity, got %d", len(keys))
	}
	advertised, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(pubLine))
	if perr != nil {
		t.Fatalf("parse the SDK's public key line: %v", perr)
	}
	if !bytes.Equal(keys[0].Blob, advertised.Marshal()) {
		t.Fatalf("agent advertises a different key: got %q, want %q", keys[0].String(), pubLine)
	}

	payload := []byte("payload signed through the agent socket")
	sig, err := client.Sign(signer.PublicKey(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(payload, sig); err != nil {
		t.Fatalf("signature did not verify under the served key: %v", err)
	}

	// Env is the handoff a consumer makes to a child process.
	want := "SSH_AUTH_SOCK=" + sess.SockPath
	if len(sess.Env) != 1 || sess.Env[0] != want {
		t.Fatalf("Env should carry exactly %q, got %v", want, sess.Env)
	}
}

// TestStartAgent_PrivateKeyNeverLeavesTheSession asserts the socket refuses to
// hand out key material: the agent is read-only, and the only public artifact
// a consumer writes to disk (user.signingkey) is a public key.
func TestStartAgent_PrivateKeyNeverLeavesTheSession(t *testing.T) {
	signer, pubLine := newAgentSigner(t, "no-export")

	sess, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{
		Signers: []gossh.Signer{signer},
	})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	defer sess.Stop()

	client := dialAgent(t, sess)

	// The advertised line is a public key and nothing else.
	for _, marker := range []string{"PRIVATE KEY", "openssh-key-v1"} {
		if strings.Contains(pubLine, marker) {
			t.Fatalf("public key line carries private material (%q): %q", marker, pubLine)
		}
	}

	// A read-only agent refuses every mutating request that reaches it, so
	// nothing can strip the served identity or lock the socket out from under
	// its owner. Both of these are refused by the server, not by the client.
	if err := client.RemoveAll(); err == nil {
		t.Fatal("RemoveAll should be refused by a read-only agent")
	}
	if err := client.Lock([]byte("passphrase")); err == nil {
		t.Fatal("Lock should be refused by a read-only agent")
	}
}

// TestStartAgent_NoSigners rejects an empty identity set through the SDK's own
// error type, so a consumer can match it without importing pkg/.
func TestStartAgent_NoSigners(t *testing.T) {
	_, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{})
	var ie *sdkssh.AgentInputError
	if !errors.As(err, &ie) {
		t.Fatalf("expected *AgentInputError, got %T: %v", err, err)
	}
	if ie.Field != "Signers" {
		t.Fatalf("expected the Signers field, got %q", ie.Field)
	}
}

// TestStartAgent_CancelledContext refuses a dead context rather than returning
// a session whose socket is already being removed.
func TestStartAgent_CancelledContext(t *testing.T) {
	signer, _ := newAgentSigner(t, "dead-context")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sess, err := sdkssh.StartAgent(ctx, sdkssh.AgentOptions{Signers: []gossh.Signer{signer}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if sess != nil {
		t.Fatal("no session should be returned for a cancelled context")
	}
}

// TestStartAgent_StopEndsTheSession covers the explicit-Stop lifetime path from
// the SDK surface: the socket is gone, a client held across Stop can no longer
// sign, and Stop is safe to call twice.
func TestStartAgent_StopEndsTheSession(t *testing.T) {
	signer, _ := newAgentSigner(t, "stop-lifetime")

	sess, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{
		Signers: []gossh.Signer{signer},
	})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	if _, serr := os.Stat(sess.SockPath); serr != nil {
		t.Fatalf("socket must exist when StartAgent returns: %v", serr)
	}
	client := dialAgent(t, sess)
	if _, serr := client.Sign(signer.PublicKey(), []byte("before stop")); serr != nil {
		t.Fatalf("held connection must sign while the session is live: %v", serr)
	}

	sess.Stop()
	sess.Stop()

	if _, serr := os.Stat(sess.SockPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("socket must be gone once Stop returns: %v", serr)
	}
	if _, serr := client.Sign(signer.PublicKey(), []byte("after stop")); serr == nil {
		t.Fatal("a connection held across Stop must no longer sign")
	}
}

// TestStartAgent_ContextCancelEndsTheSession covers the other lifetime path:
// the socket and an owned work dir die with the context, no Stop involved.
func TestStartAgent_ContextCancelEndsTheSession(t *testing.T) {
	signer, _ := newAgentSigner(t, "cancel-lifetime")

	ctx, cancel := context.WithCancel(context.Background())
	sess, err := sdkssh.StartAgent(ctx, sdkssh.AgentOptions{Signers: []gossh.Signer{signer}})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	workDir := filepath.Dir(sess.SockPath)

	cancel()
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session never finished after context cancellation")
	}

	if _, serr := os.Stat(sess.SockPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("agent socket outlived its context: %v", serr)
	}
	if _, serr := os.Stat(workDir); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("agent work dir outlived its context: %v", serr)
	}
}
