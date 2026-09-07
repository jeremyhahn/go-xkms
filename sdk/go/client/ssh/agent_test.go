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
	"io/fs"
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
	defer sess.Stop(context.Background())

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
	defer sess.Stop(context.Background())

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

	report := sess.Stop(context.Background())
	if !report.Clean() {
		t.Fatalf("expected a clean shutdown, %d abandoned", report.Abandoned)
	}
	sess.Stop(context.Background()) // idempotent

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

// privateAgentDir returns a temp directory this user alone can write to, which
// is what StartAgent requires of a SocketDir's parent: a directory another user
// can write to is one in which the session's own directory can be swapped out
// between the bind and the child process's connect. t.TempDir does not promise
// the mode, so it is stated here — which is exactly what a consumer laying out
// a tenant root has to do.
func privateAgentDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	return dir
}

// TestStartAgent_SocketDirIsHonoured is go-xkms#444: a consumer that cannot
// admit the OS temporary directory to its mount policy names where the socket
// goes, and gets a path it could compute before the call. The modes are part of
// the contract, not an implementation detail — 0700 on the directory is what
// keeps another user away from the socket, whatever the socket's own mode is.
func TestStartAgent_SocketDirIsHonoured(t *testing.T) {
	signer, _ := newAgentSigner(t, "socket-dir")
	dir := filepath.Join(privateAgentDir(t), "agent")

	sess, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{
		Signers:   []gossh.Signer{signer},
		SocketDir: dir,
	})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	defer sess.Stop(context.Background())

	want := filepath.Join(dir, "agent.sock")
	if sess.SockPath != want {
		t.Fatalf("socket path: got %q, want %q", sess.SockPath, want)
	}
	if sess.Env[0] != "SSH_AUTH_SOCK="+want {
		t.Fatalf("Env must carry the chosen socket, got %v", sess.Env)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat the session's directory: %v", err)
	}
	// No group or other access is the invariant, not the exact mode: the
	// directory is created 0700 and the process umask can only clear bits.
	if di.Mode().Perm()&0o077 != 0 {
		t.Fatalf("session directory grants access to group or other: %#o", di.Mode().Perm())
	}
	si, err := os.Lstat(sess.SockPath)
	if err != nil {
		t.Fatalf("stat the socket: %v", err)
	}
	if si.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: got %#o, want 0600", si.Mode().Perm())
	}
	if si.Mode()&os.ModeSocket == 0 {
		t.Fatal("the path must be a socket")
	}

	// A path is not an agent until something signs through it.
	payload := []byte("signed through a caller-located socket")
	sig, err := dialAgent(t, sess).Sign(signer.PublicKey(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(payload, sig); err != nil {
		t.Fatalf("signature did not verify under the served key: %v", err)
	}
}

// TestStartAgent_SocketDirExistingPathIsRefused pins the refusal. The session
// owns what it binds in, so it will not adopt a directory somebody else made —
// and will not clear one either, because that would delete whatever the caller
// keeps there, up to and including another live agent.
func TestStartAgent_SocketDirExistingPathIsRefused(t *testing.T) {
	signer, _ := newAgentSigner(t, "socket-dir-exists")
	dir := filepath.Join(privateAgentDir(t), "agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("pre-create the path: %v", err)
	}
	keeper := filepath.Join(dir, "keep-me")
	if err := os.WriteFile(keeper, []byte("caller's file"), 0o600); err != nil {
		t.Fatalf("write the caller's file: %v", err)
	}

	_, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{
		Signers:   []gossh.Signer{signer},
		SocketDir: dir,
	})
	var exists *sdkssh.AgentSocketDirExistsError
	if !errors.As(err, &exists) {
		t.Fatalf("an existing path must be refused as *AgentSocketDirExistsError, got %#v", err)
	}
	if exists.Path != dir {
		t.Fatalf("the error must name the path: got %q, want %q", exists.Path, dir)
	}
	if !errors.Is(err, fs.ErrExist) {
		t.Fatal("the error must match the standard fs.ErrExist sentinel")
	}
	if _, serr := os.Stat(keeper); serr != nil {
		t.Fatalf("a refused path must never be cleared: %v", serr)
	}
}

// TestStartAgent_SocketDirInsecureParentIsRefused covers what creating the
// directory cannot fix. In a parent another user can write to, the session's
// own directory can be renamed away and replaced wholesale, and the child
// reading SSH_AUTH_SOCK would then be talking to somebody else's agent.
func TestStartAgent_SocketDirInsecureParentIsRefused(t *testing.T) {
	signer, _ := newAgentSigner(t, "socket-dir-parent")
	parent := privateAgentDir(t)
	if err := os.Chmod(parent, 0o707); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{
		Signers:   []gossh.Signer{signer},
		SocketDir: filepath.Join(parent, "agent"),
	})
	var insecure *sdkssh.AgentInsecureSocketDirError
	if !errors.As(err, &insecure) {
		t.Fatalf("a world-writable parent must be refused, got %#v", err)
	}
	if !strings.Contains(insecure.Error(), "group or other") {
		t.Fatalf("the error must say why: %v", insecure)
	}
}

// TestStartAgent_SocketDirIsRemovedOnStop is the other half of ownership: the
// caller named a location inside its own tree, and gets it back empty. A
// leftover socket there is an unattended signing oracle in a directory the
// caller keeps.
func TestStartAgent_SocketDirIsRemovedOnStop(t *testing.T) {
	signer, _ := newAgentSigner(t, "socket-dir-cleanup")
	parent := privateAgentDir(t)
	dir := filepath.Join(parent, "agent")

	sess, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{
		Signers:   []gossh.Signer{signer},
		SocketDir: dir,
	})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	if report := sess.Stop(context.Background()); !report.Clean() {
		t.Fatalf("clean shutdown expected, %d handler(s) abandoned", report.Abandoned)
	}

	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the session must remove the directory it created, stat gave %v", err)
	}
	if _, err := os.Stat(parent); err != nil {
		t.Fatalf("the parent belongs to the caller and must survive: %v", err)
	}
}

// TestStartAgent_SocketDirServesAnotherWorkingDirectory is the consumer
// scenario behind the option: the socket is read by a process running somewhere
// else entirely — a container with its own working directory and PID namespace
// — so the path must be absolute and must not resolve against whoever reads it.
func TestStartAgent_SocketDirServesAnotherWorkingDirectory(t *testing.T) {
	signer, _ := newAgentSigner(t, "socket-dir-cwd")
	base := privateAgentDir(t)
	t.Chdir(base)

	sess, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{
		Signers:   []gossh.Signer{signer},
		SocketDir: "agent",
	})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	defer sess.Stop(context.Background())

	if !filepath.IsAbs(sess.SockPath) {
		t.Fatalf("SockPath must be absolute for a reader elsewhere, got %q", sess.SockPath)
	}
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatalf("resolve the base: %v", err)
	}
	if want := filepath.Join(resolved, "agent", "agent.sock"); sess.SockPath != want {
		t.Fatalf("a relative SocketDir resolves once, against this process: got %q, want %q",
			sess.SockPath, want)
	}

	// Sign from a different working directory, which is all a container's cwd
	// amounts to from the socket's point of view.
	t.Chdir(privateAgentDir(t))
	payload := []byte("signed from another working directory")
	sig, err := dialAgent(t, sess).Sign(signer.PublicKey(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(payload, sig); err != nil {
		t.Fatalf("signature did not verify under the served key: %v", err)
	}
}
