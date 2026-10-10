// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// This suite drives the real `xkey ssh console` command end-to-end against an
// in-process echo SSH server. The console command runs the session in-process
// through the xkms SDK console capability (the same capability the embedded GUI
// terminal uses), so it proves the embedded transport, the signer-based dial
// (no private-key export), host-key pin verification, and the PTY byte stream
// all work through the CLI surface a user actually invokes.
//
// The echo server runs inside the test process and listens on a loopback port;
// the xkey CLI subprocess connects to it over TCP, grants a PTY, and echoes the
// console byte stream back. A unique marker written to the console's stdin must
// reappear on stdout, proving the round-trip; the server closes the channel when
// it sees "exit" so the session terminates deterministically.

// startConsoleEchoServer stands up a loopback SSH server that grants a PTY,
// echoes every byte it receives, and closes the channel once it sees "exit". It
// returns the host, port, and its host key as an authorized_keys-format line
// (for pinning). The listener is torn down on test cleanup.
func startConsoleEchoServer(t *testing.T) (host string, port int, hostKey string) {
	return startConsoleEchoServerOn(t, "127.0.0.1")
}

// startConsoleEchoServerOn binds a specific loopback IP. Concurrent-session
// tests give each server its own IP: host-key pins are keyed by host (not
// host:port), so two fresh host keys on one IP would be a pin mismatch —
// a hard failure by design.
func startConsoleEchoServerOn(t *testing.T, bindIP string) (host string, port int, hostKey string) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	cfg := &gossh.ServerConfig{
		// Accept any client key — this test exercises the console byte stream
		// and host-key verification, not server-side authorization.
		PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return &gossh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", net.JoinHostPort(bindIP, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return // listener closed on cleanup
			}
			go serveConsoleEcho(conn, cfg)
		}
	}()

	return h, port, strings.TrimSpace(string(gossh.MarshalAuthorizedKey(hostSigner.PublicKey())))
}

// serveConsoleEcho handles a single SSH connection: it grants a PTY and a shell,
// then echoes the channel back to itself until it observes "exit", at which
// point it closes the channel to end the session.
func serveConsoleEcho(conn net.Conn, cfg *gossh.ServerConfig) {
	defer conn.Close()
	sc, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go gossh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(gossh.UnknownChannelType, "only session channels")
			continue
		}
		ch, requests, aerr := nc.Accept()
		if aerr != nil {
			continue
		}
		go func(ch gossh.Channel, in <-chan *gossh.Request) {
			for req := range in {
				switch req.Type {
				case "pty-req", "window-change", "env":
					_ = req.Reply(true, nil)
				case "shell":
					_ = req.Reply(true, nil)
					go echoUntilExit(ch)
				default:
					_ = req.Reply(false, nil)
				}
			}
		}(ch, requests)
	}
}

// echoUntilExit copies the channel back to itself, closing it once "exit"
// appears in the stream so the client's read loop returns and the CLI exits.
func echoUntilExit(ch gossh.Channel) {
	buf := make([]byte, 256)
	for {
		n, rerr := ch.Read(buf)
		if n > 0 {
			_, _ = ch.Write(buf[:n])
			if bytes.Contains(buf[:n], []byte("exit")) {
				_ = ch.Close()
				return
			}
		}
		if rerr != nil {
			_ = ch.Close()
			return
		}
	}
}

// runConsole executes `xkey ssh console <args>` with piped stdin under a hard
// timeout. The echo server closes the channel on "exit", so a well-behaved run
// returns well within the timeout; a hang (e.g. a session that never ends)
// surfaces as a context-deadline kill rather than blocking the suite.
func runConsole(t *testing.T, h *SSHTestHelper, stdin string, timeout time.Duration, args ...string) *CommandResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	full := append([]string{"ssh", "console"}, args...)
	cmd := exec.CommandContext(ctx, h.BinaryPath(), full...)
	cmd.Env = h.CommandEnv()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("xkey ssh console timed out after %s (session did not end)\nstdout: %s\nstderr: %s",
			timeout, stdout.String(), stderr.String())
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return &CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

// pinConsoleHost generates an SSH key and pins the echo server's host key so the
// console can verify it (host-key trust is MITM-safe: a pin must exist before
// dial). Returns the key name used for authentication.
func pinConsoleHost(t *testing.T, h *SSHTestHelper, host, hostKey string) string {
	t.Helper()

	keyName := "console-key"
	gen := h.RunSSHKeys("generate",
		"--scope", "user", "--owner", h.User(),
		"--name", keyName, "--type", "ed25519")
	if !gen.Success() {
		t.Fatalf("generate key failed: %s", gen.Combined())
	}

	pin := h.RunSSHHostKeys("add",
		"--scope", "user", "--owner", h.User(),
		"--host", host, "--key", hostKey,
		"--source", "manual")
	if !pin.Success() {
		t.Fatalf("pin host key failed: %s", pin.Combined())
	}
	return keyName
}

// TestSSHConsoleEmbedded drives `xkey ssh console user@host` against the echo
// server and asserts the console byte stream round-trips end-to-end.
func TestSSHConsoleEmbedded(t *testing.T) {
	h := NewSSHTestHelper(t)
	host, port, hostKey := startConsoleEchoServer(t)
	keyName := pinConsoleHost(t, h, host, hostKey)

	marker := "xkey-console-roundtrip-7f3a"
	res := runConsole(t, h, marker+"\nexit\n", 20*time.Second,
		h.User()+"@"+host,
		"--key", keyName,
		"--key-scope", "user",
		"--key-owner", h.User(),
		"--port", strconv.Itoa(port),
	)
	if !res.Success() {
		t.Fatalf("console exited non-zero: %s", res.Combined())
	}
	if !res.OutputContains(marker) {
		t.Fatalf("console stream did not echo marker %q\nstdout: %s\nstderr: %s",
			marker, res.Stdout, res.Stderr)
	}
}

// TestSSHConsoleProfile proves the console resolves a saved profile (host, port,
// user, key) by name, the same path the GUI uses.
func TestSSHConsoleProfile(t *testing.T) {
	h := NewSSHTestHelper(t)
	host, port, hostKey := startConsoleEchoServer(t)
	keyName := pinConsoleHost(t, h, host, hostKey)

	add := h.RunSSH("profile", "add",
		"--name", "echo-box",
		"--host", host,
		"--port", strconv.Itoa(port),
		"--user", h.User(),
		"--key", keyName,
		"--key-scope", "user",
		"--key-owner", h.User(),
	)
	if !add.Success() {
		t.Fatalf("profile add failed: %s", add.Combined())
	}

	marker := "xkey-console-profile-b91c"
	res := runConsole(t, h, marker+"\nexit\n", 20*time.Second, "echo-box")
	if !res.Success() {
		t.Fatalf("console (profile) exited non-zero: %s", res.Combined())
	}
	if !res.OutputContains(marker) {
		t.Fatalf("console (profile) did not echo marker %q\nstdout: %s\nstderr: %s",
			marker, res.Stdout, res.Stderr)
	}
}

// TestSSHConsoleHostKeyRejected proves host-key trust is MITM-safe: with no pin
// for the target, the console refuses to connect (no trust-on-first-use).
func TestSSHConsoleHostKeyRejected(t *testing.T) {
	h := NewSSHTestHelper(t)
	host, port, _ := startConsoleEchoServer(t)

	// Generate a key but DO NOT pin the host.
	gen := h.RunSSHKeys("generate",
		"--scope", "user", "--owner", h.User(),
		"--name", "no-pin-key", "--type", "ed25519")
	if !gen.Success() {
		t.Fatalf("generate key failed: %s", gen.Combined())
	}

	res := runConsole(t, h, "should-not-connect\nexit\n", 20*time.Second,
		h.User()+"@"+host,
		"--key", "no-pin-key",
		"--key-scope", "user",
		"--key-owner", h.User(),
		"--port", strconv.Itoa(port),
	)
	if res.Success() {
		t.Fatalf("console connected without a host-key pin (TOFU is forbidden)\nstdout: %s", res.Stdout)
	}
	if res.OutputContains("should-not-connect") {
		t.Fatalf("console echoed input despite missing host pin: %s", res.Stdout)
	}
}

// TestSSHConsoleNoKeyNoLocalIdentities verifies the no-key local fallback
// fails with a clear "no usable local identity" error when neither the
// agent nor ~/.ssh has anything to offer (rather than the old hard "no key
// specified" rejection — no key now means "authenticate like OpenSSH
// would", matching the GUI embedded console).
func TestSSHConsoleNoKeyNoLocalIdentities(t *testing.T) {
	h := NewSSHTestHelper(t)
	t.Setenv("HOME", t.TempDir()) // no ~/.ssh identities
	t.Setenv("SSH_AUTH_SOCK", "") // no agent

	res := runConsole(t, h, "", 10*time.Second, h.User()+"@127.0.0.1")
	if res.Success() {
		t.Fatal("console without any usable identity should fail")
	}
	if !res.OutputContains("no usable local identity") {
		t.Errorf("expected a no-usable-local-identity error, got: %s", res.Combined())
	}
}

// serveTestAgentSocket serves keyring on a fresh unix socket under
// t.TempDir() until the test ends, returning the socket path for
// SSH_AUTH_SOCK.
func serveTestAgentSocket(t *testing.T, keyring sshagent.Agent) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("agent listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = sshagent.ServeAgent(keyring, c)
			}(conn)
		}
	}()
	return sock
}

// pinConsoleHostOnly pins the echo server's host key without generating an
// xkey-managed key (for local-identity flows that never touch the store).
func pinConsoleHostOnly(t *testing.T, h *SSHTestHelper, host, hostKey string) {
	t.Helper()
	pin := h.RunSSHHostKeys("add",
		"--scope", "user", "--owner", h.User(),
		"--host", host, "--key", hostKey,
		"--source", "manual")
	if !pin.Success() {
		t.Fatalf("pin host key failed: %s", pin.Combined())
	}
}

// TestSSHConsoleLocalIdentityFile drives `xkey ssh console --identity <path>`
// end-to-end: the embedded console authenticates with a local on-disk
// identity file (no xkey-managed key involved) and the byte stream
// round-trips.
func TestSSHConsoleLocalIdentityFile(t *testing.T) {
	h := NewSSHTestHelper(t)
	host, port, hostKey := startConsoleEchoServer(t)
	pinConsoleHostOnly(t, h, host, hostKey)

	// Write an unencrypted OpenSSH identity file + .pub pair.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "console-local-test")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519_console")
	if werr := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); werr != nil {
		t.Fatalf("write identity: %v", werr)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pubLine := gossh.MarshalAuthorizedKey(signer.PublicKey())
	if werr := os.WriteFile(keyPath+".pub", pubLine, 0o644); werr != nil {
		t.Fatalf("write pub: %v", werr)
	}
	t.Setenv("SSH_AUTH_SOCK", "") // force the file-parse resolution path

	marker := "xkey-console-local-identity-4c2e"
	res := runConsole(t, h, marker+"\nexit\n", 20*time.Second,
		h.User()+"@"+host,
		"--identity", keyPath,
		"--key-owner", h.User(), // host-key pins live under the test owner
		"--port", strconv.Itoa(port),
	)
	if !res.Success() {
		t.Fatalf("console --identity exited non-zero: %s", res.Combined())
	}
	if !res.OutputContains(marker) {
		t.Fatalf("console --identity did not echo marker %q\nstdout: %s\nstderr: %s",
			marker, res.Stdout, res.Stderr)
	}
}

// TestSSHConsoleNoKeyAgentFallback proves that `xkey ssh console` with no
// --key falls back to the operator's local identities (here, a key held only
// by the system agent) instead of erroring — the same behavior as the GUI
// embedded console's "No key" option.
func TestSSHConsoleNoKeyAgentFallback(t *testing.T) {
	h := NewSSHTestHelper(t)
	host, port, hostKey := startConsoleEchoServer(t)
	pinConsoleHostOnly(t, h, host, hostKey)

	t.Setenv("HOME", t.TempDir()) // no ~/.ssh — the agent is the only source
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	keyring := sshagent.NewKeyring()
	if aerr := keyring.Add(sshagent.AddedKey{PrivateKey: priv}); aerr != nil {
		t.Fatalf("keyring.Add: %v", aerr)
	}
	t.Setenv("SSH_AUTH_SOCK", serveTestAgentSocket(t, keyring))

	marker := "xkey-console-no-key-agent-9d1b"
	res := runConsole(t, h, marker+"\nexit\n", 20*time.Second,
		h.User()+"@"+host,
		"--key-owner", h.User(), // host-key pins live under the test owner
		"--port", strconv.Itoa(port),
	)
	if !res.Success() {
		t.Fatalf("console (no key, agent) exited non-zero: %s", res.Combined())
	}
	if !res.OutputContains(marker) {
		t.Fatalf("console (no key, agent) did not echo marker %q\nstdout: %s\nstderr: %s",
			marker, res.Stdout, res.Stderr)
	}
}

// consoleRunResult carries one concurrent console run's outcome across the
// collection channel (t.Fatalf must not be called off the test goroutine).
type consoleRunResult struct {
	label  string
	marker string
	res    *CommandResult
}

// TestSSHConsoleConcurrentSessions proves the embedded console capability
// serves multiple simultaneous sessions — the backend contract behind the
// GUI's console tabs — through the real binary: two `xkey ssh console`
// processes against two SSH servers at once, each echoing its own marker.
func TestSSHConsoleConcurrentSessions(t *testing.T) {
	h := NewSSHTestHelper(t)

	hostA, portA, hostKeyA := startConsoleEchoServerOn(t, "127.0.0.1")
	hostB, portB, hostKeyB := startConsoleEchoServerOn(t, "127.0.0.2")
	keyName := pinConsoleHost(t, h, hostA, hostKeyA)
	pin := h.RunSSHHostKeys("add",
		"--scope", "user", "--owner", h.User(),
		"--host", hostB, "--key", hostKeyB,
		"--source", "manual")
	if !pin.Success() {
		t.Fatalf("pin host B failed: %s", pin.Combined())
	}

	run := func(label, host string, port int, marker string, results chan<- consoleRunResult) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, h.BinaryPath(),
			"ssh", "console", h.User()+"@"+host,
			"--key", keyName, "--key-scope", "user", "--key-owner", h.User(),
			"--port", strconv.Itoa(port))
		cmd.Env = h.CommandEnv()
		// Hold the session open briefly so the two sessions genuinely
		// overlap, then let the echo server close on "exit".
		cmd.Stdin = strings.NewReader(marker + "\n" + "exit\n")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
		results <- consoleRunResult{label: label, marker: marker, res: &CommandResult{
			Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode, Err: err,
		}}
	}

	results := make(chan consoleRunResult, 2)
	go run("A", hostA, portA, "xkey-concurrent-a-53f1", results)
	go run("B", hostB, portB, "xkey-concurrent-b-6e28", results)

	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if !r.res.Success() {
				t.Errorf("session %s exited non-zero: %s", r.label, r.res.Combined())
				continue
			}
			if !r.res.OutputContains(r.marker) {
				t.Errorf("session %s did not echo marker %q\nstdout: %s\nstderr: %s",
					r.label, r.marker, r.res.Stdout, r.res.Stderr)
			}
		case <-time.After(45 * time.Second):
			t.Fatal("timed out waiting for concurrent console sessions")
		}
	}
}
