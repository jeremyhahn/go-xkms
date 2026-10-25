// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration && linux

// This file exercises `xkey secret-service` (go-xkms#723) against the real
// secret-tool and git-credential-libsecret binaries over a private D-Bus
// session bus. It must run under `dbus-run-session` so DBUS_SESSION_BUS_ADDRESS
// is set for the whole process tree (the daemon and the tool it is tested
// against both need to land on the same bus); see the
// integration-test-secretservice Makefile target, which wraps `go test`
// exactly that way.
//
// As of this writing the devcontainer image installs neither
// libsecret-tools (secret-tool) nor git's libsecret credential helper
// (git-credential-libsecret) -- see build/docker/devcontainer/Dockerfile, which has no
// dbus/libsecret packages at all. requireTool below fails loudly with that
// explanation rather than silently skipping, per project policy (no skip
// guards): adding those packages to the devcontainer image is a separate,
// owner-approved change this issue's investigation flagged but did not make.
package xkey

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// requireTool resolves name on PATH or fails the test with an explanation,
// instead of skipping, so a devcontainer image missing the tool reports the
// gap rather than reporting a false pass.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s not found on PATH: the devcontainer image does not install it today "+
			"(see build/docker/devcontainer/Dockerfile and docs/secret-service/engineering.md); "+
			"install it in the devcontainer image to run this test, it is not skipped", name)
	}
	return path
}

// requireDBusSession fails the test with an explanation if it was not
// launched under dbus-run-session (or an equivalent private/real session
// bus), rather than silently reusing whatever bus happens to be reachable.
func requireDBusSession(t *testing.T) {
	t.Helper()
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Fatal("DBUS_SESSION_BUS_ADDRESS is not set; run this test under " +
			"`dbus-run-session -- go test ...` (see the integration-test-secretservice Makefile target)")
	}
}

// secretServiceIntegrationPassword is used for every barrier this file
// initializes; each test gets its own SetupCleanEnvironment data directory,
// so reusing one password across tests does not share any state.
const secretServiceIntegrationPassword = "integration-test-password-12345"

// startSecretServiceDaemon initializes a fresh barrier under dataDir,
// starts `xkey secret-service` against it as a background process, and
// waits for it to claim org.freedesktop.secrets on the bus dbus-run-session
// set up for this process tree. The daemon is stopped (SIGINT, escalating
// to SIGKILL after 5s) via t.Cleanup.
func startSecretServiceDaemon(t *testing.T, binary, dataDir string) {
	t.Helper()
	requireDBusSession(t)

	pw := secretServiceIntegrationPassword
	RunXKeyExpectSuccess(t, binary, pw+"\n"+pw+"\n",
		"barrier", "init", "--strategy", "software", "--data-dir", dataDir)

	cmd := exec.Command(binary, "secret-service", "--data-dir", dataDir, "--barrier-password", pw)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start xkey secret-service: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		probe := exec.Command("dbus-send", "--session", "--dest=org.freedesktop.secrets",
			"--type=method_call", "--print-reply",
			"/org/freedesktop/secrets", "org.freedesktop.DBus.Peer.Ping")
		if probe.Run() == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("xkey secret-service did not claim org.freedesktop.secrets within 10s; stderr:\n%s", stderr.String())
}

// TestSecretService_SecretToolRoundTrip is the go-xkms#723 verification
// target: `secret-tool store`, `lookup`, and `clear` against a live xkey
// secret-service daemon must round-trip a secret exactly like they do
// against gnome-keyring or kwallet.
func TestSecretService_SecretToolRoundTrip(t *testing.T) {
	binary := getOrBuildBinary(t)
	secretTool := requireTool(t, "secret-tool")
	dataDir := SetupCleanEnvironment(t)

	startSecretServiceDaemon(t, binary, dataDir)

	store := exec.Command(secretTool, "store", "--label=xkey integration test",
		"service", "xkey-integration-test", "username", "octocat")
	store.Stdin = strings.NewReader("s3cret-value\n")
	if out, err := store.CombinedOutput(); err != nil {
		t.Fatalf("secret-tool store failed: %v\n%s", err, out)
	}

	lookup := exec.Command(secretTool, "lookup", "service", "xkey-integration-test", "username", "octocat")
	out, err := lookup.Output()
	if err != nil {
		t.Fatalf("secret-tool lookup failed: %v", err)
	}
	if got := strings.TrimRight(string(out), "\n"); got != "s3cret-value" {
		t.Fatalf("secret-tool lookup returned %q, want %q", got, "s3cret-value")
	}

	clear := exec.Command(secretTool, "clear", "service", "xkey-integration-test", "username", "octocat")
	if out, err := clear.CombinedOutput(); err != nil {
		t.Fatalf("secret-tool clear failed: %v\n%s", err, out)
	}

	lookupAfterClear := exec.Command(secretTool, "lookup", "service", "xkey-integration-test", "username", "octocat")
	if out, err := lookupAfterClear.Output(); err == nil {
		t.Fatalf("secret-tool lookup succeeded after clear, got %q", out)
	}
}

// TestSecretService_GitCredentialLibsecretRoundTrip is the second go-xkms#723
// verification target: git's libsecret credential helper (store/get/erase)
// against a live xkey secret-service daemon.
func TestSecretService_GitCredentialLibsecretRoundTrip(t *testing.T) {
	binary := getOrBuildBinary(t)
	helper := requireTool(t, "git-credential-libsecret")
	dataDir := SetupCleanEnvironment(t)

	startSecretServiceDaemon(t, binary, dataDir)

	store := exec.Command(helper, "store")
	store.Stdin = strings.NewReader("protocol=https\nhost=github.com\nusername=octocat\npassword=s3cret-value\n\n")
	if out, err := store.CombinedOutput(); err != nil {
		t.Fatalf("git-credential-libsecret store failed: %v\n%s", err, out)
	}

	get := exec.Command(helper, "get")
	get.Stdin = strings.NewReader("protocol=https\nhost=github.com\nusername=octocat\n\n")
	out, err := get.Output()
	if err != nil {
		t.Fatalf("git-credential-libsecret get failed: %v", err)
	}
	if !strings.Contains(string(out), "password=s3cret-value") {
		t.Fatalf("git-credential-libsecret get did not return the stored password, got: %s", out)
	}

	erase := exec.Command(helper, "erase")
	erase.Stdin = strings.NewReader("protocol=https\nhost=github.com\nusername=octocat\n\n")
	if out, err := erase.CombinedOutput(); err != nil {
		t.Fatalf("git-credential-libsecret erase failed: %v\n%s", err, out)
	}
}
