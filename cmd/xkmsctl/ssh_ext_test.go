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

// ssh_ext_test.go covers the xkmsctl "ssh keys import", "ssh known-hosts"
// and "ssh authorized-keys" command trees against the real file-backed
// embedded SDK transport. Nothing outside t.TempDir is touched.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
)

// newSSHExtCmd builds a standalone cobra.Command carrying every flag the
// import / known-hosts / authorized-keys commands register, so each test
// gets an isolated FlagSet.
func newSSHExtCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("scope", "user", "")
	cmd.Flags().String("owner", "default", "")
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("comment", "", "")
	cmd.Flags().String("file", "", "")
	cmd.Flags().String("host", "", "")
	cmd.Flags().String("fingerprint", "", "")
	cmd.Flags().String("algorithm", "", "")
	cmd.Flags().String("source", "xkmsctl", "")
	cmd.Flags().String("key", "", "")
	cmd.Flags().String("line", "", "")
	cmd.Flags().StringSlice("option", nil, "")
	return cmd
}

// newTestSSHKeyPair returns a freshly generated ed25519 pair as an
// unencrypted OpenSSH PEM plus its authorized_keys line.
func newTestSSHKeyPair(t *testing.T) (pemBytes []byte, pub gossh.PublicKey, line string) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(privKey, "xkmsctl-test")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	return pem.EncodeToMemory(block), sshPub, strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPub)))
}

// writeTempFile writes content to a file in a fresh temp dir and returns
// its path.
func writeTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// ---------------------------------------------------------------
// ssh keys import
// ---------------------------------------------------------------

func TestRunXkmsctlSSHImport_MissingFile(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHImport(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHFile) {
		t.Fatalf("want ErrSSHFile, got %v", err)
	}
}

func TestRunXkmsctlSSHImport_UnreadableFile(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("file", filepath.Join(t.TempDir(), "absent.pem"))

	err := runXkmsctlSSHImport(cmd, nil)
	if !errors.Is(err, ErrSSHReadFile) {
		t.Fatalf("want ErrSSHReadFile, got %v", err)
	}
}

func TestRunXkmsctlSSHImport_UnparseablePEM(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("file", writeTempFile(t, "junk.pem", []byte("not a pem at all")))

	if err := runXkmsctlSSHImport(cmd, nil); err == nil {
		t.Fatal("expected an error importing a non-PEM file")
	}
}

func TestRunXkmsctlSSHImport_Success(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	pemBytes, _, _ := newTestSSHKeyPair(t)
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("file", writeTempFile(t, "id_ed25519.pem", pemBytes))
	_ = cmd.Flags().Set("name", "imported")

	out := captureStdout(t, func() {
		if err := runXkmsctlSSHImport(cmd, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "imported") {
		t.Errorf("expected key name in output, got: %q", out)
	}
	if !strings.Contains(out, "Fingerprint:") {
		t.Errorf("expected fingerprint in output, got: %q", out)
	}

	// The imported key must be retrievable through the normal get path.
	getCmd := newSSHCmd()
	_ = getCmd.Flags().Set("name", "imported")
	if err := runXkmsctlSSHGet(getCmd, nil); err != nil {
		t.Fatalf("get imported key: %v", err)
	}
}

// TestRunXkmsctlSSHImport_NameDefaultsToFileBase pins the documented
// default: an omitted --name derives from the file's base name.
func TestRunXkmsctlSSHImport_NameDefaultsToFileBase(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	pemBytes, _, _ := newTestSSHKeyPair(t)
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("file", writeTempFile(t, "laptop.pem", pemBytes))

	out := captureStdout(t, func() {
		if err := runXkmsctlSSHImport(cmd, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "laptop") {
		t.Errorf("expected the file base name to become the key name, got: %q", out)
	}
}

func TestRunXkmsctlSSHImport_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	pemBytes, _, _ := newTestSSHKeyPair(t)
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("file", writeTempFile(t, "id.pem", pemBytes))

	if err := runXkmsctlSSHImport(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

// ---------------------------------------------------------------
// ssh known-hosts
// ---------------------------------------------------------------

func TestSSHKnownHostsLifecycle(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	_, pub, _ := newTestSSHKeyPair(t)
	fingerprint := gossh.FingerprintSHA256(pub)

	// Empty store first.
	out := captureStdout(t, func() {
		if err := runXkmsctlSSHKnownHostsList(newSSHExtCmd(), nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(out, "No pinned host keys found") {
		t.Errorf("expected empty-list message, got: %q", out)
	}

	// Pin the host key.
	addCmd := newSSHExtCmd()
	_ = addCmd.Flags().Set("host", "git.example.com")
	_ = addCmd.Flags().Set("fingerprint", fingerprint)
	_ = addCmd.Flags().Set("algorithm", pub.Type())
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHKnownHostsAdd(addCmd, nil); err != nil {
			t.Fatalf("add: %v", err)
		}
	})
	if !strings.Contains(out, "git.example.com") {
		t.Errorf("expected host in add output, got: %q", out)
	}

	// The pin now lists.
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHKnownHostsList(newSSHExtCmd(), nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(out, fingerprint) {
		t.Errorf("expected fingerprint in list output, got: %q", out)
	}

	// Verifying the matching key succeeds.
	verifyCmd := newSSHExtCmd()
	_ = verifyCmd.Flags().Set("host", "git.example.com")
	_ = verifyCmd.Flags().Set("key", string(gossh.MarshalAuthorizedKey(pub)))
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHKnownHostsVerify(verifyCmd, nil); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
	if !strings.Contains(out, "matches the pin store") {
		t.Errorf("expected match message, got: %q", out)
	}

	// A different key for the same host must be rejected — this is the
	// host-key-changed alarm, so a false negative here is a real hazard.
	_, otherPub, _ := newTestSSHKeyPair(t)
	mismatchCmd := newSSHExtCmd()
	_ = mismatchCmd.Flags().Set("host", "git.example.com")
	_ = mismatchCmd.Flags().Set("key", string(gossh.MarshalAuthorizedKey(otherPub)))
	if err := runXkmsctlSSHKnownHostsVerify(mismatchCmd, nil); err == nil {
		t.Fatal("expected verification to fail for a host key that does not match the pin")
	}

	// Remove the pin.
	rmCmd := newSSHExtCmd()
	_ = rmCmd.Flags().Set("host", "git.example.com")
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHKnownHostsRemove(rmCmd, nil); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})
	if !strings.Contains(out, "Removed host-key pin") {
		t.Errorf("expected removal message, got: %q", out)
	}

	out = captureStdout(t, func() {
		if err := runXkmsctlSSHKnownHostsList(newSSHExtCmd(), nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(out, "No pinned host keys found") {
		t.Errorf("expected empty list after removal, got: %q", out)
	}
}

func TestRunXkmsctlSSHKnownHostsAdd_MissingHost(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHKnownHostsAdd(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHHost) {
		t.Fatalf("want ErrSSHHost, got %v", err)
	}
}

func TestRunXkmsctlSSHKnownHostsAdd_MissingFingerprint(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("host", "git.example.com")
	if err := runXkmsctlSSHKnownHostsAdd(cmd, nil); !errors.Is(err, ErrSSHFingerprint) {
		t.Fatalf("want ErrSSHFingerprint, got %v", err)
	}
}

func TestRunXkmsctlSSHKnownHostsAdd_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("host", "git.example.com")
	_ = cmd.Flags().Set("fingerprint", "SHA256:abc")
	if err := runXkmsctlSSHKnownHostsAdd(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHKnownHostsList_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	if err := runXkmsctlSSHKnownHostsList(newSSHExtCmd(), nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHKnownHostsRemove_MissingHost(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHKnownHostsRemove(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHHost) {
		t.Fatalf("want ErrSSHHost, got %v", err)
	}
}

func TestRunXkmsctlSSHKnownHostsRemove_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("host", "git.example.com")
	if err := runXkmsctlSSHKnownHostsRemove(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHKnownHostsVerify_MissingHost(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHKnownHostsVerify(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHHost) {
		t.Fatalf("want ErrSSHHost, got %v", err)
	}
}

func TestRunXkmsctlSSHKnownHostsVerify_MissingKey(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("host", "git.example.com")
	if err := runXkmsctlSSHKnownHostsVerify(cmd, nil); !errors.Is(err, ErrSSHLine) {
		t.Fatalf("want ErrSSHLine, got %v", err)
	}
}

// TestRunXkmsctlSSHKnownHostsVerify_KeyFromFile covers the --file
// alternative to --key.
func TestRunXkmsctlSSHKnownHostsVerify_KeyFromFile(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	_, pub, line := newTestSSHKeyPair(t)

	addCmd := newSSHExtCmd()
	_ = addCmd.Flags().Set("host", "files.example.com")
	_ = addCmd.Flags().Set("fingerprint", gossh.FingerprintSHA256(pub))
	if err := runXkmsctlSSHKnownHostsAdd(addCmd, nil); err != nil {
		t.Fatalf("add: %v", err)
	}

	verifyCmd := newSSHExtCmd()
	_ = verifyCmd.Flags().Set("host", "files.example.com")
	_ = verifyCmd.Flags().Set("file", writeTempFile(t, "host.pub", []byte(line)))
	out := captureStdout(t, func() {
		if err := runXkmsctlSSHKnownHostsVerify(verifyCmd, nil); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
	if !strings.Contains(out, "matches the pin store") {
		t.Errorf("expected match message, got: %q", out)
	}
}

// ---------------------------------------------------------------
// ssh authorized-keys
// ---------------------------------------------------------------

func TestSSHAuthorizedKeysLifecycle(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	_, pub, line := newTestSSHKeyPair(t)

	out := captureStdout(t, func() {
		if err := runXkmsctlSSHAuthorizedList(newSSHExtCmd(), nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(out, "No authorized entries found") {
		t.Errorf("expected empty-list message, got: %q", out)
	}

	addCmd := newSSHExtCmd()
	_ = addCmd.Flags().Set("name", "ci-runner")
	_ = addCmd.Flags().Set("line", line)
	_ = addCmd.Flags().Set("comment", "ci")
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHAuthorizedAdd(addCmd, nil); err != nil {
			t.Fatalf("add: %v", err)
		}
	})
	if !strings.Contains(out, "ci-runner") {
		t.Errorf("expected entry name in add output, got: %q", out)
	}

	getCmd := newSSHExtCmd()
	_ = getCmd.Flags().Set("name", "ci-runner")
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHAuthorizedGet(getCmd, nil); err != nil {
			t.Fatalf("get: %v", err)
		}
	})
	if !strings.Contains(out, "ci-runner") {
		t.Errorf("expected entry name in get output, got: %q", out)
	}

	out = captureStdout(t, func() {
		if err := runXkmsctlSSHAuthorizedList(newSSHExtCmd(), nil); err != nil {
			t.Fatalf("list: %v", err)
		}
	})
	if !strings.Contains(out, "ci-runner") {
		t.Errorf("expected entry in list output, got: %q", out)
	}

	// Verify the matching key resolves back to the entry.
	verifyCmd := newSSHExtCmd()
	_ = verifyCmd.Flags().Set("key", line)
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHAuthorizedVerify(verifyCmd, nil); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
	if !strings.Contains(out, "ci-runner") {
		t.Errorf("expected entry name in verify output, got: %q", out)
	}
	_ = pub

	// An unrelated key must not authorize.
	_, _, otherLine := newTestSSHKeyPair(t)
	denyCmd := newSSHExtCmd()
	_ = denyCmd.Flags().Set("key", otherLine)
	if err := runXkmsctlSSHAuthorizedVerify(denyCmd, nil); err == nil {
		t.Fatal("expected verification to fail for a key that was never authorized")
	}

	rmCmd := newSSHExtCmd()
	_ = rmCmd.Flags().Set("name", "ci-runner")
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHAuthorizedRemove(rmCmd, nil); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})
	if !strings.Contains(out, "Removed authorized entry") {
		t.Errorf("expected removal message, got: %q", out)
	}

	getCmd2 := newSSHExtCmd()
	_ = getCmd2.Flags().Set("name", "ci-runner")
	if err := runXkmsctlSSHAuthorizedGet(getCmd2, nil); err == nil {
		t.Fatal("expected error getting a removed authorized entry")
	}
}

func TestRunXkmsctlSSHAuthorizedAdd_MissingName(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHAuthorizedAdd(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHName) {
		t.Fatalf("want ErrSSHName, got %v", err)
	}
}

func TestRunXkmsctlSSHAuthorizedAdd_MissingLine(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("name", "ci-runner")
	if err := runXkmsctlSSHAuthorizedAdd(cmd, nil); !errors.Is(err, ErrSSHLine) {
		t.Fatalf("want ErrSSHLine, got %v", err)
	}
}

func TestRunXkmsctlSSHAuthorizedAdd_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("name", "ci-runner")
	_ = cmd.Flags().Set("line", "ssh-ed25519 AAAA")
	if err := runXkmsctlSSHAuthorizedAdd(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHAuthorizedGet_MissingName(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHAuthorizedGet(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHName) {
		t.Fatalf("want ErrSSHName, got %v", err)
	}
}

func TestRunXkmsctlSSHAuthorizedGet_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("name", "ci-runner")
	if err := runXkmsctlSSHAuthorizedGet(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHAuthorizedList_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	if err := runXkmsctlSSHAuthorizedList(newSSHExtCmd(), nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHAuthorizedRemove_MissingName(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHAuthorizedRemove(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHName) {
		t.Fatalf("want ErrSSHName, got %v", err)
	}
}

func TestRunXkmsctlSSHAuthorizedRemove_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("name", "ci-runner")
	if err := runXkmsctlSSHAuthorizedRemove(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHAuthorizedEmit_MissingLine(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHAuthorizedEmit(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHLine) {
		t.Fatalf("want ErrSSHLine, got %v", err)
	}
}

func TestRunXkmsctlSSHAuthorizedEmit_Success(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	_, _, line := newTestSSHKeyPair(t)
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("line", line)
	_ = cmd.Flags().Set("option", "no-pty,no-agent-forwarding")
	_ = cmd.Flags().Set("comment", "deploy")

	out := captureStdout(t, func() {
		if err := runXkmsctlSSHAuthorizedEmit(cmd, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "no-pty") {
		t.Errorf("expected options in emitted line, got: %q", out)
	}
	if !strings.Contains(out, "deploy") {
		t.Errorf("expected comment in emitted line, got: %q", out)
	}
}

func TestRunXkmsctlSSHAuthorizedVerify_MissingKey(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	if err := runXkmsctlSSHAuthorizedVerify(newSSHExtCmd(), nil); !errors.Is(err, ErrSSHLine) {
		t.Fatalf("want ErrSSHLine, got %v", err)
	}
}

func TestRunXkmsctlSSHAuthorizedVerify_UnparseableKey(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("key", "this is not a public key")
	if err := runXkmsctlSSHAuthorizedVerify(cmd, nil); !errors.Is(err, ErrSSHParsePublicKey) {
		t.Fatalf("want ErrSSHParsePublicKey, got %v", err)
	}
}

// ---------------------------------------------------------------
// Helper + registration
// ---------------------------------------------------------------

func TestSSHPublicKeyFromFlags_UnreadableFile(t *testing.T) {
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("file", filepath.Join(t.TempDir(), "absent.pub"))
	if _, err := sshPublicKeyFromFlags(cmd); !errors.Is(err, ErrSSHReadFile) {
		t.Fatalf("want ErrSSHReadFile, got %v", err)
	}
}

func TestSSHPublicKeyFromFlags_KeyWins(t *testing.T) {
	_, pub, line := newTestSSHKeyPair(t)
	cmd := newSSHExtCmd()
	_ = cmd.Flags().Set("key", line)
	got, err := sshPublicKeyFromFlags(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gossh.FingerprintSHA256(got) != gossh.FingerprintSHA256(pub) {
		t.Error("parsed key does not match the source key")
	}
}

func TestSSHExtCmd_Registration(t *testing.T) {
	keys := map[string]bool{}
	for _, c := range sshKeysCmd.Commands() {
		keys[c.Name()] = true
	}
	if !keys["import"] {
		t.Error("expected ssh keys subcommand \"import\" to be registered")
	}

	groups := map[string]bool{}
	for _, c := range sshCmd.Commands() {
		groups[c.Name()] = true
	}
	for _, name := range []string{"keys", "known-hosts", "authorized-keys"} {
		if !groups[name] {
			t.Errorf("expected ssh subcommand %q to be registered", name)
		}
	}

	known := map[string]bool{}
	for _, c := range sshKnownHostsCmd.Commands() {
		known[c.Name()] = true
	}
	for _, name := range []string{"add", "list", "remove", "verify"} {
		if !known[name] {
			t.Errorf("expected ssh known-hosts subcommand %q to be registered", name)
		}
	}

	authorized := map[string]bool{}
	for _, c := range sshAuthorizedKeysCmd.Commands() {
		authorized[c.Name()] = true
	}
	for _, name := range []string{"add", "get", "list", "remove", "emit", "verify"} {
		if !authorized[name] {
			t.Errorf("expected ssh authorized-keys subcommand %q to be registered", name)
		}
	}
}
