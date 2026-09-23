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

// ssh_test.go exercises the xkmsctl "ssh keys" command tree end to end
// against the real file-backed embedded SDK transport (sdk/go/client/ssh).
// No network or host mutation occurs outside t.TempDir.
package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newSSHTestConfig returns a Config wired to an embedded, file-backed SSH
// transport rooted at a fresh temp directory.
func newSSHTestConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		OutputFormat: "text",
		Protocol:     "embedded",
		KeyDir:       t.TempDir(),
	}
}

func TestXkmsctlSSHClient_Embedded(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))

	cl, closer, err := xkmsctlSSHClient()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cl == nil {
		t.Fatal("expected non-nil client")
	}
	closer()
}

func TestXkmsctlSSHClient_DefaultsToEmbedded(t *testing.T) {
	// Empty Protocol and Server also route to the embedded transport.
	withGlobalConfig(t, &Config{OutputFormat: "text", KeyDir: t.TempDir()})

	cl, closer, err := xkmsctlSSHClient()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cl == nil {
		t.Fatal("expected non-nil client")
	}
	closer()
}

func TestXkmsctlSSHClient_NonEmbeddedNoServer(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})

	_, _, err := xkmsctlSSHClient()
	if err == nil {
		t.Fatal("expected error when --server is empty for a non-embedded protocol")
	}
	if !strings.Contains(err.Error(), "--server is required") {
		t.Errorf("error %q does not mention --server", err.Error())
	}
	if !errors.Is(err, ErrSSHServerRequired) {
		t.Errorf("err = %v, want errors.Is match against ErrSSHServerRequired", err)
	}
}

// newSSHCmd builds a standalone cobra.Command carrying the same flags the
// real sshKeys* commands register, so each test gets an isolated FlagSet.
func newSSHCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("scope", "user", "")
	cmd.Flags().String("owner", "default", "")
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("type", "ed25519", "")
	cmd.Flags().Int("bits", 0, "")
	cmd.Flags().String("comment", "", "")
	cmd.Flags().String("key-backend", "", "")
	cmd.Flags().String("data", "xkmsctl-ssh-sign", "")
	return cmd
}

func TestRunXkmsctlSSHGenerate_MissingName(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHCmd()
	err := runXkmsctlSSHGenerate(cmd, nil)
	if !errors.Is(err, ErrSSHName) {
		t.Fatalf("want ErrSSHName, got %v", err)
	}
}

func TestRunXkmsctlSSHGenerate_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHCmd()
	_ = cmd.Flags().Set("name", "id1")
	err := runXkmsctlSSHGenerate(cmd, nil)
	if err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHGenerate_Success(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHCmd()
	_ = cmd.Flags().Set("name", "my-key")
	_ = cmd.Flags().Set("type", "ed25519")
	_ = cmd.Flags().Set("comment", "test comment")

	out := captureStdout(t, func() {
		if err := runXkmsctlSSHGenerate(cmd, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "my-key") {
		t.Errorf("expected key name in output, got: %q", out)
	}
	if !strings.Contains(out, "Fingerprint:") {
		t.Errorf("expected fingerprint in output, got: %q", out)
	}
}

func TestSSHKeysLifecycle(t *testing.T) {
	cfg := newSSHTestConfig(t)
	withGlobalConfig(t, cfg)

	// List with no keys yet.
	listCmd := newSSHCmd()
	out := captureStdout(t, func() {
		if err := runXkmsctlSSHList(listCmd, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "No SSH keys found") {
		t.Errorf("expected empty-list message, got: %q", out)
	}

	// Generate a key.
	genCmd := newSSHCmd()
	_ = genCmd.Flags().Set("name", "deploy-key")
	_ = genCmd.Flags().Set("type", "ed25519")
	if err := runXkmsctlSSHGenerate(genCmd, nil); err != nil {
		t.Fatalf("generate: unexpected error: %v", err)
	}

	// List should now show the key.
	listCmd2 := newSSHCmd()
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHList(listCmd2, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "deploy-key") {
		t.Errorf("expected deploy-key in list output, got: %q", out)
	}

	// Get the key.
	getCmd := newSSHCmd()
	_ = getCmd.Flags().Set("name", "deploy-key")
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHGet(getCmd, nil); err != nil {
			t.Fatalf("get: unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "deploy-key") {
		t.Errorf("expected deploy-key in get output, got: %q", out)
	}

	// Export the public key.
	exportCmd := newSSHCmd()
	_ = exportCmd.Flags().Set("name", "deploy-key")
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHExport(exportCmd, nil); err != nil {
			t.Fatalf("export: unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "ssh-ed25519") {
		t.Errorf("expected ssh-ed25519 line in export output, got: %q", out)
	}

	// Sign with the key.
	signCmd := newSSHCmd()
	_ = signCmd.Flags().Set("name", "deploy-key")
	_ = signCmd.Flags().Set("data", "hello-world")
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHSign(signCmd, nil); err != nil {
			t.Fatalf("sign: unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "Signature:") {
		t.Errorf("expected Signature in sign output, got: %q", out)
	}

	// Delete the key.
	delCmd := newSSHCmd()
	_ = delCmd.Flags().Set("name", "deploy-key")
	out = captureStdout(t, func() {
		if err := runXkmsctlSSHDelete(delCmd, nil); err != nil {
			t.Fatalf("delete: unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "Deleted SSH key") {
		t.Errorf("expected deletion message, got: %q", out)
	}

	// Getting the now-deleted key should error.
	getCmd2 := newSSHCmd()
	_ = getCmd2.Flags().Set("name", "deploy-key")
	if err := runXkmsctlSSHGet(getCmd2, nil); err == nil {
		t.Fatal("expected error getting a deleted key")
	}
}

func TestRunXkmsctlSSHList_MissingClient(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHCmd()
	if err := runXkmsctlSSHList(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHGet_MissingName(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHCmd()
	if err := runXkmsctlSSHGet(cmd, nil); !errors.Is(err, ErrSSHName) {
		t.Fatalf("want ErrSSHName, got %v", err)
	}
}

func TestRunXkmsctlSSHExport_MissingName(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHCmd()
	if err := runXkmsctlSSHExport(cmd, nil); !errors.Is(err, ErrSSHName) {
		t.Fatalf("want ErrSSHName, got %v", err)
	}
}

func TestRunXkmsctlSSHSign_MissingName(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHCmd()
	if err := runXkmsctlSSHSign(cmd, nil); !errors.Is(err, ErrSSHName) {
		t.Fatalf("want ErrSSHName, got %v", err)
	}
}

func TestRunXkmsctlSSHDelete_MissingName(t *testing.T) {
	withGlobalConfig(t, newSSHTestConfig(t))
	cmd := newSSHCmd()
	if err := runXkmsctlSSHDelete(cmd, nil); !errors.Is(err, ErrSSHName) {
		t.Fatalf("want ErrSSHName, got %v", err)
	}
}

func TestRunXkmsctlSSHDelete_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHCmd()
	_ = cmd.Flags().Set("name", "id1")
	if err := runXkmsctlSSHDelete(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHExport_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHCmd()
	_ = cmd.Flags().Set("name", "id1")
	if err := runXkmsctlSSHExport(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHSign_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHCmd()
	_ = cmd.Flags().Set("name", "id1")
	if err := runXkmsctlSSHSign(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestRunXkmsctlSSHGet_ClientError(t *testing.T) {
	withGlobalConfig(t, &Config{OutputFormat: "text", Protocol: "grpc", Server: ""})
	cmd := newSSHCmd()
	_ = cmd.Flags().Set("name", "id1")
	if err := runXkmsctlSSHGet(cmd, nil); err == nil {
		t.Fatal("expected error when the SSH client cannot be constructed")
	}
}

func TestSSHCmd_Registration(t *testing.T) {
	found := map[string]bool{}
	for _, c := range sshKeysCmd.Commands() {
		found[c.Name()] = true
	}
	for _, name := range []string{"generate", "list", "get", "export", "sign", "delete"} {
		if !found[name] {
			t.Errorf("expected ssh keys subcommand %q to be registered", name)
		}
	}
}
