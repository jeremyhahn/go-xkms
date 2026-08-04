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

package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// withCLIHome points $HOME at a fresh temp dir and resets the package-level
// resolvedHome/loadedConfig globals for the duration of the test, so the
// CLI's store-resolution helpers behave deterministically regardless of test
// execution order or the host machine's own xkey installation.
func withCLIHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	oldHome, oldConfig := resolvedHome, loadedConfig
	resolvedHome = nil
	loadedConfig = nil
	t.Cleanup(func() {
		resolvedHome = oldHome
		loadedConfig = oldConfig
	})
	return home
}

func TestResolveXKeySSHDataDir_NoResolvedHome(t *testing.T) {
	home := withCLIHome(t)

	dir, err := resolveXKeySSHDataDir()
	if err != nil {
		t.Fatalf("resolveXKeySSHDataDir: %v", err)
	}
	want := filepath.Join(home, ".xkey-store")
	if dir != want {
		t.Fatalf("dir = %q, want %q", dir, want)
	}
}

func TestXkeySSHStorageEngineKind_DefaultsToFile(t *testing.T) {
	withCLIHome(t)
	if kind := xkeySSHStorageEngineKind(); kind != xkmssdk.StorageEngineFile {
		t.Fatalf("kind = %q, want %q", kind, xkmssdk.StorageEngineFile)
	}
}

func TestXkeySSHBackend_PlainPath(t *testing.T) {
	withCLIHome(t)

	backend, err := xkeySSHBackend()
	if err != nil {
		t.Fatalf("xkeySSHBackend: %v", err)
	}
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	if err := backend.Put(ctx, "probe", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := backend.Get(ctx, "probe")
	if err != nil || string(got) != "v" {
		t.Fatalf("Get: got %q, err %v", got, err)
	}
}

func TestXkeySSHBackend_BarrierEncrypted(t *testing.T) {
	home := withCLIHome(t)

	dataDir := filepath.Join(home, ".xkey-store")
	barrierDir := filepath.Join(dataDir, "barrier")
	if err := os.MkdirAll(barrierDir, 0o700); err != nil {
		t.Fatalf("mkdir barrier dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(barrierDir, "root_key"), []byte("sealed"), 0o600); err != nil {
		t.Fatalf("write root_key: %v", err)
	}

	_, err := xkeySSHBackend()
	if !errors.Is(err, ErrSSHStoreBarrierEncrypted) {
		t.Fatalf("expected ErrSSHStoreBarrierEncrypted, got %v", err)
	}
}

func TestSSHClient_EmbeddedFallback(t *testing.T) {
	withCLIHome(t)
	t.Setenv("XKMSD_URL", "")

	client, closer, err := sshClient(nil)
	if err != nil {
		t.Fatalf("sshClient: %v", err)
	}
	defer closer()

	if _, err := client.Keys().Generate(context.Background(), sshsdk.GenerateRequest{
		Scope: "user", Owner: "local", Name: "probe", Algorithm: "ed25519",
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
}
