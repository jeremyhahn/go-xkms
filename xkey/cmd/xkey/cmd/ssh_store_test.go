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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
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
	writeBarrierRootKey(t, dataDir, []byte("sealed"))

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

// TestSSHStores_ReleaseBackendOnClose opens the embedded SSH client and every
// SSH store twice in one process over the Pebble engine, which refuses a
// second open of a store its own process still holds: each open succeeds
// only if the previous command's closer released the backend.
func TestSSHStores_ReleaseBackendOnClose(t *testing.T) {
	withCLIHome(t)
	t.Setenv("XKMSD_URL", "")
	cfg := xkeyconfig.DefaultConfig()
	cfg.State.StorageEngine = "pebble"
	loadedConfig = cfg

	opens := map[string]func() (func(), error){
		"client": func() (func(), error) {
			_, closer, err := sshClient(nil)
			return closer, err
		},
		"profiles": func() (func(), error) {
			_, closer, err := xkeyProfileStore()
			return closer, err
		},
		"host keys": func() (func(), error) {
			_, closer, err := xkeyHostKeyStore()
			return closer, err
		},
		"sessions": func() (func(), error) {
			_, closer, err := xkeySessionStore()
			return closer, err
		},
	}
	for name, open := range opens {
		for attempt := 1; attempt <= 2; attempt++ {
			closer, err := open()
			if err != nil {
				t.Fatalf("%s open %d: %v", name, attempt, err)
			}
			closer()
		}
	}
}

// TestSSHClientWithHostKeys_OneBackendOnPebble covers the storage path of
// `ssh connect`, which needs the client (for the signer) and the host-key pin
// store at the same time. The Pebble engine refuses a second open of a store
// its own process still holds, so both must run over one backend: a pin added
// through the client is visible in the host-key store, and a second command
// opens again once the closer has released it.
func TestSSHClientWithHostKeys_OneBackendOnPebble(t *testing.T) {
	withCLIHome(t)
	t.Setenv("XKMSD_URL", "")
	cfg := xkeyconfig.DefaultConfig()
	cfg.State.StorageEngine = "pebble"
	loadedConfig = cfg

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostKey, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("host public key: %v", err)
	}
	ctx := context.Background()
	const host = "host.example.com"

	for attempt := 1; attempt <= 2; attempt++ {
		client, hostKeys, closer, err := sshClientWithHostKeys(nil)
		if err != nil {
			t.Fatalf("open %d: %v", attempt, err)
		}
		if attempt == 1 {
			if err := client.KnownHosts().Add(ctx, sshsdk.AddKnownHostRequest{
				Scope: "user", Owner: "local", Host: host,
				Fingerprint: gossh.FingerprintSHA256(hostKey),
				PublicKey:   strings.TrimSpace(string(gossh.MarshalAuthorizedKey(hostKey))),
			}); err != nil {
				closer()
				t.Fatalf("pin through the client: %v", err)
			}
		}
		pins, err := hostKeys.List(ctx, "", "")
		closer()
		if err != nil {
			t.Fatalf("list %d: %v", attempt, err)
		}
		if len(pins) != 1 || pins[0].Host != host {
			t.Fatalf("list %d: got %d pins, want the one pinned through the client", attempt, len(pins))
		}
	}
}

func TestSSHClientWithHostKeys_BarrierEncryptedStore(t *testing.T) {
	home := withCLIHome(t)
	t.Setenv("XKMSD_URL", "")
	writeBarrierRootKey(t, filepath.Join(home, ".xkey-store"), []byte("sealed"))

	if _, _, _, err := sshClientWithHostKeys(nil); !errors.Is(err, ErrSSHStoreBarrierEncrypted) {
		t.Fatalf("expected ErrSSHStoreBarrierEncrypted, got %v", err)
	}
}
