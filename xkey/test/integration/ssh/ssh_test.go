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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// ----------------------------------------------------------------------------
// xkey ssh keys generate
// ----------------------------------------------------------------------------

// TestSSHKeysGenerate verifies key generation for every supported
// algorithm over the embedded transport.
func TestSSHKeysGenerate(t *testing.T) {
	cases := []struct {
		name      string
		algorithm string
		extraArgs []string
	}{
		{"ed25519", "ed25519", nil},
		{"rsa_default_bits", "rsa", nil},
		{"rsa_2048", "rsa", []string{"--bits", "2048"}},
		{"ecdsa_p256", "ecdsa-p256", nil},
		{"ecdsa_p384", "ecdsa-p384", nil},
		{"ecdsa_p521", "ecdsa-p521", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewSSHTestHelper(t)
			keyName := "gen-" + tc.name

			args := []string{"generate",
				"--scope", "user", "--owner", "alice",
				"--name", keyName, "--type", tc.algorithm,
				"--comment", "integration test key"}
			args = append(args, tc.extraArgs...)

			result := h.RunSSHKeys(args...)
			if !result.Success() {
				t.Fatalf("generate %s failed (exit %d): %s",
					tc.algorithm, result.ExitCode, result.Combined())
			}
			if !result.OutputContains("Key: user/alice/" + keyName) {
				t.Errorf("missing key identity line in output: %s", result.Combined())
			}
			if !result.OutputContains(tc.algorithm) {
				t.Errorf("missing algorithm %q in output: %s", tc.algorithm, result.Combined())
			}
			if _, ok := ExtractFingerprint(result.Combined()); !ok {
				t.Errorf("missing SHA256 fingerprint in output: %s", result.Combined())
			}

			// The generated key must be listable and exportable.
			list := h.RunSSHKeys("list", "--scope", "user", "--owner", "alice")
			if !list.Success() || !list.OutputContains(keyName) {
				t.Errorf("generated key not in list output: %s", list.Combined())
			}

			export := h.RunSSHKeys("export",
				"--scope", "user", "--owner", "alice", "--name", keyName)
			if !export.Success() {
				t.Fatalf("export failed: %s", export.Combined())
			}
			if _, ok := ExtractPublicKey(export.Stdout); !ok {
				t.Errorf("export did not emit an authorized_keys line: %s", export.Stdout)
			}
		})
	}
}

// TestSSHKeysGenerateErrors verifies generation rejects invalid input
// with the documented typed-error messages.
func TestSSHKeysGenerateErrors(t *testing.T) {
	h := NewSSHTestHelper(t)

	t.Run("missing_name", func(t *testing.T) {
		result := h.RunSSHKeys("generate", "--type", "ed25519")
		if result.Success() {
			t.Fatal("generate without --name should fail")
		}
		if !result.OutputContains("--name is required") {
			t.Errorf("expected --name-required error, got: %s", result.Combined())
		}
	})

	t.Run("invalid_type", func(t *testing.T) {
		result := h.RunSSHKeys("generate", "--name", "bad-type", "--type", "dsa")
		if result.Success() {
			t.Fatal("generate with invalid --type should fail")
		}
		if !result.OutputContains("invalid key type") {
			t.Errorf("expected invalid-key-type error, got: %s", result.Combined())
		}
	})

	t.Run("invalid_scope", func(t *testing.T) {
		result := h.RunSSHKeys("generate",
			"--name", "bad-scope", "--scope", "galactic")
		if result.Success() {
			t.Fatal("generate with invalid --scope should fail")
		}
		if !result.OutputContains("invalid scope") {
			t.Errorf("expected invalid-scope error, got: %s", result.Combined())
		}
	})

	t.Run("unknown_flag", func(t *testing.T) {
		result := h.RunSSHKeys("generate", "--name", "x", "--id", "legacy")
		if result.Success() {
			t.Fatal("generate with the removed --id flag should fail")
		}
		if !result.OutputContains("unknown flag") {
			t.Errorf("expected unknown-flag error, got: %s", result.Combined())
		}
	})
}

// ----------------------------------------------------------------------------
// Full key lifecycle
// ----------------------------------------------------------------------------

// TestSSHKeysLifecycle drives generate -> list -> get -> export ->
// delete -> verify-gone end to end.
func TestSSHKeysLifecycle(t *testing.T) {
	h := NewSSHTestHelper(t)
	sel := []string{"--scope", "user", "--owner", "alice", "--name", "lifecycle"}

	gen := h.RunSSHKeys(append([]string{"generate", "--type", "ed25519"}, sel...)...)
	if !gen.Success() {
		t.Fatalf("generate failed: %s", gen.Combined())
	}
	genFP, ok := ExtractFingerprint(gen.Combined())
	if !ok {
		t.Fatalf("generate output missing fingerprint: %s", gen.Combined())
	}

	get := h.RunSSHKeys(append([]string{"get"}, sel...)...)
	if !get.Success() {
		t.Fatalf("get failed: %s", get.Combined())
	}
	getFP, ok := ExtractFingerprint(get.Combined())
	if !ok || getFP != genFP {
		t.Errorf("get fingerprint %q does not match generate fingerprint %q", getFP, genFP)
	}

	list := h.RunSSHKeys("list", "--scope", "user", "--owner", "alice")
	if !list.Success() || !list.OutputContainsAll("lifecycle", "ed25519", genFP) {
		t.Errorf("list missing key row: %s", list.Combined())
	}

	export := h.RunSSHKeys(append([]string{"export"}, sel...)...)
	if !export.Success() {
		t.Fatalf("export failed: %s", export.Combined())
	}
	if _, ok := ExtractPublicKey(export.Stdout); !ok {
		t.Errorf("export output is not an authorized_keys line: %s", export.Stdout)
	}

	del := h.RunSSHKeys(append([]string{"delete"}, sel...)...)
	if !del.Success() {
		t.Fatalf("delete failed: %s", del.Combined())
	}
	if !del.OutputContains("Deleted user/alice/lifecycle") {
		t.Errorf("delete confirmation missing: %s", del.Combined())
	}

	// The key must be gone from both get and list.
	getGone := h.RunSSHKeys(append([]string{"get"}, sel...)...)
	if getGone.Success() {
		t.Errorf("get after delete should fail, got: %s", getGone.Combined())
	}
	listGone := h.RunSSHKeys("list", "--scope", "user", "--owner", "alice")
	if !listGone.Success() {
		t.Fatalf("list after delete failed: %s", listGone.Combined())
	}
	if listGone.OutputContains("lifecycle") {
		t.Errorf("deleted key still listed: %s", listGone.Combined())
	}
}

// TestSSHKeysDeleteErrors verifies delete input validation.
func TestSSHKeysDeleteErrors(t *testing.T) {
	h := NewSSHTestHelper(t)

	t.Run("missing_name", func(t *testing.T) {
		result := h.RunSSHKeys("delete", "--scope", "user", "--owner", "alice")
		if result.Success() {
			t.Fatal("delete without --name should fail")
		}
		if !result.OutputContains("--name is required") {
			t.Errorf("expected --name-required error, got: %s", result.Combined())
		}
	})
}

// ----------------------------------------------------------------------------
// xkey ssh keys import
// ----------------------------------------------------------------------------

// TestSSHKeysImport verifies importing unencrypted ssh-keygen keys of
// every supported on-disk type.
func TestSSHKeysImport(t *testing.T) {
	for _, keyType := range []string{"ed25519", "rsa", "ecdsa"} {
		t.Run(keyType, func(t *testing.T) {
			h := NewSSHTestHelper(t)

			keyPath, err := h.CreateTestSSHKey(keyType, "")
			if err != nil {
				t.Fatalf("ssh-keygen failed: %v", err)
			}

			keyName := "imported-" + keyType
			result := h.RunSSHKeys("import", keyPath,
				"--scope", "user", "--owner", "alice", "--name", keyName)
			if !result.Success() {
				t.Fatalf("import failed: %s", result.Combined())
			}
			if !result.OutputContains("Imported SSH key: user/alice/" + keyName) {
				t.Errorf("missing import confirmation: %s", result.Combined())
			}
			if _, ok := ExtractFingerprint(result.Combined()); !ok {
				t.Errorf("missing fingerprint in import output: %s", result.Combined())
			}

			// The imported key's exported public half must match the
			// .pub file ssh-keygen wrote (modulo the comment).
			export := h.RunSSHKeys("export",
				"--scope", "user", "--owner", "alice", "--name", keyName)
			if !export.Success() {
				t.Fatalf("export of imported key failed: %s", export.Combined())
			}
			exported, ok := ExtractPublicKey(export.Stdout)
			if !ok {
				t.Fatalf("export output is not an authorized_keys line: %s", export.Stdout)
			}
			pubBytes, err := os.ReadFile(keyPath + ".pub")
			if err != nil {
				t.Fatalf("read .pub: %v", err)
			}
			original, ok := ExtractPublicKey(string(pubBytes))
			if !ok {
				t.Fatalf("ssh-keygen .pub unparsable: %s", string(pubBytes))
			}
			if exported != original {
				t.Errorf("exported public key does not match imported key:\n got: %s\nwant: %s",
					exported, original)
			}
		})
	}
}

// TestSSHKeysImportEncrypted verifies importing a passphrase-protected
// key with the passphrase piped on stdin (StdinProvider path).
func TestSSHKeysImportEncrypted(t *testing.T) {
	h := NewSSHTestHelper(t)

	const passphrase = "integration-passphrase"
	keyPath, err := h.CreateTestSSHKey("ed25519", passphrase)
	if err != nil {
		t.Fatalf("ssh-keygen failed: %v", err)
	}

	result := h.RunCommandWithStdin(passphrase+"\n",
		"ssh", "keys", "import", keyPath,
		"--scope", "user", "--owner", "alice", "--name", "imported-encrypted")
	if !result.Success() {
		t.Fatalf("encrypted import failed: %s", result.Combined())
	}
	if !result.OutputContains("Imported SSH key: user/alice/imported-encrypted") {
		t.Errorf("missing import confirmation: %s", result.Combined())
	}

	// Wrong passphrase must fail.
	wrong := h.RunCommandWithStdin("not-the-passphrase\n",
		"ssh", "keys", "import", keyPath,
		"--scope", "user", "--owner", "alice", "--name", "imported-encrypted-2")
	if wrong.Success() {
		t.Errorf("import with wrong passphrase should fail, got: %s", wrong.Combined())
	}
}

// TestSSHKeysImportErrors verifies import input validation.
func TestSSHKeysImportErrors(t *testing.T) {
	h := NewSSHTestHelper(t)

	t.Run("missing_file_argument", func(t *testing.T) {
		result := h.RunSSHKeys("import")
		if result.Success() {
			t.Fatal("import without a file argument should fail")
		}
	})

	t.Run("nonexistent_file", func(t *testing.T) {
		result := h.RunSSHKeys("import", filepath.Join(h.TempDir(), "does-not-exist.pem"),
			"--name", "ghost")
		if result.Success() {
			t.Fatal("import of a nonexistent file should fail")
		}
	})

	t.Run("invalid_pem", func(t *testing.T) {
		badPath := filepath.Join(h.TempDir(), "garbage.pem")
		if err := os.WriteFile(badPath, []byte("this is not a private key"), 0600); err != nil {
			t.Fatalf("write garbage file: %v", err)
		}
		result := h.RunSSHKeys("import", badPath, "--name", "garbage")
		if result.Success() {
			t.Fatal("import of garbage PEM should fail")
		}
	})
}

// ----------------------------------------------------------------------------
// Scope / owner semantics
// ----------------------------------------------------------------------------

// TestSSHKeysScopeOwnerIsolation verifies that keys are namespaced by
// (scope, owner) and operations on one namespace never leak into
// another.
func TestSSHKeysScopeOwnerIsolation(t *testing.T) {
	h := NewSSHTestHelper(t)

	namespaces := []struct{ scope, owner, name string }{
		{"user", "alice", "alice-key"},
		{"user", "bob", "bob-key"},
		{"service", "ci-runner", "ci-key"},
		{"tenant", "acme", "tenant-key"},
	}

	for _, ns := range namespaces {
		result := h.RunSSHKeys("generate",
			"--scope", ns.scope, "--owner", ns.owner,
			"--name", ns.name, "--type", "ed25519")
		if !result.Success() {
			t.Fatalf("generate %s/%s/%s failed: %s",
				ns.scope, ns.owner, ns.name, result.Combined())
		}
	}

	// Owner-filtered list shows only that owner's keys.
	aliceList := h.RunSSHKeys("list", "--scope", "user", "--owner", "alice")
	if !aliceList.Success() {
		t.Fatalf("list alice failed: %s", aliceList.Combined())
	}
	if !aliceList.OutputContains("alice-key") {
		t.Errorf("alice's key missing from her list: %s", aliceList.Combined())
	}
	for _, other := range []string{"bob-key", "ci-key", "tenant-key"} {
		if aliceList.OutputContains(other) {
			t.Errorf("foreign key %q leaked into alice's list: %s", other, aliceList.Combined())
		}
	}

	// Deleting bob's key must not disturb the others.
	del := h.RunSSHKeys("delete", "--scope", "user", "--owner", "bob", "--name", "bob-key")
	if !del.Success() {
		t.Fatalf("delete bob-key failed: %s", del.Combined())
	}
	for _, ns := range []struct{ scope, owner, name string }{
		{"user", "alice", "alice-key"},
		{"service", "ci-runner", "ci-key"},
		{"tenant", "acme", "tenant-key"},
	} {
		get := h.RunSSHKeys("get", "--scope", ns.scope, "--owner", ns.owner, "--name", ns.name)
		if !get.Success() {
			t.Errorf("key %s/%s/%s lost after unrelated delete: %s",
				ns.scope, ns.owner, ns.name, get.Combined())
		}
	}
}

// TestSSHKeysDefaultScopeOwner verifies the CLI defaults: scope=user,
// owner=$USER.
func TestSSHKeysDefaultScopeOwner(t *testing.T) {
	h := NewSSHTestHelper(t)

	gen := h.RunSSHKeys("generate", "--name", "defaults", "--type", "ed25519")
	if !gen.Success() {
		t.Fatalf("generate with defaults failed: %s", gen.Combined())
	}
	if !gen.OutputContains("Key: user/" + h.User() + "/defaults") {
		t.Errorf("expected default scope/owner user/%s, got: %s", h.User(), gen.Combined())
	}

	get := h.RunSSHKeys("get", "--name", "defaults")
	if !get.Success() {
		t.Errorf("get with default scope/owner failed: %s", get.Combined())
	}
}

// TestSSHKeysAliases verifies the documented cobra aliases (ls, rm).
func TestSSHKeysAliases(t *testing.T) {
	h := NewSSHTestHelper(t)

	gen := h.RunSSHKeys("generate",
		"--scope", "user", "--owner", "alice", "--name", "aliased", "--type", "ed25519")
	if !gen.Success() {
		t.Fatalf("generate failed: %s", gen.Combined())
	}

	ls := h.RunSSHKeys("ls", "--scope", "user", "--owner", "alice")
	if !ls.Success() || !ls.OutputContains("aliased") {
		t.Errorf("keys ls alias failed: %s", ls.Combined())
	}

	rm := h.RunSSHKeys("rm", "--scope", "user", "--owner", "alice", "--name", "aliased")
	if !rm.Success() || !rm.OutputContains("Deleted user/alice/aliased") {
		t.Errorf("keys rm alias failed: %s", rm.Combined())
	}
}

// ----------------------------------------------------------------------------
// xkey ssh host-keys
// ----------------------------------------------------------------------------

// TestSSHHostKeys drives the host-key pin lifecycle: add, list, remove,
// including the known-hosts alias.
func TestSSHHostKeys(t *testing.T) {
	h := NewSSHTestHelper(t)
	const host = "bastion.example.com"
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostKey, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("host public key: %v", err)
	}
	fp := gossh.FingerprintSHA256(hostKey)

	// The key is read from a file here; the console suite pins with --key.
	keyFile := filepath.Join(t.TempDir(), "host_ed25519.pub")
	if err := os.WriteFile(keyFile, gossh.MarshalAuthorizedKey(hostKey), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}

	add := h.RunSSHHostKeys("add",
		"--scope", "user", "--owner", "alice",
		"--host", host, "--file", keyFile, "--source", "manual")
	if !add.Success() {
		t.Fatalf("host-keys add failed: %s", add.Combined())
	}
	if !add.OutputContainsAll("Pinned", host, fp) {
		t.Errorf("missing pin confirmation: %s", add.Combined())
	}

	list := h.RunSSHHostKeys("list", "--scope", "user", "--owner", "alice")
	if !list.Success() || !list.OutputContainsAll(host, fp, "ssh-ed25519") {
		t.Errorf("pinned host missing from list: %s", list.Combined())
	}

	// The known-hosts alias must reach the same data.
	aliasList := h.RunSSH("known-hosts", "list", "--scope", "user", "--owner", "alice")
	if !aliasList.Success() || !aliasList.OutputContains(host) {
		t.Errorf("known-hosts alias list failed: %s", aliasList.Combined())
	}

	remove := h.RunSSHHostKeys("remove",
		"--scope", "user", "--owner", "alice", "--host", host)
	if !remove.Success() || !remove.OutputContains("Removed pin for "+host) {
		t.Errorf("host-keys remove failed: %s", remove.Combined())
	}

	gone := h.RunSSHHostKeys("list", "--scope", "user", "--owner", "alice")
	if !gone.Success() {
		t.Fatalf("list after remove failed: %s", gone.Combined())
	}
	if gone.OutputContains(host) {
		t.Errorf("removed pin still listed: %s", gone.Combined())
	}
}

// TestSSHHostKeysErrors verifies host-key input validation.
func TestSSHHostKeysErrors(t *testing.T) {
	h := NewSSHTestHelper(t)

	t.Run("add_missing_host", func(t *testing.T) {
		result := h.RunSSHHostKeys("add", "--key", "ssh-ed25519 AAAA")
		if result.Success() {
			t.Fatal("add without --host should fail")
		}
		if !result.OutputContains("host is required") {
			t.Errorf("expected host-required error, got: %s", result.Combined())
		}
	})

	t.Run("add_missing_key", func(t *testing.T) {
		result := h.RunSSHHostKeys("add", "--host", "h.example.com")
		if result.Success() {
			t.Fatal("add without --key or --file should fail")
		}
		if !result.OutputContains("--key or --file is required") {
			t.Errorf("expected key-required error, got: %s", result.Combined())
		}
	})

	t.Run("add_unparseable_key", func(t *testing.T) {
		result := h.RunSSHHostKeys("add", "--host", "h.example.com", "--key", "not-a-key")
		if result.Success() {
			t.Fatal("add with an unparseable --key should fail")
		}
		if !result.OutputContains("cannot parse host public key") {
			t.Errorf("expected parse error, got: %s", result.Combined())
		}
	})

	t.Run("add_removed_fingerprint_flag", func(t *testing.T) {
		result := h.RunSSHHostKeys("add", "--host", "h.example.com", "--fingerprint", "SHA256:abc")
		if result.Success() || !result.OutputContains("unknown flag: --fingerprint") {
			t.Errorf("--fingerprint was removed and must be rejected, got: %s", result.Combined())
		}
	})

	t.Run("remove_missing_host", func(t *testing.T) {
		result := h.RunSSHHostKeys("remove")
		if result.Success() {
			t.Fatal("remove without --host should fail")
		}
		if !result.OutputContains("host is required") {
			t.Errorf("expected host-required error, got: %s", result.Combined())
		}
	})
}

// ----------------------------------------------------------------------------
// xkey ssh authorized-keys
// ----------------------------------------------------------------------------

// TestSSHAuthorizedKeys drives the authorized_keys lifecycle: add a
// line exported from a generated key, list it, remove it.
func TestSSHAuthorizedKeys(t *testing.T) {
	h := NewSSHTestHelper(t)

	gen := h.RunSSHKeys("generate",
		"--scope", "user", "--owner", "alice", "--name", "authz-src", "--type", "ed25519")
	if !gen.Success() {
		t.Fatalf("generate failed: %s", gen.Combined())
	}
	export := h.RunSSHKeys("export",
		"--scope", "user", "--owner", "alice", "--name", "authz-src")
	if !export.Success() {
		t.Fatalf("export failed: %s", export.Combined())
	}
	line := strings.TrimSpace(export.Stdout)
	if line == "" {
		t.Fatal("export produced an empty authorized_keys line")
	}

	add := h.RunSSHAuthorized("add", line,
		"--scope", "user", "--owner", "alice", "--name", "laptop")
	if !add.Success() {
		t.Fatalf("authorized-keys add failed: %s", add.Combined())
	}
	if !add.OutputContains("Added authorized entry user/alice/laptop") {
		t.Errorf("missing add confirmation: %s", add.Combined())
	}

	list := h.RunSSHAuthorized("list", "--scope", "user", "--owner", "alice")
	if !list.Success() {
		t.Fatalf("authorized-keys list failed: %s", list.Combined())
	}
	listedKey, ok := ExtractPublicKey(list.Stdout)
	wantKey, _ := ExtractPublicKey(line)
	if !ok || listedKey != wantKey {
		t.Errorf("listed entry does not match added line:\n got: %s\nwant: %s",
			list.Stdout, line)
	}

	// The "authorized" alias must reach the same data.
	aliasList := h.RunSSH("authorized", "list", "--scope", "user", "--owner", "alice")
	if !aliasList.Success() || !aliasList.OutputContains(wantKey) {
		t.Errorf("authorized alias list failed: %s", aliasList.Combined())
	}

	remove := h.RunSSHAuthorized("remove",
		"--scope", "user", "--owner", "alice", "--name", "laptop")
	if !remove.Success() || !remove.OutputContains("Removed authorized entry user/alice/laptop") {
		t.Errorf("authorized-keys remove failed: %s", remove.Combined())
	}

	gone := h.RunSSHAuthorized("list", "--scope", "user", "--owner", "alice")
	if !gone.Success() {
		t.Fatalf("list after remove failed: %s", gone.Combined())
	}
	if gone.OutputContains(wantKey) {
		t.Errorf("removed entry still listed: %s", gone.Combined())
	}
}

// TestSSHAuthorizedKeysErrors verifies authorized-keys input validation.
func TestSSHAuthorizedKeysErrors(t *testing.T) {
	h := NewSSHTestHelper(t)

	t.Run("add_missing_line_argument", func(t *testing.T) {
		result := h.RunSSHAuthorized("add", "--name", "no-line")
		if result.Success() {
			t.Fatal("add without a line argument should fail")
		}
	})

	t.Run("add_missing_name", func(t *testing.T) {
		result := h.RunSSHAuthorized("add", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummy")
		if result.Success() {
			t.Fatal("add without --name should fail")
		}
		if !result.OutputContains("--name is required") {
			t.Errorf("expected --name-required error, got: %s", result.Combined())
		}
	})

	t.Run("remove_missing_name", func(t *testing.T) {
		result := h.RunSSHAuthorized("remove")
		if result.Success() {
			t.Fatal("remove without --name should fail")
		}
		if !result.OutputContains("--name is required") {
			t.Errorf("expected --name-required error, got: %s", result.Combined())
		}
	})
}

// ----------------------------------------------------------------------------
// Embedded store placement
// ----------------------------------------------------------------------------

// TestSSHEmbeddedStoreLocation verifies the embedded transport roots
// its file store at $XKEY_HOME/data/ssh and persists across separate
// CLI invocations.
func TestSSHEmbeddedStoreLocation(t *testing.T) {
	h := NewSSHTestHelper(t)

	gen := h.RunSSHKeys("generate",
		"--scope", "user", "--owner", "alice", "--name", "placed", "--type", "ed25519")
	if !gen.Success() {
		t.Fatalf("generate failed: %s", gen.Combined())
	}

	info, err := os.Stat(h.StoreDir())
	if err != nil {
		t.Fatalf("embedded store dir missing at %s: %v", h.StoreDir(), err)
	}
	if !info.IsDir() {
		t.Fatalf("embedded store path %s is not a directory", h.StoreDir())
	}

	// A second, fresh CLI process against the same XKEY_HOME must see
	// the persisted key.
	get := h.RunSSHKeys("get", "--scope", "user", "--owner", "alice", "--name", "placed")
	if !get.Success() {
		t.Errorf("key did not persist across CLI invocations: %s", get.Combined())
	}
}

// ----------------------------------------------------------------------------
// REST transport dispatch
// ----------------------------------------------------------------------------

// restKeyDoc mirrors the wire shape of a key document on the
// /xkms/v1/ssh REST API.
type restKeyDoc struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// TestSSHRESTTransport verifies that setting XKMSD_URL switches the
// CLI to the REST transport, that requests carry the documented path
// prefix, query parameters and bearer token, and that server-side
// errors surface as CLI failures. The server half of the contract is
// covered by go-xkms's pkg/api/rest handler tests; this stub asserts
// the client/CLI half of the same wire shape.
func TestSSHRESTTransport(t *testing.T) {
	type recorded struct {
		method string
		path   string
		query  string
		auth   string
	}
	var lastReq recorded

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastReq = recorded{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			auth:   r.Header.Get("Authorization"),
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/xkms/v1/ssh/keys":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string][]restKeyDoc{
				"items": {{
					Scope:       "user",
					Owner:       "alice",
					Name:        "remote-key",
					Algorithm:   "ed25519",
					PublicKey:   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummy",
					Fingerprint: "SHA256:remotefingerprint",
				}},
			}); err != nil {
				t.Errorf("encode stub response: %v", err)
			}
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/xkms/v1/ssh/keys/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error":    "not_found",
				"message":  "no such key",
				"resource": "key",
			}); err != nil {
				t.Errorf("encode stub error: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Run("list_via_rest", func(t *testing.T) {
		h := NewSSHTestHelperREST(t, server.URL, "test-token")

		result := h.RunSSHKeys("list", "--scope", "user", "--owner", "alice")
		if !result.Success() {
			t.Fatalf("REST list failed: %s", result.Combined())
		}
		if !result.OutputContainsAll("user/alice/remote-key", "ed25519", "SHA256:remotefingerprint") {
			t.Errorf("REST-listed key missing from output: %s", result.Combined())
		}
		if lastReq.method != http.MethodGet || lastReq.path != "/xkms/v1/ssh/keys" {
			t.Errorf("unexpected request %s %s", lastReq.method, lastReq.path)
		}
		if !strings.Contains(lastReq.query, "scope=user") || !strings.Contains(lastReq.query, "owner=alice") {
			t.Errorf("scope/owner query parameters missing: %q", lastReq.query)
		}
		if lastReq.auth != "Bearer test-token" {
			t.Errorf("bearer token not forwarded, got %q", lastReq.auth)
		}
	})

	t.Run("server_error_surfaces", func(t *testing.T) {
		h := NewSSHTestHelperREST(t, server.URL, "test-token")

		result := h.RunSSHKeys("get",
			"--scope", "user", "--owner", "alice", "--name", "missing")
		if result.Success() {
			t.Fatal("REST get of a missing key should fail")
		}
		if !result.OutputContains("not found") {
			t.Errorf("expected not-found error, got: %s", result.Combined())
		}
	})

	t.Run("unreachable_server_fails_without_fallback", func(t *testing.T) {
		// Port 9 (discard) refuses connections; the CLI must fail
		// rather than silently falling back to the embedded store.
		h := NewSSHTestHelperREST(t, "http://127.0.0.1:9", "")

		result := h.RunSSHKeys("list")
		if result.Success() {
			t.Fatalf("list against an unreachable XKMSD_URL should fail, got: %s",
				result.Combined())
		}
	})
}

// ----------------------------------------------------------------------------
// Help output
// ----------------------------------------------------------------------------

// TestSSHHelpOutput verifies the command tree advertises the Phase 1c
// surface: keys, host-keys and authorized-keys.
func TestSSHHelpOutput(t *testing.T) {
	h := NewSSHTestHelper(t)

	t.Run("ssh_help", func(t *testing.T) {
		result := h.RunSSH("--help")
		if !result.Success() {
			t.Fatalf("ssh --help failed: %s", result.Combined())
		}
		if !result.OutputContainsAll("keys", "host-keys", "authorized-keys") {
			t.Errorf("ssh help missing subcommands: %s", result.Combined())
		}
	})

	t.Run("keys_help", func(t *testing.T) {
		result := h.RunSSHKeys("--help")
		if !result.Success() {
			t.Fatalf("ssh keys --help failed: %s", result.Combined())
		}
		if !result.OutputContainsAll("generate", "import", "list", "get", "delete", "export") {
			t.Errorf("ssh keys help missing subcommands: %s", result.Combined())
		}
	})

	t.Run("generate_help", func(t *testing.T) {
		result := h.RunSSHKeys("generate", "--help")
		if !result.Success() {
			t.Fatalf("ssh keys generate --help failed: %s", result.Combined())
		}
		if !result.OutputContainsAll("--scope", "--owner", "--name", "--type", "--bits", "--comment") {
			t.Errorf("ssh keys generate help missing flags: %s", result.Combined())
		}
	})
}
