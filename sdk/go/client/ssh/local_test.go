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
	"os"
	"path/filepath"
	"testing"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestLoadLocalSSHConfig_MissingFileIsEmptyConfig pins that an absent
// ssh_config path is not an error (mirrors OpenSSH's own treatment of a
// missing config file).
func TestLoadLocalSSHConfig_MissingFileIsEmptyConfig(t *testing.T) {
	cfg, err := sdkssh.LoadLocalSSHConfig(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("LoadLocalSSHConfig: %v", err)
	}
	hc := cfg.Lookup("anything")
	if hc.HostName != "anything" || hc.Port != 22 {
		t.Fatalf("unexpected default HostConfig: %+v", hc)
	}
}

// TestLoadLocalSSHConfig_MalformedFileIsParseError pins the typed error for
// a present-but-unparseable file.
func TestLoadLocalSSHConfig_MalformedFileIsParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	// "Match exec" is explicitly rejected by the parser (arbitrary command
	// execution from an untrusted config file).
	if err := os.WriteFile(path, []byte("Match exec true\n    HostName wat.example.com\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := sdkssh.LoadLocalSSHConfig(path)
	if err == nil {
		t.Fatal("expected a parse error for malformed ssh_config")
	}
	var pe *sdkssh.LocalConfigParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *LocalConfigParseError, got %T: %v", err, err)
	}
}

// TestDefaultLocalSSHConfigPaths_ReturnsUserThenSystem pins the two-path,
// user-before-system priority order every caller of LoadLocalSSHConfig
// relies on.
func TestDefaultLocalSSHConfigPaths_ReturnsUserThenSystem(t *testing.T) {
	paths := sdkssh.DefaultLocalSSHConfigPaths()
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(paths), paths)
	}
	if filepath.Base(paths[0]) != "config" || filepath.Base(paths[1]) != "ssh_config" {
		t.Fatalf("unexpected paths: %v", paths)
	}
	if paths[1] != "/etc/ssh/ssh_config" {
		t.Fatalf("system path = %q, want /etc/ssh/ssh_config", paths[1])
	}
}

// TestDiscoverLocalIdentities_NoFilesReturnsEmpty pins that a homeDir with no
// .ssh directory yields an empty, non-error result.
func TestDiscoverLocalIdentities_NoFilesReturnsEmpty(t *testing.T) {
	ids, err := sdkssh.DiscoverLocalIdentities(nil, t.TempDir())
	if err != nil {
		t.Fatalf("DiscoverLocalIdentities: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no identities, got %v", ids)
	}
}

// TestDiscoverLocalIdentities_FindsExistingKeyFile pins the discovery of a
// conventional identity file under homeDir/.ssh.
func TestDiscoverLocalIdentities_FindsExistingKeyFile(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("fake-private-key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	ids, err := sdkssh.DiscoverLocalIdentities(nil, home)
	if err != nil {
		t.Fatalf("DiscoverLocalIdentities: %v", err)
	}
	if len(ids) != 1 || ids[0].Path != keyPath {
		t.Fatalf("expected exactly [%q], got %v", keyPath, ids)
	}
}

// TestLocalIdentityFromPath_SetsPath pins the constructor's basic contract:
// a non-existent .pub sidecar leaves PublicKey unset rather than erroring.
func TestLocalIdentityFromPath_SetsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	id := sdkssh.LocalIdentityFromPath(path)
	if id.Path != path {
		t.Fatalf("Path = %q, want %q", id.Path, path)
	}
	if id.PublicKey != nil {
		t.Fatalf("expected nil PublicKey with no .pub sidecar, got %v", id.PublicKey)
	}
}

// TestDialLocalAgent_EmptySockPathIsUnavailable pins the deterministic
// error for an unconfigured agent socket, without touching any real agent.
func TestDialLocalAgent_EmptySockPathIsUnavailable(t *testing.T) {
	_, err := sdkssh.DialLocalAgent("")
	var uae *sdkssh.LocalAgentUnavailableError
	if !errors.As(err, &uae) {
		t.Fatalf("expected *LocalAgentUnavailableError, got %T: %v", err, err)
	}
}

// TestDialLocalAgent_UnreachableSocketIsUnavailable pins the same error type
// for a socket path that cannot be dialed (nothing is listening).
func TestDialLocalAgent_UnreachableSocketIsUnavailable(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "no-agent.sock")
	_, err := sdkssh.DialLocalAgent(sockPath)
	var uae *sdkssh.LocalAgentUnavailableError
	if !errors.As(err, &uae) {
		t.Fatalf("expected *LocalAgentUnavailableError, got %T: %v", err, err)
	}
}

// TestLocalAgentSignerForFingerprint_UnreachableSocketIsUnavailable pins the
// same deterministic failure through the fingerprint-lookup entry point.
func TestLocalAgentSignerForFingerprint_UnreachableSocketIsUnavailable(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "no-agent.sock")
	_, err := sdkssh.LocalAgentSignerForFingerprint(sockPath, "SHA256:deadbeef")
	var uae *sdkssh.LocalAgentUnavailableError
	if !errors.As(err, &uae) {
		t.Fatalf("expected *LocalAgentUnavailableError, got %T: %v", err, err)
	}
}

// TestResolveLocalSigner_MissingIdentityFileErrors pins the read-error path
// for an identity whose private-key file does not exist.
func TestResolveLocalSigner_MissingIdentityFileErrors(t *testing.T) {
	id := sdkssh.LocalIdentityFromPath(filepath.Join(t.TempDir(), "id_ed25519"))
	_, err := sdkssh.ResolveLocalSigner(context.Background(), id, "")
	if err == nil {
		t.Fatal("expected an error for a missing identity file")
	}
}

// TestLocalIdentityAttemptError_MessageAndUnwrap pins the wrapper error's
// formatting and Unwrap contract.
func TestLocalIdentityAttemptError_MessageAndUnwrap(t *testing.T) {
	underlying := errors.New("boom")
	err := &sdkssh.LocalIdentityAttemptError{Path: "/home/u/.ssh/id_ed25519", Err: underlying}
	if want := "/home/u/.ssh/id_ed25519: boom"; err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, underlying) {
		t.Fatal("errors.Is did not find the wrapped error")
	}
}

// TestNoUsableLocalIdentityError_MessageAndUnwrap pins the wrapper error's
// formatting and Unwrap contract for the joined-attempts error.
func TestNoUsableLocalIdentityError_MessageAndUnwrap(t *testing.T) {
	inner := errors.New("boom")
	err := &sdkssh.NoUsableLocalIdentityError{Alias: "prod-box", Err: inner}
	want := `ssh: no usable local identity for host "prod-box": boom`
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, inner) {
		t.Fatal("errors.Is did not find the wrapped error")
	}
}

// TestResolveLocalSigners_AgentPrefixPropagatesAgentError pins the
// "agent:<fingerprint>" selector path: it must resolve through the system
// agent alone and propagate a failure to reach it, never falling back to
// on-disk identities.
func TestResolveLocalSigners_AgentPrefixPropagatesAgentError(t *testing.T) {
	sel := sdkssh.LocalKeySelector{Identity: sdkssh.LocalIdentityAgentPrefix + "SHA256:deadbeef"}
	sockPath := filepath.Join(t.TempDir(), "no-agent.sock")

	_, err := sdkssh.ResolveLocalSigners(context.Background(), sel, sockPath)
	var uae *sdkssh.LocalAgentUnavailableError
	if !errors.As(err, &uae) {
		t.Fatalf("expected *LocalAgentUnavailableError, got %T: %v", err, err)
	}
}

// TestResolveLocalSigners_PinnedIdentityWithNoUsableSignerErrors pins the
// explicit-Identity path (sel.Identity set to a file path, not an
// "agent:" reference): it must not consult the agent or ssh_config, and
// report *NoUsableLocalIdentityError joining the single attempt's failure
// when the pinned file does not exist.
func TestResolveLocalSigners_PinnedIdentityWithNoUsableSignerErrors(t *testing.T) {
	identityPath := filepath.Join(t.TempDir(), "id_ed25519")
	sel := sdkssh.LocalKeySelector{Identity: identityPath}

	_, err := sdkssh.ResolveLocalSigners(context.Background(), sel, "")
	var nue *sdkssh.NoUsableLocalIdentityError
	if !errors.As(err, &nue) {
		t.Fatalf("expected *NoUsableLocalIdentityError, got %T: %v", err, err)
	}
	if nue.Alias != identityPath {
		t.Fatalf("Alias = %q, want the pinned identity path %q", nue.Alias, identityPath)
	}
	var lae *sdkssh.LocalIdentityAttemptError
	if !errors.As(nue, &lae) {
		t.Fatalf("expected the joined error to contain a *LocalIdentityAttemptError, got %v", nue.Unwrap())
	}
}
