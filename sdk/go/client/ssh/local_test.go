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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// generateLocalIdentityFiles generates a fresh, unencrypted ed25519 keypair
// and writes it (private + paired ".pub") to dir/name, returning the signer
// an in-process agent would serve for the same key so tests can prove
// dedup-by-fingerprint and agent-preferred resolution against a real key
// rather than two unrelated ones.
func generateLocalIdentityFiles(t *testing.T, dir, name string) (path string, signer gossh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	signer, err = gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(path+".pub", gossh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return path, signer
}

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

// TestResolveLocalSigners_AgentPrefixSuccess pins the "agent:<fingerprint>"
// selector's success path against a real in-process agent (StartAgent, the
// same production primitive the package's own agent tests serve signers
// through): the returned signer must be the exact key the agent advertised
// under that fingerprint, and it must actually sign.
func TestResolveLocalSigners_AgentPrefixSuccess(t *testing.T) {
	signer := testConnectSigner(t)
	sess, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{Signers: []gossh.Signer{signer}})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	defer sess.Stop(context.Background())

	fp := gossh.FingerprintSHA256(signer.PublicKey())
	sel := sdkssh.LocalKeySelector{Identity: sdkssh.LocalIdentityAgentPrefix + fp}

	signers, err := sdkssh.ResolveLocalSigners(context.Background(), sel, sess.SockPath)
	if err != nil {
		t.Fatalf("ResolveLocalSigners: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected exactly 1 signer, got %d", len(signers))
	}
	if string(signers[0].PublicKey().Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Fatal("resolved signer's public key does not match the agent-held key")
	}

	msg := []byte("authenticate me")
	sig, err := signers[0].Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

// TestResolveLocalSigners_AliasResolvesOnDiskIdentity pins the normal
// (non-pinned, non-agent-prefix) resolution path: with no ssh_config Host
// block for the alias and no agent reachable, ResolveLocalSigners falls
// through to ssh(1)'s own default identity-file convention
// (~/.ssh/id_ed25519) and resolves a working signer from it.
func TestResolveLocalSigners_AliasResolvesOnDiskIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	_, wantSigner := generateLocalIdentityFiles(t, sshDir, "id_ed25519")

	sel := sdkssh.LocalKeySelector{Alias: "unconfigured-host"}
	signers, err := sdkssh.ResolveLocalSigners(context.Background(), sel, "")
	if err != nil {
		t.Fatalf("ResolveLocalSigners: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected exactly 1 signer from the default identity file, got %d", len(signers))
	}
	if string(signers[0].PublicKey().Marshal()) != string(wantSigner.PublicKey().Marshal()) {
		t.Fatal("resolved signer does not match the on-disk default identity")
	}
}

// TestResolveLocalSigners_AgentAndIdentityFileDeduped pins the dedup-by-
// fingerprint contract: when the system agent and a discovered identity
// file serve the SAME key, ResolveLocalSigners must offer it exactly once
// (from the agent, which OpenSSH itself always prefers), not twice.
func TestResolveLocalSigners_AgentAndIdentityFileDeduped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	_, fileSigner := generateLocalIdentityFiles(t, sshDir, "id_ed25519")

	sess, err := sdkssh.StartAgent(context.Background(), sdkssh.AgentOptions{Signers: []gossh.Signer{fileSigner}})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	defer sess.Stop(context.Background())

	sel := sdkssh.LocalKeySelector{Alias: "unconfigured-host"}
	signers, err := sdkssh.ResolveLocalSigners(context.Background(), sel, sess.SockPath)
	if err != nil {
		t.Fatalf("ResolveLocalSigners: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected the shared key deduped to exactly 1 signer, got %d", len(signers))
	}
	if string(signers[0].PublicKey().Marshal()) != string(fileSigner.PublicKey().Marshal()) {
		t.Fatal("resolved signer does not match the shared key")
	}
}

// TestResolveLocalSigners_ConfigParseErrorPropagates pins that a malformed
// ssh_config at the default user path fails resolution outright rather than
// silently falling back to no configuration, surfacing the same
// *LocalConfigParseError LoadLocalSSHConfig itself returns.
func TestResolveLocalSigners_ConfigParseErrorPropagates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	// "Match exec" is explicitly rejected by the parser (arbitrary command
	// execution from an untrusted config file) -- same fixture
	// TestLoadLocalSSHConfig_MalformedFileIsParseError uses directly.
	cfgPath := filepath.Join(sshDir, "config")
	if err := os.WriteFile(cfgPath, []byte("Match exec true\n    HostName wat.example.com\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	sel := sdkssh.LocalKeySelector{Alias: "anything"}
	_, err := sdkssh.ResolveLocalSigners(context.Background(), sel, "")
	var pe *sdkssh.LocalConfigParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *LocalConfigParseError, got %T: %v", err, err)
	}
}

// TestResolveLocalSigners_DiscoverIdentitiesErrorPropagates pins that a
// discovery-time I/O error (distinct from "file does not exist") aborts
// resolution instead of being swallowed into an empty candidate list. The
// fault is a path that treats a regular file as a directory component
// (ENOTDIR) -- an error root cannot bypass with permission bits, unlike
// chmod-based fault injection.
func TestResolveLocalSigners_DiscoverIdentitiesErrorPropagates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	// A regular file standing in for what the config below addresses as a
	// directory.
	notADir := filepath.Join(sshDir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("regular file"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	cfgPath := filepath.Join(sshDir, "config")
	cfg := "Host badhost\n    IdentityFile ~/.ssh/not-a-dir/nested\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	sel := sdkssh.LocalKeySelector{Alias: "badhost"}
	_, err := sdkssh.ResolveLocalSigners(context.Background(), sel, "")
	var re *sdkssh.LocalIdentityReadError
	if !errors.As(err, &re) {
		t.Fatalf("expected *LocalIdentityReadError, got %T: %v", err, err)
	}
}
