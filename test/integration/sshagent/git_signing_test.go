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

//go:build integration

// Package sshagent holds the end-to-end acceptance test for agent-only SSH
// sessions (go-xkms#52): a real `git commit -S` signed through a socket served
// by the SDK, with the private key never on disk.
//
// It lives in the integration tier because it shells out to the host's git and
// ssh-keygen. The unit suite keeps its own hermetic coverage of the same SDK
// surface in sdk/go/client/ssh/agent_test.go, which speaks the agent protocol
// in-process and touches no external binary.
package sshagent

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// signingKeyEmail is the identity the test signs and verifies commits under.
const signingKeyEmail = "alice@example.com"

// newClient returns a fresh embedded SDK client over an in-memory backend.
func newClient(t *testing.T) sdkssh.Client {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	client, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: backend})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	t.Cleanup(func() {
		if cerr := client.Close(); cerr != nil {
			t.Logf("client close: %v", cerr)
		}
	})
	return client
}

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

// baseEnv builds a minimal, isolated environment for a git child process, with
// nothing inherited that could sign on the session's behalf.
func baseEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
	}
}

// runGit runs git in dir with the given environment, failing the test on a
// non-zero exit and returning combined output.
func runGit(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) // #nosec G204 -- fixed test-local argv
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// requireTools fails -- never skips -- when the host lacks the binaries the
// consumer scenario is made of. git signs SSH commits by shelling out to
// ssh-keygen, and both ship in the project's devcontainer, which is where
// integration tests are required to run. A missing one is a broken
// environment, and skipping would drop the only end-to-end coverage of
// agent-only signing exactly where it stopped working.
func requireTools(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"git", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s is required for the agent-only signing acceptance test: %v", bin, err)
		}
	}
}

// assertNoPrivateKeyOnDisk walks root and fails on any file carrying private
// key material. The agent-only session's whole claim is that the private half
// never lands in the filesystem, so this asserts by shape over everything the
// session and the consumer wrote.
//
// It fails CLOSED. Every traversal and read error fails the test rather than
// being skipped: a leak the scan could not open is exactly the case where
// skipping turns a security assertion into a green tick over an incomplete
// scan. Only symlinks are passed over, and only because the walk already
// visits every real entry -- following them would double-count, not widen
// coverage.
func assertNoPrivateKeyOnDisk(t *testing.T, root string) {
	t.Helper()
	markers := []string{"PRIVATE KEY", "openssh-key-v1"}
	inspected := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // unreadable entry: the scan is incomplete, so it failed
		}
		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if !d.Type().IsRegular() {
			// Sockets, devices and FIFOs hold no file content to leak through,
			// and opening a FIFO would block the test forever.
			return nil
		}
		body, rerr := os.ReadFile(path) // #nosec G304 -- test-local temp tree
		if rerr != nil {
			return rerr
		}
		inspected++
		for _, m := range markers {
			if strings.Contains(string(body), m) {
				t.Errorf("private key material found on disk at %s (marker %q)", path, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan of %s was incomplete, so it proves nothing: %v", root, err)
	}
	if inspected == 0 {
		t.Fatalf("scan of %s inspected no files; the assertion would pass vacuously", root)
	}
}

// assertOnlyTheSocket asserts the session's work directory holds the agent
// socket and nothing else.
//
// This is the right shape of claim for that directory, and a content scan is
// not: the socket is the only entry, and a socket has no file content, so
// walking it for key markers inspects zero bytes and passes no matter what.
// "Nothing was written here" is the assertion; make it directly.
func assertOnlyTheSocket(t *testing.T, sockPath string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(sockPath))
	if err != nil {
		t.Fatalf("read session work dir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("session work dir should hold only the agent socket, got %v", names)
	}
	if got, want := entries[0].Name(), filepath.Base(sockPath); got != want {
		t.Fatalf("unexpected entry in the session work dir: %q", got)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("stat the socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the session's only artifact should be a socket, got mode %v", info.Mode())
	}
}

// TestStartAgent_GitCommitSigning is the consumer-shaped acceptance test for
// go-xkms#52, written from outside the SDK using only what it exports: an
// xkms-held key is served over an agent-only session and git signs a real
// commit through it.
//
// It asserts the *reason* the commit is trustworthy, not just that a header
// appeared: `git verify-commit` against an allowed-signers file naming this key
// fails unless the signature was actually produced by the served key.
func TestStartAgent_GitCommitSigning(t *testing.T) {
	requireTools(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signer, pubLine := newAgentSigner(t, "commit-signing")

	sess, err := sdkssh.StartAgent(ctx, sdkssh.AgentOptions{Signers: []gossh.Signer{signer}})
	if err != nil {
		t.Fatalf("StartAgent: %v", err)
	}
	defer sess.Stop()

	// The consumer only ever writes the PUBLIC half to disk -- that is what
	// user.signingkey points at.
	home := t.TempDir()
	pubFile := filepath.Join(home, "signing.pub")
	if err := os.WriteFile(pubFile, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	allowedSigners := filepath.Join(home, "allowed_signers")
	if err := os.WriteFile(allowedSigners, []byte(signingKeyEmail+" "+pubLine+"\n"), 0o600); err != nil {
		t.Fatalf("write allowed_signers: %v", err)
	}

	repo := filepath.Join(home, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	env := append(baseEnv(home), sess.Env...)

	runGit(t, repo, env, "init", "--quiet", "--initial-branch=main")
	runGit(t, repo, env,
		"-c", "user.name=Alice",
		"-c", "user.email="+signingKeyEmail,
		"-c", "gpg.format=ssh",
		"-c", "user.signingkey="+pubFile,
		"commit", "--allow-empty", "-S", "-m", "signed through the xkms agent socket",
	)

	// The object itself carries an SSH signature.
	object := runGit(t, repo, env, "cat-file", "commit", "HEAD")
	if !strings.Contains(object, "gpgsig -----BEGIN SSH SIGNATURE-----") {
		t.Fatalf("commit object carries no SSH signature:\n%s", object)
	}

	// ...and it verifies under the served key specifically.
	verify := runGit(t, repo, env,
		"-c", "gpg.format=ssh",
		"-c", "gpg.ssh.allowedSignersFile="+allowedSigners,
		"verify-commit", "-v", "HEAD",
	)
	if !strings.Contains(verify, "Good \"git\" signature") {
		t.Fatalf("signature did not verify under the served key:\n%s", verify)
	}
	if !strings.Contains(verify, signingKeyEmail) {
		t.Fatalf("signature verified under an unexpected principal:\n%s", verify)
	}

	// Nothing the consumer wrote holds private key material, and the session
	// itself wrote nothing but its socket.
	assertNoPrivateKeyOnDisk(t, home)
	assertOnlyTheSocket(t, sess.SockPath)

	// The socket dies with the context, with no Stop call involved.
	workDir := filepath.Dir(sess.SockPath)
	cancel()
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session never finished after context cancellation")
	}
	if _, err := os.Stat(sess.SockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("agent socket outlived its context: %v", err)
	}
	if _, err := os.Stat(workDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("agent work dir outlived its context: %v", err)
	}
}

// TestStartAgent_SigningFailsWithoutTheSession is the negative half of the
// acceptance test: with no agent socket, the identical git invocation cannot
// sign. Without it, a passing signing test would not prove the session is what
// made signing work.
func TestStartAgent_SigningFailsWithoutTheSession(t *testing.T) {
	requireTools(t)

	_, pubLine := newAgentSigner(t, "commit-signing-negative")

	home := t.TempDir()
	pubFile := filepath.Join(home, "signing.pub")
	if err := os.WriteFile(pubFile, []byte(pubLine+"\n"), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	repo := filepath.Join(home, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	env := append(baseEnv(home), "SSH_AUTH_SOCK="+filepath.Join(home, "absent.sock"))
	runGit(t, repo, env, "init", "--quiet", "--initial-branch=main")

	cmd := exec.Command("git", //nolint:gosec // fixed test-local argv
		"-c", "user.name=Alice",
		"-c", "user.email="+signingKeyEmail,
		"-c", "gpg.format=ssh",
		"-c", "user.signingkey="+pubFile,
		"commit", "--allow-empty", "-S", "-m", "should not be signable",
	)
	cmd.Dir = repo
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("signing succeeded without an agent session, so the session proves nothing:\n%s", out)
	}
}
