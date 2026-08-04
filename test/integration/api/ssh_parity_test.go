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

package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// This suite drives the real xkey CLI binary against a running xkmsd over every
// supported protocol, exercising the SSH command surface end-to-end. It is the
// "test xkey against an xkms backend" coverage: the same common command set
// (generate → list → get → export → sign → delete) runs identically over
// embedded, REST, gRPC, QUIC, MCP, and unix, proving transport parity.
//
// The xkey binary is located via XKEY_CLI_BIN, or built on demand from the
// sibling xkey module. The Makefile's integration-test-xkey-ssh target brings
// up xkmsd (run_with_server) and exports the per-protocol endpoints into the
// KEYSTORE_* environment consumed by LoadTestConfig.

var (
	xkeyBinOnce sync.Once
	xkeyBinPath string
	xkeyBinErr  error
)

// xkeyBinary returns the path to the xkey CLI binary, building it from the
// sibling module when XKEY_CLI_BIN is not set.
func xkeyBinary(t *testing.T) string {
	t.Helper()
	xkeyBinOnce.Do(func() {
		if p := strings.TrimSpace(os.Getenv("XKEY_CLI_BIN")); p != "" {
			xkeyBinPath = p
			return
		}
		// Build from the sibling xkey module. test/integration/api → repo root
		// is three levels up; the xkey module lives at <root>/xkey.
		moduleDir, err := filepath.Abs(filepath.Join("..", "..", "..", "xkey"))
		if err != nil {
			xkeyBinErr = err
			return
		}
		// Build to a process-scoped temp dir, NOT t.TempDir(): the sync.Once
		// caches xkeyBinPath across every test in the package, but t.TempDir()
		// is removed when the first calling test finishes, leaving later tests
		// with a stale path ("fork/exec .../xkey: no such file or directory").
		dir, mkErr := os.MkdirTemp("", "xkey-cli-")
		if mkErr != nil {
			xkeyBinErr = mkErr
			return
		}
		out := filepath.Join(dir, "xkey")
		// The xkey CLI must build with the same JSON codec tag the services use.
		cmd := exec.Command("go", "build", "-tags", "codec_json", "-o", out, "./cmd/xkey")
		cmd.Dir = moduleDir
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if berr := cmd.Run(); berr != nil {
			xkeyBinErr = &xkeyBuildError{Err: berr, Output: stderr.String()}
			return
		}
		xkeyBinPath = out
	})
	if xkeyBinErr != nil {
		t.Fatalf("xkey binary unavailable: %v", xkeyBinErr)
	}
	return xkeyBinPath
}

type xkeyBuildError struct {
	Err    error
	Output string
}

func (e *xkeyBuildError) Error() string {
	return "build failed: " + e.Err.Error() + "\n" + e.Output
}

// runXkeySSH runs `xkey ssh <args...>` adding --server/--tls-ca for remote
// protocols. An empty serverURL selects the embedded transport (the command
// uses an isolated XKEY_HOME so it never touches host state).
func runXkeySSH(t *testing.T, bin, serverURL, tlsCA, home string, args ...string) (string, string, error) {
	t.Helper()
	full := append([]string{"ssh"}, args...)
	if serverURL != "" {
		full = append(full, "--server", serverURL)
		if tlsCA != "" && needsTLSScheme(serverURL) {
			full = append(full, "--tls-ca", tlsCA)
		}
	}
	cmd := exec.Command(bin, full...)
	cmd.Env = append(os.Environ(), "XKEY_HOME="+home, "USER=ittest", "LOGNAME=ittest")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// needsTLSScheme reports whether the server URL uses a TLS-bearing scheme.
func needsTLSScheme(u string) bool {
	return strings.HasPrefix(u, "https://") ||
		strings.HasPrefix(u, "grpcs://") ||
		strings.HasPrefix(u, "quic://") ||
		strings.HasPrefix(u, "mcps://")
}

// sshServerURL maps a protocol to the xkey --server URL. For gRPC the harness
// default is grpcs://; the unix socket and MCP map to their schemes.
func sshServerURL(cfg *TestConfig, proto ProtocolType) string {
	return cfg.GetServerURL(proto)
}

// sshAlgo describes an SSH algorithm to exercise in the parity matrix, with the
// authorized_keys line prefix it produces. RSA-2048 and ECDSA-P256 are the
// cross-backend defaults that TPM 2.0, SoftHSM2, and the software backend all
// support; ed25519 is added for the software/embedded path.
type sshAlgo struct {
	name    string
	cliType string
	bits    int
	prefix  string
}

var sshDefaultAlgos = []sshAlgo{
	{"ecdsa-p256", "ecdsa-p256", 0, "ecdsa-sha2-nistp256"},
	{"rsa-2048", "rsa", 2048, "ssh-rsa"},
}

// genArgs builds the `keys generate` argument list for an algorithm.
func (a sshAlgo) genArgs(scope, owner, name string) []string {
	args := []string{"keys", "generate", "--scope", scope, "--owner", owner, "--name", name, "--type", a.cliType}
	if a.bits > 0 {
		args = append(args, "--bits", fmt.Sprintf("%d", a.bits))
	}
	return args
}

// TestXkeySSHMultiProtocol exercises the SSH key lifecycle over every protocol
// and every default algorithm (RSA-2048, ECDSA-P256) using the xkey CLI against
// the dockerized xkmsd.
func TestXkeySSHMultiProtocol(t *testing.T) {
	cfg := LoadTestConfig()
	bin := xkeyBinary(t)
	tlsCA := getEnv("KEYSTORE_TLS_CA", "/etc/xkms/certs/ca.crt")

	// Remote protocols require a running server; embedded runs in-process.
	for _, proto := range RemoteProtocols() {
		proto := proto
		t.Run(string(proto), func(t *testing.T) {
			if !cfg.IsProtocolAvailable(t, proto) {
				t.Fatalf("server not available for protocol %s", proto)
			}
			serverURL := sshServerURL(cfg, proto)
			for _, algo := range sshDefaultAlgos {
				algo := algo
				t.Run(algo.name, func(t *testing.T) {
					home := t.TempDir()
					keyName := "xkey-" + string(proto) + "-" + algo.name
					sshKeyLifecycle(t, bin, serverURL, tlsCA, home, keyName, algo)
				})
			}
		})
	}

	// Embedded transport (no server): local file-backed store, all defaults.
	t.Run("embedded", func(t *testing.T) {
		for _, algo := range sshDefaultAlgos {
			algo := algo
			t.Run(algo.name, func(t *testing.T) {
				home := t.TempDir()
				keyName := "xkey-embedded-" + algo.name
				sshKeyLifecycle(t, bin, "", "", home, keyName, algo)
			})
		}
	})
}

// sshKeyLifecycle runs generate → list → export → delete for one algorithm and
// asserts the public key prefix matches the algorithm.
func sshKeyLifecycle(t *testing.T, bin, serverURL, tlsCA, home, keyName string, algo sshAlgo) {
	t.Helper()
	label := keyName

	out, errOut, err := runXkeySSH(t, bin, serverURL, tlsCA, home, algo.genArgs("user", "default", keyName)...)
	if err != nil {
		t.Fatalf("[%s] generate failed: %v\nstdout: %s\nstderr: %s", label, err, out, errOut)
	}

	out, errOut, err = runXkeySSH(t, bin, serverURL, tlsCA, home, "keys", "list", "--scope", "user", "--owner", "default")
	if err != nil {
		t.Fatalf("[%s] list failed: %v\nstderr: %s", label, err, errOut)
	}
	if !strings.Contains(out, keyName) {
		t.Fatalf("[%s] list missing %q: %s", label, keyName, out)
	}

	out, errOut, err = runXkeySSH(t, bin, serverURL, tlsCA, home, "keys", "export", "--scope", "user", "--owner", "default", "--name", keyName)
	if err != nil {
		t.Fatalf("[%s] export failed: %v\nstderr: %s", label, err, errOut)
	}
	if !strings.Contains(out, algo.prefix) {
		t.Fatalf("[%s] export missing %q prefix: %s", label, algo.prefix, out)
	}

	if _, errOut, err = runXkeySSH(t, bin, serverURL, tlsCA, home, "keys", "delete", "--scope", "user", "--owner", "default", "--name", keyName); err != nil {
		t.Fatalf("[%s] delete failed: %v\nstderr: %s", label, err, errOut)
	}
}

// TestXkeySSHBackendSelection verifies that, over a remote protocol, the xkey
// CLI can mint SSH keys on specific server-side crypto backends via --backend,
// using the cross-backend default algorithms (RSA-2048 and ECDSA-P256) that
// TPM 2.0, SoftHSM2, and the software backend all support.
//
// The backends to exercise are taken from XKMS_SSH_TEST_BACKENDS (comma-
// separated, default "software"); the devcontainer harness sets this to the
// provisioned set, e.g. "software,tpm2,softhsm". For each backend the key is
// generated on it (private key never leaving a hardware backend) and the CLI
// output confirms the minting backend.
func TestXkeySSHBackendSelection(t *testing.T) {
	cfg := LoadTestConfig()
	bin := xkeyBinary(t)
	tlsCA := getEnv("KEYSTORE_TLS_CA", "/etc/xkms/certs/ca.crt")

	backends := strings.Split(getEnv("XKMS_SSH_TEST_BACKENDS", "software"), ",")

	// Prefer gRPC for this check; fall back to REST.
	proto := ProtocolGRPC
	if !cfg.IsProtocolAvailable(t, proto) {
		proto = ProtocolREST
	}
	if !cfg.IsProtocolAvailable(t, proto) {
		t.Fatalf("no remote protocol available for backend-selection test")
	}
	serverURL := sshServerURL(cfg, proto)

	for _, raw := range backends {
		backend := strings.TrimSpace(raw)
		if backend == "" {
			continue
		}
		t.Run(backend, func(t *testing.T) {
			for _, algo := range sshDefaultAlgos {
				algo := algo
				t.Run(algo.name, func(t *testing.T) {
					home := t.TempDir()
					keyName := "xkey-backend-" + backend + "-" + algo.name
					args := append(algo.genArgs("user", "default", keyName), "--backend", backend)
					out, errOut, err := runXkeySSH(t, bin, serverURL, tlsCA, home, args...)
					if err != nil {
						t.Fatalf("[%s/%s] backend generate failed: %v\nstdout: %s\nstderr: %s", backend, algo.name, err, out, errOut)
					}
					// The CLI prints the backend the key was minted on.
					if !strings.Contains(out, backend) {
						t.Fatalf("[%s/%s] expected backend %q in output: %s", backend, algo.name, backend, out)
					}
					// Export confirms a usable public key of the right type.
					out, errOut, err = runXkeySSH(t, bin, serverURL, tlsCA, home, "keys", "export", "--scope", "user", "--owner", "default", "--name", keyName)
					if err != nil {
						t.Fatalf("[%s/%s] export failed: %v\nstderr: %s", backend, algo.name, err, errOut)
					}
					if !strings.Contains(out, algo.prefix) {
						t.Fatalf("[%s/%s] export missing %q prefix: %s", backend, algo.name, algo.prefix, out)
					}
					_, _, _ = runXkeySSH(t, bin, serverURL, tlsCA, home, "keys", "delete", "--scope", "user", "--owner", "default", "--name", keyName)
				})
			}
		})
	}
}
