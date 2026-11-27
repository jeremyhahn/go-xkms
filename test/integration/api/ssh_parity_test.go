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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/test/integration/api/apiharness"
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

// runXkeySSH runs `xkey ssh <args...>` adding --server, and on TLS
// schemes the --tls-ca/--tls-cert/--tls-key tlsArgs, for remote protocols. An empty
// serverURL selects the embedded transport (the command uses an isolated XKEY_HOME so it never touches host state).
func runXkeySSH(t *testing.T, bin, serverURL string, tlsArgs []string, home string, args ...string) (string, string, error) {
	t.Helper()
	full := append([]string{"ssh"}, args...)
	if serverURL != "" {
		full = append(full, "--server", serverURL)
		if needsTLSScheme(serverURL) {
			full = append(full, tlsArgs...)
		}
	}
	cmd := exec.Command(bin, full...)
	cmd.Env = append(os.Environ(), "XKEY_HOME="+home, "USER=ittest", "LOGNAME=ittest")
	if cert, key := getEnv("KEYSTORE_TLS_CERT", ""), getEnv("KEYSTORE_TLS_KEY", ""); cert != "" && key != "" {
		cmd.Env = append(cmd.Env, "XKMSD_TLS_CERT="+cert, "XKMSD_TLS_KEY="+key)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// needsTLSScheme reports whether the server URL uses a TLS-bearing scheme.
// xkmsd's unix socket is the qrdb node's TLS listener, so it takes TLS too.
func needsTLSScheme(u string) bool {
	return strings.HasPrefix(u, "https://") ||
		strings.HasPrefix(u, "unix://") ||
		strings.HasPrefix(u, "grpcs://") ||
		strings.HasPrefix(u, "quic://") ||
		strings.HasPrefix(u, "mcps://")
}

// sshServerURL maps a protocol to the xkey --server URL. For gRPC the harness
// default is grpcs://; the unix socket and MCP map to their schemes.
func sshServerURL(cfg *TestConfig, proto ProtocolType) string {
	return cfg.GetServerURL(proto)
}

var (
	sshOwnerOnce sync.Once
	sshOwnerID   string
	sshOwnerErr  error
)

// sshOwner returns the authenticated caller's subject (a user scope's owner) from /api/v1/auth/me, or "default" without a client certificate.
func sshOwner(t *testing.T) string {
	t.Helper()
	sshOwnerOnce.Do(func() {
		if getEnv("KEYSTORE_TLS_CERT", "") == "" {
			sshOwnerID = "default"
			return
		}
		client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: adminTLSConfig(t)}}
		resp, err := client.Get(LoadTestConfig().RESTBaseURL + "/api/v1/auth/me")
		if err != nil {
			sshOwnerErr = err
			return
		}
		defer resp.Body.Close()
		var me struct {
			Subject string `json:"subject"`
		}
		if resp.StatusCode != http.StatusOK {
			sshOwnerErr = fmt.Errorf("GET /api/v1/auth/me: HTTP %d", resp.StatusCode)
			return
		}
		if err := json.NewDecoder(resp.Body).Decode(&me); err != nil || me.Subject == "" {
			sshOwnerErr = fmt.Errorf("GET /api/v1/auth/me: no subject (%v)", err)
			return
		}
		sshOwnerID = me.Subject
	})
	if sshOwnerErr != nil {
		t.Fatalf("resolve the caller's subject: %v", sshOwnerErr)
	}
	return sshOwnerID
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

// sshRunSuffix makes the key names unique per run: a deleted name cannot be generated again.
var sshRunSuffix = fmt.Sprintf("%x", time.Now().UnixNano())

// genArgs builds the `keys generate` argument list for an algorithm.
func (a sshAlgo) genArgs(scope, name string) []string {
	args := []string{"keys", "generate", "--scope", scope, "--name", name, "--type", a.cliType}
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
	// The trust bundle verifies every server listener and the admin
	// credential authenticates xkey ssh over mTLS (apiharness), as xkmsctl.
	tlsArgs, err := apiharness.ClientTLSArgs()
	if err != nil {
		t.Fatalf("admin TLS credential: %v", err)
	}

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
					sshKeyLifecycle(t, bin, serverURL, tlsArgs, home, keyName, algo)
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
				sshKeyLifecycle(t, bin, "", nil, home, keyName, algo)
			})
		}
	})
}

// sshKeyLifecycle runs generate → list → export → delete for one algorithm and
// asserts the public key prefix matches the algorithm.
func sshKeyLifecycle(t *testing.T, bin, serverURL string, tlsArgs []string, home, keyName string, algo sshAlgo) {
	t.Helper()
	label := keyName

	out, errOut, err := runXkeySSH(t, bin, serverURL, tlsArgs, home, algo.genArgs("user", keyName)...)
	if err != nil {
		t.Fatalf("[%s] generate failed: %v\nstdout: %s\nstderr: %s", label, err, out, errOut)
	}

	out, errOut, err = runXkeySSH(t, bin, serverURL, tlsArgs, home, "keys", "list", "--scope", "user")
	if err != nil {
		t.Fatalf("[%s] list failed: %v\nstderr: %s", label, err, errOut)
	}
	if !strings.Contains(out, keyName) {
		t.Fatalf("[%s] list missing %q: %s", label, keyName, out)
	}

	out, errOut, err = runXkeySSH(t, bin, serverURL, tlsArgs, home, "keys", "export", "--scope", "user", "--name", keyName)
	if err != nil {
		t.Fatalf("[%s] export failed: %v\nstderr: %s", label, err, errOut)
	}
	if !strings.Contains(out, algo.prefix) {
		t.Fatalf("[%s] export missing %q prefix: %s", label, algo.prefix, out)
	}

	if serverURL != "" {
		sshForeignOwnerRefused(t, bin, serverURL, tlsArgs, home, keyName, algo)
	}

	if _, errOut, err = runXkeySSH(t, bin, serverURL, tlsArgs, home, "keys", "delete", "--scope", "user", "--name", keyName); err != nil {
		t.Fatalf("[%s] delete failed: %v\nstderr: %s", label, err, errOut)
	}
}

// sshForeignOwnerRefused checks that an explicit owner other than the caller
// is still refused on a server scheme: the empty-owner default (ruling 937)
// never widens access. Generating under someone-else fails, and the caller's
// own key is not reachable under someone-else's name.
func sshForeignOwnerRefused(t *testing.T, bin, serverURL string, tlsArgs []string, home, keyName string, algo sshAlgo) {
	t.Helper()
	const foreign = "someone-else"
	args := append(algo.genArgs("user", keyName+"-foreign"), "--owner", foreign)
	if out, _, err := runXkeySSH(t, bin, serverURL, tlsArgs, home, args...); err == nil {
		t.Fatalf("[%s] generate under --owner %s succeeded: %s", keyName, foreign, out)
	}
	if out, _, err := runXkeySSH(t, bin, serverURL, tlsArgs, home, "keys", "export", "--scope", "user", "--owner", foreign, "--name", keyName); err == nil {
		t.Fatalf("[%s] export under --owner %s succeeded: %s", keyName, foreign, out)
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
	// The trust bundle verifies every server listener and the admin
	// credential authenticates xkey ssh over mTLS (apiharness), as xkmsctl.
	tlsArgs, err := apiharness.ClientTLSArgs()
	if err != nil {
		t.Fatalf("admin TLS credential: %v", err)
	}

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
					args := append(algo.genArgs("user", keyName), "--backend", backend)
					out, errOut, err := runXkeySSH(t, bin, serverURL, tlsArgs, home, args...)
					if err != nil {
						t.Fatalf("[%s/%s] backend generate failed: %v\nstdout: %s\nstderr: %s", backend, algo.name, err, out, errOut)
					}
					// The CLI prints the backend the key was minted on.
					if !strings.Contains(out, backend) {
						t.Fatalf("[%s/%s] expected backend %q in output: %s", backend, algo.name, backend, out)
					}
					// Export confirms a usable public key of the right type.
					out, errOut, err = runXkeySSH(t, bin, serverURL, tlsArgs, home, "keys", "export", "--scope", "user", "--name", keyName)
					if err != nil {
						t.Fatalf("[%s/%s] export failed: %v\nstderr: %s", backend, algo.name, err, errOut)
					}
					if !strings.Contains(out, algo.prefix) {
						t.Fatalf("[%s/%s] export missing %q prefix: %s", backend, algo.name, algo.prefix, out)
					}
					_, _, _ = runXkeySSH(t, bin, serverURL, tlsArgs, home, "keys", "delete", "--scope", "user", "--name", keyName)
				})
			}
		})
	}
}
