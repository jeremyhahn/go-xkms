// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration && initceremony

// Package initceremony exercises `xkmsd init` end-to-end against a real
// built binary: it proves the fix for go-xkms#693 -- an admin login factor
// enrolled during `xkmsd init` must survive a server restart -- by running
// init once, starting `xkmsd run`, authenticating with the enrolled mTLS
// admin credential, restarting the server (a fresh process, same data
// directory, no second init), and authenticating again against the SAME
// credential with no re-enrollment in between.
//
// This suite manages its own xkmsd process lifecycle (build, init, run,
// restart) rather than dialing a docker-compose-managed server the way
// test/integration/logins does, because the scenario under test IS the
// process lifecycle: nothing here can be proven against a server that never
// restarts.
package initceremony

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
)

// buildTags matches the tag set `xkmsd` ships with in every other
// integration fixture in this repo (see the devcontainer compose files).
const buildTags = "codec_cbor codec_json codec_msgpack tpm_simulator"

// binaries holds the paths of the built xkmsd server and xkmsctl client.
type binaries struct {
	xkmsd   string
	xkmsctl string
}

var (
	buildOnce sync.Once
	built     binaries
	buildErr  error
)

// buildBinaries compiles xkmsd and xkmsctl once per test process and returns
// their paths. Building once keeps a multi-test suite fast; each test still gets an
// independent data directory and port set.
func buildBinaries(t *testing.T) binaries {
	t.Helper()
	buildOnce.Do(func() {
		root := projectRoot(t)
		// t.TempDir() is scoped to this subtest and removed when it ends, but
		// buildOnce makes the binaries shared by every test in this process;
		// they must outlive any one test, so they are built into their own
		// directory under the OS temp root instead.
		out, err := os.MkdirTemp("", "xkmsd-initceremony-bin")
		if err != nil {
			buildErr = err
			return
		}
		bins := binaries{
			xkmsd:   filepath.Join(out, "xkmsd"),
			xkmsctl: filepath.Join(out, "xkmsctl"),
		}
		for pkg, binPath := range map[string]string{"./cmd/xkmsd": bins.xkmsd, "./cmd/xkmsctl": bins.xkmsctl} {
			cmd := exec.Command("go", "build", "-tags", buildTags, "-o", binPath, pkg)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOWORK=off")
			if output, err := cmd.CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("go build %s: %w\n%s", pkg, err, output)
				return
			}
		}
		built = bins
	})
	if buildErr != nil {
		t.Fatalf("build binaries: %v", buildErr)
	}
	return built
}

// projectRoot walks up from the working directory to the module root.
func projectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (no go.mod found walking up from test working directory)")
		}
		dir = parent
	}
}

// freePort asks the OS for an unused TCP port and releases it immediately.
// There is an inherent, accepted race between release and xkmsd binding it;
// every other integration fixture in this repo that self-allocates ports
// accepts the same race.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// nodePorts are the listeners one xkmsd run serves its clients on.
type nodePorts struct {
	rest       int
	grpc       int
	mcp        int
	unixSocket string
}

// newNodePorts allocates a free TCP port per network listener and places the
// Unix socket in dataDir.
func newNodePorts(t *testing.T, dataDir string) nodePorts {
	t.Helper()
	return nodePorts{
		rest:       freePort(t),
		grpc:       freePort(t),
		mcp:        freePort(t),
		unixSocket: filepath.Join(dataDir, "xkmsd.sock"),
	}
}

// writeMinimalConfig writes an xkmsd config with just enough surface to run
// `init` and then `run` against a software backend: a qrdb-backed data
// directory with the node barrier's "tpm2" strategy, REST only, and TLS with
// client_auth "request" rather than "verify".
//
// Why "tpm2", not "none": `xkmsd init` refuses "none" outright (see
// validBarrierStrategies in cmd/xkmsd/init.go) -- it is a node-barrier-only
// posture, not something init's ceremony will provision. Of the strategies
// init does accept, "tpm2" is the one that ALSO auto-unseals unattended on
// every `xkmsd run`, init included (cmd/xkmsd/init_node.go's
// unsealDurableInitNode and pkg/embeddednode/embedded_node.go's ResolveNodeSeal /
// OpenEmbeddedNode), so it needs no operator step between the two `xkmsd
// run` invocations this test drives -- exactly what a restart-driven test
// needs, and a strictly stronger regression check than "none" would have
// been: the qrdb node's data plane is actually sealed and unsealed across
// the restart, not left unencrypted. tpmPort is the TCP command port of this
// test's own private swtpm instance (see swtpm_test_helpers.go); the control
// port is always tpmPort+1 by convention (config.TPM2Config.ToTPMConfig).
// "pkcs11" was considered and rejected -- see swtpm_test_helpers.go's
// package doc comment for why it cannot auto-unseal here by design, not by
// omission.
//
// TLS's client_auth "request" (rather than "verify"): the admin certificate
// is issued by `xkmsd init`'s own one-shot ceremony CA (ephemeral,
// in-memory, thrown away when init exits -- see
// cmd/xkmsd/init_ceremony.go), a DIFFERENT root than whatever `xkmsd run`
// initializes for its own CA config, so a chain-verifying listener would
// reject it. xkms's mTLS identity is the SPKI thumbprint bound to the user
// record (qrdb's stack-wide convention -- see
// user.ComputeSPKIThumbprint), not CA chain trust, so "request" (send the
// cert, do not chain-verify it) is enough for that lookup to run.
func writeMinimalConfig(t *testing.T, dataDir string, ports nodePorts, tpmPort int) string {
	t.Helper()
	// Every client transport xkmsd serves is enabled, so the admin credential
	// init issues is proven on each of them (#794). QUIC is HTTP/3 on the
	// REST port (see config.NodeServing), so quic_port only satisfies
	// Config.Validate.
	cfg := fmt.Sprintf(`
server:
  host: "127.0.0.1"
  rest_port: %d
  grpc_port: %d
  quic_port: %d
  mcp_port: %d

logging:
  level: "info"
  format: "json"

protocols:
  unix: true
  rest: true
  grpc: true
  quic: true
  mcp: true

unix:
  socket_path: %q

tls:
  enabled: true
  server_cn: "xkmsd-initceremony-test"
  client_auth: "request"

auth:
  enabled: true
  type: "composite"

barrier:
  enabled: true
  strategy: "tpm2"

datastore:
  engine: "pebble"
  path: %q

rng:
  mode: "software"
  fallback_mode: "software"

default_backend: "software"

backends:
  software:
    enabled: true
    path: %q
  tpm2:
    # enabled stays false deliberately: ResolveNodeSeal (the barrier's own
    # TPM open, used below) reads these fields directly off
    # Backends.TPM2 regardless of Enabled, but Enabled: true would ALSO
    # make (*Server).initTPM2Backend construct a second, general-purpose
    # TPM2 crypto backend that reuses the barrier's TPM handle via
    # tpm2backend.NewBackendWithTPM -- and that path is missing its
    # ExternalTPMConfig.KeyBackend (pkg/server/backend_tpm2.go never sets
    # it), which NewBackendWithTPM then refuses with "KeyBackend is nil".
    # This test only needs the node barrier's own tpm2 strategy, so the
    # general backend is neither required nor safe to turn on here; the
    # KeyBackend gap is a separate, pre-existing bug worth its own issue.
    enabled: false
    # Unused: ToTPMConfig only reads device_path when use_simulator is
    # false. Config.Validate requires a non-empty value regardless.
    device_path: "unused-tcp-simulator"
    use_simulator: true
    simulator_host: "127.0.0.1"
    simulator_port: %d

ca:
  identity:
    - subject:
        cn: "xkmsd-initceremony Root CA"
        organization: "go-xkms Integration Tests"
      valid: 10
      keys:
        - algorithm: "ECDSA"
          ecc:
            curve: "P-256"
          hash: "SHA-256"
          signature-algorithm: "ECDSAWithSHA256"
          store: "software"
          key-type: "CA"
      keystore-type: "software"
      is-root: true
      max-path-length: 1
  selected-ca: 0
  default-validity-days: 365
  home-dir: %q
`, ports.rest, ports.grpc, ports.rest, ports.mcp, ports.unixSocket,
		dataDir, filepath.Join(dataDir, "keys"), tpmPort, filepath.Join(dataDir, "ca"))

	path := filepath.Join(dataDir, "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// runInit runs `xkmsd init` to completion (it exits on its own) and fails
// the test on a non-zero exit or a missing admin credential.
func runInit(t *testing.T, bin, cfgPath, dataDir, soPin string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "init",
		"--config", cfgPath,
		"--data-dir", dataDir,
		"--hostname", "localhost",
		"--so-pin", soPin,
		"--barrier-strategy", "tpm2",
		"--admin-factor", "mtls",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xkmsd init failed: %v\n%s", err, output)
	}
	t.Logf("xkmsd init output:\n%s", output)

	for _, name := range []string{"admin-cert.pem", "admin-key.pem", "ca-bundle.pem"} {
		p := filepath.Join(dataDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist after init: %v", p, err)
		}
	}
}

// xkmsdProcess wraps a running `xkmsd run` invocation.
type xkmsdProcess struct {
	cmd *exec.Cmd
	// spkiPin is the hex SHA-256 SPKI pin of the TLS certificate this run
	// serves on every listener, captured on first contact.
	spkiPin string
}

// startRun launches xkmsd's default (daemon) command against cfgPath and
// returns once it accepts TCP connections on restPort, or fails the test.
//
// xkmsd has no "run" subcommand -- cmd/xkmsd/main.go's subcommands map
// holds only "init"; every other invocation, including the one running the
// server, parses top-level flags directly (see configs/xkmsd.service's
// `ExecStart=/usr/bin/xkmsd --config ...` and Dockerfile.server's
// `ENTRYPOINT ["/app/xkmsd"]` + `CMD ["--config", ...]`, neither of which
// pass a "run" argument). flag.Parse stops at the first non-flag argument,
// so a literal "run" positional here would have silently discarded
// --config and every flag after it, leaving xkmsd to fall back to
// /etc/xkms/xkmsd.yaml and fail to start.
func startRun(t *testing.T, bin, cfgPath string, ports nodePorts) *xkmsdProcess {
	t.Helper()
	cmd := exec.Command(bin, "--config", cfgPath)
	cmd.Stdout = &testLogWriter{t: t, prefix: "xkmsd run: "}
	cmd.Stderr = &testLogWriter{t: t, prefix: "xkmsd run: "}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xkmsd run: %v", err)
	}
	proc := &xkmsdProcess{cmd: cmd}

	// An open port does not mean the server behind it has finished composing
	// (CA, first-boot, the capability module), so readiness is the REST
	// readiness probe answering 200 and every other listener accepting.
	pinStore := bootstrap.NewMemoryPinStore()
	probe := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{TLSClientConfig: tofuTLSConfig(t, pinStore, ports.rest)},
	}
	readyURL := fmt.Sprintf("https://127.0.0.1:%d/health/ready", ports.rest)
	ready := func() bool {
		return httpOK(probe, readyURL) &&
			listenerAccepts("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.grpc))) &&
			listenerAccepts("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports.mcp))) &&
			listenerAccepts("unix", ports.unixSocket)
	}
	if !waitUntil(30*time.Second, ready) {
		_ = proc.stop()
		t.Fatalf("xkmsd run was not ready on every listener within 30s")
	}

	// A first boot serves a bootstrap certificate until composition installs
	// the CA-issued one, and the probe's kept-alive connection still carries
	// the bootstrap certificate, so the pin comes from a fresh handshake made
	// once the server is ready.
	pin, err := captureSPKIPin(t, ports.rest)
	if err != nil {
		_ = proc.stop()
		t.Fatalf("capture the server SPKI pin: %v", err)
	}
	proc.spkiPin = pin
	return proc
}

// captureSPKIPin makes a fresh TLS handshake with the REST listener on a
// trust-on-first-use pin store and returns the SPKI pin it recorded.
func captureSPKIPin(t *testing.T, restPort int) (string, error) {
	t.Helper()
	pinStore := bootstrap.NewMemoryPinStore()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(restPort))
	conn, err := tls.Dial("tcp", addr, tofuTLSConfig(t, pinStore, restPort))
	if err != nil {
		return "", err
	}
	if err := conn.Close(); err != nil {
		return "", err
	}
	pins, err := pinStore.List(context.Background())
	if err != nil {
		return "", err
	}
	if len(pins) != 1 {
		return "", fmt.Errorf("%d pins recorded, want 1", len(pins))
	}
	return pins[0].SPKISHA256, nil
}

// stop sends SIGTERM and waits for the process to exit, matching how an
// operator or a process supervisor restarts xkmsd between the two `run`
// invocations this test drives.
func (p *xkmsdProcess) stop() error {
	if p.cmd.Process == nil {
		return nil
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		return fmt.Errorf("xkmsd run did not exit after SIGTERM; killed")
	}
}

// waitUntil polls ready until it reports true, or the timeout elapses.
func waitUntil(timeout time.Duration, ready func() bool) bool {
	deadline := time.After(timeout)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-deadline:
			return false
		case <-tick.C:
		}
	}
	return true
}

// listenerAccepts reports whether something accepts connections on address.
func listenerAccepts(network, address string) bool {
	conn, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// httpOK reports whether a GET of url answers 200.
func httpOK(client *http.Client, url string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// mtlsClient builds an HTTP client presenting the admin's enrolled
// certificate, and chain-verifies the server's own TLS certificate through
// the project's canonical trust-on-first-use bootstrap rather than skipping
// verification.
//
// Why TOFU, not a loaded CA bundle: `xkmsd init`'s admin certificate is
// issued by init's own one-shot ceremony CA (ephemeral, in-memory, thrown
// away when init exits -- see cmd/xkmsd/init_ceremony.go's newBootstrapCA),
// whose root init writes to `<data dir>/ca-bundle.pem`; `xkmsd run` adds
// that root to the client CAs it advertises (pkg/server/tls_pool.go's
// configuredClientCAs) so a static client certificate list offers the admin
// certificate.
// `xkmsd run`, by contrast, builds a SEPARATE, PERSISTENT CA from the
// config's `ca:` block the first time it starts (pkg/server/server.go's
// initializeCA: trustedCA.Load falls back to trustedCA.Init on a fresh data
// directory) and issues the server's TLS leaf from that CA
// (ensureTLSServerCert). That persistent CA's key and certificate live
// inside the qrdb store this test's `datastore:` config points at, not a
// PEM file on disk, so there is no ca-bundle file to load, and
// init never touches this CA at all (its ceremony CA is fully in-memory and
// unrelated to `ca:` config) -- confirmed by tracing both paths, not
// assumed. The two CAs are intentionally distinct: mTLS client identity
// here is bound by go-qrdb's SPKI SHA-256 thumbprint
// (user.ComputeSPKIThumbprint), never by chain trust, so the admin
// certificate authenticating after a restart never depended on the
// ceremony CA surviving -- consistent with this test config's
// `tls.client_auth: "request"` (see writeMinimalConfig), which only
// requests the client certificate and never chain-verifies it.
//
// The server's own identity is a different question: a first-contact
// client has no pre-shared trust anchor for the run CA, which is exactly
// what sdk/go/bootstrap's trust-on-first-use mode is for (see
// pkg/trust/bootstrap's package doc: every consumer of trust bootstrap
// routes through this one implementation).
//
// Each call gets its OWN fresh pin store rather than one shared across both
// of this test's `xkmsd run` invocations, deliberately: `xkmsd run`'s own
// persistent CA does not actually survive the restart today, despite living
// in the same qrdb store `xkmsd init` populated -- both runs log "No
// existing CA found, initializing new CA" (trustedCA.Load fails to find
// what the prior run's trustedCA.Init persisted, pkg/server/server.go's
// initializeCA), so the server's TLS SPKI legitimately differs run to run.
// A shared pin store would then fail the SECOND connection with a TOFU pin
// mismatch -- not a simplification papering over that, but this function
// declining to assert a continuity guarantee the server does not currently
// provide. That CA-persistence gap is real and worth its own issue; it is
// not go-xkms#693 (admin login FACTOR persistence, which this test's actual
// assertions cover) and this change does not fix it.
func mtlsClient(t *testing.T, certPath, keyPath string, restPort int) *http.Client {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load admin credential: %v", err)
	}

	tlsConfig := tofuTLSConfig(t, bootstrap.NewMemoryPinStore(), restPort)
	// The static Certificates list every SDK transport and xkmsctl use:
	// crypto/tls's client sends an entry only when its issuer is among the
	// server's advertised acceptable CAs, and the server advertises the
	// ceremony root init wrote to ca-bundle.pem (#794).
	tlsConfig.Certificates = []tls.Certificate{cert}

	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
}

// tofuTLSConfig returns a client TLS config that pins the server's SPKI into
// pinStore on first contact with the REST port.
func tofuTLSConfig(t *testing.T, pinStore bootstrap.PinStore, restPort int) *tls.Config {
	t.Helper()
	endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(restPort))
	tlsConfig, err := bootstrap.NewTOFUTLSConfig(context.Background(), pinStore, endpoint, nil)
	if err != nil {
		t.Fatalf("build TOFU TLS config for %s: %v", endpoint, err)
	}
	return tlsConfig
}

// assertAdminAuthenticates proves the admin credential authenticates a
// session-gated REST route, and that the identity the server reports for it
// is the init admin, mirroring
// test/integration/logins/mtls_test.go's TestMTLS_AdminCredentialAuthenticates
// but against a self-managed, restartable server instead of a fixed
// docker-compose target.
func assertAdminAuthenticates(t *testing.T, restPort int, admin initAdmin) {
	t.Helper()
	client := mtlsClient(t, admin.certPath, admin.keyPath, restPort)
	url := fmt.Sprintf("https://127.0.0.1:%d/api/v1/auth/me", restPort)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("mTLS request to %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s response: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from %s with the admin credential, got %d: %s", url, resp.StatusCode, body)
	}

	// Roles carries role identifiers (the qrdb identity contract), so the
	// administrator check reads a permission only an administrator holds.
	var me struct {
		Username    string          `json:"username"`
		AuthMethod  string          `json:"auth_method"`
		Permissions map[string]bool `json:"permissions"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatalf("decode %s response: %v", url, err)
	}
	if me.Username != admin.username || me.AuthMethod != qrdbsdk.MethodMTLS || !me.Permissions[adminOnlyPermission] {
		t.Fatalf("%s reports username %q, auth method %q, %s=%t; want the init admin %q over %s holding %s",
			url, me.Username, me.AuthMethod, adminOnlyPermission, me.Permissions[adminOnlyPermission],
			admin.username, qrdbsdk.MethodMTLS, adminOnlyPermission)
	}
}

// testLogWriter routes a subprocess's output through t.Log so `go test -v`
// shows it inline instead of scattering it across stray stdout/stderr.
type testLogWriter struct {
	t      *testing.T
	prefix string
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s%s", w.prefix, string(p))
	return len(p), nil
}

// TestInitPersistsAdminFactor_SurvivesRestart is the regression test for
// go-xkms#693: an admin factor enrolled by `xkmsd init` must still
// authenticate after `xkmsd run` restarts, with no second init and no
// re-enrollment.
func TestInitPersistsAdminFactor_SurvivesRestart(t *testing.T) {
	bins := buildBinaries(t)
	dataDir := t.TempDir()
	ports := newNodePorts(t, dataDir)
	tpmPort := startTPM2Simulator(t)
	cfgPath := writeMinimalConfig(t, dataDir, ports, tpmPort)

	runInit(t, bins.xkmsd, cfgPath, dataDir, "test-so-pin-0123456789")
	admin := loadInitAdmin(t, dataDir)

	t.Log("starting xkmsd run (first boot of the durable node init just wrote to)")
	proc := startRun(t, bins.xkmsd, cfgPath, ports)
	assertAdminAuthenticates(t, ports.rest, admin)
	assertAdminOnEveryTransport(t, bins.xkmsctl, proc, ports, admin)
	if err := proc.stop(); err != nil {
		t.Fatalf("stop xkmsd run: %v", err)
	}

	t.Log("restarting xkmsd run against the SAME data directory -- no second init")
	proc2 := startRun(t, bins.xkmsd, cfgPath, ports)
	defer func() { _ = proc2.stop() }()
	assertAdminAuthenticates(t, ports.rest, admin)
	assertAdminOnEveryTransport(t, bins.xkmsctl, proc2, ports, admin)
}
