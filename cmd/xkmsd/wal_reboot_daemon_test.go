package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// Issue #2290, Codex P1 3 on #2291: pkg/server's
// TestWALReboot_BootCompletionFailureIsPrecise proves the post-unseal boot
// failure is a precise QRDBNodeError, but stops there. This drives the
// daemon: a passphrase-sealed node whose pebble WAL holds one corrupt byte
// in a full encfs block is unsealed over the sealed-window listener, boot
// completion fails, and xkmsd must stay up reporting that failure. Today the
// error propagates out of server.New (pkg/server/qrdb_node.go, Stage "sealed
// window") and run() logs "Failed to create server" and returns 1
// (cmd/xkmsd/main.go), so the supervisor restarts xkmsd and the barrier needs
// another unseal: the restart loop. Red until the daemon keeps a failed boot
// up (next slice, docs/plans/2290.md).

const (
	walDaemonPassphrase = "wal-2290-daemon-passphrase"
	walDaemonRecords    = 64
	// walDaemonBootStage is the QRDBNodeError stage serveSealedWindow
	// reports for a boot completion that fails after the unseal.
	walDaemonBootStage = "complete boot after sealed window"
)

// writeWALDaemonConfig writes a compliant node-seal (passphrase barrier,
// local pebble) xkmsd config in the style of writeRunLifecycleConfig, with
// REST on a free loopback port so the sealed-window listener is reachable.
// It returns the config path, the datastore path and the REST port.
func writeWALDaemonConfig(t *testing.T) (string, string, int) {
	t.Helper()
	dir := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	storage := filepath.Join(dir, "storage")
	content := fmt.Sprintf(`
server:
  host: "127.0.0.1"
  rest_port: %d

protocols:
  unix: false
  rest: true
  grpc: false
  quic: false
  mcp: false

logging:
  level: "info"
  format: "json"

tls:
  enabled: true
  server_cn: "localhost"

auth:
  enabled: true
  type: "mtls"

datastore:
  engine: "pebble"
  mode: "standalone"
  path: %q

default_backend: "software"

backends:
  software:
    enabled: true
    path: %q

barrier:
  enabled: true
  strategy: "passphrase"
  sealed_window_timeout: "2m"

ca:
  identity:
    - subject:
        cn: "xkmsd wal reboot daemon test CA"
        organization: "go-xkms"
      valid: 10
      keys:
        - algorithm: "ECDSA"
          ecc:
            curve: "P-256"
          hash: "SHA-256"
          key-type: "CA"
      keystore-type: "software"
      is-root: true
  selected-ca: 0
  default-validity-days: 365
`, port, storage, filepath.Join(dir, "software"))
	path := filepath.Join(dir, "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path, storage, port
}

// walDaemonProvision initializes the passphrase barrier on the datastore of
// cfgPath, writes enough records to fill several encfs WAL blocks and stops
// the node cleanly (Close syncs the WAL).
func walDaemonProvision(t *testing.T, cfgPath string) {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	ctx := context.Background()
	node, sealRes, err := openDurableInitNode(ctx, cfg, silentLogger())
	if err != nil {
		t.Fatalf("openDurableInitNode: %v", err)
	}
	if err := unsealDurableInitNode(ctx, node, sealRes, "passphrase", []byte(walDaemonPassphrase)); err != nil {
		_ = node.Close()
		t.Fatalf("unsealDurableInitNode: %v", err)
	}
	b := qrdbstorage.NewBackend(node.Client().KV(), qrdbstorage.WithCallContext(node.ServiceContext))
	for i := 0; i < walDaemonRecords; i++ {
		k := fmt.Sprintf("xkms/wal2290/daemon/k%04d", i)
		v := []byte(fmt.Sprintf("daemon-record-%d-%0200d", i, i))
		if err := b.Put(ctx, k, v); err != nil {
			_ = node.Close()
			t.Fatalf("put %s: %v", k, err)
		}
	}
	if err := node.Close(); err != nil {
		t.Fatalf("close provisioned node: %v", err)
	}
}

// walDaemonCorruptInteriorWALBlock flips one byte inside a full encfs WAL
// block ahead of the trailing one, the same deterministic damage as
// walRebootCorruptInteriorWALBlock in pkg/server/wal_reboot_test.go (test
// helpers there are not importable from cmd/xkmsd).
func walDaemonCorruptInteriorWALBlock(t *testing.T, pebbleDir string) {
	t.Helper()
	logs, err := filepath.Glob(filepath.Join(pebbleDir, "*.log"))
	if err != nil || len(logs) == 0 {
		t.Fatalf("no WAL in %s: %v", pebbleDir, err)
	}
	f, err := os.OpenFile(logs[len(logs)-1], os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open WAL: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close WAL: %v", err)
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat WAL: %v", err)
	}
	// 133-byte header plus at least two 4124-byte blocks: the middle byte
	// then sits in a full block ahead of the trailing one.
	if fi.Size() <= 133+2*4124 {
		t.Fatalf("the WAL must hold full blocks, size %d", fi.Size())
	}
	off := fi.Size() / 2
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatalf("read WAL byte: %v", err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatalf("write WAL byte: %v", err)
	}
}

// walDaemonTLSConfig trusts the certificate the daemon minted for itself and
// persisted under its datastore (pkg/server/unified_tls.go: unified-tls/
// cert.pem), plus the CA bundle once the daemon has written one, and verifies
// the server against the name in that certificate.
func walDaemonTLSConfig(storage string) (*tls.Config, error) {
	dir := filepath.Join(storage, "unified-tls")
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem")) //nolint:gosec // test-owned temp dir
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("daemon cert.pem holds no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse daemon certificate: %w", err)
	}
	var name string
	switch {
	case len(leaf.DNSNames) > 0:
		name = leaf.DNSNames[0]
	case len(leaf.IPAddresses) > 0:
		name = leaf.IPAddresses[0].String()
	default:
		return nil, errors.New("daemon certificate names no DNS or IP SAN")
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	if bundle, err := os.ReadFile(filepath.Join(dir, "ca-bundle.pem")); err == nil { //nolint:gosec // test-owned temp dir
		pool.AppendCertsFromPEM(bundle)
	}
	return &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12}, nil
}

func walDaemonHTTPClient(cfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}
}

// walDaemonClient builds a client pinned to the daemon's current certificate;
// rebuild it after each daemon start, the certificate may have changed.
func walDaemonClient(t *testing.T, storage string) *http.Client {
	t.Helper()
	cfg, err := walDaemonTLSConfig(storage)
	if err != nil {
		t.Fatalf("load the daemon's certificate: %v", err)
	}
	return walDaemonHTTPClient(cfg)
}

// walDaemonUnseal posts the passphrase to the sealed-window unseal verb,
// retrying until the listener answers or run() returns.
func walDaemonUnseal(t *testing.T, storage, base string, done <-chan int) {
	t.Helper()
	body, err := json.Marshal(map[string][]byte{"secret": []byte(walDaemonPassphrase)})
	if err != nil {
		t.Fatalf("marshal unseal body: %v", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case rc := <-done:
			t.Fatalf("run() returned %d before the sealed window took the unseal", rc)
		default:
		}
		// The certificate is read on every attempt: the daemon writes it
		// before its listener serves, and may replace one left by provisioning.
		cfg, err := walDaemonTLSConfig(storage)
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("daemon never wrote its certificate: %v", err)
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		resp, err := walDaemonHTTPClient(cfg).Post(base+"/v1/barrier/unseal", "application/json", bytes.NewReader(body))
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				return
			}
			t.Fatalf("sealed-window unseal answered %d, want 204", resp.StatusCode)
		}
		if time.Now().After(deadline) {
			t.Fatalf("sealed-window listener never answered the unseal: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestDaemon_WALRebootBootFailureKeepsDaemonUp is the daemon-level
// reproduction of the #2290 restart loop: after a post-unseal boot failure
// run() must not return, and the daemon must still answer on its listener
// and report the boot error precisely (stage and encfs cause).
func TestDaemon_WALRebootBootFailureKeepsDaemonUp(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()

	cfgPath, storage, port := writeWALDaemonConfig(t)
	walDaemonProvision(t, cfgPath)
	walDaemonCorruptInteriorWALBlock(t, filepath.Join(storage, "pebble"))
	setRunArgs(t, "-config", cfgPath)

	done := make(chan int, 1)
	go func() { done <- run() }()
	t.Cleanup(func() { walDaemonStop(t, done) })

	base := fmt.Sprintf("https://127.0.0.1:%d", port)
	walDaemonUnseal(t, storage, base, done)

	// (a) The boot completion that follows the unseal fails on the corrupt
	// WAL block; the daemon must survive it instead of exiting.
	select {
	case rc := <-done:
		done <- rc // let the cleanup see run() has already returned
		t.Fatalf("run() returned %d after the post-unseal boot failure: xkmsd exits "+
			"(\"Failed to create server\", cmd/xkmsd/main.go) and the supervisor restart "+
			"needs another unseal; it must stay up and report the boot error", rc)
	case <-time.After(5 * time.Second):
	}

	// (b) Still answering on its listener, with the precise boot error.
	client := walDaemonClient(t, storage)
	resp, err := client.Get(base + "/v1/barrier/status")
	if err != nil {
		t.Fatalf("daemon stopped answering after the boot failure: %v", err)
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read barrier status: %v", err)
	}
	status := string(raw)
	for _, want := range []string{walDaemonBootStage, "block authentication failed"} {
		if !strings.Contains(status, want) {
			t.Errorf("barrier status must report the boot failure precisely: missing %q in %d %s",
				want, resp.StatusCode, status)
		}
	}
}

// walDaemonStop ends a run() that is still serving via the shutdown path
// (SIGTERM). The test holds its own Notify on SIGTERM for the duration, so
// the signal never takes the default action and kills the test binary even
// if run() has not yet installed its handler.
func walDaemonStop(t *testing.T, done chan int) {
	t.Helper()
	select {
	case <-done:
		return
	default:
	}
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)
	deadline := time.After(30 * time.Second)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Errorf("send SIGTERM to self: %v", err)
			return
		}
		select {
		case <-done:
			return
		case <-tick.C:
		case <-deadline:
			t.Error("run() did not return after SIGTERM")
			return
		}
	}
}
