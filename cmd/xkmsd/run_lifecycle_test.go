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

package main

// TestRun_FullLifecycleGracefulShutdown drives run() itself (not just the
// serve() seam) end to end: flag/config resolution, the compliance gate,
// server.New with the admin ServiceModule, srv.Start, and a graceful
// shutdown -- triggered by a real SIGTERM delivered to this test process.
// That is safe here specifically because run() (unlike runProcess, which
// main calls) never calls go-qrdb's secure.CatchInterrupt: run()'s own
// setupSignalHandler is an ordinary per-call signal.Notify, so delivering
// SIGTERM cancels only this run()'s shutdown context, exactly as
// TestSetupSignalHandler_SIGTERMCancelsContext already proves for
// setupSignalHandler alone.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// writeRunLifecycleConfig writes a configuration that clears both
// config.Config.Validate and the secure-by-default ComplianceGaps gate run()
// enforces, with an embedded qrdb node rooted at a temp dir so
// finalizeAdminModule's srv.QRDBClient() requirement is met (mirrors
// newServeTestConfig in serve_test.go, in YAML form since run() loads
// configuration from a file path rather than a *config.Config value).
// Network protocols stay off (Unix socket only), so nothing here binds a
// fixed or even ephemeral TCP port.
func writeRunLifecycleConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := `
server:
  host: "127.0.0.1"

protocols:
  unix: true

unix:
  enabled: true
  socket_path: "` + filepath.Join(dir, "xkms.sock") + `"
  protocol: "grpc"

logging:
  level: "error"
  format: "json"

tls:
  enabled: true

auth:
  enabled: true
  type: "mtls"

storage:
  backend: "qrdb"
  path: "` + filepath.Join(dir, "storage") + `"
  qrdb:
    transport: "embedded"

default_backend: "software"

backends:
  software:
    enabled: true
    path: "` + filepath.Join(dir, "software") + `"

barrier:
  enabled: true
  strategy: "none"

ca:
  identity:
    - subject:
        cn: "xkmsd run lifecycle test CA"
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
`
	path := filepath.Join(dir, "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestRun_FullLifecycleGracefulShutdown(t *testing.T) {
	restoreFlags := swapFlagCommandLine(t)
	defer restoreFlags()

	path := writeRunLifecycleConfig(t)

	origArgs := os.Args
	os.Args = []string{"xkmsd", "--config", path}
	t.Cleanup(func() { os.Args = origArgs })

	done := make(chan int, 1)
	go func() { done <- run() }()

	// Give run() time to reach its shutdown wait (config load, compliance
	// gate, admin module construction, server.New, srv.Start, ACME no-op,
	// finalizeAdminModule) before delivering the "signal". This mirrors
	// TestSetupSignalHandler_SIGTERMCancelsContext's own settle delay.
	time.Sleep(300 * time.Millisecond)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to self: %v", err)
	}

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("run() = %d, want 0 for a graceful shutdown", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not return after SIGTERM was delivered")
	}

	if h := adminRouterState.Load(); h == nil {
		t.Fatal("run() returned before finalizeAdminModule published adminRouterState")
	}
}
