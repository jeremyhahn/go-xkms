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

// Tests for serve() (main.go): the live-server graceful-shutdown path
// go-xkms#1141 asked for. #1153 first split runProcess (secure.CatchInterrupt
// and the Purge/WipeAll teardown) from run(); this batch finishes the split
// named in #1141's evidence by pulling the part of run() "from srv.Start()
// through the shutdown calls" into serve(shutdownCtx, srv, cfg, logger),
// which takes its shutdown trigger as a context parameter instead of calling
// setupSignalHandler itself. A test drives it by canceling a context it
// owns, never by sending a real SIGTERM/SIGINT to the test process -- which
// would race go-qrdb's secure.CatchInterrupt handler and can kill the whole
// test binary (see #1141's evidence).

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	nativeca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newServeTestConfig returns a configuration that clears both gates serve's
// caller (run()) enforces before ever reaching it: config.Config.Validate
// and the secure-by-default ComplianceGaps check. It builds on
// embeddedQRDBConfig (admin_qrdb_test.go) -- the package's established
// "embedded qrdb node rooted at a temp dir, software backend only, no
// hardware" fixture -- and adds the barrier, TLS, mTLS authentication and CA
// ComplianceGaps requires, plus a qrdb storage backend so
// finalizeAdminModule's srv.QRDBClient() requirement is met.
func newServeTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := embeddedQRDBConfig(t)
	cfg.TLS.Enabled = true
	cfg.Auth = config.AuthConfig{Enabled: true, Type: "mtls"}
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
	cfg.CA = &nativeca.MultiIdentityCAConfig{
		SelectedCA:          0,
		DefaultValidityDays: 365,
		Identity: []nativeca.Identity{
			{
				IsRoot: true,
				Valid:  1,
				Subject: nativeca.Subject{
					CommonName:   "xkmsd serve test root CA",
					Organization: "go-xkms",
					Country:      "US",
				},
				Keys: []*types.KeyConfig{
					{
						KeyAlgorithm: types.AlgorithmECDSA,
						ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
					},
				},
			},
		},
	}
	if gaps := cfg.ComplianceGaps(); len(gaps) != 0 {
		t.Fatalf("fixture setup: newServeTestConfig is not compliant: %v", gaps)
	}
	return cfg
}

// newServeTestServer builds a *server.Server exactly as run() does before
// calling serve: the admin ServiceModule constructed and registered via
// server.WithExtraModules at New time, matching newAdminModule's
// documented requirement that registration happen during node construction.
func newServeTestServer(t *testing.T) (*server.Server, *config.Config) {
	t.Helper()
	cfg := newServeTestConfig(t)

	adminModule, err := newAdminModule()
	if err != nil {
		t.Fatalf("newAdminModule: %v", err)
	}

	srv, err := server.New(cfg, server.WithExtraModules(adminModule))
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if srv.QRDBClient() == nil {
		t.Fatal("fixture setup: QRDBClient() = nil with a qrdb storage backend")
	}
	return srv, cfg
}

// TestServe_GracefulShutdown drives serve() through its full documented
// sequence -- srv.Start, the (here disabled, so no-op) ACME server,
// finalizeAdminModule, the shutdown wait, and a graceful drain of both --
// using an already-canceled context rather than a real signal. Canceling
// before serve is even called (rather than racing a timer against serve's
// own goroutine) proves the sequence deterministically: serve unconditionally
// starts and finalizes the server before it ever consults shutdownCtx, so an
// already-Done context still exercises every step between Start and the
// wait, not just the immediate-shutdown branch.
func TestServe_GracefulShutdown(t *testing.T) {
	srv, cfg := newServeTestServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	shutdownCtx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan int, 1)
	go func() { done <- serve(shutdownCtx, srv, cfg, logger) }()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve() = %d, want 0 for a graceful shutdown", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve() did not return after its shutdown context was already canceled")
	}

	h := adminRouterState.Load()
	if h == nil {
		t.Fatal("serve() returned before finalizeAdminModule published adminRouterState")
	}
}

// TestServe_StartFailureReturnsOne proves a server that fails to start is
// reported as exit code 1 without ever waiting on the shutdown context: a
// second Start on an already-started (and already-shut-down) *server.Server
// is exactly the shape a real deployment hits when the configured port or
// Unix socket is already bound.
func TestServe_StartFailureReturnsOne(t *testing.T) {
	srv, cfg := newServeTestServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := srv.Start(); err != nil {
		t.Fatalf("fixture setup: first Start() failed: %v", err)
	}
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("fixture setup: Shutdown() failed: %v", err)
	}

	// shutdownCtx is never canceled: if serve reached the wait it would hang
	// until the test's own timeout, which is exactly what this test rules
	// out -- Start's error must return before that point.
	shutdownCtx := context.Background()

	done := make(chan int, 1)
	go func() { done <- serve(shutdownCtx, srv, cfg, logger) }()

	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("serve() = %d, want 1 when srv.Start fails", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve() did not return promptly on a Start failure")
	}
}
