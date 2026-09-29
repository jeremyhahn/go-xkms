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

// Tests for startACMEServer's early failure branches (data dir creation,
// audit trail open, keystore backend resolution, primary CA resolution),
// reached without a working TCG CA / ACME TLS listener -- standing one up
// is out of this batch's scope; see the final report for what remains
// unreached.

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	acmeserver "github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestStartACMEServer_TrustedProxiesParseFails proves a malformed
// server.trusted_proxies entry fails ACME start-up with a wrapped
// *acmeInitError around ErrACMETrustedProxies, reached before the data
// directory is even touched. Config.Validate rejects this before xkmsd
// starts in production, so this exercises the defense-in-depth path rather
// than a state an operator can actually reach.
func TestStartACMEServer_TrustedProxiesParseFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Server: config.ServerConfig{
			TrustedProxies: []string{"not-an-ip-or-cidr"},
		},
		ACME: &config.ACMEConfig{
			Enabled: true,
		},
	}

	as, err := startACMEServer(nil, cfg, logger)
	if err == nil {
		t.Fatal("expected an error for a malformed trusted proxy entry")
	}
	if as != nil {
		t.Fatalf("expected nil *acmeServer on failure, got %#v", as)
	}
	if !errors.Is(err, ErrACMETrustedProxies) {
		t.Fatalf("err = %v, want errors.Is(err, ErrACMETrustedProxies)", err)
	}
	var initErr *acmeInitError
	if !errors.As(err, &initErr) {
		t.Fatalf("err = %T, want *acmeInitError", err)
	}
	if initErr.Stage != "parse trusted proxies" {
		t.Errorf("initErr.Stage = %q, want %q", initErr.Stage, "parse trusted proxies")
	}
}

// TestStartACMEServer_WiresTrustedProxiesBeforeAnythingElse proves
// server.trusted_proxies reaches both the ACME rate limiter's resolver
// (acmeserver.TrustedProxies) and the ACME audit trail's source-IP resolver
// (audit.SetTrustedProxies) from the same parsed value, before start-up goes
// on to fail at the (unrelated) data-dir stage. This is the wiring
// go-xkms#1179 added; acmeserver.TrustedProxies was previously never set from
// configuration in production.
func TestStartACMEServer_WiresTrustedProxiesBeforeAnythingElse(t *testing.T) {
	oldACMEProxies := acmeserver.TrustedProxies
	defer func() { acmeserver.TrustedProxies = oldACMEProxies }()
	defer audit.SetTrustedProxies(nil)

	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Server: config.ServerConfig{
			TrustedProxies: []string{"10.0.0.1"},
		},
		ACME: &config.ACMEConfig{
			Enabled: true,
			DataDir: filepath.Join(blocker, "acme"),
		},
	}

	as, err := startACMEServer(nil, cfg, logger)
	if err == nil {
		t.Fatal("expected an error for an uncreatable ACME data dir")
	}
	if as != nil {
		t.Fatalf("expected nil *acmeServer on failure, got %#v", as)
	}
	var initErr *acmeInitError
	if !errors.As(err, &initErr) || initErr.Stage != "create data dir" {
		t.Fatalf("err = %v, want a *acmeInitError at stage %q (trusted-proxy wiring must complete first)", err, "create data dir")
	}

	// acmeserver.ClientIP and audit.ClientIP must now agree: 10.0.0.1 is a
	// trusted proxy, so its X-Forwarded-For is believed by both.
	req := httptest.NewRequest(http.MethodPost, "/acme/revoke-cert", nil)
	req.RemoteAddr = "10.0.0.1:4433"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	if got := acmeserver.ClientIP(req); got != "203.0.113.9" {
		t.Errorf("acmeserver.ClientIP() = %q, want %q", got, "203.0.113.9")
	}
	if got := audit.ClientIP(req); got != "203.0.113.9" {
		t.Errorf("audit.ClientIP() = %q, want %q", got, "203.0.113.9")
	}

	// An untrusted peer's forged header must still be ignored by both.
	req.RemoteAddr = "198.51.100.7:4433"
	if got := acmeserver.ClientIP(req); got != "198.51.100.7" {
		t.Errorf("acmeserver.ClientIP() from an untrusted peer = %q, want the peer address", got)
	}
	if got := audit.ClientIP(req); got != "198.51.100.7" {
		t.Errorf("audit.ClientIP() from an untrusted peer = %q, want the peer address", got)
	}
}

// TestStartACMEServer_DataDirCreateFails proves a data directory that
// cannot be created (ENOTDIR: a plain file standing where a directory is
// required) fails start-up with a wrapped *acmeInitError rather than
// panicking, reached before srv is ever touched.
func TestStartACMEServer_DataDirCreateFails(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		ACME: &config.ACMEConfig{
			Enabled: true,
			DataDir: filepath.Join(blocker, "acme"),
		},
	}

	as, err := startACMEServer(nil, cfg, logger)
	if err == nil {
		t.Fatal("expected an error for an uncreatable ACME data dir")
	}
	if as != nil {
		t.Fatalf("expected nil *acmeServer on failure, got %#v", as)
	}
	var initErr *acmeInitError
	if !errors.As(err, &initErr) {
		t.Fatalf("err = %T, want *acmeInitError", err)
	}
	if initErr.Stage != "create data dir" {
		t.Errorf("initErr.Stage = %q, want %q", initErr.Stage, "create data dir")
	}
}

// TestStartACMEServer_BackendUnavailable proves an acme.keystore_backend
// naming a backend the server never registered fails with
// *acmeBackendError / ErrACMEBackendUnavailable instead of a nil-pointer
// panic deeper in CA construction.
func TestStartACMEServer_BackendUnavailable(t *testing.T) {
	srv, _ := newEmbeddedQRDBServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		ACME: &config.ACMEConfig{
			Enabled:         true,
			DataDir:         t.TempDir(),
			KeystoreBackend: "no-such-backend",
		},
	}

	as, err := startACMEServer(srv, cfg, logger)
	if err == nil {
		t.Fatal("expected an error for an unregistered keystore backend")
	}
	if as != nil {
		t.Fatalf("expected nil *acmeServer on failure, got %#v", as)
	}
	var backendErr *acmeBackendError
	if !errors.As(err, &backendErr) {
		t.Fatalf("err = %T, want *acmeBackendError", err)
	}
	if backendErr.Backend != "no-such-backend" {
		t.Errorf("backendErr.Backend = %q, want %q", backendErr.Backend, "no-such-backend")
	}
	if !errors.Is(err, ErrACMEBackendUnavailable) {
		t.Errorf("err = %v, want errors.Is match against ErrACMEBackendUnavailable", err)
	}
}

// TestStartACMEServer_PrimaryCAUnavailable proves that once the keystore
// backend resolves, a server with no CA subsystem configured (srv.CA() ==
// nil, the fixture's default state) fails ACME start-up with a
// *acmeInitError at the "resolve primary CA" stage instead of continuing
// with a nil CA.
func TestStartACMEServer_PrimaryCAUnavailable(t *testing.T) {
	srv, _ := newEmbeddedQRDBServer(t)
	if srv.CA() != nil {
		t.Fatal("fixture setup: expected srv.CA() == nil (no CA subsystem configured)")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		ACME: &config.ACMEConfig{
			Enabled:         true,
			DataDir:         t.TempDir(),
			KeystoreBackend: "software",
		},
	}

	as, err := startACMEServer(srv, cfg, logger)
	if err == nil {
		t.Fatal("expected an error when the server has no primary CA")
	}
	if as != nil {
		t.Fatalf("expected nil *acmeServer on failure, got %#v", as)
	}
	var initErr *acmeInitError
	if !errors.As(err, &initErr) {
		t.Fatalf("err = %T, want *acmeInitError", err)
	}
	if initErr.Stage != "resolve primary CA" {
		t.Errorf("initErr.Stage = %q, want %q", initErr.Stage, "resolve primary CA")
	}
}
