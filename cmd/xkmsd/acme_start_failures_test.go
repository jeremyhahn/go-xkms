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
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

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
