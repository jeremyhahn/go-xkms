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

// go-xkms#705: two startACMEServer (acme.go) branches every existing test
// fixture happened to skip:
//
//  1. The default ACME data directory ("<storage.path>/acme") when
//     acme.data_dir is left unset -- every prior test set DataDir
//     explicitly.
//  2. The "audit trail disabled" warning log line, reached when
//     acme.audit.enabled is explicitly false -- every prior test left the
//     audit section at its (enabled) default. Config.ComplianceGaps refuses
//     this combination in production (cmd/xkmsd never boots with it), so
//     this is the same defense-in-depth exercise
//     TestStartACMEServer_TrustedProxiesParseFails documents for the
//     trusted-proxies branch.
//
// Both use newEmbeddedQRDBServer (admin_qrdb_test.go's shared fixture)
// rather than a nil *server.Server: srv.Backend, called once data-dir and
// audit-trail set-up succeed, dereferences the receiver and panics on nil.

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// boolPtr returns a pointer to b, for config.ACMEAuditConfig.Enabled's
// tri-state (nil = default-on) field.
func boolPtr(b bool) *bool { return &b }

// TestStartACMEServer_DefaultDataDirFromStoragePath proves an unset
// acme.data_dir resolves to "<storage.path>/acme" and is actually created,
// rather than an empty or relative path, before start-up goes on to fail at
// the (unrelated) keystore-backend stage.
func TestStartACMEServer_DefaultDataDirFromStoragePath(t *testing.T) {
	srv, cfg := newEmbeddedQRDBServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg.ACME = &config.ACMEConfig{
		Enabled:         true,
		KeystoreBackend: "no-such-backend",
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
		t.Fatalf("err = %T, want *acmeBackendError (data-dir default resolution must complete first)", err)
	}

	wantDataDir := filepath.Join(cfg.Datastore.Path, "acme")
	fi, statErr := os.Stat(wantDataDir)
	if statErr != nil {
		t.Fatalf("default data dir %q was not created: %v", wantDataDir, statErr)
	}
	if !fi.IsDir() {
		t.Fatalf("default data dir %q is not a directory", wantDataDir)
	}
}

// TestStartACMEServer_AuditTrailDisabledIsWarned proves an explicitly
// disabled audit trail (acme.audit.enabled=false) logs the "audit trail
// disabled" warning rather than silently proceeding as if it were on.
func TestStartACMEServer_AuditTrailDisabledIsWarned(t *testing.T) {
	srv, _ := newEmbeddedQRDBServer(t)
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := &config.Config{
		ACME: &config.ACMEConfig{
			Enabled:         true,
			DataDir:         t.TempDir(),
			KeystoreBackend: "no-such-backend",
			Audit:           config.ACMEAuditConfig{Enabled: boolPtr(false)},
		},
	}

	_, err := startACMEServer(srv, cfg, logger)
	var backendErr *acmeBackendError
	if !errors.As(err, &backendErr) {
		t.Fatalf("err = %T, want *acmeBackendError (audit trail wiring must complete first)", err)
	}
	if !strings.Contains(buf.String(), "ACME audit trail disabled") {
		t.Errorf("expected an \"ACME audit trail disabled\" warning, got log:\n%s", buf.String())
	}
}
