// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// acmeConfigWithAudit returns an otherwise valid ACME configuration whose data
// directory lives under dataDir.
func acmeConfigWithAudit(dataDir string, audit config.ACMEAuditConfig) *config.Config {
	return &config.Config{
		ACME: &config.ACMEConfig{
			Enabled:         true,
			HTTPSAddr:       "127.0.0.1:0",
			ExternalURL:     "https://acme.example.com",
			KeystoreBackend: "software",
			DataDir:         dataDir,
			Challenges:      config.ACMEChallengesConfig{HTTP01: true},
			Audit:           audit,
		},
	}
}

// TestStartACMEServer_AuditTrailUnwritable verifies the fail-closed posture: an
// ACME CA whose audit trail cannot be opened does not start. The trail is
// opened before any keystore, CA, or listener is touched, so the failure is
// reported before the CA can sign anything.
func TestStartACMEServer_AuditTrailUnwritable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dataDir := t.TempDir()

	// A directory occupying the log file's path cannot be opened for writing,
	// whichever user the daemon runs as.
	logPath := filepath.Join(dataDir, "blocked-audit.log")
	if err := os.Mkdir(logPath, 0o750); err != nil {
		t.Fatalf("failed to stage unwritable log path: %v", err)
	}

	cfg := acmeConfigWithAudit(dataDir, config.ACMEAuditConfig{LogPath: logPath})

	// srv is nil: reaching a nil-server dereference would mean the audit trail
	// was not opened first, so this also pins the start-up ordering.
	as, err := startACMEServer(nil, cfg, logger)
	if err == nil {
		t.Fatal("expected start-up to fail when the audit trail cannot be opened")
	}
	if as != nil {
		t.Fatalf("expected no ACME server, got %#v", as)
	}
	if !errors.Is(err, ErrACMEAuditLogger) {
		t.Fatalf("error must unwrap to ErrACMEAuditLogger, got %v", err)
	}

	var initErr *acmeInitError
	if !errors.As(err, &initErr) {
		t.Fatalf("error must be an *acmeInitError, got %T", err)
	}
	if initErr.Stage != "open audit trail" {
		t.Fatalf("unexpected stage %q", initErr.Stage)
	}
}

// TestACMEAuditTrail_DisabledResolvesToNoTrail verifies that an operator who
// deliberately turns the trail off gets a disabled audit configuration and no
// log file: startACMEServer then passes the audit stage without creating one.
// The runtime consequence — GET /admin/audit reporting that no trail exists —
// is covered end to end in pkg/acme/server/handlers.
func TestACMEAuditTrail_DisabledResolvesToNoTrail(t *testing.T) {
	dataDir := t.TempDir()

	disabled := false
	cfg := acmeConfigWithAudit(dataDir, config.ACMEAuditConfig{Enabled: &disabled})

	auditCfg := cfg.ACME.Audit.AuditConfig(dataDir)
	if auditCfg.Enabled {
		t.Fatal("explicitly disabled audit must map to a disabled audit config")
	}

	// Building the logger from that configuration yields the no-op logger and
	// touches no filesystem, which is what startACMEServer does at boot.
	logger, err := audit.NewFileAuditLogger(auditCfg)
	if err != nil {
		t.Fatalf("a disabled trail must not fail to build: %v", err)
	}
	defer func() { _ = logger.Close() }()

	if logger.Enabled() {
		t.Fatal("a disabled trail must produce a logger that reports itself disabled")
	}
	if _, err := os.Stat(auditCfg.LogPath); !os.IsNotExist(err) {
		t.Fatalf("a disabled trail must not create %q (stat err: %v)", auditCfg.LogPath, err)
	}
}

// TestACMEAuditTrail_DefaultsOnInDataDir verifies that an ACME section with no
// audit block still resolves to an enabled trail inside the ACME data
// directory, which is what makes the control on by default.
func TestACMEAuditTrail_DefaultsOnInDataDir(t *testing.T) {
	dataDir := t.TempDir()
	cfg := acmeConfigWithAudit(dataDir, config.ACMEAuditConfig{})

	auditCfg := cfg.ACME.Audit.AuditConfig(dataDir)
	if !auditCfg.Enabled {
		t.Fatal("an omitted audit section must leave the trail enabled")
	}

	want := filepath.Join(dataDir, config.DefaultACMEAuditFileName)
	if auditCfg.LogPath != want {
		t.Fatalf("log path = %q, want %q", auditCfg.LogPath, want)
	}

	logger, err := audit.NewFileAuditLogger(auditCfg)
	if err != nil {
		t.Fatalf("default trail failed to open: %v", err)
	}
	defer func() { _ = logger.Close() }()

	if !logger.Enabled() {
		t.Fatal("the default trail must record")
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("the default trail must create its log file: %v", err)
	}
}
