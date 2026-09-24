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

package client

import (
	"path/filepath"
	"testing"
)

// TestDefaultTrustedCAConfig_AuditEnabled verifies that an embedded TrustedCA
// records by default. A CA that has to be told to keep an audit trail will run
// without one. DefaultTrustedCAConfig leaves Audit.LogPath and DataDir unset:
// Validate is what derives the on-disk path (go-xkms#929), never a
// cwd-relative constant baked into the default.
func TestDefaultTrustedCAConfig_AuditEnabled(t *testing.T) {
	cfg := DefaultTrustedCAConfig()

	if !cfg.Audit.Enabled {
		t.Fatal("the default TrustedCA configuration must record an audit trail")
	}
	if cfg.Audit.LogPath != "" {
		t.Fatalf("Audit.LogPath = %q, want empty until Validate resolves it against DataDir", cfg.Audit.LogPath)
	}
	if cfg.Audit.Format != "json" {
		t.Fatalf("Audit.Format = %q, want json (the only queryable format)", cfg.Audit.Format)
	}
	if cfg.Audit.MaxAgeDays <= 0 || cfg.Audit.MaxSizeMB <= 0 || cfg.Audit.MaxBackups <= 0 {
		t.Fatalf("audit retention must be bounded: %+v", cfg.Audit)
	}
}

// TestTrustedCAConfig_ValidateDerivesAuditLogPathFromDataDir verifies that an
// enabled audit trail with no explicit LogPath resolves to
// DataDir/DefaultAuditLogFileName -- an absolute path under the configured
// data directory, never a path relative to the process's working directory
// (go-xkms#929).
func TestTrustedCAConfig_ValidateDerivesAuditLogPathFromDataDir(t *testing.T) {
	dataDir := t.TempDir()

	cfg := DefaultTrustedCAConfig()
	cfg.DataDir = dataDir
	cfg.ACME.ExternalURL = "https://acme.example.com"
	cfg.ACME.CAIdentifiers = []string{"ca.example.com"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with a configured DataDir must succeed: %v", err)
	}

	want := filepath.Join(dataDir, DefaultAuditLogFileName)
	if cfg.Audit.LogPath != want {
		t.Fatalf("Audit.LogPath = %q, want %q", cfg.Audit.LogPath, want)
	}
	if !filepath.IsAbs(cfg.Audit.LogPath) {
		t.Fatalf("Audit.LogPath = %q, want an absolute path", cfg.Audit.LogPath)
	}
}

// TestTrustedCAConfig_ValidateRejectsUnwritableAuditSection verifies that an
// enabled audit trail with neither LogPath nor DataDir set fails configuration
// validation with a typed error, rather than silently writing beside wherever
// the process happens to be running (go-xkms#929) or surfacing as a missing
// trail once the CA is already serving.
func TestTrustedCAConfig_ValidateRejectsUnwritableAuditSection(t *testing.T) {
	cfg := DefaultTrustedCAConfig()

	cfg.ACME.ExternalURL = "https://acme.example.com"
	cfg.ACME.CAIdentifiers = []string{"ca.example.com"}

	if err := cfg.Validate(); err == nil {
		t.Fatal("an enabled audit trail with no log path and no data_dir must be rejected")
	}

	// A disabled trail has nothing to validate, so it must not block start-up.
	cfg.Audit.Enabled = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a disabled audit trail must validate: %v", err)
	}
}
