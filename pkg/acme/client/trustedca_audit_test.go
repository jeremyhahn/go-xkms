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
	"testing"
)

// TestDefaultTrustedCAConfig_AuditEnabled verifies that an embedded TrustedCA
// records by default. A CA that has to be told to keep an audit trail will run
// without one.
func TestDefaultTrustedCAConfig_AuditEnabled(t *testing.T) {
	cfg := DefaultTrustedCAConfig()

	if !cfg.Audit.Enabled {
		t.Fatal("the default TrustedCA configuration must record an audit trail")
	}
	if cfg.Audit.LogPath != DefaultAuditLogPath {
		t.Fatalf("Audit.LogPath = %q, want %q", cfg.Audit.LogPath, DefaultAuditLogPath)
	}
	if cfg.Audit.Format != "json" {
		t.Fatalf("Audit.Format = %q, want json (the only queryable format)", cfg.Audit.Format)
	}
	if cfg.Audit.MaxAgeDays <= 0 || cfg.Audit.MaxSizeMB <= 0 || cfg.Audit.MaxBackups <= 0 {
		t.Fatalf("audit retention must be bounded: %+v", cfg.Audit)
	}

	// The rest of the default configuration deliberately leaves the external
	// URL to the operator, so validate only the audit section here.
	if err := cfg.Audit.Validate(); err != nil {
		t.Fatalf("the default audit section must validate: %v", err)
	}
}

// TestTrustedCAConfig_ValidateRejectsUnwritableAuditSection verifies that an
// invalid audit section fails configuration validation rather than surfacing as
// a missing trail once the CA is already serving.
func TestTrustedCAConfig_ValidateRejectsUnwritableAuditSection(t *testing.T) {
	cfg := DefaultTrustedCAConfig()
	cfg.Audit.LogPath = ""

	cfg.ACME.ExternalURL = "https://acme.example.com"

	if err := cfg.Validate(); err == nil {
		t.Fatal("an enabled audit trail with no log path must be rejected")
	}

	// A disabled trail has nothing to validate, so it must not block start-up.
	cfg.Audit.Enabled = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a disabled audit trail must validate: %v", err)
	}
}
