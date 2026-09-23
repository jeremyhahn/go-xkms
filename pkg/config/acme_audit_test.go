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

package config

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// enabledACME returns a valid, minimal ACME section so audit assertions are not
// masked by an unrelated validation failure.
func enabledACME() *ACMEConfig {
	return &ACMEConfig{
		Enabled:         true,
		HTTPSAddr:       ":8443",
		ExternalURL:     "https://acme.example.com",
		KeystoreBackend: "software",
		Challenges:      ACMEChallengesConfig{HTTP01: true},
		TLS:             ACMETLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
	}
}

// TestACMEAuditConfig_IsEnabled verifies the tri-state that makes the audit
// trail secure by default: absent means on, and only an explicit false is off.
func TestACMEAuditConfig_IsEnabled(t *testing.T) {
	enabled, disabled := true, false

	tests := []struct {
		name string
		cfg  ACMEAuditConfig
		want bool
	}{
		{name: "omitted section defaults to enabled", cfg: ACMEAuditConfig{}, want: true},
		{name: "explicitly enabled", cfg: ACMEAuditConfig{Enabled: &enabled}, want: true},
		{name: "explicitly disabled", cfg: ACMEAuditConfig{Enabled: &disabled}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEnabled(); got != tt.want {
				t.Fatalf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestACMEAuditConfig_UnmarshalTriState verifies the tri-state survives YAML:
// an absent key must not read as a deliberate opt-out.
func TestACMEAuditConfig_UnmarshalTriState(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{name: "no audit section", yaml: "enabled: true\n", want: true},
		{name: "audit section without enabled key", yaml: "enabled: true\naudit:\n  log_path: /var/log/acme/audit.log\n", want: true},
		{name: "audit explicitly off", yaml: "enabled: true\naudit:\n  enabled: false\n", want: false},
		{name: "audit explicitly on", yaml: "enabled: true\naudit:\n  enabled: true\n", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg ACMEConfig
			if err := yaml.Unmarshal([]byte(tt.yaml), &cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := cfg.Audit.IsEnabled(); got != tt.want {
				t.Fatalf("Audit.IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestACMEAuditConfig_ResolveLogPath verifies the trail lands beside the ACME
// state it describes unless the operator names a path.
func TestACMEAuditConfig_ResolveLogPath(t *testing.T) {
	if got := (ACMEAuditConfig{}).ResolveLogPath("/var/lib/xkms/acme"); got != filepath.Join("/var/lib/xkms/acme", DefaultACMEAuditFileName) {
		t.Fatalf("default log path = %q", got)
	}

	explicit := ACMEAuditConfig{LogPath: "/var/log/acme-audit.log"}
	if got := explicit.ResolveLogPath("/var/lib/xkms/acme"); got != "/var/log/acme-audit.log" {
		t.Fatalf("explicit log path = %q", got)
	}
}

// TestACMEAuditConfig_AuditConfig verifies the single mapping between the
// daemon YAML and the audit subsystem, including default substitution.
func TestACMEAuditConfig_AuditConfig(t *testing.T) {
	t.Run("defaults are substituted", func(t *testing.T) {
		got := ACMEAuditConfig{}.AuditConfig("/data/acme")

		if !got.Enabled {
			t.Fatal("audit must default to enabled")
		}
		if got.LogPath != filepath.Join("/data/acme", DefaultACMEAuditFileName) {
			t.Fatalf("LogPath = %q", got.LogPath)
		}
		if got.MaxSizeMB != DefaultACMEAuditMaxSizeMB ||
			got.MaxAgeDays != DefaultACMEAuditMaxAgeDays ||
			got.MaxBackups != DefaultACMEAuditMaxBackups ||
			got.BufferSize != DefaultACMEAuditBufferSize ||
			got.FlushIntervalSeconds != DefaultACMEAuditFlushIntervalSeconds {
			t.Fatalf("rotation defaults not applied: %+v", got)
		}
		if got.Format != DefaultACMEAuditFormat {
			t.Fatalf("Format = %q", got.Format)
		}
		if got.Compress {
			t.Fatal("compression must be opt-in")
		}
	})

	t.Run("operator values are preserved", func(t *testing.T) {
		disabled := false
		got := ACMEAuditConfig{
			Enabled:              &disabled,
			LogPath:              "/var/log/acme.log",
			MaxSizeMB:            5,
			MaxAgeDays:           7,
			MaxBackups:           3,
			BufferSize:           2,
			FlushIntervalSeconds: 1,
			Compress:             true,
		}.AuditConfig("/data/acme")

		if got.Enabled {
			t.Fatal("explicit disable must be carried through")
		}
		if got.LogPath != "/var/log/acme.log" || got.MaxSizeMB != 5 || got.MaxAgeDays != 7 ||
			got.MaxBackups != 3 || got.BufferSize != 2 || got.FlushIntervalSeconds != 1 || !got.Compress {
			t.Fatalf("operator values not preserved: %+v", got)
		}
	})

	t.Run("mapping satisfies the audit subsystem", func(t *testing.T) {
		cfg := ACMEAuditConfig{}.AuditConfig(t.TempDir())
		if err := cfg.Validate(); err != nil {
			t.Fatalf("audit rejected the mapped config: %v", err)
		}
	})
}

// TestACMEAuditConfig_Validate verifies that nonsensical audit settings are
// rejected up front instead of surfacing as a broken trail at run time.
func TestACMEAuditConfig_Validate(t *testing.T) {
	disabled := false

	tests := []struct {
		name    string
		cfg     ACMEAuditConfig
		wantErr error
	}{
		{name: "defaults are valid", cfg: ACMEAuditConfig{}},
		{name: "explicit json is valid", cfg: ACMEAuditConfig{Format: "json"}},
		{name: "disabled trail is never validated", cfg: ACMEAuditConfig{Enabled: &disabled, MaxSizeMB: -1, Format: "cbor"}},
		{name: "negative max size", cfg: ACMEAuditConfig{MaxSizeMB: -1}, wantErr: ErrACMEAuditNegativeRetention},
		{name: "negative max age", cfg: ACMEAuditConfig{MaxAgeDays: -1}, wantErr: ErrACMEAuditNegativeRetention},
		{name: "negative max backups", cfg: ACMEAuditConfig{MaxBackups: -1}, wantErr: ErrACMEAuditNegativeRetention},
		{name: "negative buffer size", cfg: ACMEAuditConfig{BufferSize: -1}, wantErr: ErrACMEAuditNegativeRetention},
		{name: "negative flush interval", cfg: ACMEAuditConfig{FlushIntervalSeconds: -1}, wantErr: ErrACMEAuditNegativeRetention},
		{name: "unqueryable format", cfg: ACMEAuditConfig{Format: "cbor"}, wantErr: ErrACMEAuditUnsupportedFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err != tt.wantErr {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestACMEConfig_ValidateRejectsBadAudit verifies the audit section is checked
// as part of the ACME section rather than only when the logger is built.
func TestACMEConfig_ValidateRejectsBadAudit(t *testing.T) {
	cfg := enabledACME()
	cfg.Audit.Format = "msgpack"

	if err := cfg.Validate(); err != ErrACMEAuditUnsupportedFormat {
		t.Fatalf("Validate() = %v, want %v", err, ErrACMEAuditUnsupportedFormat)
	}

	cfg.Audit.Format = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// TestComplianceGaps_ACMEAuditDisabled verifies that switching the trail off is
// reported as a compliance gap, so the daemon refuses to run an unaccountable
// CA.
func TestComplianceGaps_ACMEAuditDisabled(t *testing.T) {
	secure := func() *Config {
		return &Config{
			Barrier: BarrierConfig{Enabled: true, Strategy: "passphrase"},
			TLS:     TLSConfig{Enabled: true},
			Auth:    AuthConfig{Enabled: true, Type: "jwt"},
			CA:      &ca.MultiIdentityCAConfig{},
			ACME:    enabledACME(),
		}
	}

	auditGap := func(gaps []string) string {
		for _, gap := range gaps {
			if strings.Contains(gap, "audit trail disabled") {
				return gap
			}
		}
		return ""
	}

	t.Run("enabled by default leaves no gap", func(t *testing.T) {
		if gaps := secure().ComplianceGaps(); len(gaps) != 0 {
			t.Fatalf("unexpected gaps: %v", gaps)
		}
	})

	t.Run("explicitly disabled reports a gap", func(t *testing.T) {
		disabled := false
		cfg := secure()
		cfg.ACME.Audit.Enabled = &disabled

		gap := auditGap(cfg.ComplianceGaps())
		if gap == "" {
			t.Fatal("disabling the ACME audit trail must be reported as a compliance gap")
		}
		if !strings.Contains(gap, "acme.audit.enabled=false") {
			t.Fatalf("gap must name the setting to change: %q", gap)
		}
	})

	t.Run("gap only applies when ACME is enabled", func(t *testing.T) {
		disabled := false

		cfg := secure()
		cfg.ACME.Enabled = false
		cfg.ACME.Audit.Enabled = &disabled
		if gap := auditGap(cfg.ComplianceGaps()); gap != "" {
			t.Fatalf("disabled ACME must not report an audit gap: %q", gap)
		}

		cfg = secure()
		cfg.ACME = nil
		if gap := auditGap(cfg.ComplianceGaps()); gap != "" {
			t.Fatalf("absent ACME must not report an audit gap: %q", gap)
		}
	})
}
