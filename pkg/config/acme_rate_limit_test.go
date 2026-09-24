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

package config

import (
	"errors"
	"testing"
	"time"
)

// TestACMERateLimitConfig_IsEnabled verifies the tri-state that makes ACME
// rate limiting secure by default: an omitted "enabled" key means on, and
// only an explicit false turns it off (go-xkms#882).
func TestACMERateLimitConfig_IsEnabled(t *testing.T) {
	enabled, disabled := true, false

	tests := []struct {
		name string
		cfg  ACMERateLimitConfig
		want bool
	}{
		{name: "omitted section defaults to enabled", cfg: ACMERateLimitConfig{}, want: true},
		{name: "explicitly enabled", cfg: ACMERateLimitConfig{Enabled: &enabled}, want: true},
		{name: "explicitly disabled", cfg: ACMERateLimitConfig{Enabled: &disabled}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEnabled(); got != tt.want {
				t.Fatalf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestACMERateLimitConfig_ResolveDefaults verifies that a zero-valued
// MaxRequests/Interval resolve to the documented defaults, and that an
// operator-supplied value overrides them.
func TestACMERateLimitConfig_ResolveDefaults(t *testing.T) {
	zero := ACMERateLimitConfig{}
	if got := zero.ResolveMaxRequests(); got != DefaultACMERateLimitMaxRequests {
		t.Fatalf("ResolveMaxRequests() = %d, want default %d", got, DefaultACMERateLimitMaxRequests)
	}
	if got := zero.ResolveInterval(); got != DefaultACMERateLimitInterval {
		t.Fatalf("ResolveInterval() = %v, want default %v", got, DefaultACMERateLimitInterval)
	}

	custom := ACMERateLimitConfig{MaxRequests: 5, Interval: 30 * time.Second}
	if got := custom.ResolveMaxRequests(); got != 5 {
		t.Fatalf("ResolveMaxRequests() = %d, want 5", got)
	}
	if got := custom.ResolveInterval(); got != 30*time.Second {
		t.Fatalf("ResolveInterval() = %v, want 30s", got)
	}
}

// TestACMERateLimitConfig_Validate_NegativeValues verifies that a negative
// max_requests or interval is refused rather than silently coerced into the
// default: a typo that makes admission control disappear must fail loudly.
func TestACMERateLimitConfig_Validate_NegativeValues(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ACMERateLimitConfig
		wantErr error
	}{
		{name: "negative max_requests", cfg: ACMERateLimitConfig{MaxRequests: -1}, wantErr: ErrACMERateLimitNegativeMaxRequests},
		{name: "negative interval", cfg: ACMERateLimitConfig{Interval: -time.Second}, wantErr: ErrACMERateLimitNegativeInterval},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestACMERateLimitConfig_Validate_DisabledSkipsChecks verifies that a
// disabled limiter's stale/negative knobs do not block startup: only
// Config.ComplianceGaps needs to know it is off, not Validate.
func TestACMERateLimitConfig_Validate_DisabledSkipsChecks(t *testing.T) {
	disabled := false
	cfg := ACMERateLimitConfig{Enabled: &disabled, MaxRequests: -1}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() on a disabled limiter = %v, want nil", err)
	}
}

// TestACMEConfig_Validate_RateLimitNegative verifies that ACMEConfig.Validate
// surfaces a negative rate_limit knob, matching every other enabled-ACME
// validation failure.
func TestACMEConfig_Validate_RateLimitNegative(t *testing.T) {
	cfg := enabledACME()
	cfg.RateLimit = ACMERateLimitConfig{MaxRequests: -5}

	if err := cfg.Validate(); !errors.Is(err, ErrACMERateLimitNegativeMaxRequests) {
		t.Fatalf("Validate() = %v, want %v", err, ErrACMERateLimitNegativeMaxRequests)
	}
}

// TestComplianceGaps_ACMERateLimitDisabled verifies that disabling ACME rate
// limiting is reported as a compliance gap (go-xkms#882): there is no silent
// way to run a public ACME endpoint without admission control.
func TestComplianceGaps_ACMERateLimitDisabled(t *testing.T) {
	disabled := false
	acmeCfg := enabledACME()
	acmeCfg.RateLimit = ACMERateLimitConfig{Enabled: &disabled}

	cfg := &Config{ACME: acmeCfg}
	gaps := cfg.ComplianceGaps()

	found := false
	for _, gap := range gaps {
		if gap == "ACME rate limiting disabled (acme.rate_limit.enabled=false): the ACME endpoint "+
			"would accept unlimited new-account, new-order, and challenge requests" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ComplianceGaps() = %v, want an ACME rate limit gap", gaps)
	}
}

// TestComplianceGaps_ACMERateLimitEnabled verifies that the default
// (enabled) posture reports no rate-limit gap.
func TestComplianceGaps_ACMERateLimitEnabled(t *testing.T) {
	cfg := &Config{ACME: enabledACME()}
	gaps := cfg.ComplianceGaps()

	for _, gap := range gaps {
		if gap != "" && gap == "ACME rate limiting disabled (acme.rate_limit.enabled=false): the ACME endpoint "+
			"would accept unlimited new-account, new-order, and challenge requests" {
			t.Fatalf("ComplianceGaps() reported a rate-limit gap with the default (enabled) config: %v", gaps)
		}
	}
}
