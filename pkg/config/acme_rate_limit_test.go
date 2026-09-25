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
	"strings"
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

// TestACMERateLimitConfig_Tenant_IsEnabled verifies the tri-state that makes
// the per-tenant overall quota secure by default (go-xkms#886): an omitted
// "enabled" key means on, and only an explicit false turns it off.
func TestACMERateLimitConfig_Tenant_IsEnabled(t *testing.T) {
	enabled, disabled := true, false

	tests := []struct {
		name string
		cfg  ACMERateLimitConfig
		want bool
	}{
		{name: "omitted section defaults to enabled", cfg: ACMERateLimitConfig{}, want: true},
		{name: "explicitly enabled", cfg: ACMERateLimitConfig{Tenant: ACMECategoryRateLimitConfig{Enabled: &enabled}}, want: true},
		{name: "explicitly disabled", cfg: ACMERateLimitConfig{Tenant: ACMECategoryRateLimitConfig{Enabled: &disabled}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.TenantIsEnabled(); got != tt.want {
				t.Fatalf("TenantIsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestACMERateLimitConfig_CategoryResolveDefaults verifies that each of the
// four RFC 8555 Section 6.6 categories, plus the per-tenant overall quota,
// resolve to their own documented default when unset and to an
// operator-supplied override when set.
func TestACMERateLimitConfig_CategoryResolveDefaults(t *testing.T) {
	zero := ACMERateLimitConfig{}

	tests := []struct {
		name            string
		resolveMax      func() int
		resolveInterval func() time.Duration
		wantMax         int
		wantInterval    time.Duration
	}{
		{"tenant", zero.TenantResolveMaxRequests, zero.TenantResolveInterval, DefaultACMETenantRateLimitMaxRequests, DefaultACMETenantRateLimitInterval},
		{"new_account", zero.NewAccountResolveMaxRequests, zero.NewAccountResolveInterval, DefaultACMENewAccountRateLimitMaxRequests, DefaultACMENewAccountRateLimitInterval},
		{"new_order", zero.NewOrderResolveMaxRequests, zero.NewOrderResolveInterval, DefaultACMENewOrderRateLimitMaxRequests, DefaultACMENewOrderRateLimitInterval},
		{"certificate", zero.CertificateResolveMaxRequests, zero.CertificateResolveInterval, DefaultACMECertificateRateLimitMaxRequests, DefaultACMECertificateRateLimitInterval},
		{"failed_validation", zero.FailedValidationResolveMaxRequests, zero.FailedValidationResolveInterval, DefaultACMEFailedValidationRateLimitMaxRequests, DefaultACMEFailedValidationRateLimitInterval},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resolveMax(); got != tt.wantMax {
				t.Fatalf("%s ResolveMaxRequests() = %d, want default %d", tt.name, got, tt.wantMax)
			}
			if got := tt.resolveInterval(); got != tt.wantInterval {
				t.Fatalf("%s ResolveInterval() = %v, want default %v", tt.name, got, tt.wantInterval)
			}
		})
	}

	custom := ACMERateLimitConfig{
		NewOrder: ACMECategoryRateLimitConfig{MaxRequests: 7, Interval: 5 * time.Minute},
	}
	if got := custom.NewOrderResolveMaxRequests(); got != 7 {
		t.Fatalf("NewOrderResolveMaxRequests() = %d, want 7", got)
	}
	if got := custom.NewOrderResolveInterval(); got != 5*time.Minute {
		t.Fatalf("NewOrderResolveInterval() = %v, want 5m", got)
	}
}

// TestACMERateLimitConfig_Validate_CategoryNegativeValues verifies that a
// negative max_requests or interval on any per-tenant or per-category
// sub-section is refused, matching the top-level per-client limiter's own
// validation (go-xkms#886).
func TestACMERateLimitConfig_Validate_CategoryNegativeValues(t *testing.T) {
	tests := []struct {
		name string
		cfg  ACMERateLimitConfig
	}{
		{"tenant negative max_requests", ACMERateLimitConfig{Tenant: ACMECategoryRateLimitConfig{MaxRequests: -1}}},
		{"tenant negative interval", ACMERateLimitConfig{Tenant: ACMECategoryRateLimitConfig{Interval: -time.Second}}},
		{"new_account negative max_requests", ACMERateLimitConfig{NewAccount: ACMECategoryRateLimitConfig{MaxRequests: -1}}},
		{"new_order negative max_requests", ACMERateLimitConfig{NewOrder: ACMECategoryRateLimitConfig{MaxRequests: -1}}},
		{"certificate negative max_requests", ACMERateLimitConfig{Certificate: ACMECategoryRateLimitConfig{MaxRequests: -1}}},
		{"failed_validation negative max_requests", ACMERateLimitConfig{FailedValidation: ACMECategoryRateLimitConfig{MaxRequests: -1}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); !errors.Is(err, ErrACMERateLimitNegativeMaxRequests) && !errors.Is(err, ErrACMERateLimitNegativeInterval) {
				t.Fatalf("Validate() = %v, want a rate-limit sentinel error", err)
			}
		})
	}
}

// TestACMERateLimitConfig_Validate_DisabledCategorySkipsChecks verifies that
// a disabled category's stale/negative knobs do not block startup, mirroring
// the top-level limiter's own disabled-skips-checks behavior.
func TestACMERateLimitConfig_Validate_DisabledCategorySkipsChecks(t *testing.T) {
	disabled := false
	cfg := ACMERateLimitConfig{FailedValidation: ACMECategoryRateLimitConfig{Enabled: &disabled, MaxRequests: -1}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() on a disabled category = %v, want nil", err)
	}
}

// TestComplianceGaps_ACMETenantRateLimitDisabled verifies that disabling the
// per-tenant overall quota is reported as a compliance gap (go-xkms#886).
func TestComplianceGaps_ACMETenantRateLimitDisabled(t *testing.T) {
	disabled := false
	acmeCfg := enabledACME()
	acmeCfg.RateLimit.Tenant = ACMECategoryRateLimitConfig{Enabled: &disabled}

	cfg := &Config{ACME: acmeCfg}
	gaps := cfg.ComplianceGaps()

	found := false
	for _, gap := range gaps {
		if gap == "ACME tenant rate limiting disabled (acme.rate_limit.tenant.enabled=false): a "+
			"multi-tenant deployment's accounts would share no per-tenant quota, so one tenant's traffic is "+
			"unbounded by any other tenant's" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ComplianceGaps() = %v, want a tenant rate limit gap", gaps)
	}
}

// TestComplianceGaps_ACMEPerCategoryRateLimitDisabled verifies that
// disabling one or more RFC 8555 Section 6.6 categories is reported as a
// single compliance gap naming every disabled category (go-xkms#886).
func TestComplianceGaps_ACMEPerCategoryRateLimitDisabled(t *testing.T) {
	disabled := false
	acmeCfg := enabledACME()
	acmeCfg.RateLimit.NewOrder = ACMECategoryRateLimitConfig{Enabled: &disabled}
	acmeCfg.RateLimit.FailedValidation = ACMECategoryRateLimitConfig{Enabled: &disabled}

	cfg := &Config{ACME: acmeCfg}
	gaps := cfg.ComplianceGaps()

	found := false
	for _, gap := range gaps {
		if gap == "ACME per-category rate limiting disabled (new_order, failed_validation): the RFC 8555 "+
			"Section 6.6 quota for the listed categories would not be enforced" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ComplianceGaps() = %v, want a per-category rate limit gap naming new_order and failed_validation", gaps)
	}
}

// TestComplianceGaps_ACMETenantAndCategoryRateLimitEnabled verifies that the
// default (fully enabled) posture reports no tenant or per-category gap.
func TestComplianceGaps_ACMETenantAndCategoryRateLimitEnabled(t *testing.T) {
	cfg := &Config{ACME: enabledACME()}
	gaps := cfg.ComplianceGaps()

	for _, gap := range gaps {
		if strings.Contains(gap, "tenant rate limiting disabled") || strings.Contains(gap, "per-category rate limiting disabled") {
			t.Fatalf("ComplianceGaps() reported a tenant/category rate-limit gap with the default (enabled) config: %v", gaps)
		}
	}
}
