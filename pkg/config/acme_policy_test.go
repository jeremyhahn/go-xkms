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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/policy"
)

// TestACMEPolicyConfig_SecureDefaults verifies that omitting
// require_public_suffix, reject_reserved_ips, allow_wildcards, and
// blocklist.use_defaults leaves every enforcement on: a policy section is
// secure by default, and an operator has to take an explicit action to
// relax it.
func TestACMEPolicyConfig_SecureDefaults(t *testing.T) {
	var cfg ACMEPolicyConfig

	if !cfg.RequiresPublicSuffix() {
		t.Error("RequiresPublicSuffix() should default to true when omitted")
	}
	if !cfg.RejectsReservedIPs() {
		t.Error("RejectsReservedIPs() should default to true when omitted")
	}
	if !cfg.AllowsWildcards() {
		t.Error("AllowsWildcards() should default to true when omitted")
	}
	if !cfg.Blocklist.UsesDefaults() {
		t.Error("Blocklist.UsesDefaults() should default to true when omitted")
	}
}

// TestACMEPolicyConfig_ExplicitFalse verifies that an explicit false is
// distinguishable from an omitted key and is honored.
func TestACMEPolicyConfig_ExplicitFalse(t *testing.T) {
	no := false
	cfg := ACMEPolicyConfig{
		RequirePublicSuffix: &no,
		RejectReservedIPs:   &no,
		AllowWildcards:      &no,
		Blocklist:           ACMEBlocklistConfig{UseDefaults: &no},
	}

	if cfg.RequiresPublicSuffix() {
		t.Error("RequiresPublicSuffix() should be false when explicitly disabled")
	}
	if cfg.RejectsReservedIPs() {
		t.Error("RejectsReservedIPs() should be false when explicitly disabled")
	}
	if cfg.AllowsWildcards() {
		t.Error("AllowsWildcards() should be false when explicitly disabled")
	}
	if cfg.Blocklist.UsesDefaults() {
		t.Error("Blocklist.UsesDefaults() should be false when explicitly disabled")
	}
}

func TestACMEPolicyConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ACMEPolicyConfig
		wantErr error
	}{
		{
			name: "valid empty config",
			cfg:  ACMEPolicyConfig{},
		},
		{
			name: "valid CIDR and identifier challenge types",
			cfg: ACMEPolicyConfig{
				Blocklist: ACMEBlocklistConfig{CIDRs: []string{"10.0.0.0/8", "fc00::/7"}},
				IdentifierChallengeTypes: map[string][]string{
					policy.IdentifierTypeIP: {policy.ChallengeTypeHTTP01, policy.ChallengeTypeTLSALPN01},
				},
			},
		},
		{
			name: "invalid CIDR",
			cfg: ACMEPolicyConfig{
				Blocklist: ACMEBlocklistConfig{CIDRs: []string{"not-a-cidr"}},
			},
			wantErr: ErrACMEPolicyInvalidCIDR,
		},
		{
			name: "unknown identifier type",
			cfg: ACMEPolicyConfig{
				IdentifierChallengeTypes: map[string][]string{
					"bogus-type": {policy.ChallengeTypeHTTP01},
				},
			},
			wantErr: ErrACMEPolicyUnknownIdentifierType,
		},
		{
			name: "unknown challenge type",
			cfg: ACMEPolicyConfig{
				IdentifierChallengeTypes: map[string][]string{
					policy.IdentifierTypeDNS: {"bogus-challenge"},
				},
			},
			wantErr: ErrACMEPolicyUnknownChallengeType,
		},
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
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want error wrapping %v", err, tt.wantErr)
			}
		})
	}
}

// TestACMEPolicyConfig_PolicyConfig_Defaults verifies that the translated
// policy.PolicyConfig carries go-xkms's secure-by-default settings and seeds
// the blocklist from policy.DefaultBlocklistConfig() when use_defaults is
// not explicitly turned off, merging in the operator's own entries.
func TestACMEPolicyConfig_PolicyConfig_Defaults(t *testing.T) {
	cfg := ACMEPolicyConfig{
		Blocklist: ACMEBlocklistConfig{
			HighRiskDomains: []string{"blocked.example.com"},
			CIDRs:           []string{"203.0.113.0/24"},
		},
	}

	p := cfg.PolicyConfig()
	if !p.RequirePublicSuffix {
		t.Error("PolicyConfig().RequirePublicSuffix should default to true")
	}
	if !p.RejectReservedIPs {
		t.Error("PolicyConfig().RejectReservedIPs should default to true")
	}
	if !p.AllowWildcards {
		t.Error("PolicyConfig().AllowWildcards should default to true")
	}

	defaults := policy.DefaultBlocklistConfig()
	if len(p.Blocklist.HighRiskBlockedNames) != len(defaults.HighRiskBlockedNames)+1 {
		t.Errorf("Blocklist.HighRiskBlockedNames = %v, want the package defaults plus the operator's entry",
			p.Blocklist.HighRiskBlockedNames)
	}
	found := false
	for _, name := range p.Blocklist.HighRiskBlockedNames {
		if name == "blocked.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("Blocklist.HighRiskBlockedNames should include the operator's entry")
	}
	if len(p.Blocklist.AdminBlockedPrefixes) != len(defaults.AdminBlockedPrefixes)+1 {
		t.Errorf("Blocklist.AdminBlockedPrefixes = %v, want the package defaults plus the operator's entry",
			p.Blocklist.AdminBlockedPrefixes)
	}
}

// TestACMEPolicyConfig_PolicyConfig_NoDefaults verifies that turning off
// blocklist.use_defaults yields a blocklist containing only the operator's
// own entries, not go-xkms's built-in RFC 2606/1918/5737 defaults.
func TestACMEPolicyConfig_PolicyConfig_NoDefaults(t *testing.T) {
	no := false
	cfg := ACMEPolicyConfig{
		Blocklist: ACMEBlocklistConfig{
			UseDefaults:     &no,
			HighRiskDomains: []string{"only-this.example.com"},
		},
	}

	p := cfg.PolicyConfig()
	if len(p.Blocklist.HighRiskBlockedNames) != 1 || p.Blocklist.HighRiskBlockedNames[0] != "only-this.example.com" {
		t.Errorf("Blocklist.HighRiskBlockedNames = %v, want exactly [only-this.example.com]", p.Blocklist.HighRiskBlockedNames)
	}
	if len(p.Blocklist.AdminBlockedPrefixes) != 0 {
		t.Errorf("Blocklist.AdminBlockedPrefixes = %v, want empty", p.Blocklist.AdminBlockedPrefixes)
	}
}

// TestACMEConfig_Validate_PolicySection verifies that ACMEConfig.Validate
// surfaces a policy section error rather than silently ignoring it.
func TestACMEConfig_Validate_PolicySection(t *testing.T) {
	cfg := enabledACME()
	cfg.Policy = ACMEPolicyConfig{
		Blocklist: ACMEBlocklistConfig{CIDRs: []string{"not-a-cidr"}},
	}

	err := cfg.Validate()
	if !errors.Is(err, ErrACMEPolicyInvalidCIDR) {
		t.Fatalf("Validate() = %v, want error wrapping %v", err, ErrACMEPolicyInvalidCIDR)
	}
}
