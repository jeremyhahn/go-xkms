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

package policy

import (
	"errors"
	"slices"
	"testing"
)

func TestNewChallengePolicy(t *testing.T) {
	cp := NewChallengePolicy()
	if cp == nil {
		t.Fatal("NewChallengePolicy() returned nil")
	}

	// Verify default challenges are enabled
	defaultChallenges := []string{
		ChallengeTypeHTTP01,
		ChallengeTypeDNS01,
		ChallengeTypeTLSALPN01,
		ChallengeTypeDeviceAttest01,
		ChallengeTypeEnroll01,
		ChallengeTypeEndorse01,
	}

	for _, c := range defaultChallenges {
		if !cp.IsChallengeTypeEnabled(c) {
			t.Errorf("Challenge type %q should be enabled by default", c)
		}
	}

	// Verify dns-account-01 is disabled by default
	if cp.IsChallengeTypeEnabled(ChallengeTypeDNSAccount01) {
		t.Error("dns-account-01 should be disabled by default")
	}

	// Verify default identifiers are enabled
	defaultIdentifiers := []string{
		IdentifierTypeDNS,
		IdentifierTypeIP,
		IdentifierTypePermanentIdentifier,
	}

	for _, i := range defaultIdentifiers {
		if !cp.IsIdentifierTypeEnabled(i) {
			t.Errorf("Identifier type %q should be enabled by default", i)
		}
	}
}

func TestNewChallengePolicyFromConfig(t *testing.T) {
	config := &PolicyConfig{
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeHTTP01:       true,
			ChallengeTypeDNS01:        true,
			ChallengeTypeDNSAccount01: true, // Enable dns-account-01
		},
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeDNS: true,
		},
	}

	cp := NewChallengePolicyFromConfig(config)
	if cp == nil {
		t.Fatal("NewChallengePolicyFromConfig() returned nil")
	}

	// Verify configured challenges
	if !cp.IsChallengeTypeEnabled(ChallengeTypeHTTP01) {
		t.Error("http-01 should be enabled")
	}
	if !cp.IsChallengeTypeEnabled(ChallengeTypeDNS01) {
		t.Error("dns-01 should be enabled")
	}
	if !cp.IsChallengeTypeEnabled(ChallengeTypeDNSAccount01) {
		t.Error("dns-account-01 should be enabled")
	}
	if cp.IsChallengeTypeEnabled(ChallengeTypeTLSALPN01) {
		t.Error("tls-alpn-01 should be disabled")
	}

	// Verify configured identifiers
	if !cp.IsIdentifierTypeEnabled(IdentifierTypeDNS) {
		t.Error("dns should be enabled")
	}
	if cp.IsIdentifierTypeEnabled(IdentifierTypeIP) {
		t.Error("ip should be disabled")
	}
}

func TestNewChallengePolicyFromConfig_Nil(t *testing.T) {
	cp := NewChallengePolicyFromConfig(nil)
	if cp == nil {
		t.Fatal("NewChallengePolicyFromConfig(nil) should return default policy")
	}
	// Should have default settings
	if !cp.IsChallengeTypeEnabled(ChallengeTypeHTTP01) {
		t.Error("http-01 should be enabled with nil config")
	}
}

func TestChallengePolicy_AllowedChallenges_DNS(t *testing.T) {
	cp := NewChallengePolicy()

	// Non-wildcard DNS
	allowed := cp.AllowedChallenges(IdentifierTypeDNS, "example.com")
	expected := []string{
		ChallengeTypeHTTP01,
		ChallengeTypeDNS01,
		ChallengeTypeTLSALPN01,
		ChallengeTypeDeviceAttest01,
	}

	for _, c := range expected {
		if !slices.Contains(allowed, c) {
			t.Errorf("AllowedChallenges(dns, example.com) should include %q", c)
		}
	}

	// dns-account-01 should not be included by default
	if slices.Contains(allowed, ChallengeTypeDNSAccount01) {
		t.Error("dns-account-01 should not be included by default")
	}
}

func TestChallengePolicy_AllowedChallenges_DNSWildcard(t *testing.T) {
	cp := NewChallengePolicy()

	// Wildcard DNS - only DNS-based challenges per CA/Browser Forum BRs
	allowed := cp.AllowedChallenges(IdentifierTypeDNS, "*.example.com")

	if !slices.Contains(allowed, ChallengeTypeDNS01) {
		t.Error("Wildcard DNS should include dns-01")
	}
	if slices.Contains(allowed, ChallengeTypeHTTP01) {
		t.Error("Wildcard DNS should NOT include http-01")
	}
	if slices.Contains(allowed, ChallengeTypeTLSALPN01) {
		t.Error("Wildcard DNS should NOT include tls-alpn-01")
	}
}

func TestChallengePolicy_AllowedChallenges_DNSWildcardWithDNSAccount01(t *testing.T) {
	cp := NewChallengePolicy()
	cp.SetChallengeEnabled(ChallengeTypeDNSAccount01, true)

	allowed := cp.AllowedChallenges(IdentifierTypeDNS, "*.example.com")

	if !slices.Contains(allowed, ChallengeTypeDNS01) {
		t.Error("Wildcard DNS should include dns-01")
	}
	if !slices.Contains(allowed, ChallengeTypeDNSAccount01) {
		t.Error("Wildcard DNS should include dns-account-01 when enabled")
	}
}

func TestChallengePolicy_AllowedChallenges_IP(t *testing.T) {
	cp := NewChallengePolicy()

	// IP identifiers - only HTTP-01 and TLS-ALPN-01 per RFC 8738
	allowed := cp.AllowedChallenges(IdentifierTypeIP, "192.0.2.1")

	expected := []string{
		ChallengeTypeHTTP01,
		ChallengeTypeTLSALPN01,
	}

	for _, c := range expected {
		if !slices.Contains(allowed, c) {
			t.Errorf("AllowedChallenges(ip, ...) should include %q", c)
		}
	}

	// DNS challenges should not be included
	if slices.Contains(allowed, ChallengeTypeDNS01) {
		t.Error("IP identifier should NOT include dns-01")
	}
}

func TestChallengePolicy_AllowedChallenges_PermanentIdentifier(t *testing.T) {
	cp := NewChallengePolicy()

	// Permanent identifiers - device/TPM specific challenges
	allowed := cp.AllowedChallenges(IdentifierTypePermanentIdentifier, "device-123")

	expected := []string{
		ChallengeTypeDeviceAttest01,
		ChallengeTypeEnroll01,
		ChallengeTypeEndorse01,
	}

	for _, c := range expected {
		if !slices.Contains(allowed, c) {
			t.Errorf("AllowedChallenges(permanent-identifier, ...) should include %q", c)
		}
	}

	// Web PKI challenges should not be included
	if slices.Contains(allowed, ChallengeTypeHTTP01) {
		t.Error("Permanent identifier should NOT include http-01")
	}
}

func TestChallengePolicy_AllowedChallenges_UnknownType(t *testing.T) {
	cp := NewChallengePolicy()

	allowed := cp.AllowedChallenges("unknown", "value")
	if allowed != nil {
		t.Error("AllowedChallenges for unknown type should return nil")
	}
}

func TestChallengePolicy_AllowedChallenges_DisabledChallenge(t *testing.T) {
	cp := NewChallengePolicy()
	cp.SetChallengeEnabled(ChallengeTypeHTTP01, false)

	allowed := cp.AllowedChallenges(IdentifierTypeDNS, "example.com")

	if slices.Contains(allowed, ChallengeTypeHTTP01) {
		t.Error("Disabled http-01 should not be in allowed list")
	}
	if !slices.Contains(allowed, ChallengeTypeDNS01) {
		t.Error("Enabled dns-01 should be in allowed list")
	}
}

func TestChallengePolicy_SetChallengeEnabled(t *testing.T) {
	cp := NewChallengePolicy()

	// Disable HTTP-01
	cp.SetChallengeEnabled(ChallengeTypeHTTP01, false)
	if cp.IsChallengeTypeEnabled(ChallengeTypeHTTP01) {
		t.Error("HTTP-01 should be disabled")
	}

	// Re-enable HTTP-01
	cp.SetChallengeEnabled(ChallengeTypeHTTP01, true)
	if !cp.IsChallengeTypeEnabled(ChallengeTypeHTTP01) {
		t.Error("HTTP-01 should be enabled")
	}

	// Enable dns-account-01
	cp.SetChallengeEnabled(ChallengeTypeDNSAccount01, true)
	if !cp.IsChallengeTypeEnabled(ChallengeTypeDNSAccount01) {
		t.Error("dns-account-01 should be enabled")
	}
	if !cp.enableDNSAccount01 {
		t.Error("enableDNSAccount01 flag should be true")
	}
}

func TestChallengePolicy_SetIdentifierEnabled(t *testing.T) {
	cp := NewChallengePolicy()

	// Disable IP
	cp.SetIdentifierEnabled(IdentifierTypeIP, false)
	if cp.IsIdentifierTypeEnabled(IdentifierTypeIP) {
		t.Error("IP should be disabled")
	}

	// Re-enable IP
	cp.SetIdentifierEnabled(IdentifierTypeIP, true)
	if !cp.IsIdentifierTypeEnabled(IdentifierTypeIP) {
		t.Error("IP should be enabled")
	}
}

func TestChallengePolicy_IsChallengeAllowedForIdentifier(t *testing.T) {
	cp := NewChallengePolicy()

	tests := []struct {
		name      string
		challenge string
		idType    string
		value     string
		expected  bool
	}{
		// DNS
		{"http-01 for DNS", ChallengeTypeHTTP01, IdentifierTypeDNS, "example.com", true},
		{"dns-01 for DNS", ChallengeTypeDNS01, IdentifierTypeDNS, "example.com", true},
		{"dns-01 for DNS wildcard", ChallengeTypeDNS01, IdentifierTypeDNS, "*.example.com", true},
		{"http-01 for DNS wildcard", ChallengeTypeHTTP01, IdentifierTypeDNS, "*.example.com", false},

		// IP
		{"http-01 for IP", ChallengeTypeHTTP01, IdentifierTypeIP, "192.0.2.1", true},
		{"dns-01 for IP", ChallengeTypeDNS01, IdentifierTypeIP, "192.0.2.1", false},

		// Permanent identifier
		{"device-attest-01 for permanent", ChallengeTypeDeviceAttest01, IdentifierTypePermanentIdentifier, "dev-1", true},
		{"http-01 for permanent", ChallengeTypeHTTP01, IdentifierTypePermanentIdentifier, "dev-1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cp.IsChallengeAllowedForIdentifier(tt.challenge, tt.idType, tt.value)
			if result != tt.expected {
				t.Errorf("IsChallengeAllowedForIdentifier(%q, %q, %q) = %v, want %v",
					tt.challenge, tt.idType, tt.value, result, tt.expected)
			}
		})
	}
}

func TestChallengePolicy_ValidateChallengeForIdentifier(t *testing.T) {
	cp := NewChallengePolicy()

	// Valid combination
	err := cp.ValidateChallengeForIdentifier(ChallengeTypeHTTP01, IdentifierTypeDNS, "example.com")
	if err != nil {
		t.Errorf("ValidateChallengeForIdentifier() error = %v for valid combination", err)
	}

	// Disabled identifier type
	cp.SetIdentifierEnabled(IdentifierTypeIP, false)
	err = cp.ValidateChallengeForIdentifier(ChallengeTypeHTTP01, IdentifierTypeIP, "192.0.2.1")
	if !errors.Is(err, ErrIdentifierTypeDisabled) {
		t.Errorf("ValidateChallengeForIdentifier() error = %v, want %v", err, ErrIdentifierTypeDisabled)
	}
	cp.SetIdentifierEnabled(IdentifierTypeIP, true)

	// Disabled challenge type
	cp.SetChallengeEnabled(ChallengeTypeDNS01, false)
	err = cp.ValidateChallengeForIdentifier(ChallengeTypeDNS01, IdentifierTypeDNS, "example.com")
	if !errors.Is(err, ErrChallengeTypeDisabled) {
		t.Errorf("ValidateChallengeForIdentifier() error = %v, want %v", err, ErrChallengeTypeDisabled)
	}
	cp.SetChallengeEnabled(ChallengeTypeDNS01, true)

	// Challenge not allowed for identifier
	err = cp.ValidateChallengeForIdentifier(ChallengeTypeDNS01, IdentifierTypeIP, "192.0.2.1")
	if !errors.Is(err, ErrChallengeTypeNotAllowed) {
		t.Errorf("ValidateChallengeForIdentifier() error = %v, want %v", err, ErrChallengeTypeNotAllowed)
	}
}

func TestChallengePolicy_Clone(t *testing.T) {
	original := NewChallengePolicy()
	original.SetChallengeEnabled(ChallengeTypeHTTP01, false)
	original.SetIdentifierEnabled(IdentifierTypeIP, false)
	original.SetChallengeEnabled(ChallengeTypeDNSAccount01, true)

	clone := original.Clone()
	if clone == nil {
		t.Fatal("Clone() returned nil")
	}

	// Verify clone has same settings
	if clone.IsChallengeTypeEnabled(ChallengeTypeHTTP01) {
		t.Error("Clone should have http-01 disabled")
	}
	if clone.IsIdentifierTypeEnabled(IdentifierTypeIP) {
		t.Error("Clone should have IP disabled")
	}
	if !clone.IsChallengeTypeEnabled(ChallengeTypeDNSAccount01) {
		t.Error("Clone should have dns-account-01 enabled")
	}

	// Verify independence
	clone.SetChallengeEnabled(ChallengeTypeHTTP01, true)
	if original.IsChallengeTypeEnabled(ChallengeTypeHTTP01) {
		t.Error("Modifying clone should not affect original")
	}
}

func TestAllChallengeTypes(t *testing.T) {
	types := AllChallengeTypes()

	expected := []string{
		ChallengeTypeHTTP01,
		ChallengeTypeDNS01,
		ChallengeTypeTLSALPN01,
		ChallengeTypeDeviceAttest01,
		ChallengeTypeEnroll01,
		ChallengeTypeEndorse01,
		ChallengeTypeDNSAccount01,
	}

	if len(types) != len(expected) {
		t.Errorf("AllChallengeTypes() length = %d, want %d", len(types), len(expected))
	}

	for _, e := range expected {
		if !slices.Contains(types, e) {
			t.Errorf("AllChallengeTypes() should contain %q", e)
		}
	}
}

func TestAllIdentifierTypes(t *testing.T) {
	types := AllIdentifierTypes()

	expected := []string{
		IdentifierTypeDNS,
		IdentifierTypeIP,
		IdentifierTypePermanentIdentifier,
	}

	if len(types) != len(expected) {
		t.Errorf("AllIdentifierTypes() length = %d, want %d", len(types), len(expected))
	}

	for _, e := range expected {
		if !slices.Contains(types, e) {
			t.Errorf("AllIdentifierTypes() should contain %q", e)
		}
	}
}

func TestStandardWebPKIChallenges(t *testing.T) {
	types := StandardWebPKIChallenges()

	expected := []string{
		ChallengeTypeHTTP01,
		ChallengeTypeDNS01,
		ChallengeTypeTLSALPN01,
	}

	if len(types) != len(expected) {
		t.Errorf("StandardWebPKIChallenges() length = %d, want %d", len(types), len(expected))
	}

	for _, e := range expected {
		if !slices.Contains(types, e) {
			t.Errorf("StandardWebPKIChallenges() should contain %q", e)
		}
	}
}

func TestDeviceAttestationChallenges(t *testing.T) {
	types := DeviceAttestationChallenges()

	expected := []string{
		ChallengeTypeDeviceAttest01,
		ChallengeTypeEnroll01,
		ChallengeTypeEndorse01,
	}

	if len(types) != len(expected) {
		t.Errorf("DeviceAttestationChallenges() length = %d, want %d", len(types), len(expected))
	}

	for _, e := range expected {
		if !slices.Contains(types, e) {
			t.Errorf("DeviceAttestationChallenges() should contain %q", e)
		}
	}
}

func TestChallengePolicy_ConcurrentAccess(t *testing.T) {
	cp := NewChallengePolicy()

	done := make(chan bool)

	// Reader goroutines
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				cp.IsChallengeTypeEnabled(ChallengeTypeHTTP01)
				cp.IsIdentifierTypeEnabled(IdentifierTypeDNS)
				cp.AllowedChallenges(IdentifierTypeDNS, "example.com")
				cp.IsChallengeAllowedForIdentifier(ChallengeTypeHTTP01, IdentifierTypeDNS, "example.com")
			}
			done <- true
		}()
	}

	// Writer goroutines
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				cp.SetChallengeEnabled(ChallengeTypeHTTP01, true)
				cp.SetChallengeEnabled(ChallengeTypeHTTP01, false)
				cp.SetIdentifierEnabled(IdentifierTypeDNS, true)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 15; i++ {
		<-done
	}
}

func TestChallengePolicy_IdentifierChallengeTypesOverride(t *testing.T) {
	config := &PolicyConfig{
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeHTTP01:    true,
			ChallengeTypeDNS01:     true,
			ChallengeTypeTLSALPN01: true,
		},
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeIP: true,
		},
		IdentifierChallengeTypes: map[string][]string{
			IdentifierTypeIP: {ChallengeTypeHTTP01, ChallengeTypeTLSALPN01},
		},
	}

	cp := NewChallengePolicyFromConfig(config)

	allowed := cp.AllowedChallenges(IdentifierTypeIP, "192.0.2.1")
	if !slices.Contains(allowed, ChallengeTypeHTTP01) || !slices.Contains(allowed, ChallengeTypeTLSALPN01) {
		t.Errorf("AllowedChallenges(ip, ...) = %v, want the configured override [http-01 tls-alpn-01]", allowed)
	}
	if slices.Contains(allowed, ChallengeTypeDNS01) {
		t.Error("AllowedChallenges(ip, ...) should not include dns-01: it is not in the override")
	}
}

func TestChallengePolicy_IdentifierChallengeTypesOverride_UnnamedTypeKeepsDefault(t *testing.T) {
	config := &PolicyConfig{
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeHTTP01:         true,
			ChallengeTypeDNS01:          true,
			ChallengeTypeTLSALPN01:      true,
			ChallengeTypeDeviceAttest01: true,
		},
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeDNS: true,
			IdentifierTypeIP:  true,
		},
		IdentifierChallengeTypes: map[string][]string{
			IdentifierTypeIP: {ChallengeTypeHTTP01},
		},
	}

	cp := NewChallengePolicyFromConfig(config)

	// DNS was not named in the override: it keeps the package's built-in
	// default candidates.
	allowed := cp.AllowedChallenges(IdentifierTypeDNS, "example.com")
	for _, want := range []string{ChallengeTypeHTTP01, ChallengeTypeDNS01, ChallengeTypeTLSALPN01, ChallengeTypeDeviceAttest01} {
		if !slices.Contains(allowed, want) {
			t.Errorf("AllowedChallenges(dns, example.com) = %v, want it to include %q (default, not overridden)", allowed, want)
		}
	}
}

func TestChallengePolicy_IdentifierChallengeTypesOverride_WildcardNotOverridable(t *testing.T) {
	config := &PolicyConfig{
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeHTTP01: true,
			ChallengeTypeDNS01:  true,
		},
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeDNS: true,
		},
		IdentifierChallengeTypes: map[string][]string{
			// Even though the non-wildcard override includes http-01, the
			// wildcard restriction to dns-01 (RFC 8555 Section 7.1.4) is
			// never subject to this override.
			IdentifierTypeDNS: {ChallengeTypeHTTP01, ChallengeTypeDNS01},
		},
	}

	cp := NewChallengePolicyFromConfig(config)

	allowed := cp.AllowedChallenges(IdentifierTypeDNS, "*.example.com")
	if len(allowed) != 1 || allowed[0] != ChallengeTypeDNS01 {
		t.Errorf("AllowedChallenges(dns, *.example.com) = %v, want [dns-01]", allowed)
	}
}
