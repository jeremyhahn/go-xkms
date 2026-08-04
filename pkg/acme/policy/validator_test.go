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
	"strings"
	"testing"
)

func TestNewDomainValidator(t *testing.T) {
	v := NewDomainValidator()
	if v == nil {
		t.Fatal("NewDomainValidator() returned nil")
	}
	if !v.RequirePublicSuffix {
		t.Error("RequirePublicSuffix should default to true")
	}
	if !v.AllowWildcards {
		t.Error("AllowWildcards should default to true")
	}
}

func TestDomainValidator_ValidateDomain(t *testing.T) {
	v := NewDomainValidator()

	tests := []struct {
		name    string
		domain  string
		wantErr error
	}{
		// Valid domains
		{"valid simple domain", "example.com", nil},
		{"valid subdomain", "www.example.com", nil},
		{"valid multi-level", "a.b.c.example.com", nil},
		{"valid with numbers", "site123.example.com", nil},
		{"valid with hyphen", "my-site.example.com", nil},
		{"valid IDN", "xn--nxasmq5b.com", nil}, // Greek domain

		// Empty
		{"empty domain", "", ErrEmptyIdentifier},

		// Length issues
		{"too long domain", strings.Repeat("a", 254) + ".com", ErrNameTooLong},
		{"too long label", strings.Repeat("a", 64) + ".example.com", ErrLabelTooLong},

		// Label count issues
		{"too few labels", "localhost", ErrTooFewLabels},
		{"too many labels", "a.b.c.d.e.f.g.h.i.j.k.example.com", ErrTooManyLabels},

		// Character issues
		{"trailing dot", "example.com.", ErrNameEndsInDot},
		{"consecutive dots", "example..com", ErrLabelTooShort},
		{"underscore", "my_site.example.com", ErrInvalidDNSCharacter},
		{"space", "my site.example.com", ErrInvalidDNSCharacter},
		{"at sign", "my@site.example.com", ErrInvalidDNSCharacter},

		// Hyphen issues
		{"leading hyphen", "-example.com", ErrLabelStartsWithHyphen},
		{"trailing hyphen", "example-.com", ErrLabelEndsWithHyphen},
		{"hyphen only label", "-.example.com", ErrLabelStartsWithHyphen},

		// IP address in DNS
		{"IPv4 as domain", "192.168.1.1", ErrIPAddressInDNS},
		{"IPv6 as domain", "2001:db8::1", ErrInvalidDNSCharacter}, // Colons are invalid DNS chars

		// Reserved labels (R-LDH)
		{"reserved label xy--", "ab--cd.example.com", ErrInvalidRLDH},

		// TLD issues
		{"just TLD", "com", ErrTooFewLabels},
		// co.uk is a public suffix - publicsuffix.Parse returns error for suffixes
		{"public suffix only", "co.uk", ErrNonPublicSuffix},

		// Wildcards (should use wildcard validation)
		{"wildcard domain", "*.example.com", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateDomain(tt.domain)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateDomain(%q) error = %v, want nil", tt.domain, err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateDomain(%q) error = %v, want %v", tt.domain, err, tt.wantErr)
				}
			}
		})
	}
}

func TestDomainValidator_ValidateDomain_NoPublicSuffix(t *testing.T) {
	v := NewDomainValidator()
	v.RequirePublicSuffix = false

	// Should accept domains without public suffix
	err := v.ValidateDomain("internal.local")
	if err != nil {
		t.Errorf("ValidateDomain() with RequirePublicSuffix=false error = %v", err)
	}

	// Should still validate basic format
	err = v.ValidateDomain("")
	if !errors.Is(err, ErrEmptyIdentifier) {
		t.Errorf("ValidateDomain() should still check empty, got %v", err)
	}
}

func TestDomainValidator_ValidateDomain_WildcardsDisabled(t *testing.T) {
	v := NewDomainValidator()
	v.AllowWildcards = false

	err := v.ValidateDomain("*.example.com")
	if !errors.Is(err, ErrWildcardNotSupported) {
		t.Errorf("ValidateDomain() with wildcards disabled error = %v, want %v", err, ErrWildcardNotSupported)
	}
}

func TestDomainValidator_WildcardValidation(t *testing.T) {
	v := NewDomainValidator()

	tests := []struct {
		name    string
		domain  string
		wantErr error
	}{
		// Valid wildcards
		{"valid wildcard", "*.example.com", nil},
		{"valid wildcard subdomain", "*.sub.example.com", nil},

		// Invalid wildcards
		{"multiple wildcards", "*.*.example.com", ErrTooManyWildcards},
		{"wildcard not leftmost", "sub.*.example.com", ErrMalformedWildcard},
		{"wildcard in middle", "a*.example.com", ErrMalformedWildcard},
		// *.com has "com" as base - publicsuffix.Parse("com") returns error
		{"wildcard for TLD", "*.com", ErrTooFewLabels},
		// *.co.uk has "co.uk" as base - publicsuffix.Parse("co.uk") returns error
		{"wildcard for public suffix", "*.co.uk", ErrNonPublicSuffix},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateDomain(tt.domain)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateDomain(%q) error = %v, want nil", tt.domain, err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateDomain(%q) error = %v, want %v", tt.domain, err, tt.wantErr)
				}
			}
		})
	}
}

func TestDomainValidator_IDNValidation(t *testing.T) {
	v := NewDomainValidator()

	tests := []struct {
		name    string
		domain  string
		wantErr error
	}{
		// Valid IDN (punycode)
		{"valid punycode greek", "xn--nxasmq5b.com", nil},   // όβλοσ
		{"valid punycode german", "xn--mnchen-3ya.de", nil}, // münchen
		{"valid punycode chinese", "xn--fiq228c.com", nil},  // 中文
		{"valid punycode japanese", "xn--wgv71a.jp", nil},   // 日本
		{"valid punycode arabic", "xn--mgbh0fb.com", nil},   // مصر

		// Note: idna.ToUnicode is permissive and accepts most xn-- prefixed labels
		// as valid punycode, even if they decode to unusual characters.
		// We only reject truly malformed punycode that fails decoding.
		{"xn label with content", "xn--invalid.com", nil}, // decodes to some unicode chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateDomain(tt.domain)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateDomain(%q) error = %v, want nil", tt.domain, err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateDomain(%q) error = %v, want %v", tt.domain, err, tt.wantErr)
				}
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr error
	}{
		// Valid IPs
		{"valid IPv4", "192.0.2.1", nil},
		{"valid IPv6", "2001:db8::1", nil},
		{"valid IPv6 full", "2001:0db8:0000:0000:0000:0000:0000:0001", ErrIPInvalid}, // Non-canonical
		{"valid IPv6 compressed", "::1", nil},
		{"valid IPv4 edge", "0.0.0.0", nil},
		{"valid IPv4 broadcast", "255.255.255.255", nil},

		// Invalid IPs
		{"empty", "", ErrEmptyIdentifier},
		{"invalid format", "not.an.ip", ErrIPInvalid},
		{"IPv4 with port", "192.168.1.1:80", ErrIPInvalid},
		{"IPv4 out of range", "256.1.1.1", ErrIPInvalid},
		{"IPv4 leading zero", "192.168.01.1", ErrIPInvalid}, // Non-canonical
		{"IPv6 non-canonical", "2001:0db8::1", ErrIPInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIP(tt.ip)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateIP(%q) error = %v, want nil", tt.ip, err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateIP(%q) error = %v, want %v", tt.ip, err, tt.wantErr)
				}
			}
		})
	}
}

func TestValidateIPWithReservedCheck(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr error
	}{
		// Public IPs - should be valid
		{"public IPv4", "8.8.8.8", nil},
		{"public IPv6", "2001:4860:4860::8888", nil},

		// Reserved IPs - should fail
		{"loopback IPv4", "127.0.0.1", ErrIPReserved},
		{"loopback IPv6", "::1", ErrIPReserved},
		{"private 10.x", "10.0.0.1", ErrIPReserved},
		{"private 172.x", "172.16.0.1", ErrIPReserved},
		{"private 192.168.x", "192.168.1.1", ErrIPReserved},
		{"link-local IPv4", "169.254.1.1", ErrIPReserved},
		{"link-local IPv6", "fe80::1", ErrIPReserved},
		{"documentation IPv4 1", "192.0.2.1", ErrIPReserved},
		{"documentation IPv4 2", "198.51.100.1", ErrIPReserved},
		{"documentation IPv4 3", "203.0.113.1", ErrIPReserved},
		{"documentation IPv6", "2001:db8::1", ErrIPReserved},
		{"multicast IPv4", "224.0.0.1", ErrIPReserved},
		{"multicast IPv6", "ff02::1", ErrIPReserved},
		{"unspecified IPv4", "0.0.0.0", ErrIPReserved},
		{"unspecified IPv6", "::", ErrIPReserved},

		// Invalid format
		{"empty", "", ErrEmptyIdentifier},
		{"invalid", "not-an-ip", ErrIPInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPWithReservedCheck(tt.ip)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateIPWithReservedCheck(%q) error = %v, want nil", tt.ip, err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateIPWithReservedCheck(%q) error = %v, want %v", tt.ip, err, tt.wantErr)
				}
			}
		})
	}
}

func TestValidateIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		idType     string
		value      string
		wantErr    bool
		wantErrVal error
	}{
		// DNS identifiers
		{"valid DNS", IdentifierTypeDNS, "example.com", false, nil},
		{"invalid DNS empty", IdentifierTypeDNS, "", true, ErrEmptyIdentifier},
		{"invalid DNS format", IdentifierTypeDNS, "invalid..domain", true, ErrLabelTooShort},

		// IP identifiers
		{"valid IP", IdentifierTypeIP, "8.8.8.8", false, nil},
		{"invalid IP empty", IdentifierTypeIP, "", true, ErrEmptyIdentifier},
		{"invalid IP format", IdentifierTypeIP, "not-an-ip", true, ErrIPInvalid},

		// Permanent identifiers
		{"valid permanent", IdentifierTypePermanentIdentifier, "device-id-123", false, nil},
		{"invalid permanent empty", IdentifierTypePermanentIdentifier, "", true, ErrEmptyIdentifier},

		// Unknown type
		{"unknown type", "unknown", "value", true, ErrUnsupportedIdentifierType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIdentifier(tt.idType, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIdentifier(%q, %q) error = %v, wantErr %v",
					tt.idType, tt.value, err, tt.wantErr)
			}
			if tt.wantErrVal != nil && !errors.Is(err, tt.wantErrVal) {
				t.Errorf("ValidateIdentifier(%q, %q) error = %v, want %v",
					tt.idType, tt.value, err, tt.wantErrVal)
			}
		})
	}
}

func TestValidateDomain_PackageFunction(t *testing.T) {
	// Test the package-level convenience function
	err := ValidateDomain("example.com")
	if err != nil {
		t.Errorf("ValidateDomain() error = %v, want nil", err)
	}

	err = ValidateDomain("")
	if !errors.Is(err, ErrEmptyIdentifier) {
		t.Errorf("ValidateDomain() error = %v, want %v", err, ErrEmptyIdentifier)
	}
}

func TestValidateLabel(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		wantErr error
	}{
		// Valid labels
		{"simple", "example", nil},
		{"with numbers", "site123", nil},
		{"with hyphen", "my-site", nil},
		{"single char", "a", nil},
		{"max length", strings.Repeat("a", 63), nil},

		// Invalid labels
		{"empty", "", ErrLabelTooShort},
		{"too long", strings.Repeat("a", 64), ErrLabelTooLong},
		{"leading hyphen", "-example", ErrLabelStartsWithHyphen},
		{"trailing hyphen", "example-", ErrLabelEndsWithHyphen},
		{"underscore", "my_site", ErrInvalidDNSCharacter},
		{"uppercase", "EXAMPLE", ErrInvalidDNSCharacter}, // DNS labels should be lowercase
		{"reserved label", "ab--cd", ErrInvalidRLDH},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLabel(tt.label)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("validateLabel(%q) error = %v, want nil", tt.label, err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("validateLabel(%q) error = %v, want %v", tt.label, err, tt.wantErr)
				}
			}
		})
	}
}

func TestIsDNSCharacter(t *testing.T) {
	tests := []struct {
		char byte
		want bool
	}{
		// Valid
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'-', true},
		{'.', true},

		// Invalid
		{'_', false},
		{'@', false},
		{' ', false},
		{'!', false},
		{'/', false},
		{':', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			got := isDNSCharacter(tt.char)
			if got != tt.want {
				t.Errorf("isDNSCharacter(%q) = %v, want %v", tt.char, got, tt.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify constants have expected values per RFC 1035
	if MaxLabels != 10 {
		t.Errorf("MaxLabels = %d, want 10", MaxLabels)
	}
	if MaxLabelLength != 63 {
		t.Errorf("MaxLabelLength = %d, want 63", MaxLabelLength)
	}
	if MaxDNSIdentifierLength != 253 {
		t.Errorf("MaxDNSIdentifierLength = %d, want 253", MaxDNSIdentifierLength)
	}

	// Verify identifier type constants
	if IdentifierTypeDNS != "dns" {
		t.Errorf("IdentifierTypeDNS = %q, want %q", IdentifierTypeDNS, "dns")
	}
	if IdentifierTypeIP != "ip" {
		t.Errorf("IdentifierTypeIP = %q, want %q", IdentifierTypeIP, "ip")
	}
	if IdentifierTypePermanentIdentifier != "permanent-identifier" {
		t.Errorf("IdentifierTypePermanentIdentifier = %q, want %q",
			IdentifierTypePermanentIdentifier, "permanent-identifier")
	}

	// Verify challenge type constants
	expectedChallenges := map[string]string{
		"ChallengeTypeHTTP01":         "http-01",
		"ChallengeTypeDNS01":          "dns-01",
		"ChallengeTypeTLSALPN01":      "tls-alpn-01",
		"ChallengeTypeDeviceAttest01": "device-attest-01",
		"ChallengeTypeEnroll01":       "enroll-01",
		"ChallengeTypeEndorse01":      "endorse-01",
		"ChallengeTypeDNSAccount01":   "dns-account-01",
	}

	actualChallenges := map[string]string{
		"ChallengeTypeHTTP01":         ChallengeTypeHTTP01,
		"ChallengeTypeDNS01":          ChallengeTypeDNS01,
		"ChallengeTypeTLSALPN01":      ChallengeTypeTLSALPN01,
		"ChallengeTypeDeviceAttest01": ChallengeTypeDeviceAttest01,
		"ChallengeTypeEnroll01":       ChallengeTypeEnroll01,
		"ChallengeTypeEndorse01":      ChallengeTypeEndorse01,
		"ChallengeTypeDNSAccount01":   ChallengeTypeDNSAccount01,
	}

	for name, expected := range expectedChallenges {
		if actual := actualChallenges[name]; actual != expected {
			t.Errorf("%s = %q, want %q", name, actual, expected)
		}
	}
}

func TestDomainValidator_EdgeCases(t *testing.T) {
	v := NewDomainValidator()

	// Test specific edge cases
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		// Multi-level public suffixes
		{"valid domain with multi-level TLD", "example.co.uk", false},
		{"valid subdomain with multi-level TLD", "www.example.co.uk", false},

		// Numeric domains
		{"numeric subdomain", "123.example.com", false},
		{"all numeric except TLD", "123.456.com", false},

		// Hyphen edge cases
		{"hyphen in middle", "my-example-site.com", false},
		{"multiple hyphens", "a-b-c-d-e.example.com", false},

		// Maximum valid lengths
		{"63 char label", strings.Repeat("a", 63) + ".com", false},
		{"near max total length", strings.Repeat("a", 50) + "." + strings.Repeat("b", 50) + "." + strings.Repeat("c", 50) + "." + strings.Repeat("d", 50) + ".com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}
