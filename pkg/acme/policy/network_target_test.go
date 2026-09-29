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
	"net/netip"
	"strings"
	"testing"
)

func TestIsReservedIP(t *testing.T) {
	for _, tc := range []struct {
		ip       string
		reserved bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.0.1", true},
		{"169.254.169.254", true}, // link-local cloud metadata
		{"fd00:ec2::254", true},   // AWS IPv6 metadata (ULA)
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"100.100.100.200", true}, // CGNAT shared space, Alibaba metadata
		{"192.0.0.192", true},     // IETF protocol assignments
		{"198.18.0.1", true},
		{"192.0.2.1", true},
		{"2001:db8::1", true},
		{"::ffff:127.0.0.1", true}, // IPv4-mapped loopback
		{"::ffff:10.0.0.1", true},  // IPv4-mapped private
		{"64:ff9b::a00:1", true},   // NAT64 of 10.0.0.1
		{"2002:a00:1::1", true},    // 6to4 of 10.0.0.1
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
		{"::ffff:8.8.8.8", false},
	} {
		if got := IsReservedIP(netip.MustParseAddr(tc.ip)); got != tc.reserved {
			t.Errorf("IsReservedIP(%s) = %v, want %v", tc.ip, got, tc.reserved)
		}
	}
}

func TestValidateNetworkTarget_Accepts(t *testing.T) {
	for _, host := range []string{
		"example.com",
		"Device-01.Example.COM",
		"localhost",
		"node-1",
		"192.0.2.10",
		"2001:db8::1",
		"xn--bcher-kva.example",
	} {
		if err := ValidateNetworkTarget(host); err != nil {
			t.Errorf("ValidateNetworkTarget(%q) = %v, want nil", host, err)
		}
	}
}

// TestValidateNetworkTarget_RejectsInjection covers every shape that would
// let an identifier choose more of the URL than its host: path, query,
// fragment, userinfo, port, whitespace, and IP forms that are not canonical.
func TestValidateNetworkTarget_RejectsInjection(t *testing.T) {
	for _, host := range []string{
		"169.254.169.254/latest/meta-data/",
		"example.com/path",
		"example.com?x=1",
		"example.com#frag",
		"user:pass@example.com",
		"user@example.com",
		"example.com:22",
		"example.com ",
		" example.com",
		"exa mple.com",
		"example.com\n",
		"example.com\t",
		"fe80::1%eth0",
		"[::1]",
		"::FFFF:1.2.3.4",
		"-leading.example.com",
		"trailing-.example.com",
		"under_score.example.com",
		"example..com",
		"example.com.",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 127) + "com",
	} {
		if err := ValidateNetworkTarget(host); !errors.Is(err, ErrInvalidNetworkTarget) {
			t.Errorf("ValidateNetworkTarget(%q) = %v, want ErrInvalidNetworkTarget", host, err)
		}
	}
	if err := ValidateNetworkTarget(""); !errors.Is(err, ErrEmptyIdentifier) {
		t.Errorf("ValidateNetworkTarget(\"\") = %v, want ErrEmptyIdentifier", err)
	}
}

func TestValidatePermanentIdentifier_Accepts(t *testing.T) {
	for _, value := range []string{
		"device-serial-123456",
		"192.0.2.10",
		"attest-device-001.test.local",
		// endorse-01: a base64url-encoded PKIX public key.
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE_x-Y",
		strings.Repeat("A", MaxPermanentIdentifierLength),
	} {
		if err := ValidatePermanentIdentifier(value); err != nil {
			t.Errorf("ValidatePermanentIdentifier(%q) = %v, want nil", value, err)
		}
	}
}

func TestValidatePermanentIdentifier_Rejects(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  error
	}{
		{"", ErrEmptyIdentifier},
		{strings.Repeat("A", MaxPermanentIdentifierLength+1), ErrPermanentIdentifierTooLong},
		{"device 1", ErrPermanentIdentifierInvalidCharacter},
		{"device\t1", ErrPermanentIdentifierInvalidCharacter},
		{"device\r\nHost: evil", ErrPermanentIdentifierInvalidCharacter},
		{"device\x00", ErrPermanentIdentifierInvalidCharacter},
		{"device ", ErrPermanentIdentifierInvalidCharacter},
		{"\xff\xfe", ErrPermanentIdentifierInvalidCharacter},
	} {
		if err := ValidatePermanentIdentifier(tc.value); !errors.Is(err, tc.want) {
			t.Errorf("ValidatePermanentIdentifier(%q) = %v, want %v", tc.value, err, tc.want)
		}
	}
}

// TestValidateIdentifier_PermanentIdentifierUsesSyntaxCheck proves the
// identifier-type dispatch applies ValidatePermanentIdentifier rather than
// the former non-empty-only check.
func TestValidateIdentifier_PermanentIdentifierUsesSyntaxCheck(t *testing.T) {
	if err := ValidateIdentifier(IdentifierTypePermanentIdentifier, "dev ice"); !errors.Is(err, ErrPermanentIdentifierInvalidCharacter) {
		t.Fatalf("ValidateIdentifier(permanent-identifier, %q) = %v, want ErrPermanentIdentifierInvalidCharacter", "dev ice", err)
	}
}
