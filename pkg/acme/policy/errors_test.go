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
	"testing"
)

func TestPolicyError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *PolicyError
		expected string
	}{
		{
			name: "full error with all fields",
			err: &PolicyError{
				Err:            ErrPolicyForbidden,
				IdentifierType: "dns",
				Identifier:     "example.com",
				Detail:         "blocked by admin",
			},
			expected: "policy [dns] example.com: policy: the ACME server refuses to issue a certificate for this identifier (blocked by admin)",
		},
		{
			name: "error without detail",
			err: &PolicyError{
				Err:            ErrPolicyForbidden,
				IdentifierType: "dns",
				Identifier:     "example.com",
			},
			expected: "policy [dns] example.com: policy: the ACME server refuses to issue a certificate for this identifier",
		},
		{
			name: "error without identifier",
			err: &PolicyError{
				Err:            ErrPolicyForbidden,
				IdentifierType: "dns",
			},
			expected: "policy [dns]: policy: the ACME server refuses to issue a certificate for this identifier",
		},
		{
			name: "error without type",
			err: &PolicyError{
				Err:        ErrPolicyForbidden,
				Identifier: "example.com",
			},
			expected: "policy example.com: policy: the ACME server refuses to issue a certificate for this identifier",
		},
		{
			name: "minimal error",
			err: &PolicyError{
				Err: ErrPolicyForbidden,
			},
			expected: "policy: policy: the ACME server refuses to issue a certificate for this identifier",
		},
		{
			name: "error with only detail",
			err: &PolicyError{
				Detail: "custom detail",
			},
			expected: "policy (custom detail)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("PolicyError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestPolicyError_Unwrap(t *testing.T) {
	inner := ErrPolicyForbidden
	pe := &PolicyError{
		Err:        inner,
		Identifier: "example.com",
	}

	unwrapped := pe.Unwrap()
	if unwrapped != inner {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, inner)
	}

	// Test errors.Is with wrapped error
	if !errors.Is(pe, ErrPolicyForbidden) {
		t.Error("errors.Is() should return true for wrapped ErrPolicyForbidden")
	}
}

func TestNewPolicyError(t *testing.T) {
	pe := NewPolicyError(ErrPolicyForbidden, "dns", "example.com", "test detail")

	if pe.Err != ErrPolicyForbidden {
		t.Errorf("Err = %v, want %v", pe.Err, ErrPolicyForbidden)
	}
	if pe.IdentifierType != "dns" {
		t.Errorf("IdentifierType = %q, want %q", pe.IdentifierType, "dns")
	}
	if pe.Identifier != "example.com" {
		t.Errorf("Identifier = %q, want %q", pe.Identifier, "example.com")
	}
	if pe.Detail != "test detail" {
		t.Errorf("Detail = %q, want %q", pe.Detail, "test detail")
	}
}

func TestBlocklistError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *BlocklistError
		expected string
	}{
		{
			name: "full error with all fields",
			err: &BlocklistError{
				Err:      ErrBlocklistFileRead,
				FilePath: "/path/to/blocklist.yaml",
				Entry:    "malformed.entry",
				Detail:   "file not found",
			},
			expected: "policy: blocklist error [/path/to/blocklist.yaml] entry=malformed.entry: policy: failed to read blocklist file (file not found)",
		},
		{
			name: "error without entry",
			err: &BlocklistError{
				Err:      ErrBlocklistFileParse,
				FilePath: "/path/to/blocklist.yaml",
				Detail:   "invalid yaml",
			},
			expected: "policy: blocklist error [/path/to/blocklist.yaml]: policy: failed to parse blocklist file (invalid yaml)",
		},
		{
			name: "error without file path",
			err: &BlocklistError{
				Err:    ErrMalformedBlocklistEntry,
				Entry:  "bad.entry",
				Detail: "missing labels",
			},
			expected: "policy: blocklist error entry=bad.entry: policy: malformed blocklist entry (missing labels)",
		},
		{
			name: "minimal error",
			err: &BlocklistError{
				Err: ErrMalformedIPPrefix,
			},
			expected: "policy: blocklist error: policy: malformed IP prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("BlocklistError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestBlocklistError_Unwrap(t *testing.T) {
	inner := ErrBlocklistFileRead
	be := &BlocklistError{
		Err:      inner,
		FilePath: "/path/to/file",
	}

	unwrapped := be.Unwrap()
	if unwrapped != inner {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, inner)
	}

	// Test errors.Is with wrapped error
	if !errors.Is(be, ErrBlocklistFileRead) {
		t.Error("errors.Is() should return true for wrapped ErrBlocklistFileRead")
	}
}

func TestNewBlocklistError(t *testing.T) {
	be := NewBlocklistError(ErrMalformedBlocklistEntry, "/path/to/file", "bad.entry", "test detail")

	if be.Err != ErrMalformedBlocklistEntry {
		t.Errorf("Err = %v, want %v", be.Err, ErrMalformedBlocklistEntry)
	}
	if be.FilePath != "/path/to/file" {
		t.Errorf("FilePath = %q, want %q", be.FilePath, "/path/to/file")
	}
	if be.Entry != "bad.entry" {
		t.Errorf("Entry = %q, want %q", be.Entry, "bad.entry")
	}
	if be.Detail != "test detail" {
		t.Errorf("Detail = %q, want %q", be.Detail, "test detail")
	}
}

func TestSentinelErrors(t *testing.T) {
	// Ensure sentinel errors are distinct and have expected messages
	sentinelErrors := map[error]string{
		ErrEmptyIdentifier:           "policy: identifier value is empty",
		ErrNameTooLong:               "policy: domain name is longer than 253 bytes",
		ErrLabelTooLong:              "policy: domain label is longer than 63 bytes",
		ErrLabelTooShort:             "policy: domain name cannot have two dots in a row",
		ErrTooManyLabels:             "policy: domain name has more than 10 labels",
		ErrTooFewLabels:              "policy: domain name needs at least one dot",
		ErrNameEndsInDot:             "policy: domain name ends in a dot",
		ErrInvalidDNSCharacter:       "policy: domain name contains an invalid character",
		ErrIPAddressInDNS:            "policy: identifier type is DNS but value is an IP address",
		ErrInvalidRLDH:               "policy: domain name contains an invalid label in a reserved format",
		ErrMalformedIDN:              "policy: domain name contains malformed punycode",
		ErrNonPublicSuffix:           "policy: domain name does not end with a valid public suffix",
		ErrICANNTLD:                  "policy: domain name is an ICANN TLD",
		ErrTooManyWildcards:          "policy: domain name has more than one wildcard",
		ErrMalformedWildcard:         "policy: wildcard is only permitted before the first dot",
		ErrICANNTLDWildcard:          "policy: domain name is a wildcard for an ICANN TLD",
		ErrWildcardNotSupported:      "policy: wildcard domain names are not supported",
		ErrIPInvalid:                 "policy: IP address is invalid",
		ErrIPReserved:                "policy: IP address is in a reserved range",
		ErrIPHasZone:                 "policy: IP address contains a zone identifier",
		ErrPolicyForbidden:           "policy: the ACME server refuses to issue a certificate for this identifier",
		ErrPolicyNotLoaded:           "policy: identifier policy not yet loaded",
		ErrBlocklistFileRead:         "policy: failed to read blocklist file",
		ErrBlocklistFileParse:        "policy: failed to parse blocklist file",
		ErrMalformedBlocklistEntry:   "policy: malformed blocklist entry",
		ErrMalformedIPPrefix:         "policy: malformed IP prefix",
		ErrUnsupportedIdentifierType: "policy: unsupported identifier type",
		ErrIdentifierTypeDisabled:    "policy: identifier type is disabled",
		ErrChallengeTypeDisabled:     "policy: challenge type is disabled",
		ErrChallengeTypeNotAllowed:   "policy: challenge type not allowed for this identifier",
		ErrUnsupportedChallengeType:  "policy: unsupported challenge type",
	}

	for err, expectedMsg := range sentinelErrors {
		t.Run(expectedMsg, func(t *testing.T) {
			if err.Error() != expectedMsg {
				t.Errorf("error message = %q, want %q", err.Error(), expectedMsg)
			}
		})
	}
}

func TestErrorsAs(t *testing.T) {
	// Test errors.As for PolicyError
	pe := NewPolicyError(ErrPolicyForbidden, "dns", "example.com", "test")
	var targetPE *PolicyError
	if !errors.As(pe, &targetPE) {
		t.Error("errors.As should work for *PolicyError")
	}

	// Test errors.As for BlocklistError
	be := NewBlocklistError(ErrBlocklistFileRead, "/path", "entry", "detail")
	var targetBE *BlocklistError
	if !errors.As(be, &targetBE) {
		t.Error("errors.As should work for *BlocklistError")
	}
}
