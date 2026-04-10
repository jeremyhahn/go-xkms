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

package truststore

import (
	"errors"
	"testing"
)

func TestIsValidPurpose(t *testing.T) {
	tests := []struct {
		name    string
		purpose CertPurpose
	}{
		{"general", PurposeGeneral},
		{"tpm-manufacturer", PurposeTPMManufacturer},
		{"android-hardware", PurposeAndroidHardware},
		{"user-ca", PurposeUserCA},
		{"bootstrap-ca", PurposeBootstrapCA},
		{"idevid-issuer", PurposeIDevIDIssuer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !IsValidPurpose(tt.purpose) {
				t.Errorf("IsValidPurpose(%q) = false, want true", tt.purpose)
			}
		})
	}
}

func TestIsValidPurpose_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		purpose CertPurpose
	}{
		{"empty string", CertPurpose("")},
		{"arbitrary string", CertPurpose("foobar")},
		{"wrong case", CertPurpose("General")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsValidPurpose(tt.purpose) {
				t.Errorf("IsValidPurpose(%q) = true, want false", tt.purpose)
			}
		})
	}
}

func TestParsePurpose(t *testing.T) {
	tests := []struct {
		input    string
		expected CertPurpose
	}{
		{"general", PurposeGeneral},
		{"tpm-manufacturer", PurposeTPMManufacturer},
		{"android-hardware", PurposeAndroidHardware},
		{"user-ca", PurposeUserCA},
		{"bootstrap-ca", PurposeBootstrapCA},
		{"idevid-issuer", PurposeIDevIDIssuer},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParsePurpose(tt.input)
			if err != nil {
				t.Fatalf("ParsePurpose(%q) returned unexpected error: %v", tt.input, err)
			}
			if got != tt.expected {
				t.Errorf("ParsePurpose(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParsePurpose_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"arbitrary string", "invalid"},
		{"wrong case", "GENERAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePurpose(tt.input)
			if err == nil {
				t.Fatalf("ParsePurpose(%q) returned nil error, want ErrInvalidPurpose", tt.input)
			}
			if !errors.Is(err, ErrInvalidPurpose) {
				t.Errorf("ParsePurpose(%q) error = %v, want ErrInvalidPurpose", tt.input, err)
			}
			if got != "" {
				t.Errorf("ParsePurpose(%q) = %q, want empty string on error", tt.input, got)
			}
		})
	}
}

func TestCertPurpose_StringValue(t *testing.T) {
	tests := []struct {
		purpose  CertPurpose
		expected string
	}{
		{PurposeGeneral, "general"},
		{PurposeTPMManufacturer, "tpm-manufacturer"},
		{PurposeAndroidHardware, "android-hardware"},
		{PurposeUserCA, "user-ca"},
		{PurposeBootstrapCA, "bootstrap-ca"},
		{PurposeIDevIDIssuer, "idevid-issuer"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.purpose) != tt.expected {
				t.Errorf("CertPurpose string value = %q, want %q", string(tt.purpose), tt.expected)
			}
		})
	}
}
