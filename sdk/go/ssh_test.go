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

package xkms

import (
	"errors"
	"strings"
	"testing"
)

// validSSHFingerprint is the `ssh-keygen -lf` form of a real SHA-256
// digest: the "SHA256:" prefix plus 43 unpadded standard-base64 chars.
const validSSHFingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"

// TestSSHValidateFingerprint_Accepts confirms the alias reaches the
// canonical validator and accepts a well-formed fingerprint.
func TestSSHValidateFingerprint_Accepts(t *testing.T) {
	if err := SSHValidateFingerprint(validSSHFingerprint); err != nil {
		t.Fatalf("unexpected error for a valid fingerprint: %v", err)
	}
}

// TestSSHValidateFingerprint_Rejects confirms malformed fingerprints are
// refused as *SSHInvalidFingerprintError, so callers can match the alias
// type without importing pkg/ssh/known_hosts.
func TestSSHValidateFingerprint_Rejects(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"missing prefix", "MD5:aa:bb"},
		{"prefix only", "SHA256:"},
		{"not base64", "SHA256:***not-base64***"},
		{"three-byte digest", "SHA256:AAAA"},
		{"one-byte digest", "SHA256:AA"},
		{"41-byte digest", "SHA256:" + strings.Repeat("A", 55)},
		{"padded body", validSSHFingerprint + "="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := SSHValidateFingerprint(tc.input)
			if err == nil {
				t.Fatalf("expected error for %q", tc.input)
			}
			var inv *SSHInvalidFingerprintError
			if !errors.As(err, &inv) {
				t.Fatalf("expected *SSHInvalidFingerprintError for %q, got %T: %v", tc.input, err, err)
			}
			if inv.Value != tc.input {
				t.Fatalf("Value = %q, want %q", inv.Value, tc.input)
			}
			if inv.Reason == "" {
				t.Fatal("Reason is empty")
			}
		})
	}
}
