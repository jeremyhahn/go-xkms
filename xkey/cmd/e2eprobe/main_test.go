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

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"hash"
	"testing"
)

func withFIPSMode(t *testing.T, on bool) {
	t.Helper()

	original := fipsMode
	t.Cleanup(func() { fipsMode = original })
	fipsMode = func() bool { return on }
}

// The probe enrolled SHA-1 unconditionally and cross-computed it in Go. Under
// FIPS both halves are broken: oathGenerate refuses the credential, so the
// required step could only ever fail, and the Go-side HMAC-SHA1 PANICS with
// GODEBUG=fips140=only. Selecting SHA-256 keeps the cross-check real instead of
// skipping it (raised in review on PR #76).
func TestOathProbeAlgorithm_UsesSHA256UnderFIPS(t *testing.T) {
	withFIPSMode(t, true)

	name, digest := oathProbeAlgorithm()
	if name != "SHA256" {
		t.Fatalf("algorithm = %q, want SHA256 under FIPS", name)
	}
	if got := digest().Size(); got != sha256.Size {
		t.Fatalf("digest size = %d, want %d: the name and the hash must agree, "+
			"or the probe cross-checks against a digest the phone did not use", got, sha256.Size)
	}
}

// Outside FIPS the probe must keep exercising SHA-1, which is the RFC 6238
// default and what every enrolled credential in the field actually uses.
// Silently probing only SHA-256 would stop testing the common path.
func TestOathProbeAlgorithm_UsesSHA1Otherwise(t *testing.T) {
	withFIPSMode(t, false)

	name, digest := oathProbeAlgorithm()
	if name != "SHA1" {
		t.Fatalf("algorithm = %q, want SHA1 outside FIPS", name)
	}
	if got := digest().Size(); got != sha1.Size {
		t.Fatalf("digest size = %d, want %d", got, sha1.Size)
	}
}

// totp now takes the digest as a parameter. A version that accepted it and
// went on using SHA-1 anyway would pass both tests above and still cross-check
// against the wrong hash, so pin the arithmetic to the RFC 6238 Appendix B
// vectors: T=59s with the default 30s step is counter 1.
//
// The RFC prints 8 digits; the probe compares 6, so these are the low six.
func TestTOTP_MatchesRFC6238Vectors(t *testing.T) {
	b32 := func(seed string) string {
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(seed))
	}

	tests := []struct {
		name   string
		seed   string
		digest func() hash.Hash
		want   string
	}{
		// Appendix B seeds are the ASCII digits repeated to the hash's key size.
		{"SHA1", "12345678901234567890", sha1.New, "287082"},
		{"SHA256", "12345678901234567890123456789012", sha256.New, "119246"},
		{"SHA512", "1234567890123456789012345678901234567890123456789012345678901234", sha512.New, "693936"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := totp(b32(tc.seed), 1, tc.digest); got != tc.want {
				t.Fatalf("totp(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// A secret the phone sent that cannot be decoded must not panic the probe.
func TestTOTP_UndecodableSecretReturnsEmpty(t *testing.T) {
	if got := totp("1811!!!!not-base32!!!!", 1, sha1.New); got != "" {
		t.Fatalf("totp = %q, want empty for an undecodable secret", got)
	}
}
