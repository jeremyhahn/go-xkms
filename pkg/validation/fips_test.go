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

package validation

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
)

// fipsFiltersNonApproved reports whether this run applies the FIPS algorithm
// filter. Tests that assert on non-approved algorithms use it because the
// contract genuinely differs between a normal build and a FIPS one, and a
// FIPS-compiled binary cannot be talked out of the filter by the environment.
func fipsFiltersNonApproved() bool {
	return fips.Compiled() || fips.Enabled()
}

// nonApprovedAlgorithms are entries in validAlgorithms that a FIPS 140-3
// deployment may not use.
var nonApprovedAlgorithms = []string{
	"x25519", "x448",
	"chacha20-poly1305", "chacha20",
	"xchacha20-poly1305", "xchacha20",
	"frost-ed25519", "frost-ed25519-sha512",
	"frost-ristretto255", "frost-ristretto255-sha512",
	"frost-ed448", "frost-ed448-shake256",
	"frost-p256", "frost-p256-sha256",
	"frost-secp256k1", "frost-secp256k1-sha256",
}

// TestIsValidAlgorithm_FIPSModeRejectsNonApproved is the compliance assertion:
// with FIPS mode active, the allowlist no longer admits ChaCha20, X25519/X448
// or any FROST ciphersuite.
func TestIsValidAlgorithm_FIPSModeRejectsNonApproved(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "latest")

	for _, algo := range nonApprovedAlgorithms {
		if isValidAlgorithm(algo) {
			t.Errorf("isValidAlgorithm(%q) = true in FIPS mode, want false", algo)
		}
	}
}

// TestIsValidAlgorithm_FIPSModeAdmitsApproved guards against the filter being
// so blunt it rejects the algorithms a FIPS deployment is meant to use.
func TestIsValidAlgorithm_FIPSModeAdmitsApproved(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "latest")

	approved := []string{
		"rsa", "ecdsa-p256", "ecdsa-p-384", "p521", "ed25519", "ed448",
		"aes128-gcm", "aes256-gcm", "aes192",
		"ml-dsa-65", "mldsa87", "ml-kem-768", "mlkem1024",
		"hmac-sha256", "hmac-sha512",
	}
	for _, algo := range approved {
		if !isValidAlgorithm(algo) {
			t.Errorf("isValidAlgorithm(%q) = false in FIPS mode, want true", algo)
		}
	}
}

// TestValidateKeyReference_FIPSModeRejectsNonApproved covers the filter through
// the exported entry point callers actually use.
func TestValidateKeyReference_FIPSModeRejectsNonApproved(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "latest")

	for _, algo := range nonApprovedAlgorithms {
		ref := "software:encryption:" + algo + ":a-key"
		if err := ValidateKeyReference(ref); err == nil {
			t.Errorf("ValidateKeyReference(%q) = nil in FIPS mode, want an error", ref)
		}
	}

	if err := ValidateKeyReference("software:signing:ecdsa-p256:a-key"); err != nil {
		t.Errorf("ValidateKeyReference of an approved algorithm in FIPS mode = %v, want nil", err)
	}
}

// TestFIPSApprovedAlgorithmsAreInAllowlist catches drift between the FIPS
// policy list and this package's own allowlist: an approved algorithm that this
// package does not know about would be silently unreachable, and a typo in
// either list would go unnoticed.
func TestFIPSApprovedAlgorithmsAreInAllowlist(t *testing.T) {
	for algo := range validAlgorithms {
		if !fips.ApprovedAlgorithm(algo) {
			continue
		}
		if !isValidAlgorithmUnfiltered(algo) {
			t.Errorf("fips.ApprovedAlgorithm(%q) is true but validAlgorithms rejects it", algo)
		}
	}

	// Every non-approved entry this package knows about must be one the FIPS
	// policy actually denies.
	for _, algo := range nonApprovedAlgorithms {
		if _, ok := validAlgorithms[algo]; !ok {
			t.Errorf("nonApprovedAlgorithms lists %q, which is not in validAlgorithms", algo)
		}
		if fips.ApprovedAlgorithm(algo) {
			t.Errorf("fips.ApprovedAlgorithm(%q) = true, want false", algo)
		}
	}
}

// isValidAlgorithmUnfiltered is the allowlist lookup without the FIPS filter.
func isValidAlgorithmUnfiltered(algo string) bool {
	_, ok := validAlgorithms[algo]
	return ok
}
