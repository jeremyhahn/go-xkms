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

package fips

import "testing"

// nonApproved lists the algorithm identifiers the key-ID grammar accepts that a
// FIPS 140-3 deployment may not use. Kept as a literal rather than derived from
// approvedAlgorithms so a mistaken addition to the allowlist fails this test.
var nonApproved = []string{
	"x25519", "x448",
	"chacha20-poly1305", "chacha20",
	"xchacha20-poly1305", "xchacha20",
	"frost-ed25519", "frost-ed25519-sha512",
	"frost-ristretto255", "frost-ristretto255-sha512",
	"frost-ed448", "frost-ed448-shake256",
	"frost-p256", "frost-p256-sha256",
	"frost-secp256k1", "frost-secp256k1-sha256",
}

func TestApprovedAlgorithm(t *testing.T) {
	approved := []string{
		"rsa",
		"ecdsa-p256", "ecdsa-p-256", "p256", "p-256",
		"ecdsa-p384", "ecdsa-p-384", "p384", "p-384",
		"ecdsa-p521", "ecdsa-p-521", "p521", "p-521",
		"ed25519", "ed448",
		"aes128-gcm", "aes128", "aes192-gcm", "aes192", "aes256-gcm", "aes256",
		"ml-dsa-44", "mldsa44", "ml-dsa-65", "mldsa65", "ml-dsa-87", "mldsa87",
		"ml-kem-512", "mlkem512", "ml-kem-768", "mlkem768", "ml-kem-1024", "mlkem1024",
		"hmac-sha256", "hmac-sha384", "hmac-sha512",
	}

	for _, algo := range approved {
		if !ApprovedAlgorithm(algo) {
			t.Errorf("ApprovedAlgorithm(%q) = false, want true", algo)
		}
	}

	for _, algo := range nonApproved {
		if ApprovedAlgorithm(algo) {
			t.Errorf("ApprovedAlgorithm(%q) = true, want false (not FIPS-approved)", algo)
		}
	}
}

func TestApprovedAlgorithm_CaseInsensitive(t *testing.T) {
	if !ApprovedAlgorithm("ECDSA-P256") {
		t.Error(`ApprovedAlgorithm("ECDSA-P256") = false, want true`)
	}
	if ApprovedAlgorithm("ChaCha20") {
		t.Error(`ApprovedAlgorithm("ChaCha20") = true, want false`)
	}
}

func TestApprovedAlgorithm_UnknownIsNotApproved(t *testing.T) {
	for _, algo := range []string{"", "md5", "des", "not-an-algorithm"} {
		if ApprovedAlgorithm(algo) {
			t.Errorf("ApprovedAlgorithm(%q) = true, want false", algo)
		}
	}
}

func TestAlgorithmPermitted_FIPSMode(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "latest")

	for _, algo := range nonApproved {
		if AlgorithmPermitted(algo) {
			t.Errorf("AlgorithmPermitted(%q) = true in FIPS mode, want false", algo)
		}
	}
	for _, algo := range []string{"rsa", "aes256-gcm", "ml-kem-768", "ecdsa-p384"} {
		if !AlgorithmPermitted(algo) {
			t.Errorf("AlgorithmPermitted(%q) = false in FIPS mode, want true", algo)
		}
	}
}

func TestAlgorithmPermitted_NonFIPSMode(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "off")

	// A FIPS-compiled binary enforces the approved set regardless of the
	// environment, so the expectation depends on how this binary was built.
	want := !Compiled()

	for _, algo := range nonApproved {
		if got := AlgorithmPermitted(algo); got != want {
			t.Errorf("AlgorithmPermitted(%q) = %v with GOFIPS140=off, want %v (fips.Compiled()=%v)",
				algo, got, want, Compiled())
		}
	}
	// Approved algorithms are permitted in either build.
	if !AlgorithmPermitted("aes256-gcm") {
		t.Error(`AlgorithmPermitted("aes256-gcm") = false, want true`)
	}
}
