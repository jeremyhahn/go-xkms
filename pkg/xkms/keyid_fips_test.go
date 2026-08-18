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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
)

// fipsFiltersNonApproved reports whether this run applies the FIPS algorithm
// filter. Tests that assert on non-approved algorithms use it because the
// contract genuinely differs between a normal build and a FIPS one, and a
// FIPS-compiled binary cannot be talked out of the filter by the environment.
func fipsFiltersNonApproved() bool {
	return fips.Compiled() || fips.Enabled()
}

// keyIDNonApprovedAlgorithms are algorithms the key-ID grammar accepts that a
// FIPS 140-3 deployment may not use.
var keyIDNonApprovedAlgorithms = []string{
	"x25519", "x448",
	"chacha20-poly1305", "chacha20",
	"xchacha20-poly1305", "xchacha20",
	"frost-ed25519", "frost-ed25519-sha512",
	"frost-ristretto255", "frost-ristretto255-sha512",
	"frost-ed448", "frost-ed448-shake256",
	"frost-p256", "frost-p256-sha256",
	"frost-secp256k1", "frost-secp256k1-sha256",
}

// TestValidateAlgorithm_FIPSModeRejectsNonApproved is the compliance assertion
// for the key-ID allowlist.
func TestValidateAlgorithm_FIPSModeRejectsNonApproved(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "latest")

	for _, algo := range keyIDNonApprovedAlgorithms {
		err := validateAlgorithm(algo)
		require.Error(t, err, "algorithm %s must be rejected in FIPS mode", algo)
		assert.Contains(t, err.Error(), "FIPS 140-3",
			"the rejection should say why %s was refused", algo)
	}
}

func TestValidateAlgorithm_FIPSModeAdmitsApproved(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "latest")

	for _, algo := range []string{
		"rsa", "ecdsa-p256", "ecdsa-p-384", "p521", "ed25519", "ed448",
		"aes128-gcm", "aes256-gcm", "aes192",
		"ml-dsa-65", "mldsa87", "ml-kem-768", "mlkem1024",
		"hmac-sha256", "hmac-sha512",
	} {
		assert.NoError(t, validateAlgorithm(algo),
			"approved algorithm %s must remain valid in FIPS mode", algo)
	}
}

// TestParseKeyID_FIPSModeRejectsNonApproved covers the filter through the
// exported parser rather than the internal predicate.
func TestParseKeyID_FIPSModeRejectsNonApproved(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "latest")

	for _, algo := range keyIDNonApprovedAlgorithms {
		keyID := "software:encryption:" + algo + ":a-key"
		_, _, _, _, err := ParseKeyID(keyID)
		assert.Error(t, err, "ParseKeyID(%q) must fail in FIPS mode", keyID)
	}

	_, _, _, _, err := ParseKeyID("software:signing:ecdsa-p256:a-key")
	assert.NoError(t, err, "an approved algorithm must still parse in FIPS mode")
}

// TestKeyIDAllowlistMatchesFIPSPolicy catches drift between the key-ID grammar
// and the FIPS policy list: the two allowlists in this repo are maintained by
// hand and are documented as having to stay in sync.
func TestKeyIDAllowlistMatchesFIPSPolicy(t *testing.T) {
	for _, algo := range keyIDNonApprovedAlgorithms {
		assert.False(t, fips.ApprovedAlgorithm(algo),
			"fips.ApprovedAlgorithm(%q) should be false", algo)

		// The only reason validateAlgorithm may reject it is the FIPS filter.
		// A plain "invalid algorithm" would mean this list has drifted away
		// from the key-ID grammar it is supposed to shadow.
		if err := validateAlgorithm(algo); err != nil {
			assert.Contains(t, err.Error(), "FIPS 140-3",
				"%q is no longer in the key-ID grammar", algo)
		}
	}
}
