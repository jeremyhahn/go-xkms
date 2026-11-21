package truststore

import "testing"

// TestPurposeScope_OutOfSpecCategoriesRefused pins the public purpose
// taxonomy to docs/trust-roots/api.md: the chain-format categories
// yubikey-attestation, apple-attestation and dice-attestation are not
// accepted import or list purposes (SPEC row 2185 scope).
func TestPurposeScope_OutOfSpecCategoriesRefused(t *testing.T) {
	for _, p := range []CertPurpose{"yubikey-attestation", "apple-attestation", "dice-attestation"} {
		if validPurposes[p] {
			t.Errorf("purpose %q accepted; it is outside the SPEC taxonomy", p)
		}
	}
}
