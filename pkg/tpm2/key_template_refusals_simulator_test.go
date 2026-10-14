//go:build tpm_simulator

package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// firstUnsupported returns the first candidate the device does not
// implement, failing the test when it implements them all.
func firstUnsupported(t *testing.T, h *simHarness, candidates ...tpm2.TPMAlgID) tpm2.TPMAlgID {
	t.Helper()
	caps, err := h.TPM.Capabilities()
	require.NoError(t, err)
	for _, candidate := range candidates {
		if !caps.SupportsAlgorithm(candidate) {
			return candidate
		}
	}
	require.FailNow(t, "this TPM implements every candidate, so the refusal cannot be exercised; add one it lacks")
	return 0
}

// TestKeyTemplate_RefusesUnsupportedSchemeHash proves a scheme digest the
// device lacks is refused by name before any key is created, as the name
// algorithm already is.
func TestKeyTemplate_RefusesUnsupportedSchemeHash(t *testing.T) {
	h := newSimHarness(t, nil)
	missing := firstUnsupported(t, h,
		tpm2.TPMAlgSM3256, tpm2.TPMAlgSHA3256, tpm2.TPMAlgSHA3384, tpm2.TPMAlgSHA3512)

	_, err := h.TPM.KeyTemplate(KeyTemplateSpec{
		Algorithm:  x509.ECDSA,
		Curve:      elliptic.P256(),
		Scheme:     tpm2.TPMAlgECDSA,
		SchemeHash: missing,
	})
	var algErr *AlgorithmNotSupportedError
	require.True(t, errors.As(err, &algErr), "got %v", err)
	assert.Equal(t, algorithmName(missing), algErr.Requested)
	assert.Contains(t, algErr.Supported, algorithmName(tpm2.TPMAlgSHA256))
}
