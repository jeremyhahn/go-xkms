//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newECCLAK returns a harness with a persisted P-256 LAK and its attributes.
func newECCLAK(t *testing.T) (*simHarness, *types.KeyAttributes) {
	t.Helper()
	h := newLAKHarness(t)
	lakAttrs, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)
	return h, lakAttrs
}

// TestSign_ECCLAK_SignsTicketedDigest proves an ECC attestation key signs.
// The restricted path used to read RSA details unconditionally, so every
// ECC LAK or AK failed with "did not contain rsaDetail". Like the RSA IAK,
// the key signs the digest the TPM computed over the caller's input.
func TestSign_ECCLAK_SignsTicketedDigest(t *testing.T) {
	h, lakAttrs := newECCLAK(t)
	input := sha256.Sum256([]byte("attested payload"))

	signature, err := h.TPM.Sign(rand.Reader, input[:], &store.SignerOpts{
		KeyAttributes: lakAttrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err)

	pub, err := h.TPM.LAK()
	require.NoError(t, err)
	signed := sha256.Sum256(input[:])
	assert.True(t, ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), signed[:], signature),
		"the signature must verify over the TPM-computed digest")
	assert.False(t, ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), input[:], signature),
		"a restricted key never signs the caller's bytes directly")
}

// TestSign_ECCLAK_RefusesTPMGeneratedData proves the forgery guard holds
// for ECC attestation keys as it does for RSA ones.
func TestSign_ECCLAK_RefusesTPMGeneratedData(t *testing.T) {
	h, lakAttrs := newECCLAK(t)
	forged := append([]byte{0xFF, 0x54, 0x43, 0x47}, []byte("forged attestation structure")...)

	signature, err := h.TPM.Sign(rand.Reader, forged, &store.SignerOpts{
		KeyAttributes: lakAttrs,
		Backend:       h.Backend,
	})
	assert.ErrorIs(t, err, ErrRestrictedSignRefused)
	assert.Nil(t, signature)
}

// TestSign_RestrictedKeyFailures proves the restricted path surfaces a TPM
// that cannot hash with the key's algorithm and a key that is not persisted.
func TestSign_RestrictedKeyFailures(t *testing.T) {
	h, lakAttrs := newECCLAK(t)
	digest := sha256.Sum256([]byte("payload"))

	tests := []struct {
		name   string
		mutate func(*types.TPMAttributes)
	}{
		{"unusable hash algorithm", func(a *types.TPMAttributes) { a.HashAlg = tpm2.TPMAlgNull }},
		{"key not persisted", func(a *types.TPMAttributes) { a.Handle = 0x810100EE }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := *lakAttrs
			tpmAttrs := *lakAttrs.TPMAttributes
			tt.mutate(&tpmAttrs)
			attrs.TPMAttributes = &tpmAttrs

			signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
				KeyAttributes: &attrs,
				Backend:       h.Backend,
			})
			assert.Error(t, err)
			assert.Nil(t, signature)
		})
	}
}

// TestSign_RSALAK_SchemeRefusals proves an RSA attestation key refuses a
// signature its own scheme cannot produce: a hash other than the scheme's,
// no hash at all, and PKCS#1 v1.5 from a key whose scheme is RSA-PSS.
func TestSign_RSALAK_SchemeRefusals(t *testing.T) {
	h := newRSALAKHarness(t)
	lakAttrs, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("payload"))

	tests := []struct {
		name    string
		mutate  func(*types.KeyAttributes)
		wantErr error
	}{
		{"hash outside the key scheme", func(a *types.KeyAttributes) { a.Hash = crypto.SHA384 }, ErrSignSchemeMismatch},
		{"no hash", func(a *types.KeyAttributes) { a.Hash = 0 }, ErrRawRSASignUnsupported},
		{"PKCS#1 v1.5 from a PSS key", func(a *types.KeyAttributes) { a.SignatureAlgorithm = x509.SHA256WithRSA }, ErrSignSchemeMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := *lakAttrs
			tt.mutate(&attrs)

			signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
				KeyAttributes: &attrs,
				Backend:       h.Backend,
			})
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, signature)
		})
	}
}

// TestSign_IDevIDWithoutTPMAttributes proves an IDevID with no TPM
// attributes is refused rather than signing with a zero handle.
func TestSign_IDevIDWithoutTPMAttributes(t *testing.T) {
	h := newSimHarness(t, nil)
	digest := sha256.Sum256([]byte("payload"))

	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: &types.KeyAttributes{
			CN:      "idevid-without-tpm-attributes",
			KeyType: types.KeyTypeIDevID,
			Hash:    crypto.SHA256,
		},
		Backend: h.Backend,
	})
	assert.Error(t, err)
	assert.Nil(t, signature)
}
