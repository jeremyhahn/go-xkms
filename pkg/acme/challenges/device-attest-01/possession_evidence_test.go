package deviceattest01

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
)

// measurementsWithEvidence is the vector's measurements claim with evidence
// as the application evidence.
func measurementsWithEvidence(t *testing.T, evidence []byte) []byte {
	t.Helper()
	file := vectorFile(t)
	file[7] = []any{1, evidence}
	coswid := vectorCoswid(t)
	coswid[3] = map[int64]any{17: file}
	return measurementsOf(t, coswid)
}

// aliasWithClaims is a DICE alias certificate for key whose UCCS claims set
// is claims.
func aliasWithClaims(t *testing.T, key *ecdsa.PrivateKey, claims *dice.ClaimsSet) []byte {
	t.Helper()
	uccs, err := dice.CreateUccsEvidenceExtension(claims)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ueidExtension(t), uccs},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	return der
}

// TestVerifyPossessionCSRHoldsTheAliasEvidence is the regression for the
// finalization gap: a request signed by the attested key, for this order's
// nonce and identifier, must still carry the application evidence of the
// alias certificate the challenge verified, since only the alias's evidence
// is held to the registered reference.
func TestVerifyPossessionCSRHoldsTheAliasEvidence(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	attestedSPKI, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	evidenceA := mustHex(t, vectorApplicationEvidence)
	evidenceB := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	aliasClaims := vectorClaimsSet(t)
	aliasClaims.Nonce = DICENonce(diceKeyAuth)
	aliasClaims.Other[dice.ClaimMeasurements] = measurementsWithEvidence(t, evidenceA)
	verified := &VerifiedAttestation{
		Format:           FormatDICE,
		KeyAuthorization: diceKeyAuth,
		LeafDER:          aliasWithClaims(t, key, aliasClaims),
		AttestedSPKI:     attestedSPKI,
	}
	order := newPossessionFixture(t).order

	t.Run("the alias's evidence is accepted", func(t *testing.T) {
		claims := vectorClaimsWith(t, func(other map[int64][]byte) {
			other[dice.ClaimMeasurements] = measurementsWithEvidence(t, evidenceA)
		})
		require.NoError(t, verified.VerifyPossessionCSR(possessionRequest(t, key, claims, diceKeyAuth), order))
	})
	t.Run("other measurements under the same key, nonce and identifier are refused", func(t *testing.T) {
		claims := vectorClaimsWith(t, func(other map[int64][]byte) {
			other[dice.ClaimMeasurements] = measurementsWithEvidence(t, evidenceB)
		})
		csr := possessionRequest(t, key, claims, diceKeyAuth)
		require.NoError(t, csr.CheckSignature())
		assert.ErrorIs(t, verified.VerifyPossessionCSR(csr, order), ErrPossessionEvidenceMismatch)
	})
	t.Run("an alias whose measurements are not the shape is refused", func(t *testing.T) {
		bad := vectorClaimsSet(t)
		bad.Nonce = DICENonce(diceKeyAuth)
		bad.Other[dice.ClaimMeasurements] = encodeCBOR(t, []any{})
		malformed := *verified
		malformed.LeafDER = aliasWithClaims(t, key, bad)
		csr := possessionRequest(t, key, vectorClaimsSet(t), diceKeyAuth)
		assert.ErrorIs(t, malformed.VerifyPossessionCSR(csr, order), ErrPossessionEvidenceMismatch)
	})
}
