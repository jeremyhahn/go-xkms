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

package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certifyFixture is a complete, valid TPM2_Certify built without a TPM, so the
// verifier can be driven through every branch deterministically.
type certifyFixture struct {
	attesterPub  []byte
	subjectPub   []byte
	certifyInfo  []byte
	signature    []byte
	attesterKey  *ecdsa.PrivateKey
	qualifyingIn []byte
}

// eccPublicArea builds a TPMT_PUBLIC for an ECDSA P-256 key.
//
// restricted controls whether the area describes a key the TPM would refuse to
// sign external data with, which is the property the verifier insists on for
// an attesting key.
func eccPublicArea(t *testing.T, key *ecdsa.PrivateKey, restricted bool) tpm2.TPMTPublic {
	t.Helper()
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          restricted,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
				},
			}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: key.PublicKey.X.FillBytes(make([]byte, 32))},
				Y: tpm2.TPM2BECCParameter{Buffer: key.PublicKey.Y.FillBytes(make([]byte, 32))},
			}),
	}
}

// signAttest signs a marshalled TPMS_ATTEST the way a TPM would.
func signAttest(t *testing.T, key *ecdsa.PrivateKey, attestBytes []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(attestBytes)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)

	sig := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA,
			&tpm2.TPMSSignatureECC{
				Hash:       tpm2.TPMAlgSHA256,
				SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
				SignatureS: tpm2.TPM2BECCParameter{Buffer: s.FillBytes(make([]byte, 32))},
			}),
	}
	return tpm2.Marshal(sig)
}

// newCertifyFixture produces a genuine certification of subject by attester.
func newCertifyFixture(t *testing.T) *certifyFixture {
	t.Helper()

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	attesterArea := eccPublicArea(t, attesterKey, true)
	subjectArea := eccPublicArea(t, subjectKey, false)

	subjectName, err := tpm2.ObjectName(&subjectArea)
	require.NoError(t, err)
	attesterName, err := tpm2.ObjectName(&attesterArea)
	require.NoError(t, err)

	qualifying := []byte("enrollment-nonce-0001")

	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestCertify,
		QualifiedSigner: *attesterName,
		ExtraData:       tpm2.TPM2BData{Buffer: qualifying},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1, ResetCount: 1, RestartCount: 0, Safe: true},
		FirmwareVersion: 1,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify,
			&tpm2.TPMSCertifyInfo{
				Name:          *subjectName,
				QualifiedName: *subjectName,
			}),
	}
	certifyInfo := tpm2.Marshal(attest)

	return &certifyFixture{
		attesterPub:  tpm2.Marshal(attesterArea),
		subjectPub:   tpm2.Marshal(subjectArea),
		certifyInfo:  certifyInfo,
		signature:    signAttest(t, attesterKey, certifyInfo),
		attesterKey:  attesterKey,
		qualifyingIn: qualifying,
	}
}

func TestVerifyCertify_AcceptsAGenuineCertification(t *testing.T) {
	f := newCertifyFixture(t)

	result, err := VerifyCertify(f.certifyInfo, f.signature, f.attesterPub, f.subjectPub, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.SubjectName)
	assert.Equal(t, f.qualifyingIn, result.QualifyingData)
	assert.NotNil(t, result.AttesterPublicKey)
}

func TestVerifyCertify_AcceptsMatchingQualifyingData(t *testing.T) {
	f := newCertifyFixture(t)

	result, err := VerifyCertify(f.certifyInfo, f.signature, f.attesterPub, f.subjectPub,
		&VerifyCertifyOptions{ExpectedQualifyingData: f.qualifyingIn})

	require.NoError(t, err)
	assert.Equal(t, f.qualifyingIn, result.QualifyingData)
}

// TestVerifyCertify_RejectsAReplayedNonce is the freshness check.
//
// Without it a certification recorded from any earlier enrollment stays valid
// forever, because nothing in the structure ties it to a particular request.
func TestVerifyCertify_RejectsAReplayedNonce(t *testing.T) {
	f := newCertifyFixture(t)

	_, err := VerifyCertify(f.certifyInfo, f.signature, f.attesterPub, f.subjectPub,
		&VerifyCertifyOptions{ExpectedQualifyingData: []byte("a-different-nonce")})

	assert.ErrorIs(t, err, ErrCertifyQualifyingDataMismatch)
}

// TestVerifyCertify_RejectsADifferentSubjectKey is the binding check, and the
// reason this verifier exists.
//
// The attestation is entirely genuine: a real TPM certified a real key with a
// real signature. It simply describes a *different* key than the one being
// presented for certification. A verifier that stops at the signature accepts
// this, and issues a certificate for a key no TPM ever saw.
func TestVerifyCertify_RejectsADifferentSubjectKey(t *testing.T) {
	f := newCertifyFixture(t)

	strangerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	strangerArea := eccPublicArea(t, strangerKey, false)

	_, err = VerifyCertify(f.certifyInfo, f.signature, f.attesterPub,
		tpm2.Marshal(strangerArea), nil)

	assert.ErrorIs(t, err, ErrCertifyNameMismatch)
}

// TestVerifyCertify_RejectsForgedAttestationBytes covers the TPM_GENERATED
// check.
//
// Here the attacker holds a signing key and composes a structure naming their
// own software key, then signs it. Everything verifies except the magic, which
// only a TPM writes -- so that single field is what separates "a TPM said this"
// from "somebody with a key said this".
func TestVerifyCertify_RejectsForgedAttestationBytes(t *testing.T) {
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	victimKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	attackerArea := eccPublicArea(t, attackerKey, true)
	victimArea := eccPublicArea(t, victimKey, false)
	victimName, err := tpm2.ObjectName(&victimArea)
	require.NoError(t, err)

	forged := tpm2.TPMSAttest{
		// Anything but TPM_GENERATED_VALUE. A TPM cannot be made to emit this.
		Magic:     tpm2.TPMGenerated(0xDEADBEEF),
		Type:      tpm2.TPMSTAttestCertify,
		ExtraData: tpm2.TPM2BData{Buffer: []byte("nonce")},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify,
			&tpm2.TPMSCertifyInfo{Name: *victimName, QualifiedName: *victimName}),
	}
	forgedBytes := tpm2.Marshal(forged)

	_, err = VerifyCertify(forgedBytes, signAttest(t, attackerKey, forgedBytes),
		tpm2.Marshal(attackerArea), tpm2.Marshal(victimArea), nil)

	assert.ErrorIs(t, err, ErrCertifyNotTPMGenerated)
}

// TestVerifyCertify_RejectsAnUnrestrictedAttester covers why the magic check
// is sufficient in practice.
//
// A restricted key is one the TPM refuses to sign external data with, so a
// structure signed by it must have come from inside. An unrestricted key will
// sign whatever it is handed -- including bytes composed to look like an
// attestation, magic and all -- so accepting one reopens the forgery this
// verification is meant to close.
func TestVerifyCertify_RejectsAnUnrestrictedAttester(t *testing.T) {
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	victimKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	unrestricted := eccPublicArea(t, attackerKey, false)
	victimArea := eccPublicArea(t, victimKey, false)
	victimName, err := tpm2.ObjectName(&victimArea)
	require.NoError(t, err)

	// A perfectly-formed attestation, magic included, signed by a key the TPM
	// would have been willing to sign arbitrary data with.
	forged := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestCertify,
		ExtraData: tpm2.TPM2BData{Buffer: []byte("nonce")},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify,
			&tpm2.TPMSCertifyInfo{Name: *victimName, QualifiedName: *victimName}),
	}
	forgedBytes := tpm2.Marshal(forged)

	_, err = VerifyCertify(forgedBytes, signAttest(t, attackerKey, forgedBytes),
		tpm2.Marshal(unrestricted), tpm2.Marshal(victimArea), nil)

	assert.ErrorIs(t, err, ErrCertifyAttesterUnrestricted)

	// The escape hatch exists for tests and must be opt-in only.
	_, err = VerifyCertify(forgedBytes, signAttest(t, attackerKey, forgedBytes),
		tpm2.Marshal(unrestricted), tpm2.Marshal(victimArea),
		&VerifyCertifyOptions{AllowUnrestrictedAttester: true})
	assert.NoError(t, err)
}

func TestVerifyCertify_RejectsAForeignSignature(t *testing.T) {
	f := newCertifyFixture(t)

	strangerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = VerifyCertify(f.certifyInfo, signAttest(t, strangerKey, f.certifyInfo),
		f.attesterPub, f.subjectPub, nil)

	assert.ErrorIs(t, err, ErrCertifySignature)
}

func TestVerifyCertify_RejectsTamperedCertifyInfo(t *testing.T) {
	f := newCertifyFixture(t)

	tampered := make([]byte, len(f.certifyInfo))
	copy(tampered, f.certifyInfo)
	tampered[len(tampered)-1] ^= 0xFF

	_, err := VerifyCertify(tampered, f.signature, f.attesterPub, f.subjectPub, nil)

	assert.ErrorIs(t, err, ErrCertifySignature)
}

// TestVerifyCertify_RejectsAQuote proves a different attestation type cannot
// stand in for a certification.
//
// A quote is genuine, TPM-generated and correctly signed -- it just says
// something about PCR state rather than about a key, so reading a subject name
// out of it would be reading a field that is not there.
func TestVerifyCertify_RejectsAQuote(t *testing.T) {
	f := newCertifyFixture(t)

	quote := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: []byte("nonce")},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote,
			&tpm2.TPMSQuoteInfo{
				PCRSelect: tpm2.TPMLPCRSelection{},
				PCRDigest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
			}),
	}
	quoteBytes := tpm2.Marshal(quote)

	_, err := VerifyCertify(quoteBytes, signAttest(t, f.attesterKey, quoteBytes),
		f.attesterPub, f.subjectPub, nil)

	assert.ErrorIs(t, err, ErrCertifyWrongType)
}

func TestVerifyCertify_RejectsMalformedInput(t *testing.T) {
	f := newCertifyFixture(t)

	cases := []struct {
		name                         string
		info, sig, attester, subject []byte
	}{
		{"no certify info", nil, f.signature, f.attesterPub, f.subjectPub},
		{"no signature", f.certifyInfo, nil, f.attesterPub, f.subjectPub},
		{"garbage attester area", f.certifyInfo, f.signature, []byte{0x01, 0x02}, f.subjectPub},
		{"garbage subject area", f.certifyInfo, f.signature, f.attesterPub, []byte{0x01, 0x02}},
		{"garbage signature", f.certifyInfo, []byte{0x99, 0x99}, f.attesterPub, f.subjectPub},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyCertify(tc.info, tc.sig, tc.attester, tc.subject, nil)
			assert.ErrorIs(t, err, ErrCertifyMalformed)
		})
	}
}

// TestVerifyCertify_ErrorsAreDistinguishable keeps the refusals separable, so
// an operator can tell a forgery from a genuine attestation of another key.
func TestVerifyCertify_ErrorsAreDistinguishable(t *testing.T) {
	sentinels := []error{
		ErrCertifyMalformed,
		ErrCertifyNotTPMGenerated,
		ErrCertifyWrongType,
		ErrCertifySignature,
		ErrCertifyNameMismatch,
		ErrCertifyQualifyingDataMismatch,
		ErrCertifyAttesterUnrestricted,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j {
				assert.NotErrorIs(t, a, b, "%v and %v must be distinct", a, b)
			}
		}
	}
}
