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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

	// PublicKey.Bytes returns the SEC 1 uncompressed encoding, 0x04 || X || Y
	// with each coordinate padded to the curve's field size. Slicing it is the
	// supported way to reach the affine coordinates; the PublicKey.X and .Y
	// big.Int fields are deprecated as of Go 1.25.
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode P-256 public key: %v", err)
	}
	const coordLen = 32
	if len(point) != 1+2*coordLen {
		t.Fatalf("expected a %d-byte uncompressed P-256 point, got %d", 1+2*coordLen, len(point))
	}
	x, y := point[1:1+coordLen], point[1+coordLen:]

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
				X: tpm2.TPM2BECCParameter{Buffer: x},
				Y: tpm2.TPM2BECCParameter{Buffer: y},
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

// rsaPublicAreaWithScheme builds a minimal TPMT_PUBLIC for an RSA key
// declaring the given signature scheme, for signatureFromScheme tests that
// only need the scheme read back, not a genuine key.
func rsaPublicAreaWithScheme(scheme tpm2.TPMTRSAScheme) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{Scheme: scheme, KeyBits: 2048}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)}),
	}
}

// eccPublicAreaWithScheme builds a minimal TPMT_PUBLIC for an ECC key
// declaring the given signature scheme.
func eccPublicAreaWithScheme(scheme tpm2.TPMTECCScheme) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{CurveID: tpm2.TPMECCNistP256, Scheme: scheme}),
	}
}

// TestSignatureFromScheme_RejectsEmptySignature verifies a certification that
// carries no signature bytes at all is refused before any scheme parsing, not
// misread as a scheme-specific malformation.
func TestSignatureFromScheme_RejectsEmptySignature(t *testing.T) {
	attester := rsaPublicAreaWithScheme(tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
	})
	_, err := signatureFromScheme(&attester, nil)
	assert.ErrorIs(t, err, ErrCertifyMalformed)
}

// TestSignatureFromScheme_RSASSA verifies the RSASSA branch rebuilds a
// TPMT_SIGNATURE carrying the raw bytes verbatim and the scheme's own hash
// algorithm, not a guessed one.
func TestSignatureFromScheme_RSASSA(t *testing.T) {
	attester := rsaPublicAreaWithScheme(tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA384}),
	})
	raw := []byte{0x01, 0x02, 0x03}

	sig, err := signatureFromScheme(&attester, raw)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgRSASSA, sig.SigAlg)
	detail, err := sig.Signature.RSASSA()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgSHA384, detail.Hash)
	assert.Equal(t, raw, detail.Sig.Buffer)
}

// TestSignatureFromScheme_RSAPSS mirrors the RSASSA case for RSA-PSS.
func TestSignatureFromScheme_RSAPSS(t *testing.T) {
	attester := rsaPublicAreaWithScheme(tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSAPSS,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAPSS,
			&tpm2.TPMSSigSchemeRSAPSS{HashAlg: tpm2.TPMAlgSHA256}),
	})
	raw := []byte{0x0A, 0x0B}

	sig, err := signatureFromScheme(&attester, raw)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgRSAPSS, sig.SigAlg)
	detail, err := sig.Signature.RSAPSS()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgSHA256, detail.Hash)
	assert.Equal(t, raw, detail.Sig.Buffer)
}

// TestSignatureFromScheme_RSAUnsupportedScheme verifies an RSA attester
// declaring a non-signature scheme (here, the OAEP encryption scheme) is
// refused by name rather than mismatched into RSASSA/RSAPSS.
func TestSignatureFromScheme_RSAUnsupportedScheme(t *testing.T) {
	attester := rsaPublicAreaWithScheme(tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgOAEP,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP,
			&tpm2.TPMSEncSchemeOAEP{HashAlg: tpm2.TPMAlgSHA256}),
	})
	_, err := signatureFromScheme(&attester, []byte{0x01})
	assert.ErrorIs(t, err, ErrCertifyMalformed)
}

// TestSignatureFromScheme_ECDSA verifies the ECC branch splits a raw r||s
// signature evenly and carries the scheme's hash algorithm.
func TestSignatureFromScheme_ECDSA(t *testing.T) {
	attester := eccPublicAreaWithScheme(tpm2.TPMTECCScheme{
		Scheme: tpm2.TPMAlgECDSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
			&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
	})
	raw := make([]byte, 64)
	raw[0], raw[32] = 0xAA, 0xBB

	sig, err := signatureFromScheme(&attester, raw)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgECDSA, sig.SigAlg)
	detail, err := sig.Signature.ECDSA()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgSHA256, detail.Hash)
	assert.Equal(t, raw[:32], detail.SignatureR.Buffer)
	assert.Equal(t, raw[32:], detail.SignatureS.Buffer)
}

// TestSignatureFromScheme_ECDSAOddLengthRejected verifies a raw signature
// that cannot be an r||s pair (odd length) is refused rather than split
// unevenly into a corrupt R/S.
func TestSignatureFromScheme_ECDSAOddLengthRejected(t *testing.T) {
	attester := eccPublicAreaWithScheme(tpm2.TPMTECCScheme{
		Scheme: tpm2.TPMAlgECDSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
			&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
	})
	_, err := signatureFromScheme(&attester, []byte{0x01, 0x02, 0x03})
	assert.ErrorIs(t, err, ErrCertifyMalformed)
}

// TestSignatureFromScheme_ECCNonECDSASchemeRejected verifies an ECC attester
// that declares a non-signing scheme (ECDH) is refused rather than treated
// as ECDSA.
func TestSignatureFromScheme_ECCNonECDSASchemeRejected(t *testing.T) {
	attester := eccPublicAreaWithScheme(tpm2.TPMTECCScheme{
		Scheme: tpm2.TPMAlgECDH,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDH,
			&tpm2.TPMSKeySchemeECDH{HashAlg: tpm2.TPMAlgSHA256}),
	})
	_, err := signatureFromScheme(&attester, make([]byte, 64))
	assert.ErrorIs(t, err, ErrCertifyMalformed)
}

// TestSignatureFromScheme_UnsignableKeyTypeRejected verifies an attester
// whose type is neither RSA nor ECC (a keyed-hash object, which can only be
// certified, never sign externally) is refused by the default branch.
func TestSignatureFromScheme_UnsignableKeyTypeRejected(t *testing.T) {
	attester := tpm2.TPMTPublic{Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256}
	_, err := signatureFromScheme(&attester, []byte{0x01})
	assert.ErrorIs(t, err, ErrCertifyMalformed)
}

// rsaPublicAreaWithKey builds a TPMT_PUBLIC carrying pub's real modulus, so
// verifyCertifySignature can recover a public key that actually verifies a
// signature produced by the matching private key.
func rsaPublicAreaWithKey(pub *rsa.PublicKey, scheme tpm2.TPMTRSAScheme) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{Scheme: scheme, KeyBits: tpm2.TPMKeyBits(pub.N.BitLen())}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: pub.N.Bytes()}),
	}
}

// TestVerifyCertifySignature_RSASSA verifies a genuine RSASSA (PKCS#1 v1.5)
// signature over certifyInfo is accepted and recovers the attesting key.
func TestVerifyCertifySignature_RSASSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attester := rsaPublicAreaWithKey(&key.PublicKey, tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
	})

	certifyInfo := []byte("certify-info-rsassa")
	digest := sha256.Sum256(certifyInfo)
	rawSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	sig := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgRSASSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSignatureRSA{Hash: tpm2.TPMAlgSHA256, Sig: tpm2.TPM2BPublicKeyRSA{Buffer: rawSig}}),
	}

	pub, err := verifyCertifySignature(&attester, certifyInfo, &sig)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, key.PublicKey.N, rsaPub.N)
}

// TestVerifyCertifySignature_RSASSA_WrongSignatureRejected verifies a
// structurally valid but forged RSASSA signature is refused with
// ErrCertifySignature, not accepted or reported as a malformed input.
func TestVerifyCertifySignature_RSASSA_WrongSignatureRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attester := rsaPublicAreaWithKey(&key.PublicKey, tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
	})

	// Sign different data than what is verified, producing a genuine
	// signature that nonetheless does not cover certifyInfo.
	otherDigest := sha256.Sum256([]byte("not-certify-info"))
	rawSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, otherDigest[:])
	require.NoError(t, err)
	sig := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgRSASSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSignatureRSA{Hash: tpm2.TPMAlgSHA256, Sig: tpm2.TPM2BPublicKeyRSA{Buffer: rawSig}}),
	}

	_, err = verifyCertifySignature(&attester, []byte("certify-info-rsassa"), &sig)
	assert.ErrorIs(t, err, ErrCertifySignature)
}

// TestVerifyCertifySignature_RSAPSS verifies a genuine RSA-PSS signature is
// accepted using the same default salt-length verification the TPM's own
// scheme implies.
func TestVerifyCertifySignature_RSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	attester := rsaPublicAreaWithKey(&key.PublicKey, tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSAPSS,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAPSS,
			&tpm2.TPMSSigSchemeRSAPSS{HashAlg: tpm2.TPMAlgSHA256}),
	})

	certifyInfo := []byte("certify-info-rsapss")
	digest := sha256.Sum256(certifyInfo)
	rawSig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	require.NoError(t, err)
	sig := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgRSAPSS,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSAPSS,
			&tpm2.TPMSSignatureRSA{Hash: tpm2.TPMAlgSHA256, Sig: tpm2.TPM2BPublicKeyRSA{Buffer: rawSig}}),
	}

	pub, err := verifyCertifySignature(&attester, certifyInfo, &sig)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, key.PublicKey.N, rsaPub.N)
}

// TestVerifyCertifySignature_UnsupportedAlgorithmRejected verifies a
// signature algorithm this verifier does not implement is refused by name
// rather than silently mismatched to one of the known branches.
func TestVerifyCertifySignature_UnsupportedAlgorithmRejected(t *testing.T) {
	attester := rsaPublicAreaWithScheme(tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
	})
	sig := tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgHMAC}

	_, err := verifyCertifySignature(&attester, []byte("data"), &sig)
	assert.ErrorIs(t, err, ErrCertifyMalformed)
}
