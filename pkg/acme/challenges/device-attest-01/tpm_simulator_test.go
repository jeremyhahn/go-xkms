//go:build tpm_simulator

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

package deviceattest01

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	xtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// These tests produce their evidence with a simulated TPM: TPM2_Certify and
// TPM2_Quote are executed by the reference implementation, so certInfo, its
// Name and its signature are what a real device would send, and the key in the
// CSR is signed for by the TPM that holds it.

// simulatedTPM is one TPM, with a restricted attestation key (the AIK) and the
// device key a CSR is made for.
type simulatedTPM struct {
	tpm    transport.TPM
	ak     *tpmKey
	device *tpmKey
}

// tpmKey is a loaded TPM key.
type tpmKey struct {
	handle  tpm2.AuthHandle
	pubArea []byte
	public  crypto.PublicKey
}

func newSimulatedTPM(t *testing.T) *simulatedTPM {
	t.Helper()
	sim, err := simulator.Get()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sim.Close()) })

	s := &simulatedTPM{tpm: transport.FromReadWriter(sim)}
	s.ak = s.createKey(t, true, "aik")
	s.device = s.createKey(t, false, "device")
	return s
}

// createKey creates a P-256 ECDSA signing key. restricted makes it an
// attestation key, which the TPM will only use to sign data it generated. The
// label seeds the primary's unique field so two keys from one template differ.
func (s *simulatedTPM) createKey(t *testing.T, restricted bool, label string) *tpmKey {
	t.Helper()
	template := tpm2.TPMTPublic{
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
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: []byte(label)},
		}),
	}
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(template),
	}.Execute(s.tpm)
	require.NoError(t, err)

	public, err := rsp.OutPublic.Contents()
	require.NoError(t, err)
	pubArea := tpm2.Marshal(*public)
	key, err := xtpm2.ExtractPublicKeyFromTPMPublic(pubArea)
	require.NoError(t, err)

	return &tpmKey{
		handle:  tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil)},
		pubArea: pubArea,
		public:  key,
	}
}

// certify has signer certify subject over extraData with TPM2_Certify, and
// returns certInfo and sig as a WebAuthn "tpm" statement carries them.
func (s *simulatedTPM) certify(t *testing.T, signer, subject *tpmKey, extraData []byte) ([]byte, []byte) {
	t.Helper()
	rsp, err := tpm2.Certify{
		ObjectHandle:   subject.handle,
		SignHandle:     signer.handle,
		QualifyingData: tpm2.TPM2BData{Buffer: extraData},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(s.tpm)
	require.NoError(t, err)
	return rsp.CertifyInfo.Bytes(), asn1ECDSA(t, rsp.Signature)
}

// quote has the AIK quote PCR 0 over extraData: genuine, TPM-generated and
// signed, but an attestation of platform state rather than of a key.
func (s *simulatedTPM) quote(t *testing.T, extraData []byte) ([]byte, []byte) {
	t.Helper()
	rsp, err := tpm2.Quote{
		SignHandle:     s.ak.handle,
		QualifyingData: tpm2.TPM2BData{Buffer: extraData},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: []byte{0x01, 0x00, 0x00},
		}}},
	}.Execute(s.tpm)
	require.NoError(t, err)
	return rsp.Quoted.Bytes(), asn1ECDSA(t, rsp.Signature)
}

// asn1ECDSA re-encodes a TPMT_SIGNATURE as the ASN.1 DER ECDSA signature
// WebAuthn Level 2 section 6.5.6 specifies for ES256.
func asn1ECDSA(t *testing.T, signature tpm2.TPMTSignature) []byte {
	t.Helper()
	ecc, err := signature.Signature.ECDSA()
	require.NoError(t, err)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(ecc.SignatureR.Buffer),
		new(big.Int).SetBytes(ecc.SignatureS.Buffer),
	})
	require.NoError(t, err)
	return der
}

// tpmSigner signs with a TPM key, so a CSR for the device key is made by the
// TPM that holds it.
type tpmSigner struct {
	tpm transport.TPM
	key *tpmKey
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.key.public }

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	rsp, err := tpm2.Sign{
		KeyHandle:  s.key.handle,
		Digest:     tpm2.TPM2BDigest{Buffer: digest},
		InScheme:   tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(s.tpm)
	if err != nil {
		return nil, err
	}
	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(ecc.SignatureR.Buffer),
		new(big.Int).SetBytes(ecc.SignatureS.Buffer),
	})
}

// deviceCSR is the certificate request the device makes for its own key.
func (s *simulatedTPM) deviceCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, &tpmSigner{tpm: s.tpm, key: s.device})
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// tpmStatement is a "tpm" attestation object.
func tpmStatement(aikDER, certInfo, sig, pubArea []byte) *AttestationObject {
	return &AttestationObject{
		Format: string(FormatTPM),
		AttStatement: AttestationStatement{
			Ver:      "2.0",
			Alg:      coseES256,
			X5c:      []interface{}{aikDER},
			Sig:      sig,
			CertInfo: certInfo,
			PubArea:  pubArea,
		},
	}
}

// genuineTPMAttestation is a device answering this challenge correctly: its
// AIK, certified by issuer, certifies its device key over TPMExtraData.
func genuineTPMAttestation(t *testing.T, device *simulatedTPM, issuer *aikIssuer) *AttestationObject {
	t.Helper()
	extraData, err := TPMExtraData(coseES256, tpmKeyAuth)
	require.NoError(t, err)
	certInfo, sig := device.certify(t, device.ak, device.device, extraData)
	return tpmStatement(issuer.issue(t, device.ak.public, nil), certInfo, sig, device.device.pubArea)
}

func verifyServed(t *testing.T, ca AttestationVerifier, object *AttestationObject) (*VerifiedAttestation, error) {
	t.Helper()
	payload := attestationPayload(t, object)
	return VerifyAttestation(ca, payload, tpmKeyAuth)
}

func softwareCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return csrFor(t, key)
}

func TestTPMAttestationBindsTheDevicesOwnKey(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")
	ca := anchoredTo(issuer)

	verified, err := verifyServed(t, ca, genuineTPMAttestation(t, device, issuer))
	require.NoError(t, err)
	assert.True(t, ca.chainChecked, "x5c was never anchored")
	assert.Equal(t, FormatTPM, verified.Format)
	assert.Equal(t, device.device.pubArea, verified.PubArea)

	require.NoError(t, verified.BindCSRKey(device.deviceCSR(t)))

	// The record as a store hands it back: bytes only.
	restored := &VerifiedAttestation{
		Format:           verified.Format,
		KeyAuthorization: verified.KeyAuthorization,
		LeafDER:          verified.LeafDER,
		Algorithm:        verified.Algorithm,
		CertInfo:         verified.CertInfo,
		Signature:        verified.Signature,
		PubArea:          verified.PubArea,
	}
	require.NoError(t, restored.BindCSRKey(device.deviceCSR(t)))
}

// TestTPMAttestationRefusesASoftwareKeyInTheCSR is issue 789.
//
// The device's evidence is entirely genuine and answers this challenge. The
// CSR beside it is for a key generated in software. Before the binding, the
// server certified that key as TPM-resident, because nothing compared it with
// pubArea.
func TestTPMAttestationRefusesASoftwareKeyInTheCSR(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")

	verified, err := verifyServed(t, anchoredTo(issuer), genuineTPMAttestation(t, device, issuer))
	require.NoError(t, err)

	err = verified.BindCSRKey(softwareCSR(t))
	require.Error(t, err, "a software key was certified against a TPM's attestation")
	assert.ErrorIs(t, err, attestation.ErrKeyNotBound)

	// Another key in the same TPM is no better: the certification is of one key.
	sibling := device.createKey(t, false, "sibling")
	siblingCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, &tpmSigner{tpm: device.tpm, key: sibling})
	require.NoError(t, err)
	parsed, err := x509.ParseCertificateRequest(siblingCSR)
	require.NoError(t, err)
	assert.ErrorIs(t, verified.BindCSRKey(parsed), attestation.ErrKeyNotBound)
}

// The binding needs the CSR, which arrives a request after the challenge. So
// the one-shot verifier cannot authorize a "tpm" attestation, and says so.
func TestVerifyDoesNotAuthorizeTPMOnTheChallengeAlone(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")
	payload := attestationPayload(t, genuineTPMAttestation(t, device, issuer))

	err := Verify(anchoredTo(issuer), payload, tpmKeyAuth)
	assert.ErrorIs(t, err, ErrKeyBindingRequired)
}

func TestTPMAttestationRefusesAQuote(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")
	extraData, err := TPMExtraData(coseES256, tpmKeyAuth)
	require.NoError(t, err)

	// Signed by the AIK, carrying this challenge -- the evidence the previous
	// verifier accepted. It certifies no key.
	certInfo, sig := device.quote(t, extraData)
	object := tpmStatement(issuer.issue(t, device.ak.public, nil), certInfo, sig, device.device.pubArea)

	_, err = verifyServed(t, anchoredTo(issuer), object)
	assert.ErrorIs(t, err, ErrTPMAttestationInvalid)
	assert.ErrorIs(t, err, xtpm2.ErrCertifyWrongType)
}

func TestTPMAttestationRefusesAnotherKeysPubArea(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")
	extraData, err := TPMExtraData(coseES256, tpmKeyAuth)
	require.NoError(t, err)

	// A genuine certification of the device key, presented with the public
	// area of a different key -- one the attacker would then put in the CSR.
	certInfo, sig := device.certify(t, device.ak, device.device, extraData)
	other := device.createKey(t, false, "other")
	object := tpmStatement(issuer.issue(t, device.ak.public, nil), certInfo, sig, other.pubArea)

	_, err = verifyServed(t, anchoredTo(issuer), object)
	assert.ErrorIs(t, err, ErrTPMAttestationInvalid)
	assert.ErrorIs(t, err, xtpm2.ErrCertifyNameMismatch)
}

// The previous verifier searched all of certInfo for the key authorization.
// These certInfos contain it, and its digest, somewhere other than extraData
// -- or in extraData but not as extraData -- and must be refused.
func TestTPMAttestationRefusesTheChallengeOutsideExtraData(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")
	digest, err := TPMExtraData(coseES256, tpmKeyAuth)
	require.NoError(t, err)

	cases := map[string][]byte{
		"the raw key authorization":        []byte(tpmKeyAuth),
		"the digest inside longer data":    append(append([]byte("prefix:"), digest...), 0x00),
		"the digest after other qualifier": append([]byte{0xAA, 0xBB}, digest...),
	}
	for name, qualifying := range cases {
		t.Run(name, func(t *testing.T) {
			certInfo, sig := device.certify(t, device.ak, device.device, qualifying)
			require.True(t, bytes.Contains(certInfo, qualifying), "the case does not exercise a substring match")

			object := tpmStatement(issuer.issue(t, device.ak.public, nil), certInfo, sig, device.device.pubArea)
			_, err := verifyServed(t, anchoredTo(issuer), object)
			assert.ErrorIs(t, err, attestation.ErrStaleEvidence)
		})
	}
}

func TestTPMAttestationRefusesAnotherChallenge(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")
	stale, err := TPMExtraData(coseES256, "an-earlier-token.thumbprint-of-the-account-key")
	require.NoError(t, err)

	certInfo, sig := device.certify(t, device.ak, device.device, stale)
	object := tpmStatement(issuer.issue(t, device.ak.public, nil), certInfo, sig, device.device.pubArea)

	_, err = verifyServed(t, anchoredTo(issuer), object)
	assert.ErrorIs(t, err, attestation.ErrStaleEvidence)
	assert.ErrorIs(t, err, xtpm2.ErrCertifyQualifyingDataMismatch)
}

// A second attestation key in the same TPM certifies the device key correctly,
// but x5c[0] certifies the first. sig must verify under x5c[0].
func TestTPMAttestationRefusesASignatureByAnotherKey(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")
	extraData, err := TPMExtraData(coseES256, tpmKeyAuth)
	require.NoError(t, err)

	otherAK := device.createKey(t, true, "other-aik")
	certInfo, sig := device.certify(t, otherAK, device.device, extraData)
	object := tpmStatement(issuer.issue(t, device.ak.public, nil), certInfo, sig, device.device.pubArea)

	_, err = verifyServed(t, anchoredTo(issuer), object)
	assert.ErrorIs(t, err, ErrTPMAttestationInvalid)
	assert.ErrorIs(t, err, xtpm2.ErrCertifySignature)
}

func TestTPMAttestationRefusesAnUnanchoredAIK(t *testing.T) {
	device := newSimulatedTPM(t)
	trusted := newAIKIssuer(t, "trusted AIK CA")
	rogue := newAIKIssuer(t, "rogue AIK CA")

	// Everything is genuine except who vouches for the AIK.
	_, err := verifyServed(t, anchoredTo(trusted), genuineTPMAttestation(t, device, rogue))
	assert.ErrorIs(t, err, ErrCertificateChainInvalid)
}

// An AIK certificate is the only thing that says the key signing certInfo is a
// restricted TPM attestation key. Without tcg-kp-AIKCertificate the key could
// be one that signs whatever it is given.
func TestTPMAttestationRefusesAnAIKCertificateWithoutTheAIKUsage(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")
	extraData, err := TPMExtraData(coseES256, tpmKeyAuth)
	require.NoError(t, err)

	certInfo, sig := device.certify(t, device.ak, device.device, extraData)
	aik := issuer.issue(t, device.ak.public, func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil })
	object := tpmStatement(aik, certInfo, sig, device.device.pubArea)

	_, err = verifyServed(t, anchoredTo(issuer), object)
	assert.ErrorIs(t, err, xtpm2.ErrCertifyAttesterUnrestricted)
}

// The binding re-verifies the record rather than trusting it was verified, so
// a record that changed in storage, or is replayed for another exchange, is
// refused at finalization even beside the device's own CSR.
func TestTPMBindingReverifiesTheRecord(t *testing.T) {
	device := newSimulatedTPM(t)
	issuer := newAIKIssuer(t, "AIK CA")

	verified, err := verifyServed(t, anchoredTo(issuer), genuineTPMAttestation(t, device, issuer))
	require.NoError(t, err)
	csr := device.deviceCSR(t)

	t.Run("another exchange", func(t *testing.T) {
		replayed := *verified
		replayed.KeyAuthorization = "another-token.thumbprint-of-the-account-key"
		assert.ErrorIs(t, replayed.BindCSRKey(csr), attestation.ErrStaleEvidence)
	})

	t.Run("a substituted pubArea", func(t *testing.T) {
		substituted := *verified
		substituted.PubArea = device.createKey(t, false, "substitute").pubArea
		assert.ErrorIs(t, substituted.BindCSRKey(csr), attestation.ErrKeyNotBound)
	})

	t.Run("a tampered signature", func(t *testing.T) {
		tampered := *verified
		tampered.Signature = append([]byte{}, verified.Signature...)
		tampered.Signature[len(tampered.Signature)-1] ^= 0xFF
		assert.ErrorIs(t, tampered.BindCSRKey(csr), attestation.ErrKeyNotBound)
	})

	t.Run("a certificate request whose signature does not verify", func(t *testing.T) {
		broken := device.deviceCSR(t)
		broken.Signature[len(broken.Signature)-1] ^= 0xFF
		assert.ErrorIs(t, verified.BindCSRKey(broken), attestation.ErrKeyNotBound)
	})
}
