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
	"github.com/stretchr/testify/require"
)

// rsaPublicArea builds a TPMT_PUBLIC for an RSA key under the given
// signature scheme (TPM_ALG_RSASSA or TPM_ALG_RSAPSS), restricted so it
// qualifies as an attesting key.
func rsaPublicArea(t *testing.T, key *rsa.PrivateKey, scheme tpm2.TPMAlgID) tpm2.TPMTPublic {
	t.Helper()

	rsaScheme := tpm2.TPMTRSAScheme{Scheme: scheme}
	switch scheme {
	case tpm2.TPMAlgRSASSA:
		rsaScheme.Details = tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256})
	case tpm2.TPMAlgRSAPSS:
		rsaScheme.Details = tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAPSS,
			&tpm2.TPMSSigSchemeRSAPSS{HashAlg: tpm2.TPMAlgSHA256})
	default:
		t.Fatalf("unsupported RSA scheme for test fixture: 0x%04x", scheme)
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme:  rsaScheme,
				KeyBits: tpm2.TPMKeyBits(key.PublicKey.N.BitLen()),
			}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: key.PublicKey.N.Bytes()}),
	}
}

// buildCertifyInfo assembles a genuine (unsigned) TPMS_ATTEST/TPM2_Certify
// structure for subjectArea as attested by attesterArea, the same shape
// newCertifyFixture builds for the ECDSA-only case in certify_verify_test.go
// but generalized to any attester key type.
func buildCertifyInfo(t *testing.T, attesterArea, subjectArea tpm2.TPMTPublic, qualifying []byte) []byte {
	t.Helper()

	subjectName, err := tpm2.ObjectName(&subjectArea)
	require.NoError(t, err)
	attesterName, err := tpm2.ObjectName(&attesterArea)
	require.NoError(t, err)

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
	return tpm2.Marshal(attest)
}

// TestVerifyCertifyRaw_AcceptsGenuineRawSignatures proves VerifyCertifyRaw --
// the entry point that takes the bare signature value TPM2_Certify returns,
// rather than a pre-assembled TPMT_SIGNATURE -- correctly rebuilds the
// signature for every scheme this package's key-creation functions produce
// (RSASSA, RSAPSS, ECDSA) and that the rebuilt signature verifies.
func TestVerifyCertifyRaw_AcceptsGenuineRawSignatures(t *testing.T) {
	qualifying := []byte("raw-signature-fixture-nonce")

	t.Run("RSASSA", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		attesterArea := rsaPublicArea(t, key, tpm2.TPMAlgRSASSA)
		subjectArea := eccPublicArea(t, mustECDSAKey(t), false)
		certifyInfo := buildCertifyInfo(t, attesterArea, subjectArea, qualifying)

		digest := sha256.Sum256(certifyInfo)
		raw, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		require.NoError(t, err)

		result, err := VerifyCertifyRaw(certifyInfo, raw, tpm2.Marshal(attesterArea), tpm2.Marshal(subjectArea), nil)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("RSAPSS", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		attesterArea := rsaPublicArea(t, key, tpm2.TPMAlgRSAPSS)
		subjectArea := eccPublicArea(t, mustECDSAKey(t), false)
		certifyInfo := buildCertifyInfo(t, attesterArea, subjectArea, qualifying)

		digest := sha256.Sum256(certifyInfo)
		raw, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		require.NoError(t, err)

		result, err := VerifyCertifyRaw(certifyInfo, raw, tpm2.Marshal(attesterArea), tpm2.Marshal(subjectArea), nil)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("ECDSA", func(t *testing.T) {
		key := mustECDSAKey(t)
		attesterArea := eccPublicArea(t, key, true)
		subjectArea := rsaPublicArea(t, mustRSAKey(t), tpm2.TPMAlgRSASSA)
		subjectArea.ObjectAttributes.Restricted = false
		certifyInfo := buildCertifyInfo(t, attesterArea, subjectArea, qualifying)

		digest := sha256.Sum256(certifyInfo)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		require.NoError(t, err)
		raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)

		result, err := VerifyCertifyRaw(certifyInfo, raw, tpm2.Marshal(attesterArea), tpm2.Marshal(subjectArea), nil)
		require.NoError(t, err)
		require.NotNil(t, result)
	})
}

// TestSignatureFromScheme_RejectsEveryMalformedInput table-tests the
// defensive branches signatureFromScheme guards before ever touching a
// signature verifier: an empty raw value, an RSA key declaring a scheme that
// cannot sign (TPM_ALG_NULL), an ECDSA raw value that is not an r||s pair,
// and an attesting key type (keyedHash) that cannot certify at all. Every
// one of these must fail closed as ErrCertifyMalformed rather than panic or
// silently build a signature over the wrong bytes.
func TestSignatureFromScheme_RejectsEveryMalformedInput(t *testing.T) {
	rsaKey := mustRSAKey(t)

	tests := []struct {
		name     string
		attester tpm2.TPMTPublic
		raw      []byte
	}{
		{
			name:     "empty raw signature",
			attester: rsaPublicArea(t, rsaKey, tpm2.TPMAlgRSASSA),
			raw:      nil,
		},
		{
			name: "RSA key with no signing scheme",
			attester: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
						KeyBits: 2048,
					}),
				Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{Buffer: rsaKey.PublicKey.N.Bytes()}),
			},
			raw: []byte("some-signature-bytes"),
		},
		{
			name:     "ECDSA raw signature with odd length",
			attester: eccPublicArea(t, mustECDSAKey(t), true),
			raw:      make([]byte, 63),
		},
		{
			name: "attesting key type cannot sign",
			attester: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgKeyedHash,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
				},
			},
			raw: []byte("some-signature-bytes"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := signatureFromScheme(&tt.attester, tt.raw)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrCertifyMalformed)
			require.Nil(t, sig)
		})
	}
}

// TestVerifyCertifySignature_RejectsWrongSignature proves each signature
// branch (RSASSA, RSAPSS, ECDSA) genuinely verifies the bytes rather than
// only checking structural well-formedness: a syntactically valid signature
// produced by the WRONG key over the same certifyInfo must be rejected as
// ErrCertifySignature, and an unsupported SigAlg must be rejected as
// ErrCertifyMalformed.
func TestVerifyCertifySignature_RejectsWrongSignature(t *testing.T) {
	certifyInfo := []byte("attestation-bytes-to-sign")
	digest := sha256.Sum256(certifyInfo)

	t.Run("RSASSA wrong key", func(t *testing.T) {
		legit := mustRSAKey(t)
		impostor := mustRSAKey(t)
		attesterArea := rsaPublicArea(t, legit, tpm2.TPMAlgRSASSA)

		wrongSig, err := rsa.SignPKCS1v15(rand.Reader, impostor, crypto.SHA256, digest[:])
		require.NoError(t, err)

		sig := &tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{Hash: tpm2.TPMAlgSHA256, Sig: tpm2.TPM2BPublicKeyRSA{Buffer: wrongSig}}),
		}
		_, err = verifyCertifySignature(&attesterArea, certifyInfo, sig)
		require.ErrorIs(t, err, ErrCertifySignature)
	})

	t.Run("RSAPSS wrong key", func(t *testing.T) {
		legit := mustRSAKey(t)
		impostor := mustRSAKey(t)
		attesterArea := rsaPublicArea(t, legit, tpm2.TPMAlgRSAPSS)

		wrongSig, err := rsa.SignPSS(rand.Reader, impostor, crypto.SHA256, digest[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		require.NoError(t, err)

		sig := &tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSAPSS,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSAPSS,
				&tpm2.TPMSSignatureRSA{Hash: tpm2.TPMAlgSHA256, Sig: tpm2.TPM2BPublicKeyRSA{Buffer: wrongSig}}),
		}
		_, err = verifyCertifySignature(&attesterArea, certifyInfo, sig)
		require.ErrorIs(t, err, ErrCertifySignature)
	})

	t.Run("ECDSA wrong key", func(t *testing.T) {
		legit := mustECDSAKey(t)
		impostor := mustECDSAKey(t)
		attesterArea := eccPublicArea(t, legit, true)

		r, s, err := ecdsa.Sign(rand.Reader, impostor, digest[:])
		require.NoError(t, err)

		sig := &tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash:       tpm2.TPMAlgSHA256,
					SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
					SignatureS: tpm2.TPM2BECCParameter{Buffer: s.FillBytes(make([]byte, 32))},
				}),
		}
		_, err = verifyCertifySignature(&attesterArea, certifyInfo, sig)
		require.ErrorIs(t, err, ErrCertifySignature)
	})

	t.Run("unsupported signature algorithm", func(t *testing.T) {
		attesterArea := eccPublicArea(t, mustECDSAKey(t), true)
		sig := &tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgHMAC}
		_, err := verifyCertifySignature(&attesterArea, certifyInfo, sig)
		require.ErrorIs(t, err, ErrCertifyMalformed)
	})
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}
