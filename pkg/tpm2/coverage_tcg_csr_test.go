// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"crypto/x509"
	"encoding/binary"
	"math"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyTCG_CSR_IDevID_Stateless_HashAlgoBoundsCheck tests the hash algorithm ID bounds check
func TestVerifyTCG_CSR_IDevID_Stateless_HashAlgoBoundsCheck(t *testing.T) {
	// Create CSR with hash algorithm ID that exceeds uint16 max
	csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))

	// Manually set HashAlgoId to value larger than MaxUint16 in the unpacked content
	// This tests the bounds check: if unpacked.CsrContents.HashAlgoId > math.MaxUint16
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], math.MaxUint16+1)

	_, _, err := VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hash algorithm ID too large")
}

// TestVerifyTCG_CSR_IAK_Stateless_HashAlgoBoundsCheck tests IAK bounds check
func TestVerifyTCG_CSR_IAK_Stateless_HashAlgoBoundsCheck(t *testing.T) {
	csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], math.MaxUint16+1)

	_, _, err := VerifyTCG_CSR_IAK_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hash algorithm ID too large")
}

// TestVerifyTCG_CSR_IDevID_Stateless_InvalidHashAlgo tests invalid hash algorithm handling
func TestVerifyTCG_CSR_IDevID_Stateless_InvalidHashAlgo(t *testing.T) {
	csr := createMinimalTCGCSRIDevIDCoverage(0xFFFF, make([]byte, 64)) // Invalid hash algo
	_, _, err := VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotRestricted tests IAK attribute validation
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotRestricted(t *testing.T) {
	// Generate RSA key pair for signing
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create IAK public area (NOT restricted - should fail)
	iakPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false) // Not restricted
	iakPubBytes := tpm2.Marshal(iakPub)

	// Create IDevID public area (unrestricted - correct)
	idevidPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false) // Unrestricted
	idevidPubBytes := tpm2.Marshal(idevidPub)

	// Build CSR with proper public areas
	csr := buildTestCSRWithPubAreas(iakPubBytes, idevidPubBytes, make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAKAttributes)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedTPM tests IAK FixedTPM validation
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedTPM(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create IAK that is restricted but NOT FixedTPM
	iakPub := createRSATPMPublicForCSRWithAttrs(&rsaKey.PublicKey, tpm2.TPMAObject{
		Restricted:          true,
		FixedTPM:            false, // Should fail
		FixedParent:         true,
		SignEncrypt:         true,
		SensitiveDataOrigin: true,
	})
	iakPubBytes := tpm2.Marshal(iakPub)

	idevidPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)
	idevidPubBytes := tpm2.Marshal(idevidPub)

	csr := buildTestCSRWithPubAreas(iakPubBytes, idevidPubBytes, make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAKAttributes)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedParent tests IAK FixedParent validation
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedParent(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := createRSATPMPublicForCSRWithAttrs(&rsaKey.PublicKey, tpm2.TPMAObject{
		Restricted:          true,
		FixedTPM:            true,
		FixedParent:         false, // Should fail
		SignEncrypt:         true,
		SensitiveDataOrigin: true,
	})
	iakPubBytes := tpm2.Marshal(iakPub)

	idevidPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)
	idevidPubBytes := tpm2.Marshal(idevidPub)

	csr := buildTestCSRWithPubAreas(iakPubBytes, idevidPubBytes, make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAKAttributes)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotSignEncrypt tests IAK SignEncrypt validation
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotSignEncrypt(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := createRSATPMPublicForCSRWithAttrs(&rsaKey.PublicKey, tpm2.TPMAObject{
		Restricted:          true,
		FixedTPM:            true,
		FixedParent:         true,
		SignEncrypt:         false, // Should fail - no signing capability
		SensitiveDataOrigin: true,
	})
	iakPubBytes := tpm2.Marshal(iakPub)

	idevidPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)
	idevidPubBytes := tpm2.Marshal(idevidPub)

	csr := buildTestCSRWithPubAreas(iakPubBytes, idevidPubBytes, make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAKAttributes)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IDevIDRestricted tests IDevID must NOT be restricted
func TestVerifyTCG_CSR_IDevID_Stateless_IDevIDRestricted(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Valid IAK (restricted)
	iakPub := createRSATPMPublicForCSRWithAttrs(&rsaKey.PublicKey, tpm2.TPMAObject{
		Restricted:          true,
		FixedTPM:            true,
		FixedParent:         true,
		SignEncrypt:         true,
		SensitiveDataOrigin: true,
	})
	iakPubBytes := tpm2.Marshal(iakPub)

	// Invalid IDevID (restricted - should fail)
	idevidPub := createRSATPMPublicForCSRWithAttrs(&rsaKey.PublicKey, tpm2.TPMAObject{
		Restricted:          true, // IDevID must NOT be restricted
		FixedTPM:            true,
		FixedParent:         true,
		SignEncrypt:         true,
		SensitiveDataOrigin: true,
	})
	idevidPubBytes := tpm2.Marshal(idevidPub)

	csr := buildTestCSRWithPubAreas(iakPubBytes, idevidPubBytes, make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAKAttributes)
}

// TestVerifyTCG_CSR_IDevID_Stateless_UnsupportedKeyType tests unsupported key type
func TestVerifyTCG_CSR_IDevID_Stateless_UnsupportedKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Valid IAK
	iakPub := createRSATPMPublicForCSRWithAttrs(&rsaKey.PublicKey, tpm2.TPMAObject{
		Restricted:          true,
		FixedTPM:            true,
		FixedParent:         true,
		SignEncrypt:         true,
		SensitiveDataOrigin: true,
	})
	iakPubBytes := tpm2.Marshal(iakPub)

	// Create IDevID with unsupported algorithm type (SymCipher)
	symPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher, // Unsupported for signing
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
		},
	}
	symPubBytes := tpm2.Marshal(symPub)

	csr := buildTestCSRWithPubAreas(iakPubBytes, symPubBytes, make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
}

// TestVerifyTCG_CSR_IAK_Stateless_NotRestricted tests IAK enrollment attribute validation
func TestVerifyTCG_CSR_IAK_Stateless_NotRestricted(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// IAK NOT restricted - should fail for IAK enrollment strategy
	iakPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)
	iakPubBytes := tpm2.Marshal(iakPub)

	csr := buildTestCSRWithAttestPub(iakPubBytes, make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IAK_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAKAttributes)
}

// TestVerifyTCG_CSR_IAK_Stateless_UnsupportedKeyType tests unsupported key type for IAK
func TestVerifyTCG_CSR_IAK_Stateless_UnsupportedKeyType(t *testing.T) {
	symPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:  true,
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
		},
	}
	symPubBytes := tpm2.Marshal(symPub)

	csr := buildTestCSRWithAttestPub(symPubBytes, make([]byte, 256))

	_, _, err := VerifyTCG_CSR_IAK_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
}

// TestExtractPublicKeyFromTPMPublic_Errors tests error paths
func TestExtractPublicKeyFromTPMPublic_Errors(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		_, err := ExtractPublicKeyFromTPMPublic(nil)
		assert.Error(t, err)
	})

	t.Run("invalid TPM public data", func(t *testing.T) {
		_, err := ExtractPublicKeyFromTPMPublic([]byte{0x00, 0x01, 0x02, 0x03})
		assert.Error(t, err)
	})

	t.Run("unsupported key type", func(t *testing.T) {
		symPub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
		}
		pubBytes := tpm2.Marshal(symPub)
		_, err := ExtractPublicKeyFromTPMPublic(pubBytes)
		assert.Error(t, err)
	})
}

// TestVerifyTCG_CSR_IDevID_Wrapper tests the convenience wrapper function
func TestVerifyTCG_CSR_IDevID_Wrapper(t *testing.T) {
	csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))
	_, _, err := VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
	// Should error (invalid CSR content) but tests the wrapper path
	assert.Error(t, err)
}

// TestVerifyTCG_CSR_IAK_Wrapper tests the convenience wrapper function
func TestVerifyTCG_CSR_IAK_Wrapper(t *testing.T) {
	csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))
	_, _, err := VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
}

// TestVerifyRSASignatureStateless_AllPSSVariants tests all PSS hash variants
func TestVerifyRSASignatureStateless_AllPSSVariants(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		hash    crypto.Hash
	}{
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, crypto.SHA256},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, crypto.SHA384},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS, crypto.SHA512},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpmPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)

			h := tc.hash.New()
			h.Write([]byte("test data"))
			digest := h.Sum(nil)

			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       tc.hash,
			}
			signature, err := rsa.SignPSS(rand.Reader, rsaKey, tc.hash, digest, pssOpts)
			require.NoError(t, err)

			extractedKey, err := verifyRSASignatureStateless(&tpmPub, digest, signature, tc.sigAlgo, tc.hash)
			require.NoError(t, err)
			assert.NotNil(t, extractedKey)
		})
	}
}

// TestVerifyRSASignatureStateless_PKCS1v15Default tests default PKCS#1 v1.5
func TestVerifyRSASignatureStateless_PKCS1v15Default(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tpmPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)

	digest := sha256.Sum256([]byte("test data"))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	require.NoError(t, err)

	// Use a non-PSS algorithm to trigger PKCS#1 v1.5 branch
	extractedKey, err := verifyRSASignatureStateless(&tpmPub, digest[:], signature, x509.SHA256WithRSA, crypto.SHA256)
	require.NoError(t, err)
	assert.NotNil(t, extractedKey)
}

// TestVerifyECDSASignatureStateless_AllCurves tests ECDSA with different curves
func TestVerifyECDSASignatureStateless_AllCurves(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			tpmPub := createECDSATPMPublicForCSR(&ecKey.PublicKey)

			digest := sha256.Sum256([]byte("test data"))
			signature, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
			require.NoError(t, err)

			extractedKey, err := verifyECDSASignatureStateless(&tpmPub, digest[:], signature)
			require.NoError(t, err)
			assert.NotNil(t, extractedKey)
		})
	}
}

// TestVerifyECDSASignatureStateless_InvalidSignature_Cov tests ECDSA signature validation
func TestVerifyECDSASignatureStateless_InvalidSignature_Cov(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tpmPub := createECDSATPMPublicForCSR(&ecKey.PublicKey)

	digest := sha256.Sum256([]byte("test data"))
	invalidSig := []byte("not a valid ECDSA signature")

	_, err = verifyECDSASignatureStateless(&tpmPub, digest[:], invalidSig)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

// Helper function to create RSA TPM public for CSR tests
func createRSATPMPublicForCSR(pub *rsa.PublicKey, restricted bool) tpm2.TPMTPublic {
	modBytes := pub.N.Bytes()
	keySize := 2048 / 8
	if len(modBytes) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(modBytes):], modBytes)
		modBytes = padded
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          restricted,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: modBytes,
			},
		),
	}
}

// Helper function to create RSA TPM public with custom attributes
func createRSATPMPublicForCSRWithAttrs(pub *rsa.PublicKey, attrs tpm2.TPMAObject) tpm2.TPMTPublic {
	modBytes := pub.N.Bytes()
	keySize := 2048 / 8
	if len(modBytes) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(modBytes):], modBytes)
		modBytes = padded
	}

	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: modBytes,
			},
		),
	}
}

// Helper function to create ECDSA TPM public for CSR tests
func createECDSATPMPublicForCSR(pub *ecdsa.PublicKey) tpm2.TPMTPublic {
	var curveID tpm2.TPMECCCurve
	switch pub.Curve {
	case elliptic.P256():
		curveID = tpm2.TPMECCNistP256
	case elliptic.P384():
		curveID = tpm2.TPMECCNistP384
	case elliptic.P521():
		curveID = tpm2.TPMECCNistP521
	default:
		curveID = tpm2.TPMECCNistP256
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: curveID,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: pub.X.Bytes()},
				Y: tpm2.TPM2BECCParameter{Buffer: pub.Y.Bytes()},
			},
		),
	}
}

// Helper function to build test CSR with both IAK and IDevID public areas
func buildTestCSRWithPubAreas(iakPubBytes, idevidPubBytes, signature []byte) *TCG_CSR_IDEVID {
	csr := &TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))
	csr.Signature = signature

	content := &csr.CsrContents
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)
	binary.BigEndian.PutUint32(content.ProdModelSz[:], 4)
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], 3)
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(content.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(iakPubBytes)))
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(idevidPubBytes)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.PadSz[:], 0)

	content.ProdModel = []byte("test")
	content.ProdSerial = []byte("001")
	content.ProdCaData = []byte{}
	content.BootEvntLog = []byte{}
	content.EkCert = []byte{}
	content.AttestPub = iakPubBytes
	content.AtCreateTkt = []byte{}
	content.AtCertifyInfo = []byte{}
	content.AtCertifyInfoSig = []byte{}
	content.SigningPub = idevidPubBytes
	content.SgnCertifyInfo = []byte{}
	content.SgnCertifyInfoSig = []byte{}
	content.Pad = []byte{}

	return csr
}

// Helper function to build test CSR with only AttestPub (for IAK enrollment)
func buildTestCSRWithAttestPub(iakPubBytes, signature []byte) *TCG_CSR_IDEVID {
	csr := &TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))
	csr.Signature = signature

	content := &csr.CsrContents
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)
	binary.BigEndian.PutUint32(content.ProdModelSz[:], 4)
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], 3)
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(content.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(iakPubBytes)))
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.PadSz[:], 0)

	content.ProdModel = []byte("test")
	content.ProdSerial = []byte("001")
	content.ProdCaData = []byte{}
	content.BootEvntLog = []byte{}
	content.EkCert = []byte{}
	content.AttestPub = iakPubBytes
	content.AtCreateTkt = []byte{}
	content.AtCertifyInfo = []byte{}
	content.AtCertifyInfoSig = []byte{}
	content.SigningPub = []byte{}
	content.SgnCertifyInfo = []byte{}
	content.SgnCertifyInfoSig = []byte{}
	content.Pad = []byte{}

	return csr
}

// Note: TestCreateTCG_CSR_IDEVID_InvalidEnrollmentStrategy is not possible because
// ParseIdentityProvisioningStrategy always returns a valid strategy (defaults to IAK_IDEVID_SINGLE_PASS)
// The ErrInvalidEnrollmentStrategy code path in CreateTCG_CSR_IDEVID is unreachable.

// TestCreateTCG_CSR_IDEVID_NilEKCert tests that CreateTCG_CSR_IDEVID
// returns an error when EK certificate is nil
func TestCreateTCG_CSR_IDEVID_NilEKCert(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)

	// Set valid enrollment strategy
	originalStrategy := tpm2Impl.config.IdentityProvisioningStrategy
	tpm2Impl.config.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK)
	defer func() { tpm2Impl.config.IdentityProvisioningStrategy = originalStrategy }()

	// Ensure IDevID config exists
	if tpm2Impl.config.IDevID == nil {
		tpm2Impl.config.IDevID = &IDevIDConfig{
			Model:  "test-model",
			Serial: "test-serial",
		}
	}

	akAttrs := createMockKeyAttributesForCSR(t)
	idevidAttrs := createMockKeyAttributesForCSR(t)

	// Should fail with nil EK certificate
	_, err := tpm.CreateTCG_CSR_IDEVID(nil, akAttrs, idevidAttrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidEKCert)
}

// Helper to create mock key attributes for CSR tests
func createMockKeyAttributesForCSR(t *testing.T) *types.KeyAttributes {
	return &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSAAKTemplate),
			CreationTicketDigest: []byte("creation-ticket-digest"),
			CertifyInfo:          []byte("certify-info"),
			Signature:            []byte("signature"),
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}
}
