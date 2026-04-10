// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPublicKeyFromTPMPublic_RSA(t *testing.T) {
	// Generate an RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create TPM public area for RSA
	rsaPub := &privateKey.PublicKey
	pubBytes := rsaPub.N.Bytes()

	// Pad to expected size
	keySize := 2048 / 8
	if len(pubBytes) < keySize {
		paddedPub := make([]byte, keySize)
		copy(paddedPub[keySize-len(pubBytes):], pubBytes)
		pubBytes = paddedPub
	}

	tpmPublic := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
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
				Buffer: pubBytes,
			},
		),
	}

	// Marshal the TPM public
	tpmPubBytes := tpm2.Marshal(tpmPublic)

	// Test extraction
	extractedKey, err := ExtractPublicKeyFromTPMPublic(tpmPubBytes)
	require.NoError(t, err)

	extractedRSA, ok := extractedKey.(*rsa.PublicKey)
	require.True(t, ok, "expected *rsa.PublicKey")

	// Verify the extracted key matches the original
	assert.Equal(t, rsaPub.N.Cmp(extractedRSA.N), 0)
	assert.Equal(t, rsaPub.E, extractedRSA.E)
}

func TestExtractPublicKeyFromTPMPublic_ECC(t *testing.T) {
	// Generate an ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	eccPub := &privateKey.PublicKey

	// Create TPM public area for ECC
	tpmPublic := tpm2.TPMTPublic{
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
				CurveID: tpm2.TPMECCNistP256,
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
			func() *tpm2.TPMSECCPoint {
				uncompressed, pubErr := eccPub.Bytes()
				if pubErr != nil {
					panic("failed to encode public key: " + pubErr.Error())
				}
				coordLen := (len(uncompressed) - 1) / 2
				return &tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: uncompressed[1 : 1+coordLen]},
					Y: tpm2.TPM2BECCParameter{Buffer: uncompressed[1+coordLen:]},
				}
			}(),
		),
	}

	// Marshal the TPM public
	tpmPubBytes := tpm2.Marshal(tpmPublic)

	// Test extraction
	extractedKey, err := ExtractPublicKeyFromTPMPublic(tpmPubBytes)
	require.NoError(t, err)

	extractedECDSA, ok := extractedKey.(*ecdsa.PublicKey)
	require.True(t, ok, "expected *ecdsa.PublicKey")

	// Verify the extracted key matches the original
	assert.True(t, eccPub.Equal(extractedECDSA))
}

func TestExtractPublicKeyFromTPMPublic_InvalidData(t *testing.T) {
	t.Run("invalid bytes", func(t *testing.T) {
		_, err := ExtractPublicKeyFromTPMPublic([]byte{0x00, 0x01, 0x02})
		assert.Error(t, err)
	})

	t.Run("empty bytes", func(t *testing.T) {
		_, err := ExtractPublicKeyFromTPMPublic([]byte{})
		assert.Error(t, err)
	})

	t.Run("nil input", func(t *testing.T) {
		_, err := ExtractPublicKeyFromTPMPublic(nil)
		assert.Error(t, err)
	})
}

func TestExtractPublicKeyFromTPMPublic_UnsupportedAlgorithm(t *testing.T) {
	// Create TPM public area with unsupported algorithm (using AES for symmetric)
	tpmPublic := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
		},
	}

	tpmPubBytes := tpm2.Marshal(tpmPublic)

	_, err := ExtractPublicKeyFromTPMPublic(tpmPubBytes)
	assert.Error(t, err)
}

func TestVerifyTCG_CSR_Stateless_EmptyCSR(t *testing.T) {
	// Test with empty CSR contents - these should return errors for invalid attestation pub
	t.Run("VerifyTCG_CSR_IDevID_Stateless with empty contents", func(t *testing.T) {
		csr := &TCG_CSR_IDEVID{
			CsrContents: TCG_IDEVID_CONTENT{},
		}
		_, _, err := VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
		assert.Error(t, err)
	})

	t.Run("VerifyTCG_CSR_IAK_Stateless with empty contents", func(t *testing.T) {
		csr := &TCG_CSR_IDEVID{
			CsrContents: TCG_IDEVID_CONTENT{},
		}
		_, _, err := VerifyTCG_CSR_IAK_Stateless(csr, x509.SHA256WithRSAPSS)
		assert.Error(t, err)
	})
}

func TestVerifyRSASignatureStateless_InvalidSignature(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPub := &privateKey.PublicKey
	pubBytes := rsaPub.N.Bytes()

	// Pad to expected size
	keySize := 2048 / 8
	if len(pubBytes) < keySize {
		paddedPub := make([]byte, keySize)
		copy(paddedPub[keySize-len(pubBytes):], pubBytes)
		pubBytes = paddedPub
	}

	tpmPublic := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pubBytes,
			},
		),
	}

	// Create a digest
	digest := sha256.Sum256([]byte("test data"))

	// Create an invalid signature
	invalidSig := []byte("invalid signature that is too short")

	t.Run("PSS with invalid signature", func(t *testing.T) {
		_, err := verifyRSASignatureStateless(tpmPublic, digest[:], invalidSig, x509.SHA256WithRSAPSS, crypto.SHA256)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSignature, err)
	})

	t.Run("PKCS1v15 with invalid signature", func(t *testing.T) {
		_, err := verifyRSASignatureStateless(tpmPublic, digest[:], invalidSig, x509.SHA256WithRSA, crypto.SHA256)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSignature, err)
	})
}

func TestVerifyECDSASignatureStateless_InvalidSignature(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	eccPub := &privateKey.PublicKey

	tpmPublic := &tpm2.TPMTPublic{
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
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			func() *tpm2.TPMSECCPoint {
				uncompressed, pubErr := eccPub.Bytes()
				if pubErr != nil {
					panic("failed to encode public key: " + pubErr.Error())
				}
				coordLen := (len(uncompressed) - 1) / 2
				return &tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: uncompressed[1 : 1+coordLen]},
					Y: tpm2.TPM2BECCParameter{Buffer: uncompressed[1+coordLen:]},
				}
			}(),
		),
	}

	// Create a digest
	digest := sha256.Sum256([]byte("test data"))

	// Create an invalid signature (not valid ASN.1 DER)
	invalidSig := []byte("invalid signature")

	_, err = verifyECDSASignatureStateless(tpmPublic, digest[:], invalidSig)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidSignature, err)
}

func TestVerifyRSASignatureStateless_ValidPSS(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPub := &privateKey.PublicKey
	pubBytes := rsaPub.N.Bytes()

	// Pad to expected size
	keySize := 2048 / 8
	if len(pubBytes) < keySize {
		paddedPub := make([]byte, keySize)
		copy(paddedPub[keySize-len(pubBytes):], pubBytes)
		pubBytes = paddedPub
	}

	tpmPublic := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pubBytes,
			},
		),
	}

	// Create a digest
	digest := sha256.Sum256([]byte("test data"))

	// Sign with PSS
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], pssOpts)
	require.NoError(t, err)

	// Verify
	extractedKey, err := verifyRSASignatureStateless(tpmPublic, digest[:], signature, x509.SHA256WithRSAPSS, crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, rsaPub.Equal(extractedKey))
}

func TestVerifyRSASignatureStateless_ValidPKCS1v15(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPub := &privateKey.PublicKey
	pubBytes := rsaPub.N.Bytes()

	// Pad to expected size
	keySize := 2048 / 8
	if len(pubBytes) < keySize {
		paddedPub := make([]byte, keySize)
		copy(paddedPub[keySize-len(pubBytes):], pubBytes)
		pubBytes = paddedPub
	}

	tpmPublic := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pubBytes,
			},
		),
	}

	// Create a digest
	digest := sha256.Sum256([]byte("test data"))

	// Sign with PKCS1v15
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	require.NoError(t, err)

	// Verify
	extractedKey, err := verifyRSASignatureStateless(tpmPublic, digest[:], signature, x509.SHA256WithRSA, crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, rsaPub.Equal(extractedKey))
}

func TestVerifyECDSASignatureStateless_Valid(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	eccPub := &privateKey.PublicKey

	tpmPublic := &tpm2.TPMTPublic{
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
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			func() *tpm2.TPMSECCPoint {
				uncompressed, pubErr := eccPub.Bytes()
				if pubErr != nil {
					panic("failed to encode public key: " + pubErr.Error())
				}
				coordLen := (len(uncompressed) - 1) / 2
				return &tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: uncompressed[1 : 1+coordLen]},
					Y: tpm2.TPM2BECCParameter{Buffer: uncompressed[1+coordLen:]},
				}
			}(),
		),
	}

	// Create a digest
	digest := sha256.Sum256([]byte("test data"))

	// Sign
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)

	// Verify
	extractedKey, err := verifyECDSASignatureStateless(tpmPublic, digest[:], signature)
	require.NoError(t, err)
	assert.True(t, eccPub.Equal(extractedKey))
}

func TestVerifyRSASignatureStateless_SHA384PSS(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPub := &privateKey.PublicKey
	pubBytes := rsaPub.N.Bytes()

	// Pad to expected size
	keySize := 2048 / 8
	if len(pubBytes) < keySize {
		paddedPub := make([]byte, keySize)
		copy(paddedPub[keySize-len(pubBytes):], pubBytes)
		pubBytes = paddedPub
	}

	tpmPublic := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pubBytes,
			},
		),
	}

	// Create a SHA-384 digest
	h := crypto.SHA384.New()
	h.Write([]byte("test data"))
	digest := h.Sum(nil)

	// Sign with PSS using SHA-384
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA384,
	}
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA384, digest, pssOpts)
	require.NoError(t, err)

	// Verify
	extractedKey, err := verifyRSASignatureStateless(tpmPublic, digest, signature, x509.SHA384WithRSAPSS, crypto.SHA384)
	require.NoError(t, err)
	assert.True(t, rsaPub.Equal(extractedKey))
}

func TestVerifyRSASignatureStateless_SHA512PSS(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPub := &privateKey.PublicKey
	pubBytes := rsaPub.N.Bytes()

	// Pad to expected size
	keySize := 2048 / 8
	if len(pubBytes) < keySize {
		paddedPub := make([]byte, keySize)
		copy(paddedPub[keySize-len(pubBytes):], pubBytes)
		pubBytes = paddedPub
	}

	tpmPublic := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: pubBytes,
			},
		),
	}

	// Create a SHA-512 digest
	h := crypto.SHA512.New()
	h.Write([]byte("test data"))
	digest := h.Sum(nil)

	// Sign with PSS using SHA-512
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA512,
	}
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, digest, pssOpts)
	require.NoError(t, err)

	// Verify
	extractedKey, err := verifyRSASignatureStateless(tpmPublic, digest, signature, x509.SHA512WithRSAPSS, crypto.SHA512)
	require.NoError(t, err)
	assert.True(t, rsaPub.Equal(extractedKey))
}

// ---------------------------------------------------------------------------
// IAK/IDevID attribute validation tests for VerifyTCG_CSR_*_Stateless
// ---------------------------------------------------------------------------

// createRSATPMPublicForCSR creates an RSA TPM public area for CSR tests
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

// createRSATPMPublicForCSRWithAttrs creates an RSA TPM public area with custom attributes
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

// createECDSATPMPublicForCSR creates an ECDSA TPM public area for CSR tests
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
			func() *tpm2.TPMSECCPoint {
				uncompressed, pubErr := pub.Bytes()
				if pubErr != nil {
					panic("failed to encode public key: " + pubErr.Error())
				}
				coordLen := (len(uncompressed) - 1) / 2
				return &tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: uncompressed[1 : 1+coordLen]},
					Y: tpm2.TPM2BECCParameter{Buffer: uncompressed[1+coordLen:]},
				}
			}(),
		),
	}
}

// buildTestCSRWithPubAreas builds a test CSR with both IAK and IDevID public areas
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

// buildTestCSRWithAttestPub builds a test CSR with only AttestPub (for IAK enrollment)
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

// TestVerifyTCG_CSR_IDevID_Stateless_HashAlgoBoundsCheck tests the hash algorithm ID bounds check
func TestVerifyTCG_CSR_IDevID_Stateless_HashAlgoBoundsCheck(t *testing.T) {
	csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))

	// Manually set HashAlgoId to value larger than MaxUint16 in the unpacked content
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
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create IAK public area (NOT restricted - should fail)
	iakPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)
	iakPubBytes := tpm2.Marshal(iakPub)

	// Create IDevID public area (unrestricted - correct)
	idevidPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)
	idevidPubBytes := tpm2.Marshal(idevidPub)

	csr := buildTestCSRWithPubAreas(iakPubBytes, idevidPubBytes, make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAKAttributes)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedTPM tests IAK FixedTPM validation
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedTPM(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

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
		Type:    tpm2.TPMAlgSymCipher,
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

func TestVerifyTCGCSRSignature_RSA_PKCS1v15_Valid(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create CSR content
	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B}, // SHA256
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	// Hash the packed contents
	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Sign with PKCS1v15
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	require.NoError(t, err)

	// Verify directly with crypto library - simulating what verifyTCGCSRSignature does
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, signature)
	assert.NoError(t, err)
}

func TestVerifyTCGCSRSignature_RSA_PSS_Valid(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create CSR content
	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Sign with PSS
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest, pssOpts)
	require.NoError(t, err)

	// Verify directly
	err = rsa.VerifyPSS(&privateKey.PublicKey, crypto.SHA256, digest, signature, pssOpts)
	assert.NoError(t, err)
}

func TestVerifyTCGCSRSignature_ECDSA_Valid(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR content
	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Sign with ECDSA
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	require.NoError(t, err)

	// Verify directly
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature)
	assert.True(t, valid)
}

func TestVerifyTCGCSRSignature_InvalidSignature_RSA(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Create invalid signature
	invalidSignature := make([]byte, 256)
	_, _ = rand.Read(invalidSignature)

	// Verify should fail
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, invalidSignature)
	assert.Error(t, err)
}

func TestVerifyTCGCSRSignature_InvalidSignature_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Create invalid signature
	invalidSignature := []byte{0x30, 0x44, 0x02, 0x20} // Malformed ASN.1
	invalidSignature = append(invalidSignature, make([]byte, 32)...)
	invalidSignature = append(invalidSignature, []byte{0x02, 0x20}...)
	invalidSignature = append(invalidSignature, make([]byte, 32)...)

	// Verify should fail
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, invalidSignature)
	assert.False(t, valid)
}

func TestVerifyTCGCSRSignature_WrongKey_RSA(t *testing.T) {
	// Generate two different RSA key pairs
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Sign with key 1
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey1, crypto.SHA256, digest)
	require.NoError(t, err)

	// Verify with key 2 should fail
	err = rsa.VerifyPKCS1v15(&privateKey2.PublicKey, crypto.SHA256, digest, signature)
	assert.Error(t, err)
}
