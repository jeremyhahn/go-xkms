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
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: eccPub.X.Bytes()},
				Y: tpm2.TPM2BECCParameter{Buffer: eccPub.Y.Bytes()},
			},
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
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: eccPub.X.Bytes()},
				Y: tpm2.TPM2BECCParameter{Buffer: eccPub.Y.Bytes()},
			},
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
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: eccPub.X.Bytes()},
				Y: tpm2.TPM2BECCParameter{Buffer: eccPub.Y.Bytes()},
			},
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
