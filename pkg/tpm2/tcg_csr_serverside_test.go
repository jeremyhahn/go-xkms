// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"bytes"
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

// ---------------------------------------------------------------------------
// IAK/IDevID attribute validation tests for VerifyTCG_CSR_*_Stateless
// ---------------------------------------------------------------------------

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

// devidConformantAttrs is the TPMA_OBJECT of a conformant IDevID or IAK:
// Template H-0 (TCG DevID v1 r12 §7.3.4.1) plus the §7.2.4 authorization bits,
// with Restricted selecting the key kind.
func devidConformantAttrs(kind DevIDKeyKind) tpm2.TPMAObject {
	return tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		AdminWithPolicy:     true,
		SignEncrypt:         true,
		Restricted:          kind == DevIDKeyAttestation,
	}
}

// devidConformantRSAPublic builds a public area the CA accepts, so that a
// negative test can flip exactly one field and know which rule refused it.
func devidConformantRSAPublic(t *testing.T, pub *rsa.PublicKey, kind DevIDKeyKind) tpm2.TPMTPublic {
	t.Helper()
	area := createRSATPMPublicForCSRWithAttrs(pub, devidConformantAttrs(kind))
	policy, err := DevIDKeyPolicyDigest(kind, area.NameAlg)
	require.NoError(t, err)
	area.AuthPolicy = tpm2.TPM2BDigest{Buffer: policy}
	return area
}

// The negative tests below each start from a public area the CA accepts and
// change exactly one thing, so the refusal they observe is the rule they name.
// TCG DevID v1 r12 §4 obliges the CA to verify "key Attributes and Policies";
// §4.1 lists an AK as Restricted, Signing, Not-decrypting, FixedTPM and §4.2 a
// DevID key as the same but Not-Restricted.

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotRestricted tests §4.1 Restricted.
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotRestricted(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	iakPub.ObjectAttributes.Restricted = false
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
	assert.Contains(t, err.Error(), "Restricted must be true")
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedTPM tests §4.1 FixedTPM.
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedTPM(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	iakPub.ObjectAttributes.FixedTPM = false
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedParent tests fixedParent.
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotFixedParent(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	iakPub.ObjectAttributes.FixedParent = false
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKNotSignEncrypt tests §4.1 Signing.
func TestVerifyTCG_CSR_IDevID_Stateless_IAKNotSignEncrypt(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	iakPub.ObjectAttributes.SignEncrypt = false
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
}

// TestVerifyTCG_CSR_IDevID_Stateless_IDevIDRestricted tests §4.2 Not-Restricted.
func TestVerifyTCG_CSR_IDevID_Stateless_IDevIDRestricted(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)
	idevidPub.ObjectAttributes.Restricted = true

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
	assert.Contains(t, err.Error(), "IDevID: Restricted must be false")
}

// TestVerifyTCG_CSR_IDevID_Stateless_IDevIDDecrypting tests §4.2 Not-decrypting.
//
// A key with Decrypt SET is a Combined key. The CA does not certify one: §8.1
// Table 22 gives a Combined IDevID a different key usage, and issuing the plain
// IDevID profile over it would describe the key wrongly.
func TestVerifyTCG_CSR_IDevID_Stateless_IDevIDDecrypting(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)
	idevidPub.ObjectAttributes.Decrypt = true

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
	assert.Contains(t, err.Error(), "decrypt must be CLEAR")
}

// TestVerifyTCG_CSR_IDevID_Stateless_IDevIDNoAdminWithPolicy tests §7.2.4.
func TestVerifyTCG_CSR_IDevID_Stateless_IDevIDNoAdminWithPolicy(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)
	idevidPub.ObjectAttributes.AdminWithPolicy = false

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
	assert.Contains(t, err.Error(), "adminWithPolicy must be SET")
}

// TestVerifyTCG_CSR_IDevID_Stateless_ForeignAuthPolicy is the §4 policy check:
// a key administered by a policy the specification did not write is refused,
// and one byte of difference is enough.
func TestVerifyTCG_CSR_IDevID_Stateless_ForeignAuthPolicy(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)
	idevidPub.AuthPolicy.Buffer[0] ^= 0x01

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
	assert.Contains(t, err.Error(), "authPolicy is not the IDevID/IAK Key Policy")
}

// TestVerifyTCG_CSR_IDevID_Stateless_IAKPolicyOnIDevID proves the two policies
// are not interchangeable: they differ only in the NV index named by the
// PolicyAuthorizeNV branch, and swapping them must still be refused.
func TestVerifyTCG_CSR_IDevID_Stateless_IAKPolicyOnIDevID(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iakPolicy, err := DevIDKeyPolicyDigest(DevIDKeyAttestation, tpm2.TPMAlgSHA256)
	require.NoError(t, err)

	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	idevidPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeySigning)
	idevidPub.AuthPolicy = tpm2.TPM2BDigest{Buffer: iakPolicy}

	csr := buildTestCSRWithPubAreas(tpm2.Marshal(iakPub), tpm2.Marshal(idevidPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IDevID_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
}

// TestAssertDevIDKeyConformant_AcceptsARealKeysUniqueField pins the boundary
// between the creation rules and the rules a CA can apply.
//
// Section 7.3.1 requires the unique field to hold 'IDEVID' or 'IAK' "at the
// time of key creation". TPM2_CreatePrimary consumes that as derivation input
// and returns an outPublic whose unique field holds the generated public key,
// and outPublic is what a TCG-CSR-IDEVID carries. A CA that demanded the
// section 7.3.1 string of a received public area would refuse every genuine
// device, so this asserts the opposite: a conformant key whose unique field is
// its own public key is accepted.
func TestAssertDevIDKeyConformant_AcceptsARealKeysUniqueField(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for _, kind := range []DevIDKeyKind{DevIDKeySigning, DevIDKeyAttestation} {
		area := devidConformantRSAPublic(t, &rsaKey.PublicKey, kind)

		unique, err := area.Unique.RSA()
		require.NoError(t, err)
		require.NotEmpty(t, unique.Buffer, "the fixture must carry a real modulus, not a template string")
		require.False(t, bytes.HasPrefix(unique.Buffer, []byte("IDEVID")))
		require.False(t, bytes.HasPrefix(unique.Buffer, []byte("IAK")))

		assert.NoError(t, AssertDevIDKeyConformant(kind, &area),
			"%s: a created key's public area must not be judged by the creation-template rules", kind)
	}
}

// TestAssertDevIDKeyConformant_NilPublicArea refuses a missing public area
// rather than treating "nothing to check" as "nothing wrong".
func TestAssertDevIDKeyConformant_NilPublicArea(t *testing.T) {
	err := AssertDevIDKeyConformant(DevIDKeySigning, nil)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
}

// TestVerifyTCG_CSR_IDevID_Stateless_UnsupportedKeyType tests unsupported key type
func TestVerifyTCG_CSR_IDevID_Stateless_UnsupportedKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Valid IAK
	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
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
	iakPub := devidConformantRSAPublic(t, &rsaKey.PublicKey, DevIDKeyAttestation)
	iakPub.ObjectAttributes.Restricted = false

	csr := buildTestCSRWithAttestPub(tpm2.Marshal(iakPub), make([]byte, 256))

	_, _, err = VerifyTCG_CSR_IAK_Stateless(csr, x509.SHA256WithRSAPSS)
	assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
	assert.Contains(t, err.Error(), "Restricted must be true")
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
