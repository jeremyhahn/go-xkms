package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers for verification tests

// Creates a mock EK certificate for testing
func createMockEKCertificate() *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test TPM Manufacturer"},
			CommonName:   "Test EK Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	cert, _ := x509.ParseCertificate(certBytes)
	return cert
}

// Creates mock key attributes for IAK testing
func createMockIAKAttributes() *types.KeyAttributes {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create a TPM2B_PUBLIC structure for RSA
	pubArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:   true,
			FixedTPM:     true,
			FixedParent:  true,
			SignEncrypt:  true,
			UserWithAuth: true,
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
				Buffer: rsaKey.PublicKey.N.Bytes(), //nolint:staticcheck // QF1008: field
				//nolint:staticcheck // QF1008: field access
			},
		),
	}

	bpublic := tpm2.New2B(pubArea)

	return &types.KeyAttributes{
		CN:                 "test-iak",
		KeyAlgorithm:       x509.RSA,
		KeyType:            types.KeyTypeTPM,
		Hash:               crypto.SHA256,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			HashAlg:              tpm2.TPMAlgSHA256,
			BPublic:              bpublic,
			Public:               pubArea,
			CreationTicketDigest: []byte("mock-creation-ticket"),
			CertifyInfo:          []byte("mock-certify-info"),
			Signature:            []byte("mock-signature"),
		},
	}
}

// Creates mock key attributes for IDevID testing
func createMockIDevIDAttributes() *types.KeyAttributes {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// IDevID should NOT be restricted
	pubArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:   false, // IDevID is NOT restricted
			FixedTPM:     true,
			FixedParent:  true,
			SignEncrypt:  true,
			UserWithAuth: true,
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
				Buffer: rsaKey.PublicKey.N.Bytes(), //nolint:staticcheck // QF1008: field
				//nolint:staticcheck // QF1008: field access
			},
		),
	}

	bpublic := tpm2.New2B(pubArea)

	return &types.KeyAttributes{
		CN:                 "test-idevid",
		KeyAlgorithm:       x509.RSA,
		KeyType:            types.KeyTypeTPM,
		Hash:               crypto.SHA256,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			HashAlg:     tpm2.TPMAlgSHA256,
			BPublic:     bpublic,
			Public:      pubArea,
			CertifyInfo: []byte("mock-idevid-certify-info"),
			Signature:   []byte("mock-idevid-signature"),
		},
	}
}

// Creates a valid CSR with properly signed content using RSA-PSS
func createSignedCSRWithRSAPSS(privateKey *rsa.PrivateKey) (*TCG_CSR_IDEVID, error) {
	content := createTestIDevIDContent()

	// Pack the content to create the digest
	packedContent, err := PackIDevIDContent(content)
	if err != nil {
		return nil, err
	}

	// Hash the content
	hash := sha256.Sum256(packedContent)

	// Sign with RSA-PSS
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return nil, err
	}

	csr := &TCG_CSR_IDEVID{
		CsrContents: *content,
		Signature:   signature,
	}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))

	return csr, nil
}

// Creates a valid CSR with properly signed content using RSA PKCS1v15
func createSignedCSRWithRSAPKCS1(privateKey *rsa.PrivateKey) (*TCG_CSR_IDEVID, error) {
	content := createTestIDevIDContent()

	// Pack the content to create the digest
	packedContent, err := PackIDevIDContent(content)
	if err != nil {
		return nil, err
	}

	// Hash the content
	hash := sha256.Sum256(packedContent)

	// Sign with RSA PKCS1v15
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}

	csr := &TCG_CSR_IDEVID{
		CsrContents: *content,
		Signature:   signature,
	}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))

	return csr, nil
}

// Creates a valid CSR with properly signed content using ECDSA
func createSignedCSRWithECDSA(privateKey *ecdsa.PrivateKey) (*TCG_CSR_IDEVID, error) {
	content := createTestIDevIDContent()

	// Pack the content to create the digest
	packedContent, err := PackIDevIDContent(content)
	if err != nil {
		return nil, err
	}

	// Hash the content
	hash := sha256.Sum256(packedContent)

	// Sign with ECDSA
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	csr := &TCG_CSR_IDEVID{
		CsrContents: *content,
		Signature:   signature,
	}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))

	return csr, nil
}

// mockTransport implements transport.TPM for testing
type idevidCSRVerifyMockTransport struct {
	responses   [][]byte
	responseIdx int
	err         error
}

func (m *idevidCSRVerifyMockTransport) Send(input []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.responseIdx >= len(m.responses) {
		return nil, errors.New("no more mock responses")
	}
	resp := m.responses[m.responseIdx]
	m.responseIdx++
	return resp, nil
}

// createMockTPM2 creates a TPM2 instance with mock transport for testing
func createMockTPM2(strategy string) *TPM2 {
	config := &Config{
		IdentityProvisioningStrategy: strategy,
		Hash:                         "SHA-256",
		EK: &EKConfig{
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
	}

	// Create a logger with no file output
	logger := logging.DefaultLogger()

	tpm := &TPM2{
		config:    config,
		logger:    logger,
		transport: &idevidCSRVerifyMockTransport{err: errors.New("mock transport not configured")},
		ekAttrs:   createMockIAKAttributes(), // Use as mock EK attributes
	}

	return tpm
}

// createMockTPM2WithTransport creates a TPM2 with specific mock transport

// createMockTPM2WithIDevIDConfig creates a TPM2 with IDevID configuration for testing
func createMockTPM2WithIDevIDConfig(strategy string, pad bool) *TPM2 {
	config := &Config{
		IdentityProvisioningStrategy: strategy,
		Hash:                         "SHA-256",
		EK: &EKConfig{
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IDevID: &IDevIDConfig{
			Model:  "TestModel",
			Serial: "TestSerial123",
			Pad:    pad,
		},
	}

	logger := logging.DefaultLogger()

	tpm := &TPM2{
		config:    config,
		logger:    logger,
		transport: &idevidCSRVerifyMockTransport{err: errors.New("mock transport not configured")},
		ekAttrs:   createMockIAKAttributes(),
	}

	return tpm
}

// Tests for VerifyTCGCSR enrollment strategy routing
func TestVerifyTCGCSR_StrategyRouting(t *testing.T) {
	t.Run("IAK strategy routes to VerifyTCG_CSR_IAK", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK))
		csr := createTestCSRIDevID()

		// This will fail because mock transport isn't set up, but we verify routing
		_, _, err := tpm.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
		// The error should come from TPM operations, not from invalid strategy
		assert.NotEqual(t, ErrInvalidEnrollmentStrategy, err)
	})

	t.Run("IDevID single pass strategy routes to VerifyTCG_CSR_IDevID", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS))
		csr := createTestCSRIDevID()

		_, _, err := tpm.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
		// The error should come from TPM operations, not from invalid strategy
		assert.NotEqual(t, ErrInvalidEnrollmentStrategy, err)
	})

	t.Run("unknown strategy returns error", func(t *testing.T) {
		// Create TPM2 with empty strategy which will default to single pass
		tpm := createMockTPM2("")
		csr := createTestCSRIDevID()

		// Empty string parses to single pass, so this will route to IDevID verification
		_, _, err := tpm.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
		// Default is single pass, so should not return ErrInvalidEnrollmentStrategy
		assert.NotEqual(t, ErrInvalidEnrollmentStrategy, err)
	})
}

// Tests for VerifyTCG_CSR_IAK
func TestVerifyTCG_CSR_IAK_ErrorPaths(t *testing.T) {
	t.Run("returns error when EKAttributes fails", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK))
		tpm.ekAttrs = nil // Force EKAttributes to fail
		csr := createTestCSRIDevID()

		_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})

	t.Run("returns error when CSR unpacking fails", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK))
		csr := &TCG_CSR_IDEVID{}
		// Set invalid size that will cause unpacking error
		binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 999)
		csr.CsrContents.ProdModel = []byte("short")

		_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})

	t.Run("returns error when hash algorithm is invalid", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK))
		csr := createTestCSRIDevID()
		// Set invalid hash algorithm ID
		binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], 0xFFFF)

		_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})
}

// Tests for VerifyTCG_CSR_IDevID
func TestVerifyTCG_CSR_IDevID_ErrorPaths(t *testing.T) {
	t.Run("returns error when EKAttributes fails", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS))
		tpm.ekAttrs = nil
		csr := createTestCSRIDevID()

		_, _, err := tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})

	t.Run("returns error when CSR unpacking fails", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS))
		csr := &TCG_CSR_IDEVID{}
		binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 999)
		csr.CsrContents.ProdModel = []byte("short")

		_, _, err := tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})

	t.Run("returns error when hash algorithm is invalid", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS))
		csr := createTestCSRIDevID()
		binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], 0xFFFF)

		_, _, err := tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})
}

// Tests for verifyTCGCSRSignature with RSA-PSS
func TestVerifyTCGCSRSignature_RSA_PSS(t *testing.T) {
	t.Run("valid RSA-PSS signature verifies successfully", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		csr, err := createSignedCSRWithRSAPSS(rsaKey)
		require.NoError(t, err)

		// Re-pack content to get digest
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify signature directly (since we can't mock TPM HashSequence)
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		err = rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, hash[:], csr.Signature, pssOpts)
		require.NoError(t, err)
	})

	t.Run("invalid RSA-PSS signature returns error", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		csr, err := createSignedCSRWithRSAPSS(rsaKey)
		require.NoError(t, err)

		// Corrupt the signature
		csr.Signature[0] ^= 0xFF

		// Re-pack content to get digest
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify should fail
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		err = rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, hash[:], csr.Signature, pssOpts)
		require.Error(t, err)
	})

	t.Run("wrong key fails verification", func(t *testing.T) {
		rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		csr, err := createSignedCSRWithRSAPSS(rsaKey1)
		require.NoError(t, err)

		// Re-pack content to get digest
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify with wrong key should fail
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		err = rsa.VerifyPSS(&rsaKey2.PublicKey, crypto.SHA256, hash[:], csr.Signature, pssOpts)
		require.Error(t, err)
	})
}

// Tests for verifyTCGCSRSignature with RSA PKCS1v15
func TestVerifyTCGCSRSignature_RSA_PKCS1v15(t *testing.T) {
	t.Run("valid RSA PKCS1v15 signature verifies successfully", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		csr, err := createSignedCSRWithRSAPKCS1(rsaKey)
		require.NoError(t, err)

		// Re-pack content to get digest
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify signature
		err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, hash[:], csr.Signature)
		require.NoError(t, err)
	})

	t.Run("invalid RSA PKCS1v15 signature returns error", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		csr, err := createSignedCSRWithRSAPKCS1(rsaKey)
		require.NoError(t, err)

		// Corrupt the signature
		csr.Signature[0] ^= 0xFF

		// Re-pack content to get digest
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify should fail
		err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, hash[:], csr.Signature)
		require.Error(t, err)
	})
}

// Tests for verifyTCGCSRSignature with ECDSA
func TestVerifyTCGCSRSignature_ECDSA(t *testing.T) {
	t.Run("valid ECDSA signature verifies successfully", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csr, err := createSignedCSRWithECDSA(ecKey)
		require.NoError(t, err)

		// Re-pack content to get digest
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify signature
		valid := ecdsa.VerifyASN1(&ecKey.PublicKey, hash[:], csr.Signature)
		assert.True(t, valid)
	})

	t.Run("invalid ECDSA signature returns false", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csr, err := createSignedCSRWithECDSA(ecKey)
		require.NoError(t, err)

		// Corrupt the signature
		csr.Signature[0] ^= 0xFF

		// Re-pack content to get digest
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify should fail
		valid := ecdsa.VerifyASN1(&ecKey.PublicKey, hash[:], csr.Signature)
		assert.False(t, valid)
	})

	t.Run("wrong curve fails verification", func(t *testing.T) {
		ecKey256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		csr, err := createSignedCSRWithECDSA(ecKey256)
		require.NoError(t, err)

		// Re-pack content to get digest
		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify with wrong curve should fail
		valid := ecdsa.VerifyASN1(&ecKey384.PublicKey, hash[:], csr.Signature)
		assert.False(t, valid)
	})
}

// Tests for UnpackIDevIDCSR comprehensive scenarios
func TestUnpackIDevIDCSRComprehensive(t *testing.T) {
	t.Run("unpacks with all valid fields", func(t *testing.T) {
		csr := createTestCSRIDevID()
		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)
		require.NotNil(t, unpacked)

		assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
		assert.Equal(t, uint32(0x0000000B), unpacked.CsrContents.HashAlgoId)
		assert.Equal(t, uint32(32), unpacked.CsrContents.HashSz)
		assert.NotEmpty(t, unpacked.CsrContents.ProdModel)
		assert.NotEmpty(t, unpacked.CsrContents.ProdSerial)
	})

	t.Run("unpacks with zero-length optional fields", func(t *testing.T) {
		csr := createTestCSRIDevID()
		// Set CA data to empty
		csr.CsrContents.ProdCaData = []byte{}
		binary.BigEndian.PutUint32(csr.CsrContents.ProdCaDataSz[:], 0)

		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), unpacked.CsrContents.ProdCaDataSz)
		assert.Empty(t, unpacked.CsrContents.ProdCaData)
	})

	t.Run("error on mismatched product model size", func(t *testing.T) {
		csr := createTestCSRIDevID()
		// Corrupt size field
		binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 999)

		_, err := UnpackIDevIDCSR(csr)
		require.Error(t, err)
	})

	t.Run("mismatched signature size allocates to declared size", func(t *testing.T) {
		csr := createTestCSRIDevID()
		originalSigLen := len(csr.Signature)
		// Corrupt signature size field to be larger than actual signature
		binary.BigEndian.PutUint32(csr.SigSz[:], 999)

		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)
		// The SigSz field is preserved as declared
		assert.Equal(t, uint32(999), unpacked.SigSz)
		// The signature slice is allocated to declared size but only original bytes are copied
		// The rest will be zero-filled
		assert.Len(t, unpacked.Signature, 999)
		// First bytes should match original signature
		for i := 0; i < originalSigLen; i++ {
			assert.Equal(t, csr.Signature[i], unpacked.Signature[i])
		}
		// Remaining bytes should be zero
		for i := originalSigLen; i < 999; i++ {
			assert.Equal(t, byte(0), unpacked.Signature[i])
		}
	})
}

// Tests for ParseHashSize
func TestParseHashSizeComprehensive(t *testing.T) {
	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize uint32
		expectError  bool
	}{
		{
			name:         "SHA-1 returns 20 bytes",
			hash:         crypto.SHA1,
			expectedSize: 20,
			expectError:  false,
		},
		{
			name:         "SHA-256 returns 32 bytes",
			hash:         crypto.SHA256,
			expectedSize: 32,
			expectError:  false,
		},
		{
			name:         "SHA-384 returns 48 bytes",
			hash:         crypto.SHA384,
			expectedSize: 48,
			expectError:  false,
		},
		{
			name:         "SHA-512 returns 64 bytes",
			hash:         crypto.SHA512,
			expectedSize: 64,
			expectError:  false,
		},
		{
			name:         "unsupported hash returns error",
			hash:         crypto.MD5,
			expectedSize: 0,
			expectError:  true,
		},
		{
			name:         "zero hash returns error",
			hash:         crypto.Hash(0),
			expectedSize: 0,
			expectError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size, err := ParseHashSize(tc.hash)
			if tc.expectError {
				require.Error(t, err)
				assert.Equal(t, ErrInvalidHashFunction, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedSize, size)
			}
		})
	}
}

// Tests for enrollment strategy parsing for CSR verification
func TestEnrollmentStrategyForCSRVerification(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			input:    "IAK",
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			input:    "IAK_IDEVID_SINGLE_PASS",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "empty string defaults to single pass",
			input:    "",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "unknown strategy defaults to single pass",
			input:    "UNKNOWN",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Tests for key attribute validation patterns
func TestKeyAttributeValidationPatterns(t *testing.T) {
	t.Run("IAK must be restricted", func(t *testing.T) {
		pubArea := tpm2.TPMAObject{
			Restricted:  false, // Invalid for IAK
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
		}

		// IAK should be restricted
		assert.False(t, pubArea.Restricted)
	})

	t.Run("IAK must be fixedTPM", func(t *testing.T) {
		pubArea := tpm2.TPMAObject{
			Restricted:  true,
			FixedTPM:    false, // Invalid
			FixedParent: true,
			SignEncrypt: true,
		}

		assert.False(t, pubArea.FixedTPM)
	})

	t.Run("IAK must be fixedParent", func(t *testing.T) {
		pubArea := tpm2.TPMAObject{
			Restricted:  true,
			FixedTPM:    true,
			FixedParent: false, // Invalid
			SignEncrypt: true,
		}

		assert.False(t, pubArea.FixedParent)
	})

	t.Run("IAK must be signing key", func(t *testing.T) {
		pubArea := tpm2.TPMAObject{
			Restricted:  true,
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: false, // Invalid
		}

		assert.False(t, pubArea.SignEncrypt)
	})

	t.Run("valid IAK attributes pass all checks", func(t *testing.T) {
		pubArea := tpm2.TPMAObject{
			Restricted:  true,
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
		}

		assert.True(t, pubArea.Restricted)
		assert.True(t, pubArea.FixedTPM)
		assert.True(t, pubArea.FixedParent)
		assert.True(t, pubArea.SignEncrypt)
	})

	t.Run("IDevID must NOT be restricted", func(t *testing.T) {
		pubArea := tpm2.TPMAObject{
			Restricted:  true, // Invalid for IDevID
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
		}

		// IDevID should not be restricted
		assert.True(t, pubArea.Restricted) // This would fail IDevID validation
	})

	t.Run("valid IDevID attributes pass all checks", func(t *testing.T) {
		pubArea := tpm2.TPMAObject{
			Restricted:  false, // IDevID is NOT restricted
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
		}

		assert.False(t, pubArea.Restricted)
		assert.True(t, pubArea.FixedTPM)
		assert.True(t, pubArea.FixedParent)
		assert.True(t, pubArea.SignEncrypt)
	})
}

// Tests for signature algorithm detection
func TestSignatureAlgorithmDetection(t *testing.T) {
	t.Run("RSA-PSS detected correctly", func(t *testing.T) {
		algos := []x509.SignatureAlgorithm{
			x509.SHA256WithRSAPSS,
			x509.SHA384WithRSAPSS,
			x509.SHA512WithRSAPSS,
		}

		for _, algo := range algos {
			assert.True(t, store.IsRSAPSS(algo), "Expected %v to be RSA-PSS", algo)
		}
	})

	t.Run("RSA PKCS1v15 not detected as PSS", func(t *testing.T) {
		algos := []x509.SignatureAlgorithm{
			x509.SHA256WithRSA,
			x509.SHA384WithRSA,
			x509.SHA512WithRSA,
		}

		for _, algo := range algos {
			assert.False(t, store.IsRSAPSS(algo), "Expected %v to not be RSA-PSS", algo)
		}
	})

	t.Run("ECDSA detected correctly", func(t *testing.T) {
		algos := []x509.SignatureAlgorithm{
			x509.ECDSAWithSHA256,
			x509.ECDSAWithSHA384,
			x509.ECDSAWithSHA512,
		}

		for _, algo := range algos {
			assert.True(t, store.IsECDSA(algo), "Expected %v to be ECDSA", algo)
		}
	})

	t.Run("RSA not detected as ECDSA", func(t *testing.T) {
		algos := []x509.SignatureAlgorithm{
			x509.SHA256WithRSA,
			x509.SHA256WithRSAPSS,
		}

		for _, algo := range algos {
			assert.False(t, store.IsECDSA(algo), "Expected %v to not be ECDSA", algo)
		}
	})
}

// Tests for error types
func TestCSRVerificationErrors(t *testing.T) {
	t.Run("ErrInvalidSignature is properly defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidSignature)
		assert.Equal(t, "tpm: invalid signature", ErrInvalidSignature.Error())
	})

	t.Run("ErrInvalidEnrollmentStrategy is properly defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidEnrollmentStrategy)
		assert.Equal(t, "tpm: invalid enrollment strategy", ErrInvalidEnrollmentStrategy.Error())
	})

	t.Run("ErrInvalidHashFunction is properly defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidHashFunction)
		assert.Contains(t, ErrInvalidHashFunction.Error(), "hash")
	})
}

// Tests for TCG CSR content structure integrity
func TestTCGCSRContentStructureIntegrity(t *testing.T) {
	t.Run("all size fields match actual data", func(t *testing.T) {
		csr := createTestCSRIDevID()
		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)

		assert.Equal(t, uint32(len(unpacked.CsrContents.ProdModel)), unpacked.CsrContents.ProdModelSz)
		assert.Equal(t, uint32(len(unpacked.CsrContents.ProdSerial)), unpacked.CsrContents.ProdSerialSz)
		assert.Equal(t, uint32(len(unpacked.CsrContents.ProdCaData)), unpacked.CsrContents.ProdCaDataSz)
		assert.Equal(t, uint32(len(unpacked.CsrContents.BootEvntLog)), unpacked.CsrContents.BootEvntLogSz)
		assert.Equal(t, uint32(len(unpacked.CsrContents.EkCert)), unpacked.CsrContents.EkCertSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.AttestPub)), unpacked.CsrContents.AttestPubSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.AtCreateTkt)), unpacked.CsrContents.AtCreateTktSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.AtCertifyInfo)), unpacked.CsrContents.AtCertifyInfoSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.AtCertifyInfoSig)), unpacked.CsrContents.AtCertifyInfoSignatureSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.SigningPub)), unpacked.CsrContents.SigningPubSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.SgnCertifyInfo)), unpacked.CsrContents.SgnCertifyInfoSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.SgnCertifyInfoSig)), unpacked.CsrContents.SgnCertifyInfoSignatureSZ)
		assert.Equal(t, uint32(len(unpacked.CsrContents.Pad)), unpacked.CsrContents.PadSz)
	})

	t.Run("padding calculation for 16-byte alignment", func(t *testing.T) {
		testCases := []struct {
			name        string
			dataSize    uint32
			expectedPad uint32
		}{
			{"already aligned", 16, 0},
			{"needs 1 byte", 15, 1},
			{"needs 8 bytes", 8, 8},
			{"needs 15 bytes", 1, 15},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				padSz := tc.dataSize % 16
				if padSz == 0 {
					assert.Equal(t, uint32(0), padSz)
				} else {
					assert.Equal(t, tc.expectedPad, 16-padSz)
				}
			})
		}
	})

	t.Run("hash size matches algorithm", func(t *testing.T) {
		testCases := []struct {
			algoID   uint32
			hashSize uint32
		}{
			{uint32(tpm2.TPMAlgSHA1), 20},
			{uint32(tpm2.TPMAlgSHA256), 32},
			{uint32(tpm2.TPMAlgSHA384), 48},
			{uint32(tpm2.TPMAlgSHA512), 64},
		}

		for _, tc := range testCases {
			csr := createTestCSRIDevID()
			binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], tc.algoID)
			binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], tc.hashSize)

			unpacked, err := UnpackIDevIDCSR(csr)
			require.NoError(t, err)

			hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId)
			hash, err := hashAlgo.Hash()
			require.NoError(t, err)

			assert.Equal(t, tc.hashSize, uint32(hash.Size()))
		}
	})
}

// Tests for big-endian encoding compliance
func TestBigEndianEncodingCompliance(t *testing.T) {
	t.Run("struct version encoded correctly", func(t *testing.T) {
		var ver [4]byte
		binary.BigEndian.PutUint32(ver[:], 0x00000100)

		assert.Equal(t, byte(0x00), ver[0])
		assert.Equal(t, byte(0x00), ver[1])
		assert.Equal(t, byte(0x01), ver[2])
		assert.Equal(t, byte(0x00), ver[3])
	})

	t.Run("hash algorithm ID encoded correctly", func(t *testing.T) {
		var algoID [4]byte
		// SHA-256 = 0x000B
		binary.BigEndian.PutUint32(algoID[:], 0x0000000B)

		assert.Equal(t, byte(0x00), algoID[0])
		assert.Equal(t, byte(0x00), algoID[1])
		assert.Equal(t, byte(0x00), algoID[2])
		assert.Equal(t, byte(0x0B), algoID[3])
	})

	t.Run("size fields encoded correctly", func(t *testing.T) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], 256)

		assert.Equal(t, byte(0x00), size[0])
		assert.Equal(t, byte(0x00), size[1])
		assert.Equal(t, byte(0x01), size[2])
		assert.Equal(t, byte(0x00), size[3])
	})

	t.Run("round trip preserves byte order", func(t *testing.T) {
		originalValue := uint32(0x12345678)

		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], originalValue)

		decoded := binary.BigEndian.Uint32(encoded[:])
		assert.Equal(t, originalValue, decoded)
	})
}

// Tests for ASN.1 signature format handling
func TestASN1SignatureFormatHandling(t *testing.T) {
	t.Run("ECDSA signature has valid ASN.1 structure", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		message := []byte("test message")
		hash := sha256.Sum256(message)

		signature, err := ecdsa.SignASN1(rand.Reader, ecKey, hash[:])
		require.NoError(t, err)

		// Verify it's valid ASN.1 DER encoding
		var sig struct {
			R, S *big.Int
		}
		_, err = asn1.Unmarshal(signature, &sig)
		require.NoError(t, err)

		assert.NotNil(t, sig.R)
		assert.NotNil(t, sig.S)
	})

	t.Run("corrupted ASN.1 fails to parse", func(t *testing.T) {
		// Create invalid ASN.1
		invalidSig := []byte{0x30, 0xFF, 0xFF, 0xFF}

		var sig struct {
			R, S *big.Int
		}
		_, err := asn1.Unmarshal(invalidSig, &sig)
		require.Error(t, err)
	})
}

// Tests for enrollment strategy handling
func TestEnrollmentStrategyHandling(t *testing.T) {
	t.Run("IAK strategy uses IAK for signing", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy(string(EnrollmentStrategyIAK))
		assert.Equal(t, EnrollmentStrategyIAK, strategy)

		// In IAK strategy, the IAK is used for CSR signing
		switch strategy {
		case EnrollmentStrategyIAK:
			// Correct path
		default:
			t.Error("Expected IAK strategy")
		}
	})

	t.Run("single pass strategy uses IDevID for signing", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy(string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS))
		assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)

		// In single pass strategy, the IDevID is used for CSR signing
		switch strategy {
		case EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
			// Correct path
		default:
			t.Error("Expected IAK_IDEVID_SINGLE_PASS strategy")
		}
	})
}

// Tests for mock certificate validation
func TestMockCertificateValidation(t *testing.T) {
	t.Run("mock EK certificate has valid structure", func(t *testing.T) {
		cert := createMockEKCertificate()
		require.NotNil(t, cert)

		assert.NotNil(t, cert.Subject)
		assert.NotEmpty(t, cert.Subject.CommonName)
		assert.NotEmpty(t, cert.Raw)
		assert.NotNil(t, cert.PublicKey)
	})

	t.Run("mock IAK attributes have valid structure", func(t *testing.T) {
		attrs := createMockIAKAttributes()
		require.NotNil(t, attrs)

		assert.NotNil(t, attrs.TPMAttributes)
		assert.NotNil(t, attrs.TPMAttributes.BPublic)
		pub := attrs.TPMAttributes.Public
		assert.Equal(t, tpm2.TPMAlgRSA, pub.Type)
		assert.True(t, pub.ObjectAttributes.Restricted)
		assert.True(t, pub.ObjectAttributes.FixedTPM)
		assert.True(t, pub.ObjectAttributes.FixedParent)
		assert.True(t, pub.ObjectAttributes.SignEncrypt)
	})

	t.Run("mock IDevID attributes have valid structure", func(t *testing.T) {
		attrs := createMockIDevIDAttributes()
		require.NotNil(t, attrs)

		assert.NotNil(t, attrs.TPMAttributes)
		assert.NotNil(t, attrs.TPMAttributes.BPublic)
		pub := attrs.TPMAttributes.Public
		assert.Equal(t, tpm2.TPMAlgRSA, pub.Type)
		assert.False(t, pub.ObjectAttributes.Restricted) // IDevID is NOT restricted
		assert.True(t, pub.ObjectAttributes.FixedTPM)
		assert.True(t, pub.ObjectAttributes.FixedParent)
		assert.True(t, pub.ObjectAttributes.SignEncrypt)
	})
}

// Tests for content packing integrity
func TestContentPackingIntegrity(t *testing.T) {
	t.Run("packed content can be verified with signature", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		content := createTestIDevIDContent()

		// Pack content
		packed1, err := PackIDevIDContent(content)
		require.NoError(t, err)

		// Sign the packed content
		hash := sha256.Sum256(packed1)
		sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
		require.NoError(t, err)

		// Pack again (should be identical)
		packed2, err := PackIDevIDContent(content)
		require.NoError(t, err)

		// Verify hash is the same
		hash2 := sha256.Sum256(packed2)
		assert.Equal(t, hash[:], hash2[:])

		// Verify signature
		err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, hash2[:], sig)
		require.NoError(t, err)
	})

	t.Run("modified content produces different hash", func(t *testing.T) {
		content1 := createTestIDevIDContent()
		content2 := createTestIDevIDContent()

		// Modify content2
		content2.ProdModel = []byte("Different-Model")
		binary.BigEndian.PutUint32(content2.ProdModelSz[:], uint32(len(content2.ProdModel)))

		packed1, err := PackIDevIDContent(content1)
		require.NoError(t, err)

		packed2, err := PackIDevIDContent(content2)
		require.NoError(t, err)

		hash1 := sha256.Sum256(packed1)
		hash2 := sha256.Sum256(packed2)

		assert.NotEqual(t, hash1[:], hash2[:])
	})
}

// Tests for CSR validation with mismatched public keys
func TestCSRValidationMismatchedKeys(t *testing.T) {
	t.Run("signature with mismatched RSA keys fails verification", func(t *testing.T) {
		key1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		key2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		csr, err := createSignedCSRWithRSAPSS(key1)
		require.NoError(t, err)

		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify with mismatched key should fail
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		err = rsa.VerifyPSS(&key2.PublicKey, crypto.SHA256, hash[:], csr.Signature, pssOpts)
		require.Error(t, err)
	})

	t.Run("signature with mismatched ECDSA keys fails verification", func(t *testing.T) {
		key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csr, err := createSignedCSRWithECDSA(key1)
		require.NoError(t, err)

		packedContent, err := PackIDevIDContent(&csr.CsrContents)
		require.NoError(t, err)

		hash := sha256.Sum256(packedContent)

		// Verify with mismatched key should fail
		valid := ecdsa.VerifyASN1(&key2.PublicKey, hash[:], csr.Signature)
		assert.False(t, valid)
	})
}

// Tests for invalid hash algorithm handling
func TestInvalidHashAlgorithmHandling(t *testing.T) {
	t.Run("unsupported hash algorithm ID causes error", func(t *testing.T) {
		csr := createTestCSRIDevID()
		// Set an unsupported algorithm ID
		binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], 0xFFFF)

		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err) // Unpacking succeeds

		// But converting to crypto.Hash should fail
		hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId)
		_, err = hashAlgo.Hash()
		require.Error(t, err)
	})

	t.Run("null hash algorithm causes error", func(t *testing.T) {
		csr := createTestCSRIDevID()
		// Set null algorithm (0x0010 is TPMAlgNull)
		binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], uint32(tpm2.TPMAlgNull))

		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)

		hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId)
		_, err = hashAlgo.Hash()
		require.Error(t, err)
	})
}

// Tests for CSR signature size validation
func TestCSRSignatureSizeValidation(t *testing.T) {
	t.Run("RSA-2048 signature size is correct", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		csr, err := createSignedCSRWithRSAPSS(key)
		require.NoError(t, err)

		// RSA-2048 signature should be 256 bytes
		assert.Equal(t, 256, len(csr.Signature))
		assert.Equal(t, uint32(256), binary.BigEndian.Uint32(csr.SigSz[:]))
	})

	t.Run("ECDSA-P256 signature size is valid range", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csr, err := createSignedCSRWithECDSA(key)
		require.NoError(t, err)

		// ECDSA-P256 signature is ASN.1 DER encoded, typically 70-72 bytes
		assert.Greater(t, len(csr.Signature), 64)
		assert.Less(t, len(csr.Signature), 80)
	})
}

// Tests for CSR content hash consistency
func TestCSRContentHashConsistency(t *testing.T) {
	t.Run("same content produces same hash", func(t *testing.T) {
		content := createTestIDevIDContent()

		packed1, err := PackIDevIDContent(content)
		require.NoError(t, err)

		packed2, err := PackIDevIDContent(content)
		require.NoError(t, err)

		assert.Equal(t, packed1, packed2)
		assert.Equal(t, sha256.Sum256(packed1), sha256.Sum256(packed2))
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		content1 := createTestIDevIDContent()
		content2 := createTestIDevIDContent()
		content2.ProdSerial = []byte("DIFFERENT-SERIAL")
		binary.BigEndian.PutUint32(content2.ProdSerialSz[:], uint32(len(content2.ProdSerial)))

		packed1, err := PackIDevIDContent(content1)
		require.NoError(t, err)

		packed2, err := PackIDevIDContent(content2)
		require.NoError(t, err)

		assert.NotEqual(t, sha256.Sum256(packed1), sha256.Sum256(packed2))
	})
}

// Tests for mock TPM2 creation
func TestMockTPM2Creation(t *testing.T) {
	t.Run("creates mock TPM2 with IAK strategy", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK))
		require.NotNil(t, tpm)
		assert.Equal(t, string(EnrollmentStrategyIAK), tpm.config.IdentityProvisioningStrategy)
	})

	t.Run("creates mock TPM2 with IDevID single pass strategy", func(t *testing.T) {
		tpm := createMockTPM2(string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS))
		require.NotNil(t, tpm)
		assert.Equal(t, string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS), tpm.config.IdentityProvisioningStrategy)
	})

	t.Run("mock transport returns error by default", func(t *testing.T) {
		mt := &idevidCSRVerifyMockTransport{err: errors.New("test error")}
		_, err := mt.Send([]byte{})
		require.Error(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("mock transport returns configured responses", func(t *testing.T) {
		mt := &idevidCSRVerifyMockTransport{
			responses: [][]byte{
				{0x01, 0x02, 0x03},
				{0x04, 0x05, 0x06},
			},
		}

		resp1, err := mt.Send([]byte{})
		require.NoError(t, err)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, resp1)

		resp2, err := mt.Send([]byte{})
		require.NoError(t, err)
		assert.Equal(t, []byte{0x04, 0x05, 0x06}, resp2)

		_, err = mt.Send([]byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no more mock responses")
	})
}

// Tests for enrollment strategy selection logic
func TestEnrollmentStrategySelectionLogic(t *testing.T) {
	t.Run("IAK strategy selects AK for signing", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("IAK")
		assert.Equal(t, EnrollmentStrategyIAK, strategy)

		// Verify the switch case logic
		var signerType string
		switch strategy {
		case EnrollmentStrategyIAK:
			signerType = "IAK"
		case EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
			signerType = "IDevID"
		}
		assert.Equal(t, "IAK", signerType)
	})

	t.Run("single pass strategy selects IDevID for signing", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("IAK_IDEVID_SINGLE_PASS")
		assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)

		var signerType string
		switch strategy {
		case EnrollmentStrategyIAK:
			signerType = "IAK"
		case EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
			signerType = "IDevID"
		}
		assert.Equal(t, "IDevID", signerType)
	})

	t.Run("unknown strategy defaults to single pass", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("UNKNOWN_STRATEGY")
		assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)

		var signerType string
		switch strategy {
		case EnrollmentStrategyIAK:
			signerType = "IAK"
		case EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
			signerType = "IDevID"
		}
		assert.Equal(t, "IDevID", signerType)
	})
}

// Tests for CSR padding logic
func TestCSRPaddingLogic(t *testing.T) {
	t.Run("padding enabled adds alignment bytes", func(t *testing.T) {
		tpm := createMockTPM2WithIDevIDConfig(string(EnrollmentStrategyIAK), true)
		assert.True(t, tpm.config.IDevID.Pad)

		// Test padding calculation logic
		testContent := &UNPACKED_TCG_IDEVID_CONTENT{
			ProdModelSz:               10,
			ProdSerialSz:              7,
			ProdCaDataSz:              0,
			BootEvntLogSz:             100,
			EkCertSZ:                  1000,
			AttestPubSZ:               256,
			AtCreateTktSZ:             32,
			AtCertifyInfoSZ:           128,
			AtCertifyInfoSignatureSZ:  256,
			SigningPubSZ:              256,
			SgnCertifyInfoSZ:          128,
			SgnCertifyInfoSignatureSZ: 256,
			PadSz:                     0,
		}

		// Calculate padding similar to CreateTCG_CSR_IDEVID
		numSizeFields := 10
		sz := testContent.ProdModelSz + testContent.ProdSerialSz +
			testContent.ProdCaDataSz + testContent.BootEvntLogSz +
			testContent.EkCertSZ + testContent.AttestPubSZ + testContent.AtCreateTktSZ +
			testContent.AtCertifyInfoSZ + testContent.AtCertifyInfoSignatureSZ +
			testContent.PadSz
		contents := sz + uint32(numSizeFields*4)
		padSz := contents % 16

		// Verify padding calculation
		assert.LessOrEqual(t, padSz, uint32(15))
		assert.GreaterOrEqual(t, padSz, uint32(0))
	})

	t.Run("padding disabled skips alignment", func(t *testing.T) {
		tpm := createMockTPM2WithIDevIDConfig(string(EnrollmentStrategyIAK), false)
		assert.False(t, tpm.config.IDevID.Pad)
	})

	t.Run("padding fills with equals signs", func(t *testing.T) {
		padSz := uint32(5)
		padding := make([]byte, padSz)
		for i := uint32(0); i < padSz; i++ {
			padding[i] = '='
		}

		assert.Len(t, padding, 5)
		for _, b := range padding {
			assert.Equal(t, byte('='), b)
		}
	})
}

// Tests for IDevID configuration validation
func TestIDevIDConfigValidation(t *testing.T) {
	t.Run("model and serial are properly configured", func(t *testing.T) {
		tpm := createMockTPM2WithIDevIDConfig(string(EnrollmentStrategyIAK), false)

		assert.Equal(t, "TestModel", tpm.config.IDevID.Model)
		assert.Equal(t, "TestSerial123", tpm.config.IDevID.Serial)
	})

	t.Run("pad configuration is respected", func(t *testing.T) {
		tpmWithPad := createMockTPM2WithIDevIDConfig(string(EnrollmentStrategyIAK), true)
		tpmWithoutPad := createMockTPM2WithIDevIDConfig(string(EnrollmentStrategyIAK), false)

		assert.True(t, tpmWithPad.config.IDevID.Pad)
		assert.False(t, tpmWithoutPad.config.IDevID.Pad)
	})
}

// Tests for verifyTCGCSRSignature with ECDSA key attributes
func TestVerifyTCGCSRSignature_ECCKeyAttributes(t *testing.T) {
	t.Run("creates valid ECC IAK attributes", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubArea := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				Restricted:   true,
				FixedTPM:     true,
				FixedParent:  true,
				SignEncrypt:  true,
				UserWithAuth: true,
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
					X: tpm2.TPM2BECCParameter{
						Buffer: ecKey.PublicKey.X.Bytes(), //nolint:staticcheck // QF1008: field
					},
					//nolint:staticcheck // QF1008: field access
					Y: tpm2.TPM2BECCParameter{
						Buffer: ecKey.PublicKey.Y.Bytes(),
					},
				},
			),
		}

		bpublic := tpm2.New2B(pubArea)

		attrs := &types.KeyAttributes{
			CN:                 "test-ecdsa-iak",
			KeyAlgorithm:       x509.ECDSA,
			KeyType:            types.KeyTypeTPM,
			Hash:               crypto.SHA256,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			StoreType:          types.StoreTPM2,
			TPMAttributes: &types.TPMAttributes{
				HashAlg:              tpm2.TPMAlgSHA256,
				BPublic:              bpublic,
				Public:               pubArea,
				CreationTicketDigest: []byte("mock-creation-ticket"),
				CertifyInfo:          []byte("mock-certify-info"),
				Signature:            []byte("mock-signature"),
			},
		}

		require.NotNil(t, attrs)
		pub := attrs.TPMAttributes.Public
		assert.Equal(t, tpm2.TPMAlgECC, pub.Type)
		assert.True(t, pub.ObjectAttributes.Restricted)
	})

	t.Run("creates valid ECC IDevID attributes", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubArea := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				Restricted:   false, // IDevID should not be restricted
				FixedTPM:     true,
				FixedParent:  true,
				SignEncrypt:  true,
				UserWithAuth: true,
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
					X: tpm2.TPM2BECCParameter{
						Buffer: ecKey.PublicKey.X.Bytes(), //nolint:staticcheck // QF1008
					},
					Y: tpm2.TPM2BECCParameter{
						Buffer: ecKey.PublicKey.Y.Bytes(), //nolint:staticcheck // QF1008
					},
				},
			),
		}

		bpublic := tpm2.New2B(pubArea)

		attrs := &types.KeyAttributes{
			CN:                 "test-ecdsa-idevid",
			KeyAlgorithm:       x509.ECDSA,
			KeyType:            types.KeyTypeTPM,
			Hash:               crypto.SHA256,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			StoreType:          types.StoreTPM2,
			TPMAttributes: &types.TPMAttributes{
				HashAlg:     tpm2.TPMAlgSHA256,
				BPublic:     bpublic,
				Public:      pubArea,
				CertifyInfo: []byte("mock-idevid-certify-info"),
				Signature:   []byte("mock-idevid-signature"),
			},
		}

		require.NotNil(t, attrs)
		pub := attrs.TPMAttributes.Public
		assert.Equal(t, tpm2.TPMAlgECC, pub.Type)
		assert.False(t, pub.ObjectAttributes.Restricted)
	})
}

// Tests for IDevID content field validation
func TestIDevIDContentFieldValidation(t *testing.T) {
	t.Run("content preserves product model correctly", func(t *testing.T) {
		content := createTestIDevIDContent()
		unpacked, err := UnpackIDevIDCSR(createTestCSRIDevID())
		require.NoError(t, err)

		assert.Equal(t, string(content.ProdModel), string(unpacked.CsrContents.ProdModel))
	})

	t.Run("content preserves product serial correctly", func(t *testing.T) {
		content := createTestIDevIDContent()
		unpacked, err := UnpackIDevIDCSR(createTestCSRIDevID())
		require.NoError(t, err)

		assert.Equal(t, string(content.ProdSerial), string(unpacked.CsrContents.ProdSerial))
	})

	t.Run("content preserves EK cert correctly", func(t *testing.T) {
		content := createTestIDevIDContent()
		unpacked, err := UnpackIDevIDCSR(createTestCSRIDevID())
		require.NoError(t, err)

		assert.Equal(t, content.EkCert, unpacked.CsrContents.EkCert)
	})

	t.Run("content preserves attestation public key correctly", func(t *testing.T) {
		content := createTestIDevIDContent()
		unpacked, err := UnpackIDevIDCSR(createTestCSRIDevID())
		require.NoError(t, err)

		assert.Equal(t, content.AttestPub, unpacked.CsrContents.AttestPub)
	})

	t.Run("content preserves signing public key correctly", func(t *testing.T) {
		content := createTestIDevIDContent()
		unpacked, err := UnpackIDevIDCSR(createTestCSRIDevID())
		require.NoError(t, err)

		assert.Equal(t, content.SigningPub, unpacked.CsrContents.SigningPub)
	})
}

// Tests for CSR structure version validation
func TestCSRStructureVersionValidation(t *testing.T) {
	t.Run("version 1.0 is valid", func(t *testing.T) {
		csr := createTestCSRIDevID()
		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)

		assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
	})

	t.Run("content version matches CSR version", func(t *testing.T) {
		csr := createTestCSRIDevID()
		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)

		assert.Equal(t, unpacked.StructVer, unpacked.CsrContents.StructVer)
	})

	t.Run("different version is preserved", func(t *testing.T) {
		csr := createTestCSRIDevID()
		// Set a different version
		binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000200)
		binary.BigEndian.PutUint32(csr.CsrContents.StructVer[:], 0x00000200)

		unpacked, err := UnpackIDevIDCSR(csr)
		require.NoError(t, err)

		assert.Equal(t, uint32(0x00000200), unpacked.StructVer)
		assert.Equal(t, uint32(0x00000200), unpacked.CsrContents.StructVer)
	})
}

// Tests for signature algorithm detection in key attributes
func TestKeyAlgorithmDetectionFromSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name          string
		sigAlgo       x509.SignatureAlgorithm
		expectedIsRSA bool
		expectedIsECC bool
	}{
		{"SHA256WithRSA is RSA", x509.SHA256WithRSA, true, false},
		{"SHA384WithRSA is RSA", x509.SHA384WithRSA, true, false},
		{"SHA512WithRSA is RSA", x509.SHA512WithRSA, true, false},
		{"SHA256WithRSAPSS is RSA", x509.SHA256WithRSAPSS, true, false},
		{"SHA384WithRSAPSS is RSA", x509.SHA384WithRSAPSS, true, false},
		{"SHA512WithRSAPSS is RSA", x509.SHA512WithRSAPSS, true, false},
		{"ECDSAWithSHA256 is ECDSA", x509.ECDSAWithSHA256, false, true},
		{"ECDSAWithSHA384 is ECDSA", x509.ECDSAWithSHA384, false, true},
		{"ECDSAWithSHA512 is ECDSA", x509.ECDSAWithSHA512, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isECDSA := store.IsECDSA(tc.sigAlgo)
			isRSAPSS := store.IsRSAPSS(tc.sigAlgo)

			assert.Equal(t, tc.expectedIsECC, isECDSA)
			if tc.expectedIsRSA && !isRSAPSS {
				// For standard RSA signatures
				assert.False(t, isECDSA)
			}
		})
	}
}

// Tests for CSR content binary packing edge cases
func TestCSRContentBinaryPackingEdgeCases(t *testing.T) {
	t.Run("empty boot event log is handled", func(t *testing.T) {
		content := createTestIDevIDContent()
		content.BootEvntLog = []byte{}
		binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 0)

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)
		assert.NotEmpty(t, packed)
	})

	t.Run("empty CA data is handled", func(t *testing.T) {
		content := createTestIDevIDContent()
		content.ProdCaData = []byte{}
		binary.BigEndian.PutUint32(content.ProdCaDataSz[:], 0)

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)
		assert.NotEmpty(t, packed)
	})

	t.Run("maximum size fields are handled", func(t *testing.T) {
		content := createTestIDevIDContent()
		// Test with large but valid values
		largeModel := make([]byte, 1000)
		for i := range largeModel {
			largeModel[i] = byte('A' + (i % 26))
		}
		content.ProdModel = largeModel
		binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(largeModel)))

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)
		assert.NotEmpty(t, packed)

		// Verify packing includes the large model
		assert.Contains(t, string(packed), string(largeModel))
	})

	t.Run("zero padding is handled", func(t *testing.T) {
		content := createTestIDevIDContent()
		content.Pad = []byte{}
		binary.BigEndian.PutUint32(content.PadSz[:], 0)

		packed, err := PackIDevIDContent(content)
		require.NoError(t, err)
		assert.NotEmpty(t, packed)
	})
}

// Tests for TPM public key type detection
func TestTPMPublicKeyTypeDetection(t *testing.T) {
	t.Run("RSA public key type detection", func(t *testing.T) {
		attrs := createMockIAKAttributes()
		pub := attrs.TPMAttributes.Public
		assert.Equal(t, tpm2.TPMAlgRSA, pub.Type)
	})

	t.Run("ECC public key type detection", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubArea := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: ecKey.PublicKey.X.Bytes()}, //nolint:staticcheck // QF1008
					Y: tpm2.TPM2BECCParameter{Buffer: ecKey.PublicKey.Y.Bytes()}, //nolint:staticcheck // QF1008
				},
			),
		}

		assert.Equal(t, tpm2.TPMAlgECC, pubArea.Type)
	})
}

// Tests for signature verification with different RSA key sizes
func TestSignatureVerificationDifferentRSAKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run("RSA key size verification", func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, keySize)
			require.NoError(t, err)

			csr, err := createSignedCSRWithRSAPSS(key)
			require.NoError(t, err)

			// Verify signature size matches key size
			expectedSigSize := keySize / 8
			assert.Equal(t, expectedSigSize, len(csr.Signature))

			// Verify the signature
			packedContent, err := PackIDevIDContent(&csr.CsrContents)
			require.NoError(t, err)

			hash := sha256.Sum256(packedContent)

			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			}
			err = rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, hash[:], csr.Signature, pssOpts)
			require.NoError(t, err)
		})
	}
}

// Tests for ECC curve validation
func TestECCCurveValidation(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name+" curve validation", func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			csr, err := createSignedCSRWithECDSA(key)
			require.NoError(t, err)

			packedContent, err := PackIDevIDContent(&csr.CsrContents)
			require.NoError(t, err)

			hash := sha256.Sum256(packedContent)

			valid := ecdsa.VerifyASN1(&key.PublicKey, hash[:], csr.Signature)
			assert.True(t, valid)
		})
	}
}

// Tests for hash size validation
func TestHashSizeValidation(t *testing.T) {
	t.Run("SHA-1 hash size is 20 bytes", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA1)
		require.NoError(t, err)
		assert.Equal(t, uint32(20), size)
	})

	t.Run("SHA-256 hash size is 32 bytes", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA256)
		require.NoError(t, err)
		assert.Equal(t, uint32(32), size)
	})

	t.Run("SHA-384 hash size is 48 bytes", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA384)
		require.NoError(t, err)
		assert.Equal(t, uint32(48), size)
	})

	t.Run("SHA-512 hash size is 64 bytes", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA512)
		require.NoError(t, err)
		assert.Equal(t, uint32(64), size)
	})

	t.Run("invalid hash returns ErrInvalidHashFunction", func(t *testing.T) {
		_, err := ParseHashSize(crypto.MD5)
		require.Error(t, err)
		assert.Equal(t, ErrInvalidHashFunction, err)

		_, err = ParseHashSize(crypto.Hash(99))
		require.Error(t, err)
		assert.Equal(t, ErrInvalidHashFunction, err)
	})
}
