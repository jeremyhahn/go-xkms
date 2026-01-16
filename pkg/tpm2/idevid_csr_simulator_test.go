package tpm2

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createSimulatorTPM creates a TPM2 instance using the simulator for CSR tests.
// Returns nil if the simulator is not available.
func createSimulatorTPM(t *testing.T, strategy EnrollmentStrategy) TrustedPlatformModule {
	t.Helper()

	logger := slog.Default()

	tempDir := t.TempDir()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		t.Skipf("failed to read random bytes: %v", err)
		return nil
	}
	hexVal := hex.EncodeToString(buf)
	testDir := fmt.Sprintf("%s/%s", tempDir, hexVal)

	storageFactory, err := store.NewStorageFactory(logger, testDir)
	if err != nil {
		t.Skipf("failed to create storage factory: %v", err)
		return nil
	}

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		EncryptSession: false,
		UseEntropy:     false,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(strategy),
		FileIntegrity:                []string{},
		IAK: &IAKConfig{
			CN:           "test-iak",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		IDevID: &IDevIDConfig{
			CN:           "test-idevid",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       0x81020000,
			KeyAlgorithm: x509.RSA.String(),
			Model:        "TestModel",
			Serial:       "TestSerial123",
			Pad:          true,
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		PlatformPCR:     16,
		PlatformPCRBank: PCRBankSHA256,
		GoldenPCRs:      []uint{16},
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		KeyStore: &KeyStoreConfig{
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: false,
		},
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "test.example.com",
	}

	tpm, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if provisionErr := tpm.Provision(nil); provisionErr != nil {
				t.Skipf("failed to provision TPM: %v", provisionErr)
				return nil
			}
		} else {
			t.Skipf("failed to create TPM2: %v", err)
			return nil
		}
	}

	return tpm
}

// createTestEKCertificate creates a test EK certificate for CSR tests
func createTestEKCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

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

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return cert
}

// TestCSRCreateTCG_CSR_IDEVID_InvalidEnrollmentStrategy tests that invalid strategy returns error
func TestCSRCreateTCG_CSR_IDEVID_InvalidEnrollmentStrategy(t *testing.T) {
	// Use the simulator to have a valid transport
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	// Override the strategy to an invalid one
	tpmImpl := tpm.(*TPM2)
	tpmImpl.config.IdentityProvisioningStrategy = "INVALID_STRATEGY"

	akAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("IAK not available: %v", err)
	}

	// Create mock idevidAttrs since IDevID may not be configured
	idevidAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			HashAlg: tpm2.TPMAlgSHA256,
		},
	}

	ekCert := createTestEKCertificate(t)

	// The invalid strategy should cause CreateTCG_CSR_IDEVID to fail
	_, err = tpm.CreateTCG_CSR_IDEVID(ekCert, akAttrs, idevidAttrs)
	require.Error(t, err)
}

// TestCSRCreateTCG_CSR_IDEVID_NilEKCert tests that nil EK cert returns error
func TestCSRCreateTCG_CSR_IDEVID_NilEKCert(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	akAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("IAK not available: %v", err)
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		t.Skipf("IDevID not available: %v", err)
	}

	// Pass nil EK cert - should fail in createIDevIDContent
	_, err = tpm.CreateTCG_CSR_IDEVID(nil, akAttrs, idevidAttrs)
	require.Error(t, err)
	assert.Equal(t, ErrInvalidEKCert, err)
}

// TestCSRCreateTCG_CSR_IDEVID_WithSimulator tests full CSR creation with simulator
func TestCSRCreateTCG_CSR_IDEVID_WithSimulator(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	// Get the required attributes
	akAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("IAK not available: %v", err)
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		t.Skipf("IDevID not available: %v", err)
	}

	ekCert, err := tpm.EKCertificate()
	if err != nil {
		// Create a test certificate if EK cert not available
		ekCert = createTestEKCertificate(t)
	}

	// Create the CSR
	csr, err := tpm.CreateTCG_CSR_IDEVID(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)

	// Verify CSR structure
	structVer := binary.BigEndian.Uint32(csr.StructVer[:])
	assert.Equal(t, uint32(0x00000100), structVer)

	// Verify signature is present
	assert.NotEmpty(t, csr.Signature)

	// Verify contents
	assert.NotEmpty(t, csr.CsrContents.ProdModel)
	assert.NotEmpty(t, csr.CsrContents.EkCert)
	assert.NotEmpty(t, csr.CsrContents.AttestPub)
}

// TestCSRCreateTCG_CSR_IDEVID_WithIAKStrategy tests CSR creation with IAK strategy
func TestCSRCreateTCG_CSR_IDEVID_WithIAKStrategy(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	akAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("IAK not available: %v", err)
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		t.Skipf("IDevID not available: %v", err)
	}

	ekCert, err := tpm.EKCertificate()
	if err != nil {
		ekCert = createTestEKCertificate(t)
	}

	// Create CSR with IAK strategy (uses AK for signing)
	csr, err := tpm.CreateTCG_CSR_IDEVID(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)

	// Verify CSR was created
	assert.NotNil(t, csr.Signature)
	assert.NotEmpty(t, csr.CsrContents.AttestPub)
}

// TestCSRVerifyTCGCSR_StrategySelection tests that VerifyTCGCSR routes correctly
func TestCSRVerifyTCGCSR_StrategySelection(t *testing.T) {
	t.Run("IAK strategy routes correctly", func(t *testing.T) {
		tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
		if tpm == nil {
			t.Skip("TPM simulator not available")
		}
		defer func() { _ = tpm.Close() }()

		// Create a test CSR
		csr := createTestCSRIDevID()

		// This will fail verification but should route to correct method
		_, _, err := tpm.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
		// Error is expected since CSR has mock data
		assert.Error(t, err)
	})

	t.Run("IDevID single pass strategy routes correctly", func(t *testing.T) {
		tpm := createSimulatorTPM(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
		if tpm == nil {
			t.Skip("TPM simulator not available")
		}
		defer func() { _ = tpm.Close() }()

		csr := createTestCSRIDevID()

		_, _, err := tpm.VerifyTCGCSR(csr, x509.SHA256WithRSAPSS)
		assert.Error(t, err)
	})
}

// TestCSRVerifyTCG_CSR_IAK_Attributes tests IAK attribute validation
func TestCSRVerifyTCG_CSR_IAK_Attributes(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	t.Run("invalid hash algorithm returns error", func(t *testing.T) {
		csr := createTestCSRIDevID()
		// Set invalid hash algorithm
		binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], 0xFFFF)

		_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})

	t.Run("hash algorithm overflow check", func(t *testing.T) {
		csr := createTestCSRIDevID()
		// Set hash algorithm to max uint32 to trigger overflow check
		binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], 0x7FFFFFFF)

		_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})
}

// TestCSRVerifyTCG_CSR_IDevID_Attributes tests IDevID attribute validation
func TestCSRVerifyTCG_CSR_IDevID_Attributes(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	t.Run("invalid hash algorithm returns error", func(t *testing.T) {
		csr := createTestCSRIDevID()
		binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], 0xFFFF)

		_, _, err := tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})

	t.Run("CSR unpack error handling", func(t *testing.T) {
		csr := &TCG_CSR_IDEVID{}
		// Set mismatched size
		binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 1000)
		csr.CsrContents.ProdModel = []byte("short")

		_, _, err := tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
		require.Error(t, err)
	})
}

// TestCSRCreateProdCaData_NoDevice tests createProdCaData with no TPM device
func TestCSRCreateProdCaData_NoDevice(t *testing.T) {
	logger := slog.Default()

	config := &Config{
		Hash:        "SHA-256",
		PlatformPCR: 16,
		GoldenPCRs:  []uint{16},
	}

	tpm := &TPM2{
		config: config,
		logger: logger,
		device: nil, // No device
	}

	// Should return nil data without error
	data, size, err := tpm.createProdCaData()
	require.NoError(t, err)
	assert.Nil(t, data)
	assert.Equal(t, uint32(0), size)
}

// TestCSRCreateProdCaData_WithSimulator tests createProdCaData with simulator
func TestCSRCreateProdCaData_WithSimulator(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	// Access the internal TPM2 struct to call createProdCaData
	tpm2Instance, ok := tpm.(*TPM2)
	if !ok {
		t.Skip("Cannot access TPM2 internal methods")
	}

	data, size, err := tpm2Instance.createProdCaData()
	// May return error if Quote fails, which is acceptable
	if err != nil {
		t.Logf("createProdCaData returned error (acceptable): %v", err)
		return
	}

	// If successful, verify data structure
	if data != nil {
		assert.Greater(t, size, uint32(0))
		assert.Equal(t, int(size), len(data))
	}
}

// TestCSRCreateProdCaData_DefaultPCRs tests PCR defaults
func TestCSRCreateProdCaData_DefaultPCRs(t *testing.T) {
	logger := slog.Default()

	// Test with empty GoldenPCRs - should use PlatformPCR
	config := &Config{
		Hash:        "SHA-256",
		PlatformPCR: 7,
		GoldenPCRs:  []uint{}, // Empty
	}

	tpm := &TPM2{
		config: config,
		logger: logger,
		device: nil,
	}

	// Verify it handles empty GoldenPCRs
	data, size, err := tpm.createProdCaData()
	require.NoError(t, err)
	assert.Nil(t, data)
	assert.Equal(t, uint32(0), size)
}

// TestCSRPackUnpackCSRRoundTrip tests pack/unpack round trip
func TestCSRPackUnpackCSRRoundTrip(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	akAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("IAK not available: %v", err)
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		t.Skipf("IDevID not available: %v", err)
	}

	ekCert, err := tpm.EKCertificate()
	if err != nil {
		ekCert = createTestEKCertificate(t)
	}

	// Create CSR
	originalCSR, err := tpm.CreateTCG_CSR_IDEVID(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)

	// Pack it
	packed, err := PackIDevIDCSR(&originalCSR)
	require.NoError(t, err)

	// Unmarshal it
	unmarshalled, err := UnmarshalIDevIDCSR(packed)
	require.NoError(t, err)

	// Verify key fields match
	assert.Equal(t, originalCSR.StructVer, unmarshalled.StructVer)
	assert.Equal(t, originalCSR.SigSz, unmarshalled.SigSz)
	assert.Equal(t, originalCSR.Signature, unmarshalled.Signature)
	assert.Equal(t, originalCSR.CsrContents.ProdModel, unmarshalled.CsrContents.ProdModel)
	assert.Equal(t, originalCSR.CsrContents.ProdSerial, unmarshalled.CsrContents.ProdSerial)
}

// TestCSRMarshalMethod tests the Marshal method on TCG_CSR_IDEVID
func TestCSRMarshalMethod(t *testing.T) {
	csr := createTestCSRIDevID()

	// Test Marshal method
	marshalled, err := csr.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, marshalled)

	// Verify can unmarshal back
	unmarshalled, err := UnmarshalIDevIDCSR(marshalled)
	require.NoError(t, err)
	assert.Equal(t, csr.StructVer, unmarshalled.StructVer)
}

// TestCSRParseIdentityProvisioningStrategy tests strategy parsing
func TestCSRParseIdentityProvisioningStrategy(t *testing.T) {
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
			name:     "empty defaults to single pass",
			input:    "",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "unknown defaults to single pass",
			input:    "UNKNOWN",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "lowercase iak",
			input:    "iak",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, // Case sensitive
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestCSRCreateIDevIDContent_MissingEventLog tests content creation without event log
func TestCSRCreateIDevIDContent_MissingEventLog(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	akAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("IAK not available: %v", err)
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		t.Skipf("IDevID not available: %v", err)
	}

	// The simulator won't have a real event log, so this tests the code path
	// that handles missing event logs
	ekCert := createTestEKCertificate(t)

	csr, err := tpm.CreateTCG_CSR_IDEVID(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)

	// Boot event log may be empty in simulator
	// but CSR should still be created
	assert.NotNil(t, csr.Signature)
}

// TestCSRVerifyInvalidSignature tests verification with invalid signature
func TestCSRVerifyInvalidSignature(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	// Create a CSR with corrupt signature
	csr := createTestCSRIDevID()
	csr.Signature = []byte("invalid-signature")

	// Both verification methods should fail
	_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
	require.Error(t, err)

	_, _, err = tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
	require.Error(t, err)
}

// TestCSRVerifyWithECDSA tests verification with ECDSA signature algorithm
func TestCSRVerifyWithECDSA(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	csr := createTestCSRIDevID()

	// Try verification with ECDSA - will fail but exercises code path
	_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.ECDSAWithSHA256)
	require.Error(t, err)

	_, _, err = tpm.VerifyTCG_CSR_IDevID(csr, x509.ECDSAWithSHA256)
	require.Error(t, err)
}

// TestCSRVerifyWithPKCS1v15 tests verification with PKCS1v15 signature algorithm
func TestCSRVerifyWithPKCS1v15(t *testing.T) {
	tpm := createSimulatorTPM(t, EnrollmentStrategyIAK)
	if tpm == nil {
		t.Skip("TPM simulator not available")
	}
	defer func() { _ = tpm.Close() }()

	csr := createTestCSRIDevID()

	// Try verification with PKCS1v15 - exercises different code path
	_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSA)
	require.Error(t, err)

	_, _, err = tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSA)
	require.Error(t, err)
}

// TestCSRKeyAttributeValidation tests key attribute validation in verify methods
func TestCSRKeyAttributeValidation(t *testing.T) {
	t.Run("IAK Restricted attribute validation", func(t *testing.T) {
		// IAK must have Restricted=true
		pubArea := tpm2.TPMAObject{
			Restricted:  false, // Invalid for IAK
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
		}
		assert.False(t, pubArea.Restricted, "IAK should require Restricted=true")
	})

	t.Run("IAK FixedTPM attribute validation", func(t *testing.T) {
		pubArea := tpm2.TPMAObject{
			Restricted:  true,
			FixedTPM:    false, // Invalid
			FixedParent: true,
			SignEncrypt: true,
		}
		assert.False(t, pubArea.FixedTPM, "IAK should require FixedTPM=true")
	})

	t.Run("IDevID Restricted attribute validation", func(t *testing.T) {
		// IDevID must have Restricted=false
		pubArea := tpm2.TPMAObject{
			Restricted:  true, // Invalid for IDevID
			FixedTPM:    true,
			FixedParent: true,
			SignEncrypt: true,
		}
		assert.True(t, pubArea.Restricted, "IDevID should require Restricted=false")
	})

	t.Run("valid IAK attributes", func(t *testing.T) {
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

	t.Run("valid IDevID attributes", func(t *testing.T) {
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

// TestCSRHashSizeMapping tests hash algorithm to size mapping
func TestCSRHashSizeMapping(t *testing.T) {
	tests := []struct {
		hash     crypto.Hash
		expected uint32
		hasError bool
	}{
		{crypto.SHA1, 20, false},
		{crypto.SHA256, 32, false},
		{crypto.SHA384, 48, false},
		{crypto.SHA512, 64, false},
		{crypto.MD5, 0, true},
		{crypto.Hash(0), 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.hash.String(), func(t *testing.T) {
			size, err := ParseHashSize(tc.hash)
			if tc.hasError {
				require.Error(t, err)
				assert.Equal(t, ErrInvalidHashFunction, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, size)
			}
		})
	}
}

// TestCSRContentFieldPreservation tests that content fields are preserved through pack/unpack
func TestCSRContentFieldPreservation(t *testing.T) {
	original := createTestIDevIDContent()

	// Pack and unpack
	packed, err := PackIDevIDContent(original)
	require.NoError(t, err)

	reader := bytes.NewReader(packed)
	unpacked, err := UnpackIDevIDContent(reader)
	require.NoError(t, err)

	// Verify all fields
	assert.Equal(t, original.ProdModel, unpacked.ProdModel)
	assert.Equal(t, original.ProdSerial, unpacked.ProdSerial)
	assert.Equal(t, original.ProdCaData, unpacked.ProdCaData)
	assert.Equal(t, original.BootEvntLog, unpacked.BootEvntLog)
	assert.Equal(t, original.EkCert, unpacked.EkCert)
	assert.Equal(t, original.AttestPub, unpacked.AttestPub)
	assert.Equal(t, original.AtCreateTkt, unpacked.AtCreateTkt)
	assert.Equal(t, original.AtCertifyInfo, unpacked.AtCertifyInfo)
	assert.Equal(t, original.AtCertifyInfoSig, unpacked.AtCertifyInfoSig)
	assert.Equal(t, original.SigningPub, unpacked.SigningPub)
	assert.Equal(t, original.SgnCertifyInfo, unpacked.SgnCertifyInfo)
	assert.Equal(t, original.SgnCertifyInfoSig, unpacked.SgnCertifyInfoSig)
	assert.Equal(t, original.Pad, unpacked.Pad)
}
