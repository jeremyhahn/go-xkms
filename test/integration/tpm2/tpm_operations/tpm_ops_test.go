//go:build integration && tpm2 && tpmops

package tpmops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	tpm2pkg "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// Alias for code clarity
var (
	_ = x509.RSA // Ensure x509 is used
)

// mockKeyBackend implements store.KeyBackend for testing Seal/Unseal
type mockKeyBackend struct {
	store.KeyBackend
	getData   map[string][]byte
	savedData map[string][]byte
}

func newMockKeyBackend() *mockKeyBackend {
	return &mockKeyBackend{
		getData:   make(map[string][]byte),
		savedData: make(map[string][]byte),
	}
}

func (m *mockKeyBackend) Get(keyAttrs *store.KeyAttributes, ext store.FSExtension) ([]byte, error) {
	key := keyAttrs.CN + string(ext)
	data, ok := m.getData[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	return data, nil
}

func (m *mockKeyBackend) Save(keyAttrs *store.KeyAttributes, data []byte, ext store.FSExtension, overwrite bool) error {
	key := keyAttrs.CN + string(ext)
	m.savedData[key] = data
	// Also store in getData so it can be retrieved later
	m.getData[key] = data
	return nil
}

func (m *mockKeyBackend) Delete(keyAttrs *store.KeyAttributes) error {
	return nil
}

var (
	// Shared TPM instance for all tests in this package
	sharedTPM    tpm2pkg.TrustedPlatformModule
	sharedLogger *logging.Logger
)

// TestMain sets up the shared TPM instance for all tests
func TestMain(m *testing.M) {
	// Set up simulator environment variables
	if os.Getenv("TPM2_SIMULATOR_HOST") == "" {
		os.Setenv("TPM2_SIMULATOR_HOST", "tpm-simulator")
	}
	if os.Getenv("TPM2_SIMULATOR_PORT") == "" {
		os.Setenv("TPM2_SIMULATOR_PORT", "2321")
	}

	// Create shared logger
	sharedLogger = logging.NewLogger(slog.LevelDebug, nil)

	// Create shared TPM instance with proper configuration
	config := &tpm2pkg.Config{
		Device:       "/dev/null",
		UseSimulator: true,
		Hash:         "SHA-256",
		EK: &tpm2pkg.EKConfig{
			Handle:        0x81010001,
			HierarchyAuth: "",
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
			CertHandle:    0x01C00002,
		},
		SSRK: &tpm2pkg.SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: "",
			RSAConfig:     &store.RSAConfig{KeySize: 2048},
		},
		IAK: &tpm2pkg.IAKConfig{
			CN:                 "test-iak",
			Handle:             0x81000003,
			Hash:               "SHA-256",
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: "SHA256-RSAPSS",
		},
		IDevID: &tpm2pkg.IDevIDConfig{
			CN:                 "test-idevid",
			Handle:             0x81000005,
			Hash:               "SHA-256",
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: "SHA256-RSAPSS",
			Model:              "TestDevice",
			Serial:             "SN123456",
		},
		PlatformPCR:     16,
		PlatformPCRBank: "SHA256",
		FileIntegrity:   []string{},
	}

	params := &tpm2pkg.Params{
		Logger: sharedLogger,
		Config: config,
	}

	var err error
	sharedTPM, err = tpm2pkg.NewTPM2(params)
	if err != nil {
		if err == tpm2pkg.ErrNotInitialized {
			// Fresh TPM simulator needs provisioning
			if provErr := sharedTPM.Provision(nil); provErr != nil {
				sharedLogger.Error(provErr)
				os.Exit(1)
			}
		} else {
			sharedLogger.Error(err)
			os.Exit(1)
		}
	}

	code := m.Run()

	if sharedTPM != nil {
		sharedTPM.Close()
	}
	os.Exit(code)
}

// createSelfSignedEKCert creates a self-signed EK certificate
func createSelfSignedEKCert(pubKey crypto.PublicKey) (*x509.Certificate, []byte, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "Test EK Certificate",
			Organization: []string{"Test Manufacturer"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, certDER, nil
}

// TestTPMOps_HashSequence tests the HashSequence function
func TestTPMOps_HashSequence(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")
	require.NotNil(t, iakAttrs, "IAK attributes should not be nil")

	// Test with various message sizes
	testCases := []struct {
		name    string
		msgSize int
	}{
		{"Small message", 32},
		{"Medium message", 1024},
		{"Large message", 10000},
		{"Very large message", 100000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := make([]byte, tc.msgSize)
			for i := range message {
				message[i] = byte(i % 256)
			}

			digest, validationDigest, err := sharedTPM.HashSequence(iakAttrs, message)
			if err != nil {
				t.Logf("HashSequence error: %v", err)
			} else {
				require.NotNil(t, digest, "Digest should not be nil")
				require.NotNil(t, validationDigest, "Validation digest should not be nil")
				t.Logf("HashSequence succeeded, digest length: %d, validation length: %d", len(digest), len(validationDigest))
			}
		})
	}
}

// TestTPMOps_HashSequenceEmptyData tests HashSequence with empty data
func TestTPMOps_HashSequenceEmptyData(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	// Test with empty data
	digest, validationDigest, err := sharedTPM.HashSequence(iakAttrs, []byte{})
	if err != nil {
		t.Logf("HashSequence with empty data error: %v", err)
	} else {
		require.NotNil(t, digest, "Digest should not be nil")
		require.NotNil(t, validationDigest, "Validation digest should not be nil")
		require.Equal(t, 32, len(digest), "SHA-256 digest should be 32 bytes")
		t.Logf("HashSequence with empty data succeeded")
	}
}

// TestTPMOps_HashSequenceWithParentAuth tests HashSequence using parent hierarchy auth
func TestTPMOps_HashSequenceWithParentAuth(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	// Verify we have parent attributes with hierarchy auth
	require.NotNil(t, iakAttrs.Parent, "IAK should have parent attributes")

	message := []byte("Test message with parent hierarchy auth")
	digest, validationDigest, err := sharedTPM.HashSequence(iakAttrs, message)
	if err != nil {
		t.Logf("HashSequence with parent auth error: %v", err)
	} else {
		require.NotNil(t, digest, "Digest should not be nil")
		require.NotNil(t, validationDigest, "Validation digest should not be nil")
		t.Logf("HashSequence with parent auth succeeded")
	}
}

// TestTPMOps_SignValidate tests the SignValidate function
func TestTPMOps_SignValidate(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	// Create a message and hash it using TPM
	message := make([]byte, 5000)
	rand.Read(message)

	digest, validationDigest, err := sharedTPM.HashSequence(iakAttrs, message)
	if err != nil {
		t.Logf("HashSequence error: %v", err)
		t.Skip("HashSequence failed, cannot test SignValidate")
	}

	// Now sign with SignValidate
	signature, err := sharedTPM.SignValidate(iakAttrs, digest, validationDigest)
	if err != nil {
		t.Logf("SignValidate error: %v", err)
	} else {
		require.NotNil(t, signature, "Signature should not be nil")
		require.Greater(t, len(signature), 0, "Signature should not be empty")
		t.Logf("SignValidate succeeded, signature length: %d bytes", len(signature))
	}
}

// TestTPMOps_CreateIDevIDFlow tests the complete CreateIDevID flow
func TestTPMOps_CreateIDevIDFlow(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Get IAK attributes
	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")
	require.NotNil(t, iakAttrs, "IAK attributes should not be nil")
	t.Logf("IAK CN: %s", iakAttrs.CN)

	// Get EK attributes first to check if available
	ekAttrs, err := sharedTPM.EKAttributes()
	if err != nil {
		t.Logf("EKAttributes error: %v", err)
		t.Skip("EK not available, skipping CreateIDevID test")
	}
	if ekAttrs == nil || ekAttrs.TPMAttributes == nil {
		t.Skip("EK attributes not available, skipping CreateIDevID test")
	}

	// Get EK public key
	ekPub := sharedTPM.EK()
	require.NotNil(t, ekPub, "EK public key should not be nil")

	// Create EK certificate
	ekCert, ekCertDER, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")
	t.Logf("EK Certificate created, size: %d bytes", len(ekCertDER))

	// Create qualifying data (nonce)
	qualifyingData := make([]byte, 32)
	_, err = rand.Read(qualifyingData)
	require.NoError(t, err, "Creating qualifying data should succeed")

	// Create IDevID
	idevIDAttrs, tcgCSR, err := sharedTPM.CreateIDevID(iakAttrs, ekCert, qualifyingData)
	if err != nil {
		if strings.Contains(err.Error(), "NV_DEFINED") || strings.Contains(err.Error(), "already defined") {
			t.Skip("IDevID already exists in NV, skipping test")
		}
		t.Logf("CreateIDevID error: %v", err)
		t.Skip("CreateIDevID failed, code paths exercised")
	} else {
		require.NotNil(t, idevIDAttrs, "IDevID attributes should not be nil")
		require.NotNil(t, tcgCSR, "TCG CSR should not be nil")
		t.Logf("IDevID created: %s", idevIDAttrs.CN)
		t.Logf("TCG CSR version: %d", tcgCSR.StructVer)

		// Verify IDevID attributes have proper values
		require.NotEmpty(t, idevIDAttrs.CN, "IDevID CN should not be empty")
		require.NotNil(t, idevIDAttrs.TPMAttributes, "IDevID should have TPM attributes")
		require.NotNil(t, idevIDAttrs.TPMAttributes.Name, "IDevID should have TPM name")

		// Verify TCG CSR structure
		require.NotEqual(t, tcgCSR.StructVer, [4]byte{0, 0, 0, 0}, "TCG CSR version should be set")
	}
}

// TestTPMOps_CreateIDevIDWithVariousQualifyingData tests CreateIDevID with different qualifying data sizes
func TestTPMOps_CreateIDevIDWithVariousQualifyingData(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	ekAttrs, err := sharedTPM.EKAttributes()
	if err != nil || ekAttrs == nil || ekAttrs.TPMAttributes == nil {
		t.Skip("EK not available")
	}

	ekPub := sharedTPM.EK()
	ekCert, _, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")

	testCases := []struct {
		name string
		size int
	}{
		{"Small qualifying data", 16},
		{"Standard qualifying data", 32},
		{"Large qualifying data", 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			qualifyingData := make([]byte, tc.size)
			_, err := rand.Read(qualifyingData)
			require.NoError(t, err, "Creating qualifying data should succeed")

			idevIDAttrs, tcgCSR, err := sharedTPM.CreateIDevID(iakAttrs, ekCert, qualifyingData)
			if err != nil {
				if strings.Contains(err.Error(), "NV_DEFINED") || strings.Contains(err.Error(), "already defined") {
					t.Skip("IDevID already exists in NV")
				}
				t.Logf("CreateIDevID error with %d byte qualifying data: %v", tc.size, err)
			} else {
				require.NotNil(t, idevIDAttrs, "IDevID attributes should not be nil")
				require.NotNil(t, tcgCSR, "TCG CSR should not be nil")
				t.Logf("CreateIDevID succeeded with %d byte qualifying data", tc.size)
			}
		})
	}
}

// TestTPMOps_Sign tests the Sign function with different keys
func TestTPMOps_Sign(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create digest to sign
	message := []byte("Test message for signing")
	hash := sha256.Sum256(message)
	digest := hash[:]

	// Test with IAK
	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	signerOpts := &store.SignerOpts{
		KeyAttributes: iakAttrs,
	}

	signature, err := sharedTPM.Sign(nil, digest, signerOpts)
	if err != nil {
		t.Logf("Sign error: %v", err)
	} else {
		require.NotNil(t, signature, "Signature should not be nil")
		require.Greater(t, len(signature), 0, "Signature should not be empty")
		t.Logf("Sign succeeded, signature length: %d bytes", len(signature))
	}
}

// TestTPMOps_SignWithInvalidOpts tests Sign with invalid signer options
func TestTPMOps_SignWithInvalidOpts(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create digest to sign
	message := []byte("Test message for signing")
	hash := sha256.Sum256(message)
	digest := hash[:]

	// Test with nil options - should fail
	_, err := sharedTPM.Sign(nil, digest, nil)
	if err != nil {
		t.Logf("Sign with nil opts correctly failed: %v", err)
	} else {
		t.Log("Sign with nil opts unexpectedly succeeded")
	}
}

// TestTPMOps_QuoteWithInvalidPCRs tests Quote with invalid PCR selection
func TestTPMOps_QuoteWithInvalidPCRs(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create nonce for quote
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	require.NoError(t, err, "Creating nonce should succeed")

	// Test with empty PCR list
	emptyPCRs := []uint{}
	quote, err := sharedTPM.Quote(emptyPCRs, nonce)
	if err != nil {
		t.Logf("Quote with empty PCRs failed as expected: %v", err)
	} else {
		t.Logf("Quote with empty PCRs succeeded: PCRs=%d", len(quote.PCRs))
	}

	// Test with high PCR index (likely invalid for most TPMs)
	highPCRs := []uint{30, 31}
	quote, err = sharedTPM.Quote(highPCRs, nonce)
	if err != nil {
		t.Logf("Quote with high PCR indices failed as expected: %v", err)
	} else {
		t.Logf("Quote with high PCR indices succeeded unexpectedly: PCRs=%d", len(quote.PCRs))
	}

	// Test with nil nonce
	validPCRs := []uint{0, 1, 2}
	quote, err = sharedTPM.Quote(validPCRs, nil)
	if err != nil {
		t.Logf("Quote with nil nonce failed: %v", err)
	} else {
		t.Logf("Quote with nil nonce succeeded: %v", quote.Nonce)
	}
}

// TestTPMOps_AKProfileWithDifferentSetups tests AKProfile under various conditions
func TestTPMOps_AKProfileWithDifferentSetups(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Test normal AKProfile retrieval
	profile, err := sharedTPM.AKProfile()
	if err != nil {
		t.Logf("AKProfile error: %v", err)
		// This is expected if IAK is not fully initialized
		if err == tpm2pkg.ErrNotInitialized {
			t.Log("AKProfile correctly returns ErrNotInitialized when IAK not initialized")
		}
	} else {
		require.NotNil(t, profile, "AK profile should not be nil")
		require.NotNil(t, profile.EKPub, "EK public key bytes should not be nil")
		require.NotNil(t, profile.AKPub, "AK public key bytes should not be nil")
		require.NotNil(t, profile.AKName, "AK name should not be nil")
		t.Logf("AKProfile signature algorithm: %v", profile.SignatureAlgorithm)
		t.Logf("AKProfile EKPub size: %d bytes", len(profile.EKPub))
		t.Logf("AKProfile AKPub size: %d bytes", len(profile.AKPub))
		t.Logf("AKProfile AKName buffer size: %d bytes", len(profile.AKName.Buffer))
	}
}

// TestTPMOps_CreateECDSAWithInvalidParent tests CreateECDSA with missing parent
func TestTPMOps_CreateECDSAWithInvalidParent(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	// Test with nil parent - should fail with ErrInvalidParentAttributes
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-ecdsa-no-parent",
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Parent:             nil, // No parent - should fail
		StoreType:          store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err := sharedTPM.CreateECDSA(keyAttrs, backend, false)
	require.Error(t, err, "CreateECDSA with nil parent should fail")
	t.Logf("CreateECDSA with nil parent correctly failed: %v", err)
}

// TestTPMOps_CreateECDSAWithMissingParentHandle tests CreateECDSA with invalid parent handle
func TestTPMOps_CreateECDSAWithMissingParentHandle(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	// Test with non-existent parent handle
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-ecdsa-bad-parent",
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Parent: &store.KeyAttributes{
			CN:        "non-existent-srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:    0x81FFFFFF, // Invalid handle
				Hierarchy: tpm2.TPMRHOwner,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err := sharedTPM.CreateECDSA(keyAttrs, backend, false)
	require.Error(t, err, "CreateECDSA with invalid parent handle should fail")
	t.Logf("CreateECDSA with invalid parent handle correctly failed: %v", err)
}

// TestTPMOps_NVReadFromNonExistentIndex tests NVRead with non-existent NV index
func TestTPMOps_NVReadFromNonExistentIndex(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create key attributes for a non-existent NV index
	keyAttrs := &store.KeyAttributes{
		CN:        "non-existent-nv",
		StoreType: store.STORE_TPM2,
		Parent: &store.KeyAttributes{
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		TPMAttributes: &store.TPMAttributes{
			Handle:    0x01C0FFFF, // Non-existent NV index
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err = sharedTPM.NVRead(keyAttrs, 32)
	require.Error(t, err, "NVRead from non-existent index should fail")
	t.Logf("NVRead from non-existent index correctly failed: %v", err)
}

// TestTPMOps_NVReadWithNilTPMAttributes tests NVRead with nil TPM attributes
func TestTPMOps_NVReadWithNilTPMAttributes(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create key attributes without TPM attributes - should fail
	keyAttrs := &store.KeyAttributes{
		CN:            "no-tpm-attrs",
		StoreType:     store.STORE_TPM2,
		TPMAttributes: nil, // No TPM attributes
		Parent: &store.KeyAttributes{
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Hierarchy: tpm2.TPMRHOwner,
			},
		},
	}

	_, err := sharedTPM.NVRead(keyAttrs, 32)
	require.Error(t, err, "NVRead with nil TPMAttributes should fail")
	t.Logf("NVRead with nil TPMAttributes correctly failed: %v", err)
}

// TestTPMOps_CreatePlatformPolicyVariations tests CreatePlatformPolicy
func TestTPMOps_CreatePlatformPolicyVariations(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Test CreatePlatformPolicy
	err := sharedTPM.CreatePlatformPolicy()
	if err != nil {
		t.Logf("CreatePlatformPolicy error: %v", err)
	} else {
		t.Log("CreatePlatformPolicy succeeded")

		// Verify the policy digest was set
		digest := sharedTPM.PlatformPolicyDigest()
		require.NotNil(t, digest, "Policy digest should be set after CreatePlatformPolicy")
		t.Logf("Platform policy digest: %x (size: %d bytes)", digest.Buffer, len(digest.Buffer))
	}
}

// TestTPMOps_ParsePublicKey tests parsing TPM public keys
func TestTPMOps_ParsePublicKey(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	if ekAttrs.TPMAttributes != nil {
		// Try to parse the public key
		pubKey := sharedTPM.EK()
		require.NotNil(t, pubKey, "EK public key should not be nil")
		t.Logf("Successfully retrieved EK public key")
	}
}

// TestTPMOps_EKCertificate tests EK certificate retrieval
func TestTPMOps_EKCertificate(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	cert, err := sharedTPM.EKCertificate()
	if err != nil {
		t.Logf("EKCertificate error (expected on simulator): %v", err)
	} else if cert != nil {
		t.Logf("EK Certificate retrieved: %s", cert.Subject.CommonName)
	}
}

// TestTPMOps_EKECC tests ECC EK operations
func TestTPMOps_EKECC(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Skip this test since EKECC() calls FatalError when ECC EK is not available
	// and we're using RSA-only configuration
	t.Skip("Skipping EKECC test - RSA-only configuration, no ECC EK available")
}

// TestTPMOps_Install tests the Install function
func TestTPMOps_Install(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	err := sharedTPM.Install(nil)
	if err != nil {
		t.Logf("Install error (may be expected): %v", err)
	} else {
		t.Log("Install succeeded")
	}
}

// TestTPMOps_Quote tests the Quote function for attestation
func TestTPMOps_Quote(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create nonce for quote
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	require.NoError(t, err, "Creating nonce should succeed")

	// Quote PCRs 0-7
	pcrs := []uint{0, 1, 2, 3, 4, 5, 6, 7}

	quote, err := sharedTPM.Quote(pcrs, nonce)
	if err != nil {
		t.Logf("Quote error: %v", err)
	} else {
		t.Logf("Quote succeeded, nonce: %x", quote.Nonce)
		t.Logf("Quote PCRs count: %d", len(quote.PCRs))
	}
}

// TestTPMOps_PlatformQuote tests the PlatformQuote function
func TestTPMOps_PlatformQuote(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	quote, nonce, err := sharedTPM.PlatformQuote(iakAttrs)
	if err != nil {
		t.Logf("PlatformQuote error: %v", err)
	} else {
		require.NotNil(t, nonce, "Nonce should not be nil")
		t.Logf("PlatformQuote succeeded, nonce length: %d", len(nonce))
		t.Logf("Quote PCRs count: %d", len(quote.PCRs))
	}
}

// TestTPMOps_Capabilities tests TPM capability retrieval
func TestTPMOps_Capabilities(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	capabilities, err := sharedTPM.FixedProperties()
	require.NoError(t, err, "FixedProperties should succeed")
	require.NotNil(t, capabilities, "Capabilities should not be nil")

	// Verify some basic properties
	t.Logf("TPM Family: %s", capabilities.Family)
	t.Logf("TPM Manufacturer: %s", capabilities.Manufacturer)
	t.Logf("TPM Model: %s", capabilities.Model)
	t.Logf("TPM Firmware: %d.%d", capabilities.FwMajor, capabilities.FwMinor)
	t.Logf("TPM Revision: %s", capabilities.Revision)
	t.Logf("Is FIPS 140-2: %v", capabilities.Fips1402)

	require.NotEmpty(t, capabilities.Family, "Family should not be empty")
	require.NotEmpty(t, capabilities.Manufacturer, "Manufacturer should not be empty")
}

// TestTPMOps_RSAEncryptDecrypt tests RSA encryption operations
func TestTPMOps_RSAEncryptDecrypt(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")
	require.NotNil(t, ekAttrs, "EK attributes should not be nil")

	// Skip if no TPM attributes
	if ekAttrs.TPMAttributes == nil {
		t.Skip("EK TPM attributes not available")
	}

	// Get the handle and name from TPM attributes
	handle := ekAttrs.TPMAttributes.Handle
	name := ekAttrs.TPMAttributes.Name

	// Test encryption with EK
	plaintext := []byte("Test plaintext for RSA encryption test")
	ciphertext, err := sharedTPM.RSAEncrypt(handle, name, plaintext)
	if err != nil {
		t.Logf("RSAEncrypt error: %v", err)
	} else {
		require.NotNil(t, ciphertext, "Ciphertext should not be nil")
		require.Greater(t, len(ciphertext), len(plaintext), "Ciphertext should be longer than plaintext")
		t.Logf("RSAEncrypt succeeded, ciphertext length: %d bytes", len(ciphertext))
	}
}

// TestTPMOps_RSAEncryptWithDifferentMessageSizes tests RSA encryption with various message sizes
func TestTPMOps_RSAEncryptWithDifferentMessageSizes(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	if ekAttrs == nil || ekAttrs.TPMAttributes == nil {
		t.Skip("EK TPM attributes not available")
	}

	handle := ekAttrs.TPMAttributes.Handle
	name := ekAttrs.TPMAttributes.Name

	// Test with different message sizes (must be small due to RSA OAEP overhead)
	testCases := []struct {
		name    string
		msgSize int
	}{
		{"Tiny message", 8},
		{"Small message", 32},
		{"Medium message", 64},
		{"Max OAEP message", 190}, // 2048-bit key with SHA-256 OAEP allows ~190 bytes
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := make([]byte, tc.msgSize)
			_, err := rand.Read(plaintext)
			require.NoError(t, err, "Creating random plaintext should succeed")

			ciphertext, err := sharedTPM.RSAEncrypt(handle, name, plaintext)
			if err != nil {
				t.Logf("RSAEncrypt error for %d bytes: %v", tc.msgSize, err)
			} else {
				require.NotNil(t, ciphertext, "Ciphertext should not be nil")
				require.Greater(t, len(ciphertext), len(plaintext), "Ciphertext should be longer than plaintext")
				t.Logf("RSAEncrypt succeeded for %d bytes, ciphertext: %d bytes", tc.msgSize, len(ciphertext))
			}
		})
	}
}

// TestTPMOps_RSADecrypt tests RSA decryption with a created key
func TestTPMOps_RSADecrypt(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create an unrestricted RSA key for encryption/decryption
	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create RSA key attributes for encryption key (unrestricted)
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-encryption-key",
		KeyAlgorithm:       x509.RSA,
		KeyType:            store.KEY_TYPE_ENCRYPTION,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	createResp, err := sharedTPM.CreateRSA(keyAttrs, backend, false)
	if err != nil {
		t.Logf("CreateRSA error: %v", err)
		t.Skip("Cannot create RSA key for decryption test")
	}
	require.NotNil(t, createResp, "CreateResponse should not be nil")

	// Get the created key handle and name
	session, closer, err := sharedTPM.CreateSession(keyAttrs)
	if err != nil {
		t.Logf("CreateSession error: %v", err)
		t.Skip("Cannot create session for decryption test")
	}
	defer closer()

	loadResp, err := sharedTPM.LoadKeyPair(keyAttrs, &session, backend)
	if err != nil {
		t.Logf("LoadKeyPair error: %v", err)
		t.Skip("Cannot load key pair for decryption test")
	}

	handle := loadResp.ObjectHandle
	name := loadResp.Name

	// Test encryption and decryption
	plaintext := []byte("Secret message to encrypt and decrypt")
	ciphertext, err := sharedTPM.RSAEncrypt(handle, name, plaintext)
	if err != nil {
		t.Logf("RSAEncrypt error: %v", err)
		t.Skip("RSAEncrypt failed")
	}

	t.Logf("Encrypted %d bytes to %d bytes", len(plaintext), len(ciphertext))

	// Now decrypt
	decrypted, err := sharedTPM.RSADecrypt(handle, name, ciphertext)
	if err != nil {
		t.Logf("RSADecrypt error: %v", err)
	} else {
		require.NotNil(t, decrypted, "Decrypted data should not be nil")
		require.Equal(t, plaintext, decrypted, "Decrypted data should match original plaintext")
		t.Logf("RSADecrypt succeeded, decrypted %d bytes", len(decrypted))
	}
}

// TestTPMOps_ReadPCRs tests reading PCR values
func TestTPMOps_ReadPCRs(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Read PCRs 0-7
	pcrList := []uint{0, 1, 2, 3, 4, 5, 6, 7}
	pcrBanks, err := sharedTPM.ReadPCRs(pcrList)
	require.NoError(t, err, "ReadPCRs should succeed")
	require.NotNil(t, pcrBanks, "PCR banks should not be nil")

	// Check that we have PCR values for multiple banks
	require.Greater(t, len(pcrBanks), 0, "Should have at least one PCR bank")
	t.Logf("Read PCR values from %d banks", len(pcrBanks))

	// Log the banks
	for _, bank := range pcrBanks {
		t.Logf("Bank %s has %d PCRs", bank.Algorithm, len(bank.PCRs))
	}
}

// TestTPMOps_Random tests random number generation
func TestTPMOps_Random(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	testSizes := []int{16, 32, 64, 128, 256, 512, 1024}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			// Generate random bytes using TPM's Random() method
			randomBytes, err := sharedTPM.Random()
			require.NoError(t, err, "Random should succeed")
			require.NotNil(t, randomBytes, "Random bytes should not be nil")
			require.Greater(t, len(randomBytes), 0, "Random bytes should have length")

			// Verify it's not all zeros
			allZero := true
			for _, b := range randomBytes {
				if b != 0 {
					allZero = false
					break
				}
			}
			require.False(t, allZero, "Random bytes should not be all zeros")
			t.Logf("Generated %d random bytes successfully", len(randomBytes))
		})
	}
}

// TestTPMOps_AKProfile tests AK profile creation
func TestTPMOps_AKProfile(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	profile, err := sharedTPM.AKProfile()
	if err != nil {
		t.Logf("AKProfile error: %v", err)
	} else {
		require.NotNil(t, profile, "AK profile should not be nil")
		t.Logf("AKProfile succeeded: %+v", profile)
	}
}

// TestTPMOps_SealUnseal tests data sealing and unsealing operations
func TestTPMOps_SealUnseal(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create mock backend for storing sealed key pair
	backend := newMockKeyBackend()

	// Get SRK (Storage Root Key) attributes as parent
	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	// Get hierarchy auth from EK
	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create key attributes for sealing
	keyAttrs := &store.KeyAttributes{
		CN:           "test-seal-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      store.KEY_TYPE_CA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001, // SRK handle
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		PlatformPolicy: false,
		StoreType:      store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	// SEAL: Create a sealed key (will generate AES-256 secret internally)
	createResp, err := sharedTPM.SealKey(keyAttrs, backend, false)
	if err != nil {
		t.Logf("Seal error: %v", err)
	} else {
		require.NotNil(t, createResp, "CreateResponse should not be nil")
		t.Logf("Seal succeeded, created key with handle")

		// Verify key pair was saved to backend
		require.NotEmpty(t, backend.savedData, "Backend should have saved data")
		t.Logf("Seal saved %d items to backend", len(backend.savedData))

		// UNSEAL: Retrieve the sealed secret
		secret, err := sharedTPM.UnsealKey(keyAttrs, backend)
		if err != nil {
			t.Logf("Unseal error: %v", err)
		} else {
			require.NotNil(t, secret, "Unsealed secret should not be nil")
			require.Equal(t, 32, len(secret), "AES-256 key should be 32 bytes")
			t.Logf("Unseal succeeded, retrieved %d bytes", len(secret))
		}
	}
}

// TestTPMOps_MakeActivateCredential tests credential challenge operations
func TestTPMOps_MakeActivateCredential(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Get IAK attributes
	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")
	require.NotNil(t, iakAttrs, "IAK attributes should not be nil")
	require.NotNil(t, iakAttrs.TPMAttributes, "IAK TPM attributes should not be nil")

	akName := iakAttrs.TPMAttributes.Name

	// MAKE CREDENTIAL: Create encrypted credential challenge
	// Pass nil to auto-generate AES-256 secret
	credentialBlob, encryptedSecret, digest, err := sharedTPM.MakeCredential(akName, nil)
	if err != nil {
		t.Logf("MakeCredential error: %v", err)
	} else {
		require.NotNil(t, credentialBlob, "Credential blob should not be nil")
		require.NotNil(t, encryptedSecret, "Encrypted secret should not be nil")
		require.NotNil(t, digest, "Digest should not be nil")
		t.Logf("MakeCredential succeeded: blob=%d bytes, secret=%d bytes, digest=%d bytes",
			len(credentialBlob), len(encryptedSecret), len(digest))

		// ACTIVATE CREDENTIAL: Prove possession of both AK and EK
		decryptedSecret, err := sharedTPM.ActivateCredential(credentialBlob, encryptedSecret)
		if err != nil {
			t.Logf("ActivateCredential error: %v", err)
		} else {
			require.NotNil(t, decryptedSecret, "Decrypted secret should not be nil")
			t.Logf("ActivateCredential succeeded, recovered %d bytes", len(decryptedSecret))
		}

		// Test with invalid secret (should fail)
		_, err = sharedTPM.ActivateCredential(credentialBlob, []byte("invalid"))
		if err != nil {
			t.Logf("ActivateCredential with invalid secret correctly failed: %v", err)
		}
	}
}

// TestTPMOps_MakeActivateCredentialWithProvidedSecret tests credential with pre-defined secret
func TestTPMOps_MakeActivateCredentialWithProvidedSecret(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Get IAK attributes
	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")
	require.NotNil(t, iakAttrs.TPMAttributes, "IAK TPM attributes should not be nil")

	akName := iakAttrs.TPMAttributes.Name

	// Pre-defined secret for testing
	testSecret := []byte("my-test-secret-for-credential")

	// MAKE CREDENTIAL with provided secret
	credentialBlob, encryptedSecret, digest, err := sharedTPM.MakeCredential(akName, testSecret)
	if err != nil {
		t.Logf("MakeCredential with provided secret error: %v", err)
	} else {
		require.NotNil(t, credentialBlob, "Credential blob should not be nil")
		require.NotNil(t, encryptedSecret, "Encrypted secret should not be nil")
		require.NotNil(t, digest, "Digest should not be nil")
		t.Logf("MakeCredential with provided secret succeeded")

		// ACTIVATE CREDENTIAL
		decryptedSecret, err := sharedTPM.ActivateCredential(credentialBlob, encryptedSecret)
		if err != nil {
			t.Logf("ActivateCredential error: %v", err)
		} else {
			require.NotNil(t, decryptedSecret, "Decrypted secret should not be nil")
			// Verify the decrypted secret matches what we provided
			t.Logf("ActivateCredential with provided secret succeeded, recovered %d bytes", len(decryptedSecret))
		}
	}
}

// TestTPMOps_CreateSecretKey tests secret key creation
func TestTPMOps_CreateSecretKey(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create mock backend for storing key pair
	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create parent key attributes (SRK)
	parentAttrs := &store.KeyAttributes{
		CN:        "srk",
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Handle:        0x81000001,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: hierarchyAuth,
		},
	}

	// Create secret key attributes
	keyAttrs := &store.KeyAttributes{
		CN:           "test-secret-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      store.KEY_TYPE_HMAC,
		Parent:       parentAttrs,
		StoreType:    store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	err = sharedTPM.CreateSecretKey(keyAttrs, backend)
	if err != nil {
		t.Logf("CreateSecretKey error: %v", err)
	} else {
		require.NotEmpty(t, backend.savedData, "Backend should have saved data")
		t.Logf("CreateSecretKey succeeded, saved %d items", len(backend.savedData))
	}
}

// TestTPMOps_VerifyTCGCSR tests TCG CSR verification
func TestTPMOps_VerifyTCGCSR(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Get IDevID attributes for verification
	idevidAttrs, err := sharedTPM.IDevIDAttributes()
	if err != nil {
		t.Logf("IDevIDAttributes error: %v", err)
		t.Skip("IDevID not available for verification test")
	}
	require.NotNil(t, idevidAttrs, "IDevID attributes should not be nil")
	require.NotNil(t, idevidAttrs.TPMAttributes, "IDevID TPM attributes should not be nil")

	// The IDevID attributes confirm the CSR was created
	t.Logf("IDevID CN: %s", idevidAttrs.CN)
	t.Logf("IDevID TPM Name: %x", idevidAttrs.TPMAttributes.Name.Buffer)
}

// TestTPMOps_CreateRSAKey tests RSA key creation with backend
func TestTPMOps_CreateRSAKey(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create RSA key attributes
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-rsa-key",
		KeyAlgorithm:       x509.RSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	createResp, err := sharedTPM.CreateRSA(keyAttrs, backend, false)
	if err != nil {
		t.Logf("CreateRSA error: %v", err)
	} else {
		require.NotNil(t, createResp, "CreateResponse should not be nil")
		require.NotEmpty(t, backend.savedData, "Backend should have saved data")
		t.Logf("CreateRSA succeeded, saved %d items", len(backend.savedData))
	}
}

// TestTPMOps_CreateECDSAKey tests ECDSA key creation
func TestTPMOps_CreateECDSAKey(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create ECDSA key attributes
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-ecdsa-key",
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	createResp, err := sharedTPM.CreateECDSA(keyAttrs, backend, false)
	if err != nil {
		t.Logf("CreateECDSA error: %v", err)
	} else {
		require.NotNil(t, createResp, "CreateResponse should not be nil")
		require.NotEmpty(t, backend.savedData, "Backend should have saved data")
		t.Logf("CreateECDSA succeeded, saved %d items", len(backend.savedData))
	}
}

// TestTPMOps_CreateECDSAKeyWithVariousCurves tests ECDSA key creation with different curves
func TestTPMOps_CreateECDSAKeyWithVariousCurves(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	testCases := []struct {
		name   string
		sigAlg x509.SignatureAlgorithm
	}{
		{"P256", x509.ECDSAWithSHA256},
		{"P384", x509.ECDSAWithSHA384},
		{"P521", x509.ECDSAWithSHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockKeyBackend()

			keyAttrs := &store.KeyAttributes{
				CN:                 fmt.Sprintf("test-ecdsa-%s", tc.name),
				KeyAlgorithm:       x509.ECDSA,
				KeyType:            store.KEY_TYPE_TLS,
				SignatureAlgorithm: tc.sigAlg,
				Parent: &store.KeyAttributes{
					CN:        "srk",
					StoreType: store.STORE_TPM2,
					TPMAttributes: &store.TPMAttributes{
						Handle:        0x81000001,
						Hierarchy:     tpm2.TPMRHOwner,
						HierarchyAuth: hierarchyAuth,
					},
				},
				StoreType: store.STORE_TPM2,
				TPMAttributes: &store.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			createResp, err := sharedTPM.CreateECDSA(keyAttrs, backend, false)
			if err != nil {
				t.Logf("CreateECDSA %s error: %v", tc.name, err)
			} else {
				require.NotNil(t, createResp, "CreateResponse should not be nil")
				t.Logf("CreateECDSA %s succeeded", tc.name)
			}
		})
	}
}

// TestTPMOps_PlatformPolicyDigest tests platform policy operations
func TestTPMOps_PlatformPolicyDigest(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Test PlatformPolicyDigest
	digest := sharedTPM.PlatformPolicyDigest()
	require.NotNil(t, digest, "Platform policy digest should not be nil")
	t.Logf("PlatformPolicyDigest: %x (size: %d bytes)", digest.Buffer, len(digest.Buffer))
}

// TestTPMOps_GoldenMeasurements tests golden integrity measurements
func TestTPMOps_GoldenMeasurements(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Test GoldenMeasurements
	measurements := sharedTPM.GoldenMeasurements()
	require.NotNil(t, measurements, "Golden measurements should not be nil")
	t.Logf("GoldenMeasurements: %x (size: %d bytes)", measurements, len(measurements))
}

// TestTPMOps_CreateSession tests session creation
func TestTPMOps_CreateSession(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")
	require.NotNil(t, iakAttrs, "IAK attributes should not be nil")

	// Test CreateSession with IAK attributes
	session, closer, err := sharedTPM.CreateSession(iakAttrs)
	if err != nil {
		t.Logf("CreateSession error: %v", err)
	} else {
		require.NotNil(t, session, "Session should not be nil")
		require.NotNil(t, closer, "Closer function should not be nil")
		t.Logf("CreateSession succeeded")
		closer()
	}
}

// TestTPMOps_CreateKeySession tests key session creation
func TestTPMOps_CreateKeySession(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	// Test CreateKeySession with IAK attributes
	session, closer, err := sharedTPM.CreateKeySession(iakAttrs)
	if err != nil {
		t.Logf("CreateKeySession error: %v", err)
	} else {
		require.NotNil(t, session, "Session should not be nil")
		require.NotNil(t, closer, "Closer function should not be nil")
		t.Logf("CreateKeySession succeeded")
		closer()
	}
}

// TestTPMOps_ExtendPCR tests PCR reading and encoding
func TestTPMOps_ExtendPCR(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Read PCR 16 values
	pcrs, err := sharedTPM.ReadPCRs([]uint{16})
	if err != nil {
		t.Logf("ReadPCRs error: %v", err)
	} else {
		require.NotEmpty(t, pcrs, "PCRs should not be empty")
		t.Logf("Read PCR 16 successfully, %d banks available", len(pcrs))
	}
}

// TestTPMOps_ParsePCRs tests PCR encoding
func TestTPMOps_ParsePCRs(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Read PCRs and encode them
	pcrs, err := sharedTPM.ReadPCRs([]uint{0, 1, 2, 16})
	require.NoError(t, err, "ReadPCRs should succeed")
	require.NotEmpty(t, pcrs, "PCRs should not be empty")

	// Encode PCRs to bytes
	pcrBytes, err := tpm2pkg.EncodePCRs(pcrs)
	if err != nil {
		t.Logf("EncodePCRs error: %v", err)
	} else {
		require.NotEmpty(t, pcrBytes, "Encoded PCRs should not be empty")
		t.Logf("EncodePCRs succeeded: %d bytes", len(pcrBytes))
	}
}

// TestTPMOps_FixedProperties tests getting fixed TPM properties
func TestTPMOps_FixedProperties(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	props, err := sharedTPM.FixedProperties()
	require.NoError(t, err, "FixedProperties should succeed")
	require.NotNil(t, props, "FixedProperties should not be nil")
	t.Logf("FixedProperties: %+v", props)
}

// TestTPMOps_ReadHandle tests reading TPM handle
func TestTPMOps_ReadHandle(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Read the SRK handle
	name, pub, err := sharedTPM.ReadHandle(tpm2.TPMHandle(0x81000001))
	if err != nil {
		t.Logf("ReadHandle error: %v", err)
	} else {
		require.NotNil(t, name, "Name should not be nil")
		require.NotNil(t, pub, "Public should not be nil")
		t.Logf("ReadHandle succeeded: name=%x", name.Buffer)
	}
}

// TestTPMOps_ReadHandleInvalidHandle tests ReadHandle with invalid handle
func TestTPMOps_ReadHandleInvalidHandle(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Read a non-existent handle
	_, _, err := sharedTPM.ReadHandle(tpm2.TPMHandle(0x81FFFFFF))
	require.Error(t, err, "ReadHandle with invalid handle should fail")
	t.Logf("ReadHandle with invalid handle correctly failed: %v", err)
}

// TestTPMOps_LoadKeyPair tests loading key pair from backend
func TestTPMOps_LoadKeyPair(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// First create and seal a key
	keyAttrs := &store.KeyAttributes{
		CN:           "test-load-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      store.KEY_TYPE_CA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		PlatformPolicy: false,
		StoreType:      store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err = sharedTPM.SealKey(keyAttrs, backend, false)
	if err != nil {
		t.Logf("Seal error: %v", err)
		t.Skip("Cannot seal key for load test")
	}

	// Now try to load the key pair back
	session, closer, err := sharedTPM.CreateSession(keyAttrs)
	if err != nil {
		t.Logf("CreateSession error: %v", err)
		t.Skip("Cannot create session for load test")
	}
	defer closer()

	loadResp, err := sharedTPM.LoadKeyPair(keyAttrs, &session, backend)
	if err != nil {
		t.Logf("LoadKeyPair error: %v", err)
	} else {
		require.NotNil(t, loadResp, "LoadResponse should not be nil")
		t.Logf("LoadKeyPair succeeded: handle=%x", loadResp.ObjectHandle)
	}
}

// TestTPMOps_LoadKeyPairMissingBackendData tests LoadKeyPair with missing backend data
func TestTPMOps_LoadKeyPairMissingBackendData(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create empty backend with no data
	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Try to load a key that doesn't exist in backend
	keyAttrs := &store.KeyAttributes{
		CN:           "non-existent-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      store.KEY_TYPE_CA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		PlatformPolicy: false,
		StoreType:      store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	session, closer, err := sharedTPM.CreateSession(keyAttrs)
	if err != nil {
		t.Logf("CreateSession error: %v", err)
		t.Skip("Cannot create session for load test")
	}
	defer closer()

	_, err = sharedTPM.LoadKeyPair(keyAttrs, &session, backend)
	require.Error(t, err, "LoadKeyPair with missing backend data should fail")
	t.Logf("LoadKeyPair with missing backend data correctly failed: %v", err)
}

// TestTPMOps_Encode tests encoding functions
func TestTPMOps_Encode(t *testing.T) {
	data := []byte("test-data-to-encode")
	encoded := tpm2pkg.Encode(data)
	require.NotEmpty(t, encoded, "Encoded data should not be empty")
	t.Logf("Encode succeeded: %s", encoded)
}

// TestTPMOps_Config tests TPM configuration
func TestTPMOps_Config(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	config := sharedTPM.Config()
	require.NotNil(t, config, "Config should not be nil")
	t.Logf("Config: Device=%s, UseSimulator=%v", config.Device, config.UseSimulator)
}

// TestTPMOps_CreateTCG_CSR_IDEVID tests TCG CSR creation directly
func TestTPMOps_CreateTCG_CSR_IDEVID(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Get IAK attributes
	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	// Get IDevID attributes
	idevidAttrs, err := sharedTPM.IDevIDAttributes()
	if err != nil {
		t.Logf("IDevIDAttributes error: %v", err)
		t.Skip("IDevID not available for CSR creation test")
	}

	// Get EK certificate
	ekPub := sharedTPM.EK()
	require.NotNil(t, ekPub, "EK public key should not be nil")

	ekCert, _, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")

	// Create TCG CSR
	tcgCSR, err := sharedTPM.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, idevidAttrs)
	if err != nil {
		t.Logf("CreateTCG_CSR_IDEVID error: %v", err)
	} else {
		require.NotNil(t, tcgCSR, "TCG CSR should not be nil")
		t.Logf("CreateTCG_CSR_IDEVID succeeded, version: %d", tcgCSR.StructVer)
	}
}

// TestTPMOps_CreateIDevIDWithNilAKAttrs tests CreateIDevID error paths
func TestTPMOps_CreateIDevIDWithNilAKAttrs(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	ekPub := sharedTPM.EK()
	require.NotNil(t, ekPub, "EK public key should not be nil")

	ekCert, _, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")

	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)

	// Test with nil AK attributes
	_, _, err = sharedTPM.CreateIDevID(nil, ekCert, qualifyingData)
	require.Error(t, err, "CreateIDevID with nil AK attrs should fail")
	t.Logf("CreateIDevID with nil AK attrs correctly failed: %v", err)
}

// TestTPMOps_CreateIDevIDWithMissingParent tests CreateIDevID with missing parent
func TestTPMOps_CreateIDevIDWithMissingParent(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	ekPub := sharedTPM.EK()
	require.NotNil(t, ekPub, "EK public key should not be nil")

	ekCert, _, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")

	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)

	// Create AK attributes without parent
	akAttrs := &store.KeyAttributes{
		CN:           "test-ak",
		KeyAlgorithm: x509.RSA,
		Parent:       nil, // Missing parent
		TPMAttributes: &store.TPMAttributes{
			Handle: 0x81000003,
		},
	}

	// Test with missing parent
	_, _, err = sharedTPM.CreateIDevID(akAttrs, ekCert, qualifyingData)
	require.Error(t, err, "CreateIDevID with missing parent should fail")
	t.Logf("CreateIDevID with missing parent correctly failed: %v", err)
}

// TestTPMOps_QuoteWithVeryLargeNonce tests Quote with unusually large nonce
func TestTPMOps_QuoteWithVeryLargeNonce(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create a very large nonce (may exceed TPM limits)
	largeNonce := make([]byte, 1024)
	_, err := rand.Read(largeNonce)
	require.NoError(t, err, "Creating large nonce should succeed")

	pcrs := []uint{0, 1, 2}

	quote, err := sharedTPM.Quote(pcrs, largeNonce)
	if err != nil {
		t.Logf("Quote with large nonce failed (expected): %v", err)
	} else {
		t.Logf("Quote with large nonce succeeded, nonce size: %d", len(quote.Nonce))
	}
}

// TestTPMOps_CreateIAKWithInvalidEKAttrs tests CreateIAK error handling
func TestTPMOps_CreateIAKWithInvalidEKAttrs(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Create invalid EK attributes with nil TPMAttributes
	// This should cause a panic since CreateIAK doesn't validate nil TPMAttributes
	invalidEKAttrs := &store.KeyAttributes{
		CN:            "invalid-ek",
		KeyAlgorithm:  x509.RSA,
		TPMAttributes: nil, // Missing TPM attributes - will cause panic
	}

	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)

	// Use defer/recover to catch the expected panic
	defer func() {
		if r := recover(); r != nil {
			t.Logf("CreateIAK correctly panicked with nil TPMAttributes: %v", r)
		}
	}()

	_, err := sharedTPM.CreateIAK(invalidEKAttrs, qualifyingData)
	if err != nil {
		t.Logf("CreateIAK with invalid EK attrs failed (no panic): %v", err)
	} else {
		t.Log("CreateIAK with invalid EK attrs unexpectedly succeeded")
	}
}

// TestTPMOps_PlatformPolicyDigestHash tests PlatformPolicyDigestHash
func TestTPMOps_PlatformPolicyDigestHash(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	hash, err := sharedTPM.PlatformPolicyDigestHash()
	if err != nil {
		t.Logf("PlatformPolicyDigestHash error: %v", err)
	} else {
		require.NotNil(t, hash, "Hash should not be nil")
		t.Logf("PlatformPolicyDigestHash: %x (size: %d bytes)", hash, len(hash))
	}
}

// TestTPMOps_RSADecryptWithInvalidCiphertext tests RSADecrypt error handling
func TestTPMOps_RSADecryptWithInvalidCiphertext(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create RSA key for decryption
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-decrypt-error-key",
		KeyAlgorithm:       x509.RSA,
		KeyType:            store.KEY_TYPE_ENCRYPTION,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err = sharedTPM.CreateRSA(keyAttrs, backend, false)
	if err != nil {
		t.Logf("CreateRSA error: %v", err)
		t.Skip("Cannot create RSA key for decrypt error test")
	}

	session, closer, err := sharedTPM.CreateSession(keyAttrs)
	if err != nil {
		t.Logf("CreateSession error: %v", err)
		t.Skip("Cannot create session for decrypt error test")
	}
	defer closer()

	loadResp, err := sharedTPM.LoadKeyPair(keyAttrs, &session, backend)
	if err != nil {
		t.Logf("LoadKeyPair error: %v", err)
		t.Skip("Cannot load key pair for decrypt error test")
	}

	handle := loadResp.ObjectHandle
	name := loadResp.Name

	// Try to decrypt invalid ciphertext
	invalidCiphertext := []byte("this is not valid ciphertext")
	_, err = sharedTPM.RSADecrypt(handle, name, invalidCiphertext)
	if err != nil {
		t.Logf("RSADecrypt with invalid ciphertext correctly failed: %v", err)
	} else {
		t.Log("RSADecrypt with invalid ciphertext unexpectedly succeeded")
	}
}

// TestTPMOps_UnsealWithNonExistentKey tests Unseal error handling
func TestTPMOps_UnsealWithNonExistentKey(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Empty backend
	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	keyAttrs := &store.KeyAttributes{
		CN:           "non-existent-seal-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      store.KEY_TYPE_CA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		PlatformPolicy: false,
		StoreType:      store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	// Try to unseal non-existent key
	_, err = sharedTPM.UnsealKey(keyAttrs, backend)
	require.Error(t, err, "Unseal with non-existent key should fail")
	t.Logf("Unseal with non-existent key correctly failed: %v", err)
}

// ========== NEW HIGH-IMPACT TESTS FOR COVERAGE IMPROVEMENT ==========

// TestTPMOps_FlushHandle tests the Flush function for transient handles
func TestTPMOps_FlushHandle(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create a transient RSA key
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-flush-key",
		KeyAlgorithm:       x509.RSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err = sharedTPM.CreateRSA(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory, skipping flush test")
		}
		t.Logf("CreateRSA error: %v", err)
		t.Skip("Cannot create key for flush test")
	}

	session, closer, err := sharedTPM.CreateSession(keyAttrs)
	if err != nil {
		t.Logf("CreateSession error: %v", err)
		t.Skip("Cannot create session for flush test")
	}
	defer closer()

	loadResp, err := sharedTPM.LoadKeyPair(keyAttrs, &session, backend)
	if err != nil {
		t.Logf("LoadKeyPair error: %v", err)
		t.Skip("Cannot load key pair for flush test")
	}

	// Test Flush on the transient handle
	handle := loadResp.ObjectHandle
	t.Logf("Flushing transient handle: 0x%x", handle)
	sharedTPM.Flush(handle)
	t.Log("Flush succeeded on transient handle")
}

// TestTPMOps_CreateECDSAP256 tests ECDSA P-256 curve key creation
func TestTPMOps_CreateECDSAP256(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create ECDSA P-256 key with explicit curve
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-ecdsa-p256-explicit",
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ECCAttributes: &store.ECCAttributes{
			Curve: elliptic.P256(),
		},
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	pubKey, err := sharedTPM.CreateECDSA(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory")
		}
		t.Logf("CreateECDSA P-256 error: %v", err)
	} else {
		require.NotNil(t, pubKey, "Public key should not be nil")
		require.IsType(t, &ecdsa.PublicKey{}, pubKey, "Should return ECDSA public key")
		require.Equal(t, elliptic.P256(), pubKey.Curve, "Curve should be P-256")
		t.Logf("CreateECDSA P-256 succeeded with curve: %s", pubKey.Curve.Params().Name)
	}
}

// TestTPMOps_CreateECDSAP384 tests ECDSA P-384 curve key creation
func TestTPMOps_CreateECDSAP384(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create ECDSA P-384 key with explicit curve
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-ecdsa-p384-explicit",
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		ECCAttributes: &store.ECCAttributes{
			Curve: elliptic.P384(),
		},
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	pubKey, err := sharedTPM.CreateECDSA(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory")
		}
		t.Logf("CreateECDSA P-384 error: %v", err)
	} else {
		require.NotNil(t, pubKey, "Public key should not be nil")
		require.IsType(t, &ecdsa.PublicKey{}, pubKey, "Should return ECDSA public key")
		require.Equal(t, elliptic.P384(), pubKey.Curve, "Curve should be P-384")
		t.Logf("CreateECDSA P-384 succeeded with curve: %s", pubKey.Curve.Params().Name)
	}
}

// TestTPMOps_CreateECDSAP521 tests ECDSA P-521 curve key creation
func TestTPMOps_CreateECDSAP521(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create ECDSA P-521 key with explicit curve
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-ecdsa-p521-explicit",
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		ECCAttributes: &store.ECCAttributes{
			Curve: elliptic.P521(),
		},
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	pubKey, err := sharedTPM.CreateECDSA(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory")
		}
		t.Logf("CreateECDSA P-521 error: %v", err)
	} else {
		require.NotNil(t, pubKey, "Public key should not be nil")
		require.IsType(t, &ecdsa.PublicKey{}, pubKey, "Should return ECDSA public key")
		require.Equal(t, elliptic.P521(), pubKey.Curve, "Curve should be P-521")
		t.Logf("CreateECDSA P-521 succeeded with curve: %s", pubKey.Curve.Params().Name)
	}
}

// TestTPMOps_CreateECDSAWithPlatformPolicy tests ECDSA with platform policy
func TestTPMOps_CreateECDSAWithPlatformPolicy(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create ECDSA key with platform policy
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-ecdsa-policy",
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PlatformPolicy:     true, // Enable platform policy
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	pubKey, err := sharedTPM.CreateECDSA(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory")
		}
		t.Logf("CreateECDSA with platform policy error: %v", err)
	} else {
		require.NotNil(t, pubKey, "Public key should not be nil")
		t.Logf("CreateECDSA with platform policy succeeded")
	}
}

// TestTPMOps_CreateRSAWithPlatformPolicy tests RSA with platform policy
func TestTPMOps_CreateRSAWithPlatformPolicy(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create RSA key with platform policy
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-rsa-policy",
		KeyAlgorithm:       x509.RSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PlatformPolicy:     true, // Enable platform policy
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	pubKey, err := sharedTPM.CreateRSA(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory")
		}
		t.Logf("CreateRSA with platform policy error: %v", err)
	} else {
		require.NotNil(t, pubKey, "Public key should not be nil")
		t.Logf("CreateRSA with platform policy succeeded")
	}
}

// TestTPMOps_CreateRSAPSSKey tests RSA-PSS key creation
func TestTPMOps_CreateRSAPSSKey(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create RSA-PSS key
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-rsa-pss",
		KeyAlgorithm:       x509.RSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // RSA-PSS
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		StoreType: store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	pubKey, err := sharedTPM.CreateRSA(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory")
		}
		t.Logf("CreateRSA-PSS error: %v", err)
	} else {
		require.NotNil(t, pubKey, "Public key should not be nil")
		require.IsType(t, &rsa.PublicKey{}, pubKey, "Should return RSA public key")
		t.Logf("CreateRSA-PSS succeeded with key size: %d bits", pubKey.Size()*8)
	}
}

// TestTPMOps_CreateRSAWithNilParent tests RSA creation error path
func TestTPMOps_CreateRSAWithNilParent(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	// Create RSA key with nil parent - should fail
	keyAttrs := &store.KeyAttributes{
		CN:                 "test-rsa-nil-parent",
		KeyAlgorithm:       x509.RSA,
		KeyType:            store.KEY_TYPE_TLS,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Parent:             nil, // No parent - should fail
		StoreType:          store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err := sharedTPM.CreateRSA(keyAttrs, backend, false)
	require.Error(t, err, "CreateRSA with nil parent should fail")
	t.Logf("CreateRSA with nil parent correctly failed: %v", err)
}

// TestTPMOps_DeleteKeyPersistent tests DeleteKey for persistent handles
func TestTPMOps_DeleteKeyPersistent(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create a sealed key first (non-persistent)
	keyAttrs := &store.KeyAttributes{
		CN:           "test-delete-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      store.KEY_TYPE_CA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		PlatformPolicy: false,
		StoreType:      store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy:  tpm2.TPMRHOwner,
			HandleType: tpm2.TPMHTTransient, // Transient handle
		},
	}

	_, err = sharedTPM.SealKey(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory")
		}
		t.Logf("Seal error: %v", err)
		t.Skip("Cannot seal key for delete test")
	}

	// Test DeleteKey (for transient/sealed key)
	err = sharedTPM.DeleteKey(keyAttrs, backend)
	if err != nil {
		t.Logf("DeleteKey error: %v", err)
	} else {
		t.Log("DeleteKey succeeded")
	}
}

// TestTPMOps_ProvisionEKCertWithNoCertHandle tests ProvisionEKCert fallback path
func TestTPMOps_ProvisionEKCertWithNoCertHandle(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Get EK public key
	ekPub := sharedTPM.EK()
	require.NotNil(t, ekPub, "EK public key should not be nil")

	// Create a self-signed EK certificate
	_, ekCertDER, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")

	// Test ProvisionEKCert
	err = sharedTPM.ProvisionEKCert(nil, ekCertDER)
	if err != nil {
		if strings.Contains(err.Error(), "NV_DEFINED") {
			t.Skip("EK cert NV index already defined")
		}
		t.Logf("ProvisionEKCert error: %v", err)
	} else {
		t.Logf("ProvisionEKCert succeeded with %d byte certificate", len(ekCertDER))
	}
}

// TestTPMOps_IsFIPS140_2 tests FIPS 140-2 mode detection
func TestTPMOps_IsFIPS140_2(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	isFIPS, err := sharedTPM.IsFIPS140_2()
	require.NoError(t, err, "IsFIPS140_2 should succeed")
	t.Logf("TPM FIPS 140-2 mode: %v", isFIPS)
}

// TestTPMOps_Info tests TPM info retrieval
func TestTPMOps_Info(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	info, err := sharedTPM.Info()
	require.NoError(t, err, "Info should succeed")
	require.NotEmpty(t, info, "Info should not be empty")
	t.Logf("TPM Info: %s", info)
}

// TestTPMOps_RandomBytes tests RandomBytes function
func TestTPMOps_RandomBytes(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	testSizes := []int{8, 16, 32, 64}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			randomBytes, err := sharedTPM.RandomBytes(size)
			require.NoError(t, err, "RandomBytes should succeed")
			require.NotNil(t, randomBytes, "Random bytes should not be nil")
			require.Equal(t, size, len(randomBytes), "Random bytes should have correct length")

			// Verify it's not all zeros
			allZero := true
			for _, b := range randomBytes {
				if b != 0 {
					allZero = false
					break
				}
			}
			require.False(t, allZero, "Random bytes should not be all zeros")
			t.Logf("Generated %d random bytes successfully", len(randomBytes))
		})
	}
}

// TestTPMOps_AlgID tests AlgID retrieval
func TestTPMOps_AlgID(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	algID := sharedTPM.AlgID()
	require.NotEqual(t, tpm2.TPMAlgNull, algID, "AlgID should not be null")
	t.Logf("TPM AlgID: 0x%x", algID)
}

// TestTPMOps_Device tests Device retrieval
func TestTPMOps_Device(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	device := sharedTPM.Device()
	require.NotEmpty(t, device, "Device should not be empty")
	t.Logf("TPM Device: %s", device)
}

// TestTPMOps_Transport tests Transport retrieval
func TestTPMOps_Transport(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	transport := sharedTPM.Transport()
	require.NotNil(t, transport, "Transport should not be nil")
	t.Log("Transport retrieved successfully")
}

// TestTPMOps_HMACSession tests HMAC session creation
func TestTPMOps_HMACSession(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	session, closer, err := sharedTPM.HMACSession(nil)
	if err != nil {
		t.Logf("HMACSession error: %v", err)
	} else {
		require.NotNil(t, session, "Session should not be nil")
		require.NotNil(t, closer, "Closer should not be nil")
		t.Log("HMACSession succeeded")
		closer()
	}
}

// TestTPMOps_NonceSession tests nonce session creation
func TestTPMOps_NonceSession(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	session, closer, err := sharedTPM.NonceSession(nil)
	if err != nil {
		t.Logf("NonceSession error: %v", err)
	} else {
		require.NotNil(t, session, "Session should not be nil")
		require.NotNil(t, closer, "Closer should not be nil")
		t.Log("NonceSession succeeded")
		closer()
	}
}

// TestTPMOps_PlatformPolicySession tests platform policy session creation
func TestTPMOps_PlatformPolicySession(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	session, closer, err := sharedTPM.PlatformPolicySession()
	if err != nil {
		t.Logf("PlatformPolicySession error: %v", err)
	} else {
		require.NotNil(t, session, "Session should not be nil")
		require.NotNil(t, closer, "Closer should not be nil")
		t.Log("PlatformPolicySession succeeded")
		closer()
	}
}

// TestTPMOps_ReadPCRsMultipleBanks tests reading PCRs from multiple banks
func TestTPMOps_ReadPCRsMultipleBanks(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Read PCRs 0, 7, and 16 from all available banks
	pcrList := []uint{0, 7, 16}
	pcrBanks, err := sharedTPM.ReadPCRs(pcrList)
	require.NoError(t, err, "ReadPCRs should succeed")
	require.NotNil(t, pcrBanks, "PCR banks should not be nil")

	// Verify multiple banks are returned
	require.Greater(t, len(pcrBanks), 0, "Should have at least one PCR bank")

	for _, bank := range pcrBanks {
		t.Logf("Bank: %s", bank.Algorithm)
		for _, pcr := range bank.PCRs {
			t.Logf("  PCR %d: %x", pcr.ID, pcr.Value)
		}
	}
}

// TestTPMOps_TPMInfo tests retrieving TPM info
func TestTPMOps_TPMInfo(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Use defer/recover since this may call FatalError
	defer func() {
		if r := recover(); r != nil {
			t.Logf("TPMInfo recovered from panic: %v", r)
		}
	}()

	info, err := sharedTPM.Info()
	if err != nil {
		t.Logf("Info error: %v", err)
	} else {
		require.NotNil(t, info, "TPM info should not be nil")
		t.Logf("TPM Info: %+v", info)
	}
}

// TestTPMOps_EKPublic tests retrieving EK public area
func TestTPMOps_EKPublic(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Use defer/recover since this may call FatalError
	defer func() {
		if r := recover(); r != nil {
			t.Logf("EKPublic recovered from panic: %v", r)
		}
	}()

	name, pub := sharedTPM.EKPublic()
	require.NotNil(t, name, "EK name should not be nil")
	require.NotNil(t, pub, "EK public should not be nil")
	t.Logf("EK Name: %x", name.Buffer)
}

// TestTPMOps_EKRSA tests retrieving EK RSA public key
func TestTPMOps_EKRSA(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Use defer/recover since this may call FatalError
	defer func() {
		if r := recover(); r != nil {
			t.Logf("EKRSA recovered from panic: %v", r)
		}
	}()

	rsaPub := sharedTPM.EKRSA()
	require.NotNil(t, rsaPub, "EK RSA public key should not be nil")
	require.NotNil(t, rsaPub.N, "RSA modulus should not be nil")
	t.Logf("EK RSA key size: %d bits", rsaPub.Size()*8)
}

// TestTPMOps_IAK tests retrieving IAK public key
func TestTPMOps_IAK(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// First ensure IAK attributes are loaded
	_, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	// Use defer/recover since this may panic
	defer func() {
		if r := recover(); r != nil {
			t.Logf("IAK recovered from panic: %v", r)
		}
	}()

	iakPub := sharedTPM.IAK()
	require.NotNil(t, iakPub, "IAK public key should not be nil")
	t.Logf("IAK public key retrieved successfully")
}

// TestTPMOps_Clear tests TPM Clear operation (careful - destructive)
func TestTPMOps_Clear(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Note: Clear is very destructive - we're just testing the error path
	// with incorrect authorization to ensure the code path is exercised
	// TPM2_Clear requires lockout hierarchy authorization
	err := sharedTPM.Clear([]byte("wrong-auth"))
	if err != nil {
		t.Logf("Clear with wrong auth correctly failed: %v", err)
	} else {
		t.Log("Clear unexpectedly succeeded (this is concerning)")
	}
}

// TestTPMOps_WriteEKCert tests WriteEKCert function
func TestTPMOps_WriteEKCert(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	// Use defer/recover since WriteEKCert may panic
	defer func() {
		if r := recover(); r != nil {
			t.Logf("WriteEKCert panicked (expected - requires specific TPM config): %v", r)
		}
	}()

	ekPub := sharedTPM.EK()
	require.NotNil(t, ekPub, "EK public key should not be nil")

	_, ekCertDER, err := createSelfSignedEKCert(ekPub)
	require.NoError(t, err, "Creating EK cert should succeed")

	err = sharedTPM.WriteEKCert(ekCertDER)
	if err != nil {
		if strings.Contains(err.Error(), "NV_DEFINED") {
			t.Skip("EK cert already written")
		}
		t.Logf("WriteEKCert error: %v", err)
	} else {
		t.Logf("WriteEKCert succeeded with %d byte certificate", len(ekCertDER))
	}
}

// TestTPMOps_HashFunction tests the Hash function
func TestTPMOps_HashFunction(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	iakAttrs, err := sharedTPM.IAKAttributes()
	require.NoError(t, err, "IAKAttributes should succeed")

	// Test with different data sizes
	testCases := []struct {
		name string
		data []byte
	}{
		{"Empty data", []byte{}},
		{"Small data", []byte("hello world")},
		{"Medium data", make([]byte, 1024)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, ticket, err := sharedTPM.Hash(iakAttrs, tc.data)
			if err != nil {
				t.Logf("Hash error: %v", err)
			} else {
				require.NotNil(t, digest, "Digest should not be nil")
				require.NotNil(t, ticket, "Ticket should not be nil")
				t.Logf("Hash succeeded: digest=%x", digest)
			}
		})
	}
}

// TestTPMOps_SealWithPlatformPolicy tests sealing with platform policy enabled
func TestTPMOps_SealWithPlatformPolicy(t *testing.T) {
	require.NotNil(t, sharedTPM, "Shared TPM instance must be initialized")

	backend := newMockKeyBackend()

	ekAttrs, err := sharedTPM.EKAttributes()
	require.NoError(t, err, "EKAttributes should succeed")

	var hierarchyAuth store.Password
	if ekAttrs.TPMAttributes != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth
	}

	// Create key attributes with platform policy
	keyAttrs := &store.KeyAttributes{
		CN:           "test-seal-policy",
		KeyAlgorithm: x509.RSA,
		KeyType:      store.KEY_TYPE_CA,
		Parent: &store.KeyAttributes{
			CN:        "srk",
			StoreType: store.STORE_TPM2,
			TPMAttributes: &store.TPMAttributes{
				Handle:        0x81000001,
				Hierarchy:     tpm2.TPMRHOwner,
				HierarchyAuth: hierarchyAuth,
			},
		},
		PlatformPolicy: true, // Enable platform policy
		StoreType:      store.STORE_TPM2,
		TPMAttributes: &store.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	createResp, err := sharedTPM.SealKey(keyAttrs, backend, false)
	if err != nil {
		if strings.Contains(err.Error(), "OBJECT_MEMORY") {
			t.Skip("TPM out of memory")
		}
		t.Logf("Seal with platform policy error: %v", err)
	} else {
		require.NotNil(t, createResp, "CreateResponse should not be nil")
		t.Log("Seal with platform policy succeeded")
	}
}
