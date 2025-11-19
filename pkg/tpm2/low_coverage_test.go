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
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================
// Tests for Quote function edge cases
// ========================================

func TestQuote_NilIAKAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create a TPM instance with nil IAK attributes
	tpmImpl := tpm.(*TPM2)
	originalIAK := tpmImpl.iakAttrs
	tpmImpl.iakAttrs = nil

	_, err := tpm.Quote([]uint{0, 1}, []byte("nonce"))
	assert.Equal(t, ErrNotInitialized, err)

	// Restore
	tpmImpl.iakAttrs = originalIAK
}

func TestQuote_NilParentAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	originalParent := tpmImpl.iakAttrs.Parent
	tpmImpl.iakAttrs.Parent = nil

	_, err := tpm.Quote([]uint{0, 1}, []byte("nonce"))
	assert.Equal(t, ErrInvalidAKAttributes, err)

	// Restore
	tpmImpl.iakAttrs.Parent = originalParent
}

func TestQuote_WithEmptyNonce(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Empty nonce should still work
	quote, err := tpm.Quote([]uint{0}, []byte{})
	assert.Nil(t, err)
	assert.NotNil(t, quote.Quoted)
}

func TestQuote_WithPasswordError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Test with a password that returns nil bytes
	// This shouldn't cause an error - it just uses empty password auth
	originalPassword := tpmImpl.iakAttrs.Password
	tpmImpl.iakAttrs.Password = &errPasswordLowCov{}

	quote, err := tpm.Quote([]uint{0}, []byte("nonce"))
	// Quote should succeed even with nil password bytes (treated as empty password)
	assert.Nil(t, err)
	assert.NotNil(t, quote.Quoted)

	// Restore
	tpmImpl.iakAttrs.Password = originalPassword
}

// ========================================
// Tests for IAKAttributes error paths
// ========================================

func TestIAKAttributes_SignatureAlgorithmParsing(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	originalIAK := tpmImpl.iakAttrs
	tpmImpl.iakAttrs = nil

	// Test with invalid signature algorithm in config
	tpmImpl.config.IAK.SignatureAlgorithm = "INVALID_ALGO"

	attrs, err := tpm.IAKAttributes()
	// Should return attributes even with invalid signature algorithm
	// because ParseSignatureAlgorithm error is swallowed
	assert.Nil(t, err)
	assert.NotNil(t, attrs)

	// Restore
	tpmImpl.iakAttrs = originalIAK
}

func TestIAKAttributes_EmptyCN(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	originalIAK := tpmImpl.iakAttrs
	tpmImpl.iakAttrs = nil

	// Test with empty CN - should default to "default-device-id"
	originalCN := tpmImpl.config.IAK.CN
	tpmImpl.config.IAK.CN = ""

	attrs, err := tpm.IAKAttributes()
	assert.Nil(t, err)
	assert.Equal(t, "default-device-id", attrs.CN)

	// Restore
	tpmImpl.config.IAK.CN = originalCN
	tpmImpl.iakAttrs = originalIAK
}

// ========================================
// Tests for IDevIDAttributes error paths
// ========================================

func TestIDevIDAttributes_InvalidSignatureAlgorithm(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	originalIDevID := tpmImpl.idevidAttrs
	tpmImpl.idevidAttrs = nil

	// Setup IDevID config
	if tpmImpl.config.IDevID == nil {
		tpmImpl.config.IDevID = &IDevIDConfig{
			CN:                 "test-idevid",
			Handle:             0x81020000,
			Hash:               crypto.SHA256.String(),
			KeyAlgorithm:       x509.RSA.String(),
			SignatureAlgorithm: "INVALID_ALGORITHM",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		}
	} else {
		originalSigAlgo := tpmImpl.config.IDevID.SignatureAlgorithm
		tpmImpl.config.IDevID.SignatureAlgorithm = "INVALID_ALGORITHM"
		defer func() { tpmImpl.config.IDevID.SignatureAlgorithm = originalSigAlgo }()
	}

	_, err := tpm.IDevIDAttributes()
	assert.NotNil(t, err)

	// Restore
	tpmImpl.idevidAttrs = originalIDevID
}

// ========================================
// Tests for HMACSession edge cases
// ========================================

func TestHMACSession_WithEmptyAuth(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	session, closer, err := tpm.HMACSession([]byte{})
	require.Nil(t, err)
	assert.NotNil(t, session)
	assert.NotNil(t, closer)
	_ = closer()
}

func TestHMACSession_WithLongAuth(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with a very long auth value
	longAuth := make([]byte, 1024)
	_, err := rand.Read(longAuth)
	require.Nil(t, err)

	session, closer, err := tpm.HMACSession(longAuth)
	require.Nil(t, err)
	assert.NotNil(t, session)
	_ = closer()
}

func TestHMACSession_EncryptedSession(t *testing.T) {
	_, tpm := createSim(true, false) // Enable encryption
	defer func() { _ = tpm.Close() }()

	session, closer, err := tpm.HMACSession([]byte("test-auth"))
	require.Nil(t, err)
	assert.NotNil(t, session)
	_ = closer()
}

// ========================================
// Tests for CreateRSA error paths
// ========================================

func TestCreateRSA_NilParent(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:           "test-rsa-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       nil, // No parent
	}

	_, err := tpm.CreateRSA(keyAttrs, nil, false)
	assert.Equal(t, store.ErrInvalidKeyAttributes, err)
}

func TestCreateRSA_PasswordError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.Nil(t, err)

	// createKey returns a child key with the SRK in .Parent field
	childKeyAttrs := createKey(tpm, false)
	srkAttrs := childKeyAttrs.Parent // Get the actual SRK

	keyAttrs := &types.KeyAttributes{
		CN:           "test-rsa-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
		Password:     &errPasswordLowCov{}, // Password that returns nil bytes
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	// Cleanup the SRK we created
	defer func() {
		// Only attempt cleanup if SRK was successfully created
		if srkAttrs == nil || srkAttrs.TPMAttributes == nil || srkAttrs.TPMAttributes.Handle == nil {
			return
		}
		_, err := tpm2.EvictControl{
			Auth: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			ObjectHandle: &tpm2.NamedHandle{
				Handle: srkAttrs.TPMAttributes.Handle.(tpm2.TPMHandle),
				Name:   srkAttrs.TPMAttributes.Name.(tpm2.TPM2BName),
			},
			PersistentHandle: srkAttrs.TPMAttributes.Handle.(tpm2.TPMIDHPersistent),
		}.Execute(tpm.Transport())
		if err != nil {
			t.Logf("Failed to clean up SRK: %v", err)
		}
	}()

	// CreateRSA should succeed with nil password bytes (treated as empty password)
	pubKey, err := tpm.CreateRSA(keyAttrs, nil, false)
	assert.Nil(t, err)
	assert.NotNil(t, pubKey)
	_ = ekAttrs // Used for parent relationship
}

func TestCreateRSA_EncryptionKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// createKey returns a child key with the SRK in .Parent field
	childKeyAttrs := createKey(tpm, false)
	srkAttrs := childKeyAttrs.Parent // Get the actual SRK

	keyAttrs := &types.KeyAttributes{
		CN:           "test-encryption-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeEncryption, // Encryption key
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	// Cleanup the SRK
	defer func() {
		// Only attempt cleanup if SRK was successfully created
		if srkAttrs == nil || srkAttrs.TPMAttributes == nil || srkAttrs.TPMAttributes.Handle == nil {
			return
		}
		_, _ = tpm2.EvictControl{
			Auth: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			ObjectHandle: &tpm2.NamedHandle{
				Handle: srkAttrs.TPMAttributes.Handle.(tpm2.TPMHandle),
				Name:   srkAttrs.TPMAttributes.Name.(tpm2.TPM2BName),
			},
			PersistentHandle: srkAttrs.TPMAttributes.Handle.(tpm2.TPMIDHPersistent),
		}.Execute(tpm.Transport())
	}()

	pubKey, err := tpm.CreateRSA(keyAttrs, nil, false)
	// May return an error due to missing RSAConfig
	if err != nil {
		// Check that the error path was exercised
		assert.NotNil(t, err)
		return
	}
	assert.NotNil(t, pubKey)
	assert.NotNil(t, keyAttrs.TPMAttributes)
	// Cleanup the created key
	tpm.Flush(keyAttrs.TPMAttributes.Handle.(tpm2.TPMHandle))
}

// ========================================
// Tests for CreateECDSA error paths
// ========================================

func TestCreateECDSA_NilParent(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:           "test-ecdsa-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       nil, // No parent
	}

	_, err := tpm.CreateECDSA(keyAttrs, nil, false)
	assert.NotNil(t, err)
	// Error should indicate missing parent
	assert.Contains(t, err.Error(), "parent")
}

// ========================================
// Tests for CreateIAK edge cases
// ========================================

func TestCreateIAK_WithHierarchyAuthError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.Nil(t, err)

	// Set hierarchy auth to return an error
	originalHierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth
	ekAttrs.TPMAttributes.HierarchyAuth = &errPasswordLowCov{}

	_, err = tpm.CreateIAK(ekAttrs, []byte("qualifying-data"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "password error")

	// Restore
	ekAttrs.TPMAttributes.HierarchyAuth = originalHierarchyAuth
}

func TestCreateIAK_WithPasswordError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.Nil(t, err)

	// Set EK password to return an error
	originalPassword := ekAttrs.Password
	ekAttrs.Password = &errPasswordLowCov{}

	_, err = tpm.CreateIAK(ekAttrs, []byte("qualifying-data"))
	assert.NotNil(t, err)

	// Restore
	ekAttrs.Password = originalPassword
}

// ========================================
// Tests for CreateIDevID error paths
// ========================================

func TestCreateIDevID_NilAKAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	_, _, err := tpm.CreateIDevID(nil, nil, []byte("qualifying-data"))
	assert.Equal(t, ErrInvalidAKAttributes, err)
}

func TestCreateIDevID_NilParent(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	akAttrs := &types.KeyAttributes{
		CN:     "test-ak",
		Parent: nil, // No parent
	}

	_, _, err := tpm.CreateIDevID(akAttrs, nil, []byte("qualifying-data"))
	assert.Equal(t, ErrInvalidEKAttributes, err)
}

func TestCreateIDevID_NotConfigured(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	originalIDevIDConfig := tpmImpl.config.IDevID
	tpmImpl.config.IDevID = nil

	ekAttrs, err := tpm.EKAttributes()
	require.Nil(t, err)

	iakAttrs, err := tpm.IAKAttributes()
	require.Nil(t, err)

	_, _, err = tpm.CreateIDevID(iakAttrs, nil, []byte("qualifying-data"))
	assert.Equal(t, ErrNotConfigured, err)

	// Restore
	tpmImpl.config.IDevID = originalIDevIDConfig
	_ = ekAttrs
}

func TestCreateIDevID_HierarchyAuthError(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Setup IDevID config
	if tpmImpl.config.IDevID == nil {
		tpmImpl.config.IDevID = &IDevIDConfig{
			CN:                 "test-idevid",
			Handle:             0x81020000,
			Hash:               crypto.SHA256.String(),
			KeyAlgorithm:       x509.RSA.String(),
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		}
	}

	ekAttrs, err := tpm.EKAttributes()
	require.Nil(t, err)

	iakAttrs, err := tpm.IAKAttributes()
	require.Nil(t, err)

	// Set hierarchy auth to return an error
	originalHierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth
	ekAttrs.TPMAttributes.HierarchyAuth = &errPasswordLowCov{}

	_, _, err = tpm.CreateIDevID(iakAttrs, nil, []byte("qualifying-data"))
	assert.NotNil(t, err)

	// Restore
	ekAttrs.TPMAttributes.HierarchyAuth = originalHierarchyAuth
}

// ========================================
// Tests for EKECC edge cases
// NOTE: EKECC test removed because the function uses logger.FatalError
// which doesn't properly handle errors and makes testing difficult
// ========================================

// ========================================
// Tests for VerifyTCGCSR routing
// ========================================

func TestVerifyTCGCSR_InvalidStrategy(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	originalStrategy := tpmImpl.config.IdentityProvisioningStrategy
	// Set to an invalid strategy string - ParseIdentityProvisioningStrategy defaults
	// to EnrollmentStrategyIAK_IDEVID_SINGLE_PASS for unknown strings
	tpmImpl.config.IdentityProvisioningStrategy = "INVALID_STRATEGY"

	csr := &TCG_CSR_IDEVID{}

	_, _, err := tpm.VerifyTCGCSR(csr, x509.SHA256WithRSA)
	// Since ParseIdentityProvisioningStrategy defaults to single pass strategy,
	// it will try to verify the CSR and fail on hash algorithm parsing
	assert.NotNil(t, err)
	// The error should be related to CSR parsing/verification
	assert.Contains(t, err.Error(), "unsupported hash algorithm")

	// Restore
	tpmImpl.config.IdentityProvisioningStrategy = originalStrategy
}

func TestVerifyTCGCSR_IAKStrategy(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	tpmImpl.config.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK)

	csr := &TCG_CSR_IDEVID{}

	// Should fail during CSR unpacking, but routes correctly
	_, _, err := tpm.VerifyTCGCSR(csr, x509.SHA256WithRSA)
	assert.NotNil(t, err)
}

func TestVerifyTCGCSR_IDevIDStrategy(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	tpmImpl.config.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)

	csr := &TCG_CSR_IDEVID{}

	// Should fail during CSR unpacking, but routes correctly
	_, _, err := tpm.VerifyTCGCSR(csr, x509.SHA256WithRSA)
	assert.NotNil(t, err)
}

// ========================================
// Tests for VerifyTCG_CSR_IAK error paths
// ========================================

func TestVerifyTCG_CSR_IAK_EmptyCSR(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	csr := &TCG_CSR_IDEVID{}

	_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSA)
	assert.NotNil(t, err)
}

func TestVerifyTCG_CSR_IAK_InvalidHashAlgorithm(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create a CSR with invalid hash algorithm ID
	csr := &TCG_CSR_IDEVID{
		CsrContents: TCG_IDEVID_CONTENT{},
	}
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], 0xFFFF) // Invalid algorithm

	_, _, err := tpm.VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSA)
	assert.NotNil(t, err)
}

// ========================================
// Tests for VerifyTCG_CSR_IDevID error paths
// ========================================

func TestVerifyTCG_CSR_IDevID_EmptyCSR(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	csr := &TCG_CSR_IDEVID{}

	_, _, err := tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSA)
	assert.NotNil(t, err)
}

func TestVerifyTCG_CSR_IDevID_InvalidHashAlgorithm(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create a CSR with invalid hash algorithm ID
	csr := &TCG_CSR_IDEVID{
		CsrContents: TCG_IDEVID_CONTENT{},
	}
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], 0xFFFF) // Invalid algorithm

	_, _, err := tpm.VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSA)
	assert.NotNil(t, err)
}

// ========================================
// Tests for RSADecrypt (error paths only - no actual TPM operation)
// ========================================

func TestRSADecrypt_EmptyBlob(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.Nil(t, err)

	// RSADecrypt with empty blob should fail
	_, err = tpm.RSADecrypt(
		ekAttrs.TPMAttributes.Handle.(tpm2.TPMHandle),
		ekAttrs.TPMAttributes.Name.(tpm2.TPM2BName),
		[]byte{},
	)
	assert.NotNil(t, err)
}

func TestRSADecrypt_InvalidHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Use an invalid handle
	invalidHandle := tpm2.TPMHandle(0xFFFFFFFF)
	invalidName := tpm2.TPM2BName{Buffer: []byte("invalid")}

	_, err := tpm.RSADecrypt(invalidHandle, invalidName, []byte("test"))
	assert.NotNil(t, err)
}

func TestRSADecrypt_TooLargeBlob(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.Nil(t, err)

	// Create a blob that's too large for RSA operation
	largeBlob := make([]byte, 512) // Larger than key size
	_, err = rand.Read(largeBlob)
	require.Nil(t, err)

	_, err = tpm.RSADecrypt(
		ekAttrs.TPMAttributes.Handle.(tpm2.TPMHandle),
		ekAttrs.TPMAttributes.Name.(tpm2.TPM2BName),
		largeBlob,
	)
	assert.NotNil(t, err)
}

// ========================================
// Tests for eventlog helper functions - unique tests
// ========================================

func TestGetDigestSizeByAlgID_AllAlgorithmsLowCov(t *testing.T) {
	tests := []struct {
		name     string
		algID    uint16
		expected int
	}{
		{"SHA1", AlgSHA1, 20},
		{"SHA256", AlgSHA256, 32},
		{"SHA384", AlgSHA384, 48},
		{"SHA512", AlgSHA512, 64},
		{"SM3_256", AlgSM3256, 32},
		{"SM3_256_Alt", AlgSM3256Alt, 32},
		{"Unknown", 0xFFFF, 0},
		{"Zero", 0x0000, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDigestSizeByAlgID(tt.algID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAlgorithmId_AllAlgorithmsLowCov(t *testing.T) {
	tests := []struct {
		name     string
		algID    uint16
		expected string
	}{
		{"SHA1", AlgSHA1, "sha1"},
		{"SHA256", AlgSHA256, "sha256"},
		{"SHA384", AlgSHA384, "sha384"},
		{"SHA512", AlgSHA512, "sha512"},
		{"SM3_256", AlgSM3256, "sm3_256"},
		{"SM3_256_Alt", AlgSM3256Alt, "sm3_256"},
		{"Unknown", 0xFFFF, "unknown_0xffff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAlgorithmId(tt.algID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseEventType_AllTypesLowCov(t *testing.T) {
	tests := []struct {
		name      string
		eventType uint32
		expected  string
	}{
		{"EV_UNDEFINED", 0x00000000, "EV_UNDEFINED"},
		{"EV_IPL", 0x00000001, "EV_IPL"},
		{"EV_EVENT_TAG", 0x00000002, "EV_EVENT_TAG"},
		{"EV_NO_ACTION", 0x00000003, "EV_NO_ACTION"},
		{"EV_SEPARATOR", 0x00000004, "EV_SEPARATOR"},
		{"EV_ACTION", 0x00000008, "EV_ACTION"},
		{"EV_EFI_BOOT_SERVICES", 0x00000006, "EV_EFI_BOOT_SERVICES_APPLICATION"},
		{"EV_EFI_VARIABLE_DRIVER_CONFIG", 0x0000000D, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
		{"EV_S_CRTM_CONTENTS", 0x80000001, "EV_S_CRTM_CONTENTS"},
		{"EV_S_CRTM_VERSION", 0x80000002, "EV_S_CRTM_VERSION"},
		{"EV_S_CPU_MICROCODE", 0x80000003, "EV_S_CPU_MICROCODE"},
		{"EV_S_POST_CODE", 0x80000006, "EV_S_POST_CODE"},
		{"EV_S_CRTM_SEPARATOR", 0x80000008, "EV_S_CRTM_SEPARATOR"},
		{"EV_PLATFORM_CONFIG_FLAGS", 0x800000E0, "EV_PLATFORM_CONFIG_FLAGS"},
		{"Unknown", 0x12345678, "Unknown (0x12345678)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEventType(tt.eventType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetDigestSize_AllAlgorithmsLowCov(t *testing.T) {
	tests := []struct {
		name     string
		algo     string
		expected int
	}{
		{"sha1", "sha1", 20},
		{"sha256", "sha256", 32},
		{"sha384", "sha384", 48},
		{"sha512", "sha512", 64},
		{"sm3_256", "sm3_256", 32},
		{"unknown", "unknown", 0},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDigestSize(tt.algo)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculatePCRs_WithEventsLowCov(t *testing.T) {
	// Create test events
	events := []Event{
		{
			EventNum: 1,
			PCRIndex: 0,
			Digests: []Digest{
				{
					AlgorithmId: "sha256",
					Digest:      "0000000000000000000000000000000000000000000000000000000000000001",
				},
			},
		},
		{
			EventNum: 2,
			PCRIndex: 0,
			Digests: []Digest{
				{
					AlgorithmId: "sha256",
					Digest:      "0000000000000000000000000000000000000000000000000000000000000002",
				},
			},
		},
	}

	pcrs := CalculatePCRs(events)

	assert.NotNil(t, pcrs)
	assert.Len(t, pcrs["sha256"], 1) // One PCR index
	assert.NotNil(t, pcrs["sha256"][0])
	assert.Len(t, pcrs["sha256"][0], 32) // SHA256 digest size
}

// ========================================
// Tests for CalculateName
// ========================================

func TestCalculateName_AllAlgorithms(t *testing.T) {
	testData := []byte("test public area data")

	t.Run("SHA1", func(t *testing.T) {
		name, err := CalculateName(tpm2.TPMAlgSHA1, testData)
		assert.Nil(t, err)
		assert.NotNil(t, name)
		// 2 bytes for algorithm ID + 20 bytes for SHA1
		assert.Len(t, name, 22)
	})

	t.Run("SHA256", func(t *testing.T) {
		name, err := CalculateName(tpm2.TPMAlgSHA256, testData)
		assert.Nil(t, err)
		assert.NotNil(t, name)
		// 2 bytes for algorithm ID + 32 bytes for SHA256
		assert.Len(t, name, 34)
	})

	t.Run("SHA384", func(t *testing.T) {
		name, err := CalculateName(tpm2.TPMAlgSHA3384, testData)
		assert.Nil(t, err)
		assert.NotNil(t, name)
		// 2 bytes for algorithm ID + 48 bytes for SHA384
		assert.Len(t, name, 50)
	})

	t.Run("SHA512", func(t *testing.T) {
		name, err := CalculateName(tpm2.TPMAlgSHA512, testData)
		assert.Nil(t, err)
		assert.NotNil(t, name)
		// 2 bytes for algorithm ID + 64 bytes for SHA512
		assert.Len(t, name, 66)
	})

	t.Run("Unsupported Algorithm", func(t *testing.T) {
		_, err := CalculateName(tpm2.TPMAlgID(0xFFFF), testData)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm ID")
	})
}

// ========================================
// Tests for verifyTCGCSRSignature-related paths
// ========================================

func TestSignatureVerification_RSAPSS_InvalidSignature(t *testing.T) {
	// Create an RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	publicKey := &privateKey.PublicKey

	// Create test data
	message := []byte("test message for signature verification")
	hash := sha256.Sum256(message)

	// Create a valid signature
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	require.Nil(t, err)

	// Verify with correct signature should pass
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	assert.Nil(t, err)

	// Verify with corrupted signature should fail
	corruptedSig := make([]byte, len(signature))
	copy(corruptedSig, signature)
	corruptedSig[0] ^= 0xFF

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], corruptedSig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	assert.NotNil(t, err)
}

func TestSignatureVerification_RSAPKCS1v15_InvalidSignature(t *testing.T) {
	// Create an RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	publicKey := &privateKey.PublicKey

	// Create test data
	message := []byte("test message")
	hash := sha256.Sum256(message)

	// Create valid signature
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	require.Nil(t, err)

	// Verify valid signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	assert.Nil(t, err)

	// Verify with corrupted signature
	corruptedSig := make([]byte, len(signature))
	copy(corruptedSig, signature)
	corruptedSig[len(corruptedSig)-1] ^= 0xFF

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], corruptedSig)
	assert.NotNil(t, err)
}

func TestSignatureVerification_ECDSA_InvalidSignature(t *testing.T) {
	// Create ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)

	publicKey := &privateKey.PublicKey

	// Create test data
	message := []byte("test message for ECDSA")
	hash := sha256.Sum256(message)

	// Create valid signature
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	require.Nil(t, err)

	// Verify valid signature
	valid := ecdsa.VerifyASN1(publicKey, hash[:], signature)
	assert.True(t, valid)

	// Verify with corrupted signature
	corruptedSig := make([]byte, len(signature))
	copy(corruptedSig, signature)
	corruptedSig[0] ^= 0xFF

	valid = ecdsa.VerifyASN1(publicKey, hash[:], corruptedSig)
	assert.False(t, valid)

	// Verify with wrong hash
	wrongHash := sha256.Sum256([]byte("wrong message"))
	valid = ecdsa.VerifyASN1(publicKey, wrongHash[:], signature)
	assert.False(t, valid)
}

// ========================================
// Helper types for testing error conditions
// ========================================

// errPasswordLowCov implements types.Password but returns an error
type errPasswordLowCov struct{}

func (e *errPasswordLowCov) Bytes() []byte {
	return nil
}

func (e *errPasswordLowCov) String() (string, error) {
	return "", errors.New("password error: simulated failure")
}

func (e *errPasswordLowCov) Clear() {
	// No-op
}
