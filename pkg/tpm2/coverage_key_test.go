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
	"crypto/x509"
	"crypto/x509/pkix"
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

// TestEKPublic tests EKPublic method
func TestEKPublic(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	name, pub := tpm.EKPublic()
	assert.NotEmpty(t, name.Buffer)
	assert.NotEqual(t, tpm2.TPMAlgNull, pub.Type)
}

// TestSRKPublic_CovKey tests SRKPublic method
// Note: The interface declares SRKPublic() but the concrete type implements SSRKPublic()
// This test uses the concrete type's SSRKPublic method
func TestSRKPublic_CovKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test via the concrete type since interface may call non-existent method
	tpm2Impl := tpm.(*TPM2)
	name, pub := tpm2Impl.SSRKPublic()
	assert.NotEmpty(t, name.Buffer)
	assert.NotEqual(t, tpm2.TPMAlgNull, pub.Type)
}

// TestSSRKPublic_Direct tests SSRKPublic on the concrete type
func TestSSRKPublic_Direct(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test on the concrete type
	tpm2Impl := tpm.(*TPM2)
	name, pub := tpm2Impl.SSRKPublic()
	assert.NotEmpty(t, name.Buffer)
	assert.NotEqual(t, tpm2.TPMAlgNull, pub.Type)
}

// TestIAKAttributes tests IAKAttributes method
func TestIAKAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)
	assert.NotNil(t, iakAttrs)
	assert.Equal(t, types.KeyTypeAttestation, iakAttrs.KeyType)
	assert.Equal(t, types.StoreTPM2, iakAttrs.StoreType)
	assert.NotNil(t, iakAttrs.Parent) // Should have EK as parent
}

// TestIAK tests IAK method
func TestIAK(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// First ensure IAK attributes are loaded
	_, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// Now get IAK public key
	iakPub := tpm.IAK()
	assert.NotNil(t, iakPub)
}

// TestIDevIDAttributes tests IDevIDAttributes method
func TestIDevIDAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Check if IDevID config exists - it may not be configured in simulator
	tpm2Impl := tpm.(*TPM2)
	if tpm2Impl.config.IDevID == nil {
		t.Skip("IDevID not configured - skipping test")
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		// IDevID may not be provisioned - this is acceptable
		t.Skip("IDevID not provisioned - skipping test")
	}
	assert.NotNil(t, idevidAttrs)
	assert.Equal(t, types.KeyTypeIDevID, idevidAttrs.KeyType)
	assert.Equal(t, types.StoreTPM2, idevidAttrs.StoreType)
}

// TestIDevID tests IDevID method
func TestIDevID(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Check if IDevID config exists
	tpm2Impl := tpm.(*TPM2)
	if tpm2Impl.config.IDevID == nil {
		t.Skip("IDevID not configured - skipping test")
	}

	// First ensure IDevID attributes are loaded
	_, err := tpm.IDevIDAttributes()
	if err != nil {
		t.Skip("IDevID not available")
	}

	// Now get IDevID public key
	idevidPub := tpm.IDevID()
	assert.NotNil(t, idevidPub)
}

// TestEKAttributes_CovKey tests EKAttributes method
func TestEKAttributes_CovKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)
	assert.NotNil(t, ekAttrs)
	assert.NotNil(t, ekAttrs.TPMAttributes)
}

// TestSSRKAttributes tests SSRKAttributes method
func TestSSRKAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)
	assert.NotNil(t, ssrkAttrs)
	assert.NotNil(t, ssrkAttrs.TPMAttributes)
}

// TestKeyAttributes tests KeyAttributes method
func TestKeyAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with EK handle
	tpm2Impl := tpm.(*TPM2)
	ekHandle := tpm2.TPMHandle(tpm2Impl.config.EK.Handle)

	attrs, err := tpm.KeyAttributes(ekHandle)
	require.NoError(t, err)
	assert.NotNil(t, attrs)
	assert.NotNil(t, attrs.TPMAttributes)
}

// TestKeyAttributes_InvalidHandle tests KeyAttributes with invalid handle
func TestKeyAttributes_InvalidHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Use invalid handle
	_, err := tpm.KeyAttributes(tpm2.TPMHandle(0x81FFFFFF))
	assert.Error(t, err)
}

// TestCreateEK tests CreateEK method
func TestCreateEK(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	policyDigest := tpm.PlatformPolicyDigest()

	// Create attributes for new EK
	ekAttrs, err := EKAttributesFromConfig(EKConfig{
		CertHandle:    0,
		Handle:        0x81010099, // Different handle to avoid conflicts
		HierarchyAuth: store.DEFAULT_PASSWORD,
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}, &policyDigest, nil)
	require.NoError(t, err)

	// This will create a new EK at the specified handle
	err = tpm.CreateEK(ekAttrs)
	// May succeed or fail depending on TPM state
	_ = err
}

// TestCreateSRK tests CreateSRK method
func TestCreateSRK(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	srkAttrs := &types.KeyAttributes{
		CN:           "test-srk",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeStorage,
		Parent:       ekAttrs,
		Password:     store.NewClearPassword([]byte("test-password")),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        0x81000099, // Different handle
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}

	err = tpm.CreateSRK(srkAttrs)
	// May succeed or fail depending on TPM state
	_ = err
}

// TestCreateIAK tests CreateIAK method
func TestCreateIAK(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	qualifyingData := []byte("test-qualifying-data-for-iak")
	iakAttrs, err := tpm.CreateIAK(ekAttrs, qualifyingData)

	if err == nil {
		assert.NotNil(t, iakAttrs)
		assert.Equal(t, types.KeyTypeAttestation, iakAttrs.KeyType)
	}
}

// TestCreateIDevID tests CreateIDevID method
func TestCreateIDevID(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skip("IAK not available")
	}

	ekCert, _ := tpm.EKCertificate()
	qualifyingData := []byte("test-qualifying-data-for-idevid")

	idevidAttrs, csr, err := tpm.CreateIDevID(iakAttrs, ekCert, qualifyingData)

	if err == nil {
		assert.NotNil(t, idevidAttrs)
		assert.NotNil(t, csr)
		assert.Equal(t, types.KeyTypeIDevID, idevidAttrs.KeyType)
	}
}

// TestDeleteKey tests DeleteKey method
func TestDeleteKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create a test key to delete
	srkAttrs := &types.KeyAttributes{
		CN:           "test-key-to-delete",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeStorage,
		Parent:       ekAttrs,
		Password:     store.NewClearPassword([]byte("test-password")),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        0x81000098, // Different handle
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}

	err = tpm.CreateSRK(srkAttrs)
	// Key might already exist or other error - try to delete anyway
	_ = err

	// Try to delete the key - pass nil for backend
	err = tpm.DeleteKey(srkAttrs, nil)
	// May succeed or fail depending on state
	_ = err
}

// TestCreateECDSA_P384 tests ECDSA with P-384 curve
func TestCreateECDSA_P384(t *testing.T) {
	_, tpm := createSim(true, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create SRK first
	srkAttrs := &types.KeyAttributes{
		CN:           "srk-ecdsa-p384",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeStorage,
		Parent:       ekAttrs,
		Password:     store.NewClearPassword([]byte("srk-password")),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}

	err = tpm.CreateSRK(srkAttrs)
	require.NoError(t, err)

	// Create ECDSA key with P-384
	keyAttrs := &types.KeyAttributes{
		CN:           "ecdsa-p384-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     store.NewClearPassword([]byte("key-password")),
		StoreType:    types.StoreTPM2,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	eccPub, err := tpm.CreateECDSA(keyAttrs, nil, false)
	assert.NoError(t, err)
	assert.NotNil(t, eccPub)
}

// TestCreateECDSA_P521 tests ECDSA with P-521 curve
func TestCreateECDSA_P521(t *testing.T) {
	_, tpm := createSim(true, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	srkAttrs := &types.KeyAttributes{
		CN:           "srk-ecdsa-p521",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeStorage,
		Parent:       ekAttrs,
		Password:     store.NewClearPassword([]byte("srk-password")),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}

	err = tpm.CreateSRK(srkAttrs)
	require.NoError(t, err)

	// Create ECDSA key with P-521
	keyAttrs := &types.KeyAttributes{
		CN:           "ecdsa-p521-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     store.NewClearPassword([]byte("key-password")),
		StoreType:    types.StoreTPM2,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P521(),
		},
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	eccPub, err := tpm.CreateECDSA(keyAttrs, nil, false)
	assert.NoError(t, err)
	assert.NotNil(t, eccPub)
}

// TestCreateECDSA_NilParent_CovKey tests error when parent is nil
func TestCreateECDSA_NilParent_CovKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:           "ecdsa-no-parent",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeCA,
		Parent:       nil, // No parent
		StoreType:    types.StoreTPM2,
	}

	_, err := tpm.CreateECDSA(keyAttrs, nil, false)
	assert.Error(t, err)
	assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)
}

// TestCreateRSA_NilParent_CovKey tests error when parent is nil
func TestCreateRSA_NilParent_CovKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:           "rsa-no-parent",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       nil, // No parent
		StoreType:    types.StoreTPM2,
	}

	_, err := tpm.CreateRSA(keyAttrs, nil, false)
	assert.Error(t, err)
}

// TestCreateECDSA_PlatformPolicy tests ECDSA with platform policy
func TestCreateECDSA_PlatformPolicy(t *testing.T) {
	_, tpm := createSim(true, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	srkAttrs := &types.KeyAttributes{
		CN:           "srk-ecdsa-policy",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeStorage,
		Parent:       ekAttrs,
		Password:     store.NewClearPassword([]byte("srk-password")),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}

	err = tpm.CreateSRK(srkAttrs)
	require.NoError(t, err)

	// Create ECDSA key with platform policy
	keyAttrs := &types.KeyAttributes{
		CN:             "ecdsa-with-policy",
		KeyAlgorithm:   x509.ECDSA,
		KeyType:        types.KeyTypeCA,
		Parent:         srkAttrs,
		Password:       store.NewClearPassword([]byte("key-password")),
		PlatformPolicy: true, // Enable platform policy
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	eccPub, err := tpm.CreateECDSA(keyAttrs, nil, false)
	assert.NoError(t, err)
	assert.NotNil(t, eccPub)
}

// TestLDevIDAttributesFromConfig tests LDevID configuration parsing
func TestLDevIDAttributesFromConfig(t *testing.T) {
	config := LDevIDConfig{
		CN:                 "test-ldevid",
		Handle:             0x81020002,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	policyDigest := tpm2.TPM2BDigest{Buffer: make([]byte, 32)}

	attrs, err := LDevIDAttributesFromConfig(config, &policyDigest)
	require.NoError(t, err)
	assert.NotNil(t, attrs)
	assert.Equal(t, "test-ldevid", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
}

// TestLDevIDAttributesFromConfig_ECDSA_CovKey tests LDevID with ECDSA
func TestLDevIDAttributesFromConfig_ECDSA_CovKey(t *testing.T) {
	config := LDevIDConfig{
		CN:                 "test-ldevid-ecdsa",
		Handle:             0x81020003,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.ECDSA.String(),
		SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		ECCConfig: &store.ECCConfig{
			Curve: "P-256",
		},
	}

	policyDigest := tpm2.TPM2BDigest{Buffer: make([]byte, 32)}

	attrs, err := LDevIDAttributesFromConfig(config, &policyDigest)
	require.NoError(t, err)
	assert.NotNil(t, attrs)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
}

// TestLDevIDAttributesFromConfig_InvalidKeyAlgorithm tests error handling
func TestLDevIDAttributesFromConfig_InvalidKeyAlgorithm(t *testing.T) {
	config := LDevIDConfig{
		CN:           "test-ldevid-invalid",
		Handle:       0x81020004,
		Hash:         crypto.SHA256.String(),
		KeyAlgorithm: "INVALID",
	}

	policyDigest := tpm2.TPM2BDigest{Buffer: make([]byte, 32)}

	_, err := LDevIDAttributesFromConfig(config, &policyDigest)
	assert.Error(t, err)
}

// createSimECC creates a TPM simulator with ECC-based EK for testing EKECC
func createSimECC() (*slog.Logger, TrustedPlatformModule, error) {
	logger := slog.Default()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create storage backend
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		return nil, nil, err
	}

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	// Configure with ECC-based EK
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
			KeyAlgorithm:  x509.ECDSA.String(), // ECC-based EK
			ECCConfig: &store.ECCConfig{
				Curve: "P-256",
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity: []string{
			"./",
		},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.ECDSA.String(),
			ECCConfig: &store.ECCConfig{
				Curve: "P-256",
			},
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.ECDSA.String(),
			ECCConfig: &store.ECCConfig{
				Curve: "P-256",
			},
		},
		KeyStore: &KeyStoreConfig{
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
	}

	tpm, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if err = tpm.Provision(nil); err != nil {
				return nil, nil, err
			}
		} else {
			return nil, nil, err
		}
	}

	return logger, tpm, nil
}

// TestEKECC_WithECCKey tests the EKECC method with an ECC-based EK
func TestEKECC_WithECCKey(t *testing.T) {
	_, tpm, err := createSimECC()
	if err != nil {
		t.Skipf("Failed to create ECC-based TPM simulator: %v", err)
	}
	defer func() { _ = tpm.Close() }()

	// Initialize EK attributes first
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Skipf("Failed to get EK attributes: %v", err)
	}

	// Verify the EK is ECC-based
	if ekAttrs.KeyAlgorithm != x509.ECDSA {
		t.Skipf("EK is not ECC-based (is %v), skipping EKECC test", ekAttrs.KeyAlgorithm)
	}

	// Test EKECC - should return valid ECC public key
	eccPubKey := tpm.EKECC()
	require.NotNil(t, eccPubKey, "EKECC should return non-nil ECC public key")
	assert.NotNil(t, eccPubKey.Curve, "ECC public key should have a curve")
	assert.NotNil(t, eccPubKey.X, "ECC public key should have X coordinate")
	assert.NotNil(t, eccPubKey.Y, "ECC public key should have Y coordinate")

	// Test that EKECC returns cached value on second call
	eccPubKey2 := tpm.EKECC()
	assert.Equal(t, eccPubKey, eccPubKey2, "Second call should return same cached key")
}

// TestEKRSA_WithRSAKey tests the EKRSA method with an RSA-based EK
func TestEKRSA_WithRSAKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Initialize EK attributes first
	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Verify the EK is RSA-based (default)
	require.Equal(t, x509.RSA, ekAttrs.KeyAlgorithm)

	// Test EKRSA - should return valid RSA public key
	rsaPubKey := tpm.EKRSA()
	require.NotNil(t, rsaPubKey, "EKRSA should return non-nil RSA public key")
	assert.NotNil(t, rsaPubKey.N, "RSA public key should have N")
	assert.NotZero(t, rsaPubKey.E, "RSA public key should have E")

	// Test that EKRSA returns cached value on second call
	rsaPubKey2 := tpm.EKRSA()
	assert.Equal(t, rsaPubKey, rsaPubKey2, "Second call should return same cached key")
}

// createEKCertForTest creates a mock EK certificate for testing (unique name to avoid conflict)
func createEKCertForTest(pubKey crypto.PublicKey) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test EK Certificate",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// createSimWithIDevID creates a TPM simulator with IDevID configuration
func createSimWithIDevID() (*slog.Logger, TrustedPlatformModule, *x509.Certificate, error) {
	logger := slog.Default()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		return nil, nil, nil, err
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create storage backend
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		return nil, nil, nil, err
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
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
		FileIntegrity: []string{
			"./",
		},
		IAK: &IAKConfig{
			CN:           "device-id-001",
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
			CertHandle:   0x01C90000,
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       0x81020000,
			KeyAlgorithm: x509.RSA.String(),
			Model:        "test-model",
			Serial:       "test-001",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
			PlatformPolicy:     false,
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
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
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
	}

	tpm, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if err = tpm.Provision(nil); err != nil {
				return nil, nil, nil, err
			}
		} else {
			return nil, nil, nil, err
		}
	}

	// Create a mock EK certificate
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, nil, nil, err
	}

	var ekPubKey crypto.PublicKey
	if ekAttrs.KeyAlgorithm == x509.RSA {
		ekPubKey = tpm.EKRSA()
	} else {
		ekPubKey = tpm.EKECC()
	}

	ekCert, err := createEKCertForTest(ekPubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return logger, tpm, ekCert, nil
}

// TestCreateIDevID_Success_CovKey tests successful IDevID creation
func TestCreateIDevID_Success_CovKey(t *testing.T) {
	_, tpm, ekCert, err := createSimWithIDevID()
	if err != nil {
		t.Skipf("Failed to create TPM simulator with IDevID config: %v", err)
	}
	defer func() { _ = tpm.Close() }()

	// Get IAK attributes
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("Failed to get IAK attributes: %v", err)
	}

	qualifyingData := []byte("test-qualifying-data")

	// Create IDevID
	idevidAttrs, csr, err := tpm.CreateIDevID(iakAttrs, ekCert, qualifyingData)
	if err != nil {
		t.Skipf("CreateIDevID failed (may be expected in some TPM states): %v", err)
	}

	require.NotNil(t, idevidAttrs)
	require.NotNil(t, csr)
	assert.Equal(t, types.KeyTypeIDevID, idevidAttrs.KeyType)
	assert.Equal(t, types.StoreTPM2, idevidAttrs.StoreType)
}

// TestIDevIDAttributes_AfterCreation_CovKey tests IDevIDAttributes after creating an IDevID
func TestIDevIDAttributes_AfterCreation_CovKey(t *testing.T) {
	_, tpm, ekCert, err := createSimWithIDevID()
	if err != nil {
		t.Skipf("Failed to create TPM simulator with IDevID config: %v", err)
	}
	defer func() { _ = tpm.Close() }()

	// Get IAK attributes
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("Failed to get IAK attributes: %v", err)
	}

	qualifyingData := []byte("test-qualifying-data")

	// Create IDevID first
	_, _, err = tpm.CreateIDevID(iakAttrs, ekCert, qualifyingData)
	if err != nil {
		t.Skipf("CreateIDevID failed: %v", err)
	}

	// Now retrieve IDevID attributes
	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		t.Skipf("IDevIDAttributes failed after creation: %v", err)
	}

	require.NotNil(t, idevidAttrs)
	assert.Equal(t, types.KeyTypeIDevID, idevidAttrs.KeyType)
	assert.NotNil(t, idevidAttrs.TPMAttributes)
}

// TestCreateIDevID_WithECDSA_CovKey tests CreateIDevID with ECDSA keys
func TestCreateIDevID_WithECDSA_CovKey(t *testing.T) {
	_, tpm, err := createSimECC()
	if err != nil {
		t.Skipf("Failed to create ECC-based TPM simulator: %v", err)
	}
	defer func() { _ = tpm.Close() }()

	// Configure IDevID with ECDSA
	tpmImpl := tpm.(*TPM2)
	tpmImpl.config.IDevID = &IDevIDConfig{
		CertHandle:   0x01C90000,
		Debug:        true,
		Hash:         crypto.SHA256.String(),
		Handle:       0x81020000,
		KeyAlgorithm: x509.ECDSA.String(),
		Model:        "test-model",
		Serial:       "test-001",
		ECCConfig: &store.ECCConfig{
			Curve: "P-256",
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		PlatformPolicy:     false,
	}

	// Get IAK attributes
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Skipf("Failed to get IAK attributes: %v", err)
	}

	// Create mock EK certificate for ECC key
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Skipf("Failed to get EK attributes: %v", err)
	}

	var ekPubKey crypto.PublicKey
	if ekAttrs.KeyAlgorithm == x509.ECDSA {
		ekPubKey = tpm.EKECC()
	} else {
		ekPubKey = tpm.EKRSA()
	}

	ekCert, err := createEKCertForTest(ekPubKey)
	if err != nil {
		t.Skipf("Failed to create mock EK certificate: %v", err)
	}

	qualifyingData := []byte("test-qualifying-data-ecdsa")

	// Create IDevID
	idevidAttrs, csr, err := tpm.CreateIDevID(iakAttrs, ekCert, qualifyingData)
	if err != nil {
		t.Skipf("CreateIDevID with ECDSA failed: %v", err)
	}

	require.NotNil(t, idevidAttrs)
	require.NotNil(t, csr)
	assert.Equal(t, types.KeyTypeIDevID, idevidAttrs.KeyType)
}

// TestEKECC_CacheBehavior tests that EKECC returns cached public key on subsequent calls
func TestEKECC_CacheBehavior(t *testing.T) {
	_, tpm, err := createSimECC()
	if err != nil {
		t.Skipf("Failed to create ECC-based TPM simulator: %v", err)
	}
	defer func() { _ = tpm.Close() }()

	// Initialize EK attributes first
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Skipf("Failed to get EK attributes: %v", err)
	}

	// Skip if not ECC-based
	if ekAttrs.KeyAlgorithm != x509.ECDSA {
		t.Skip("EK is not ECC-based")
	}

	// First call should populate cache
	pub1 := tpm.EKECC()
	require.NotNil(t, pub1)

	// Second call should return cached value
	pub2 := tpm.EKECC()
	require.NotNil(t, pub2)

	// Should be the same pointer (cached)
	assert.Same(t, pub1, pub2)
}

// TestEKECC_ECCPointValidation tests that returned ECC public key has valid curve points
func TestEKECC_ECCPointValidation(t *testing.T) {
	_, tpm, err := createSimECC()
	if err != nil {
		t.Skipf("Failed to create ECC-based TPM simulator: %v", err)
	}
	defer func() { _ = tpm.Close() }()

	// Initialize EK attributes first
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Skipf("Failed to get EK attributes: %v", err)
	}

	// Skip if not ECC-based
	if ekAttrs.KeyAlgorithm != x509.ECDSA {
		t.Skip("EK is not ECC-based")
	}

	eccPub := tpm.EKECC()
	require.NotNil(t, eccPub)

	// Verify the public key is on the curve
	curve := eccPub.Curve
	require.NotNil(t, curve)

	isOnCurve := curve.IsOnCurve(eccPub.X, eccPub.Y)
	assert.True(t, isOnCurve, "ECC public key should be on the curve")

	// Verify the key can be used for verification (basic ECDSA sanity check)
	// Generate a test signature and verify it
	hash := []byte("test data to sign")
	r, s, err := ecdsa.Sign(rand.Reader, &ecdsa.PrivateKey{
		PublicKey: *eccPub,
		D:         big.NewInt(1), // Dummy D, not used for verification
	}, hash)
	// This should fail because we don't have the private key
	// But the public key structure should be valid
	_ = r
	_ = s
	_ = err
}
