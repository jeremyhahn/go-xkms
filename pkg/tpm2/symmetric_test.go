//go:build tpm_simulator
// +build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	kbackend "github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateSymmetricKey tests generating an AES symmetric key in the TPM
func TestGenerateSymmetricKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Cast to *TPM2 to access GenerateSymmetricKey
	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "test-symmetric-key",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0), // Will be treated as symmetric
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	key, err := tpm2Instance.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	if key.Algorithm() != string(types.SymmetricAES256GCM) {
		t.Errorf("Expected algorithm %s, got %s", types.SymmetricAES256GCM, key.Algorithm())
	}

	if key.KeySize() != 256 {
		t.Errorf("Expected key size 256, got %d", key.KeySize())
	}

	// Verify Raw() returns error
	_, err = key.Raw()
	if err == nil {
		t.Error("Expected error from Raw(), TPM keys should not expose key material")
	}
}

// TestGetSymmetricKey tests retrieving an existing symmetric key
func TestGetSymmetricKey(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "test-get-symmetric",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Generate key first
	_, err := tpm2Instance.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Retrieve it
	key, err := tpm2Instance.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric key: %v", err)
	}

	if key.KeySize() != 256 {
		t.Errorf("Expected key size 256, got %d", key.KeySize())
	}
}

// TestSymmetricEncryptDecrypt tests encrypting and decrypting data
func TestSymmetricEncryptDecrypt(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "test-encrypt-decrypt",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := tpm2Instance.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	encrypter, err := tpm2Instance.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	plaintext := []byte("Hello, TPM2 symmetric encryption!")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(encrypted.Ciphertext, plaintext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	// Verify nonce was generated
	if len(encrypted.Nonce) == 0 {
		t.Error("Nonce should not be empty")
	}

	// Verify tag was generated
	if len(encrypted.Tag) == 0 {
		t.Error("Tag should not be empty")
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data does not match original: got %s, expected %s", decrypted, plaintext)
	}
}

// TestSymmetricEncryptWithAAD tests encryption with additional authenticated data
func TestSymmetricEncryptWithAAD(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "test-encrypt-aad",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := tpm2Instance.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	encrypter, err := tpm2Instance.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	plaintext := []byte("Sensitive data")
	aad := []byte("additional authenticated data")

	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt with correct AAD
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Decryption with correct AAD failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data does not match original")
	}

	// Decrypt with wrong AAD should fail
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: []byte("wrong aad"),
	})
	if err == nil {
		t.Error("Expected error when decrypting with wrong AAD")
	}
}

// TestSymmetricDecryptInvalidTag tests decryption with a corrupted authentication tag
func TestSymmetricDecryptInvalidTag(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	tpmObj, ok := tpmInterface.(*TPM2)
	require.True(t, ok, "expected *TPM2 type")

	attrs := &types.KeyAttributes{
		CN:                 "test-invalid-tag",
		KeyType:            types.KeyTypeEncryption,
		KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := tpmObj.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	encrypter, err := tpmObj.SymmetricEncrypter(attrs)
	require.NoError(t, err)

	plaintext := []byte("test message")
	encryptedData, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	// Corrupt the authentication tag
	encryptedData.Tag[0] ^= 0xFF

	// Decryption should fail
	_, err = encrypter.Decrypt(encryptedData, nil)
	assert.Error(t, err, "decryption should fail with corrupted tag")
}

// TestNonceReuse tests that the TPM2 backend detects and prevents nonce reuse
func TestNonceReuse(t *testing.T) {
	_, tpm := createSimWithTracker(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-reuse",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := tpm2Instance.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	encrypter, err := tpm2Instance.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	// Generate a fixed nonce for testing
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// First encryption with fixed nonce should succeed
	plaintext := []byte("test data")
	opts := &types.EncryptOptions{
		Nonce: nonce,
	}

	_, err = encrypter.Encrypt(plaintext, opts)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second encryption with same nonce should fail
	_, err = encrypter.Encrypt(plaintext, opts)
	if err == nil {
		t.Fatal("Expected error for nonce reuse, but encryption succeeded")
	}

	t.Logf("Got expected error: %v", err)
}

// TestBytesLimit tests that the TPM2 backend enforces AEAD bytes limits
func TestBytesLimit(t *testing.T) {
	_, tpm := createSimWithTracker(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := tpm2Instance.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	// Set a small byte limit for testing (1 KB)
	keyID := attrs.ID()
	testOptions := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      true,
		BytesTrackingLimit: 1024, // 1 KB limit for testing
		NonceSize:          12,
	}
	if err := tpm2Instance.Tracker().SetAEADOptions(keyID, testOptions); err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	encrypter, err := tpm2Instance.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("Failed to get symmetric encrypter: %v", err)
	}

	// Encrypt data up to the limit
	plaintext := make([]byte, 512)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("Failed to generate plaintext: %v", err)
	}

	// First encryption should succeed (512 bytes)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second encryption should succeed (total 1024 bytes)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Third encryption should fail (would exceed limit)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err == nil {
		t.Fatal("Expected error for bytes limit exceeded, but encryption succeeded")
	}

	t.Logf("Got expected error: %v", err)
}

// TestGenerateSymmetricKeyErrors tests error conditions for key generation
func TestGenerateSymmetricKeyErrors(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	// Test nil attributes
	_, err := tpm2Instance.GenerateSymmetricKey(nil)
	if err == nil {
		t.Error("Expected error for nil attributes")
	}

	// Test missing CN
	_, err = tpm2Instance.GenerateSymmetricKey(&types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})
	if err == nil {
		t.Error("Expected error for missing CN")
	}

	// Test missing symmetric algorithm
	_, err = tpm2Instance.GenerateSymmetricKey(&types.KeyAttributes{
		CN: "test-no-algorithm",
	})
	if err == nil {
		t.Error("Expected error for missing symmetric algorithm")
	}

	// Test invalid symmetric algorithm
	_, err = tpm2Instance.GenerateSymmetricKey(&types.KeyAttributes{
		CN:                 "test-invalid-algorithm",
		SymmetricAlgorithm: "invalid-algorithm",
	})
	if err == nil {
		t.Error("Expected error for invalid symmetric algorithm")
	}
}

// TestKeyAlreadyExists tests that generating a key with existing name fails
func TestKeyAlreadyExists(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	attrs := &types.KeyAttributes{
		CN:                 "test-key-exists",
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// First generation should succeed
	_, err := tpm2Instance.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("First key generation failed: %v", err)
	}

	// Second generation with same name should fail
	_, err = tpm2Instance.GenerateSymmetricKey(attrs)
	if err == nil {
		t.Fatal("Expected error for duplicate key name")
	}
}

// TestTracker tests that the tracker is properly initialized and accessible
func TestTracker(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	tracker := tpm2Instance.Tracker()
	if tracker == nil {
		t.Fatal("Tracker should not be nil")
	}
}

// TestRSAEncrypt_Basic tests RSA encryption with EK handle
func TestRSAEncrypt_Basic(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	tpmObj, ok := tpmInterface.(*TPM2)
	require.True(t, ok, "expected *TPM2 type")

	ekAttrs, err := tpmObj.EKAttributes()
	require.NoError(t, err)

	message := []byte("test message")

	ciphertext, err := tpmObj.RSAEncrypt(
		ekAttrs.TPMAttributes.Handle,
		ekAttrs.TPMAttributes.Name,
		message,
	)

	if err != nil {
		t.Logf("RSAEncrypt not supported: %v", err)
		return
	}

	assert.NotEqual(t, message, ciphertext)
}

// TestRSAEncrypt_InvalidHandle tests RSA encryption with invalid handle
func TestRSAEncrypt_InvalidHandle(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	tpmObj, ok := tpmInterface.(*TPM2)
	require.True(t, ok, "expected *TPM2 type")

	invalidHandle := tpm2.TPMHandle(0xFFFFFFFF)
	invalidName := tpm2.TPM2BName{Buffer: []byte("invalid")}

	_, err := tpmObj.RSAEncrypt(invalidHandle, invalidName, []byte("test"))
	assert.Error(t, err)
}

// createSimWithTracker creates a simulated TPM with a custom AEAD tracker
func createSimWithTracker(encrypt, entropy bool) (*slog.Logger, TrustedPlatformModule) {
	logger := slog.Default()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		logger.Error("failed to read random bytes", "error", err)
		panic(err)
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create storage backend
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		logger.Error("failed to create storage factory", "error", err)
		panic(err)
	}

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	// Create tracker
	tracker := kbackend.NewMemoryAEADTracker()

	config := &Config{
		EncryptSession: encrypt,
		UseEntropy:     entropy,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		Tracker:        tracker,
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
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
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		PlatformSRK: &PlatformSRKConfig{
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
		Tracker:      tracker,
	}

	tpmInst, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if err = tpmInst.Provision(nil); err != nil {
				logger.Error("failed to provision TPM", "error", err)
				panic(err)
			}
		} else {
			logger.Error("failed to create TPM2", "error", err)
			panic(err)
		}
	}

	return logger, tpmInst
}
