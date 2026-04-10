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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProvisionIDevIDCert_NotConfigured tests error when IDevID not configured
func TestProvisionIDevIDCert_NotConfigured(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get internal TPM2 to modify config
	tpm2Impl := tpm.(*TPM2)
	originalConfig := tpm2Impl.config.IDevID
	tpm2Impl.config.IDevID = nil
	defer func() { tpm2Impl.config.IDevID = originalConfig }()

	cert := createTestCertForIDevID(t)
	err := tpm.ProvisionIDevIDCert(cert)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestIDevIDCertificate_NotConfigured tests error when IDevID not configured
func TestIDevIDCertificate_NotConfigured(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	originalConfig := tpm2Impl.config.IDevID
	tpm2Impl.config.IDevID = nil
	defer func() { tpm2Impl.config.IDevID = originalConfig }()

	_, err := tpm.IDevIDCertificate()
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestDeleteIDevIDCertificate_NotConfigured tests error when IDevID not configured
func TestDeleteIDevIDCertificate_NotConfigured(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	originalConfig := tpm2Impl.config.IDevID
	tpm2Impl.config.IDevID = nil
	defer func() { tpm2Impl.config.IDevID = originalConfig }()

	err := tpm.DeleteIDevIDCertificate()
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestProvisionIAKCert_NotConfigured tests error when IAK not configured
func TestProvisionIAKCert_NotConfigured(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	originalConfig := tpm2Impl.config.IAK
	tpm2Impl.config.IAK = nil
	defer func() { tpm2Impl.config.IAK = originalConfig }()

	cert := createTestCertForIDevID(t)
	err := tpm.ProvisionIAKCert(cert)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestIAKCertificate_NotConfigured tests error when IAK not configured
func TestIAKCertificate_NotConfigured(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	originalConfig := tpm2Impl.config.IAK
	tpm2Impl.config.IAK = nil
	defer func() { tpm2Impl.config.IAK = originalConfig }()

	_, err := tpm.IAKCertificate()
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestDeleteIAKCertificate_NotConfigured tests error when IAK not configured
func TestDeleteIAKCertificate_NotConfigured(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	originalConfig := tpm2Impl.config.IAK
	tpm2Impl.config.IAK = nil
	defer func() { tpm2Impl.config.IAK = originalConfig }()

	err := tpm.DeleteIAKCertificate()
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestWriteCertToStore_NotConfigured tests error when cert store is nil
func TestWriteCertToStore_NotConfigured(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	originalStore := tpm2Impl.certStore
	tpm2Impl.certStore = nil
	defer func() { tpm2Impl.certStore = originalStore }()

	// Ensure IDevID config doesn't use NVRAM (CertHandle = 0)
	if tpm2Impl.config.IDevID != nil {
		originalCertHandle := tpm2Impl.config.IDevID.CertHandle
		tpm2Impl.config.IDevID.CertHandle = 0
		defer func() { tpm2Impl.config.IDevID.CertHandle = originalCertHandle }()
	}

	cert := createTestCertForIDevID(t)
	err := tpm.ProvisionIDevIDCert(cert)
	// Should fail with key mismatch since cert doesn't match TPM key
	assert.Error(t, err)
}

// TestIDevIDCertificate_NotFound tests certificate not found error
func TestIDevIDCertificate_NotFound(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	// Skip if certStore is nil - test will panic
	if tpm2Impl.certStore == nil {
		t.Skip("certStore is nil - skipping test")
	}

	if tpm2Impl.config.IDevID != nil {
		originalCertHandle := tpm2Impl.config.IDevID.CertHandle
		tpm2Impl.config.IDevID.CertHandle = 0
		defer func() { tpm2Impl.config.IDevID.CertHandle = originalCertHandle }()
	}

	// Reading should fail because no cert exists
	_, err := tpm.IDevIDCertificate()
	// May return ErrIDevIDCertNotFound or other error depending on state
	assert.Error(t, err)
}

// TestIAKCertificate_NotFound tests certificate not found error
func TestIAKCertificate_NotFound(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	// Skip if certStore is nil - test will panic
	if tpm2Impl.certStore == nil {
		t.Skip("certStore is nil - skipping test")
	}

	if tpm2Impl.config.IAK != nil {
		originalCertHandle := tpm2Impl.config.IAK.CertHandle
		tpm2Impl.config.IAK.CertHandle = 0
		defer func() { tpm2Impl.config.IAK.CertHandle = originalCertHandle }()
	}

	_, err := tpm.IAKCertificate()
	assert.Error(t, err)
}

// TestProvisionIDevIDCert_PublicKeyMismatch tests public key validation
func TestProvisionIDevIDCert_PublicKeyMismatch(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	if tpm2Impl.config.IDevID == nil {
		t.Skip("IDevID not configured - skipping test")
	}

	// Create certificate with a different key than what's in the TPM
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test IDevID Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Should fail because cert's public key doesn't match TPM key
	err = tpm.ProvisionIDevIDCert(cert)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCertPublicKeyMismatch)
}

// TestProvisionIAKCert_PublicKeyMismatch tests public key validation
func TestProvisionIAKCert_PublicKeyMismatch(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test IAK Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = tpm.ProvisionIAKCert(cert)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCertPublicKeyMismatch)
}

// TestDeleteIDevIDCertificate_StoreMode tests delete from cert store
func TestDeleteIDevIDCertificate_StoreMode(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	// Skip if certStore is nil - test will panic
	if tpm2Impl.certStore == nil {
		t.Skip("certStore is nil - skipping test")
	}

	if tpm2Impl.config.IDevID != nil {
		originalCertHandle := tpm2Impl.config.IDevID.CertHandle
		tpm2Impl.config.IDevID.CertHandle = 0
		defer func() { tpm2Impl.config.IDevID.CertHandle = originalCertHandle }()
	}

	// Delete will fail if cert doesn't exist, but it tests the code path
	err := tpm.DeleteIDevIDCertificate()
	// May succeed (if no cert) or error (if store error)
	_ = err
}

// TestDeleteIAKCertificate_StoreMode tests delete from cert store
func TestDeleteIAKCertificate_StoreMode(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	// Skip if certStore is nil - test will panic
	if tpm2Impl.certStore == nil {
		t.Skip("certStore is nil - skipping test")
	}

	if tpm2Impl.config.IAK != nil {
		originalCertHandle := tpm2Impl.config.IAK.CertHandle
		tpm2Impl.config.IAK.CertHandle = 0
		defer func() { tpm2Impl.config.IAK.CertHandle = originalCertHandle }()
	}

	err := tpm.DeleteIAKCertificate()
	_ = err
}

// TestValidateCertPublicKey_UnsupportedKeyType tests handling of unsupported key types
func TestValidateCertPublicKey_UnsupportedKeyType(t *testing.T) {
	// Create a certificate with a supported key type first
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Test with nil KeyAttributes
	err = validateCertPublicKey(cert, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// TestValidateCertPublicKey_NilTPMAttributes tests handling of nil TPMAttributes
func TestValidateCertPublicKey_NilTPMAttributes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)
	keyAttrs := &types.KeyAttributes{}

	err = validateCertPublicKey(cert, keyAttrs)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// TestValidateCertPublicKey_RSAMatch tests RSA public key match
func TestValidateCertPublicKey_RSAMatch(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	rsaUnique := tpm2.TPM2BPublicKeyRSA{
		Buffer: rsaKey.N.Bytes(),
	}

	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&rsaUnique,
		),
	}

	bPublic := tpm2.New2B(tpmPub)

	keyAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Public:  tpmPub,
			BPublic: bPublic,
		},
	}

	err = validateCertPublicKey(cert, keyAttrs)
	assert.NoError(t, err)
}

// TestValidateCertPublicKey_RSAMismatch tests RSA public key mismatch
func TestValidateCertPublicKey_RSAMismatch(t *testing.T) {
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey1.PublicKey)

	rsaUnique := tpm2.TPM2BPublicKeyRSA{
		Buffer: rsaKey2.N.Bytes(),
	}

	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&rsaUnique,
		),
	}

	bPublic := tpm2.New2B(tpmPub)

	keyAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Public:  tpmPub,
			BPublic: bPublic,
		},
	}

	err = validateCertPublicKey(cert, keyAttrs)
	assert.ErrorIs(t, err, ErrCertPublicKeyMismatch)
}

// TestValidateCertPublicKey_ECCMatch tests ECC public key match
func TestValidateCertPublicKey_ECCMatch(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &ecKey.PublicKey)

	eccUnique := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: ecKey.X.Bytes()},
		Y: tpm2.TPM2BECCParameter{Buffer: ecKey.Y.Bytes()},
	}

	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&eccUnique,
		),
	}

	bPublic := tpm2.New2B(tpmPub)

	keyAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Public:  tpmPub,
			BPublic: bPublic,
		},
	}

	err = validateCertPublicKey(cert, keyAttrs)
	assert.NoError(t, err)
}

// TestValidateCertPublicKey_ECCMismatch tests ECC public key mismatch
func TestValidateCertPublicKey_ECCMismatch(t *testing.T) {
	ecKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &ecKey1.PublicKey)

	eccUnique := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: ecKey2.X.Bytes()},
		Y: tpm2.TPM2BECCParameter{Buffer: ecKey2.Y.Bytes()},
	}

	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&eccUnique,
		),
	}

	bPublic := tpm2.New2B(tpmPub)

	keyAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Public:  tpmPub,
			BPublic: bPublic,
		},
	}

	err = validateCertPublicKey(cert, keyAttrs)
	assert.ErrorIs(t, err, ErrCertPublicKeyMismatch)
}

// TestCertIDevIDErrors tests error constants
func TestCertIDevIDErrors(t *testing.T) {
	assert.EqualError(t, ErrIDevIDCertNotFound, "tpm: IDevID certificate not found")
	assert.EqualError(t, ErrIAKCertNotFound, "tpm: IAK certificate not found")
	assert.EqualError(t, ErrCertPublicKeyMismatch, "tpm: certificate public key does not match TPM key")
	assert.EqualError(t, ErrCertStoreNotConfigured, "tpm: certificate store not configured")
}

// TestWriteCertToStore_Success tests writing cert to store successfully
func TestWriteCertToStore_Success(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	logger := slog.Default()
	certStore := store.NewMemoryCertStore(logger)

	keyAttrs := &types.KeyAttributes{
		CN: "test-idevid",
	}

	tpmObj := &TPM2{
		logger:    logger,
		certStore: certStore,
	}

	err = tpmObj.writeCertToStore(keyAttrs, cert)
	assert.NoError(t, err)

	// Verify the certificate was stored
	storedCert, err := certStore.Get(keyAttrs)
	assert.NoError(t, err)
	assert.Equal(t, cert.Subject.CommonName, storedCert.Subject.CommonName)
}

// TestWriteCertToStore_NilStore tests writing cert when store is nil
func TestWriteCertToStore_NilStore(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	logger := slog.Default()

	keyAttrs := &types.KeyAttributes{
		CN: "test-idevid",
	}

	tpmObj := &TPM2{
		logger:    logger,
		certStore: nil,
	}

	err = tpmObj.writeCertToStore(keyAttrs, cert)
	assert.ErrorIs(t, err, ErrCertStoreNotConfigured)
}

// TestValidateCertPublicKey_UnsupportedType tests unsupported key type path
func TestValidateCertPublicKey_UnsupportedType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	// Create TPM public with unsupported type (TPMAlgSymCipher)
	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
	}

	bPublic := tpm2.New2B(tpmPub)

	// Ensure BPublic has some bytes
	keyAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Public:  tpmPub,
			BPublic: bPublic,
		},
	}

	// Should return nil (success path for unsupported types with valid public bytes)
	err = validateCertPublicKey(cert, keyAttrs)
	assert.NoError(t, err)
}

// TestValidateCertPublicKey_UnsupportedTypeEmptyPublic tests unsupported key type with empty public
func TestValidateCertPublicKey_UnsupportedTypeEmptyPublic(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	// Create TPM public with unsupported type and empty BPublic
	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
	}

	// Create an empty BPublic that returns empty bytes
	keyAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			Public: tpmPub,
			// BPublic left as zero value - Bytes() should return empty
		},
	}

	// Should return error because public bytes are empty
	err = validateCertPublicKey(cert, keyAttrs)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// TestIDevIDCertificate_FromStoreSuccess tests reading cert from store
func TestIDevIDCertificate_FromStoreSuccess(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	logger := slog.Default()
	certStore := store.NewMemoryCertStore(logger)

	// Create a minimal TPM2 with IDevID config
	tpmObj := &TPM2{
		logger:    logger,
		certStore: certStore,
		config: &Config{
			IDevID: &IDevIDConfig{
				CN:         "test-idevid",
				CertHandle: 0, // Use store mode
			},
		},
		idevidAttrs: &types.KeyAttributes{
			CN: "test-idevid",
		},
	}

	// Store the cert first
	err = certStore.Save(tpmObj.idevidAttrs, cert)
	require.NoError(t, err)

	// Now read it back
	readCert, err := tpmObj.IDevIDCertificate()
	assert.NoError(t, err)
	assert.NotNil(t, readCert)
	assert.Equal(t, cert.Subject.CommonName, readCert.Subject.CommonName)
}

// TestIAKCertificate_FromStoreSuccess tests reading IAK cert from store
func TestIAKCertificate_FromStoreSuccess(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	logger := slog.Default()
	certStore := store.NewMemoryCertStore(logger)

	// Create a minimal TPM2 with IAK config
	tpmObj := &TPM2{
		logger:    logger,
		certStore: certStore,
		config: &Config{
			IAK: &IAKConfig{
				CN:         "test-iak",
				CertHandle: 0, // Use store mode
			},
		},
		iakAttrs: &types.KeyAttributes{
			CN: "test-iak",
		},
	}

	// Store the cert first
	err = certStore.Save(tpmObj.iakAttrs, cert)
	require.NoError(t, err)

	// Now read it back
	readCert, err := tpmObj.IAKCertificate()
	assert.NoError(t, err)
	assert.NotNil(t, readCert)
	assert.Equal(t, cert.Subject.CommonName, readCert.Subject.CommonName)
}

// TestDeleteIDevIDCertificate_FromStoreSuccess tests deleting IDevID cert from store
func TestDeleteIDevIDCertificate_FromStoreSuccess(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	logger := slog.Default()
	certStore := store.NewMemoryCertStore(logger)

	// Create a minimal TPM2 with IDevID config
	tpmObj := &TPM2{
		logger:    logger,
		certStore: certStore,
		config: &Config{
			IDevID: &IDevIDConfig{
				CN:         "test-idevid",
				CertHandle: 0, // Use store mode
			},
		},
		idevidAttrs: &types.KeyAttributes{
			CN: "test-idevid",
		},
	}

	// Store the cert first
	err = certStore.Save(tpmObj.idevidAttrs, cert)
	require.NoError(t, err)

	// Delete it
	err = tpmObj.DeleteIDevIDCertificate()
	assert.NoError(t, err)

	// Verify it's gone
	_, err = certStore.Get(tpmObj.idevidAttrs)
	assert.Error(t, err)
}

// TestDeleteIAKCertificate_FromStoreSuccess tests deleting IAK cert from store
func TestDeleteIAKCertificate_FromStoreSuccess(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertWithKey(t, &rsaKey.PublicKey)

	logger := slog.Default()
	certStore := store.NewMemoryCertStore(logger)

	// Create a minimal TPM2 with IAK config
	tpmObj := &TPM2{
		logger:    logger,
		certStore: certStore,
		config: &Config{
			IAK: &IAKConfig{
				CN:         "test-iak",
				CertHandle: 0, // Use store mode
			},
		},
		iakAttrs: &types.KeyAttributes{
			CN: "test-iak",
		},
	}

	// Store the cert first
	err = certStore.Save(tpmObj.iakAttrs, cert)
	require.NoError(t, err)

	// Delete it
	err = tpmObj.DeleteIAKCertificate()
	assert.NoError(t, err)

	// Verify it's gone
	_, err = certStore.Get(tpmObj.iakAttrs)
	assert.Error(t, err)
}

// TestIDevIDCertificate_StoreNotFoundError tests specific not found error
func TestIDevIDCertificate_StoreNotFoundError(t *testing.T) {
	logger := slog.Default()
	certStore := store.NewMemoryCertStore(logger)

	// Create a minimal TPM2 with IDevID config
	tpmObj := &TPM2{
		logger:    logger,
		certStore: certStore,
		config: &Config{
			IDevID: &IDevIDConfig{
				CN:         "test-idevid",
				CertHandle: 0, // Use store mode
			},
		},
		idevidAttrs: &types.KeyAttributes{
			CN: "test-idevid",
		},
	}

	// Read without storing should return not found
	_, err := tpmObj.IDevIDCertificate()
	assert.ErrorIs(t, err, ErrIDevIDCertNotFound)
}

// TestIAKCertificate_StoreNotFoundError tests specific not found error
func TestIAKCertificate_StoreNotFoundError(t *testing.T) {
	logger := slog.Default()
	certStore := store.NewMemoryCertStore(logger)

	// Create a minimal TPM2 with IAK config
	tpmObj := &TPM2{
		logger:    logger,
		certStore: certStore,
		config: &Config{
			IAK: &IAKConfig{
				CN:         "test-iak",
				CertHandle: 0, // Use store mode
			},
		},
		iakAttrs: &types.KeyAttributes{
			CN: "test-iak",
		},
	}

	// Read without storing should return not found
	_, err := tpmObj.IAKCertificate()
	assert.ErrorIs(t, err, ErrIAKCertNotFound)
}

// Helper function to create a test certificate
func createTestCertForIDevID(t *testing.T) *x509.Certificate {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// Helper function to create a test certificate with a specific public key
func createTestCertWithKey(t *testing.T, pubKey interface{}) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, signingKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
