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
	"crypto"
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

// newCertStoreTPM returns a simulator-backed TPM provisioned with an IDevID key
// and wired to a real certificate store.
//
// The certificate lifecycle under test needs two things the default createSim
// configuration does not supply: an IDevID key (createSim configures no IDevID
// section at all, so IDevIDAttributes reports ErrIDevIDConfigNil) and a
// certificate store (createSim passes no CertStore, leaving tpm.certStore nil).
// Tests used to skip when either was missing. Both are provisioned here
// instead, so the store-backed paths in cert_idevid.go actually execute.
//
// CertHandle is left at zero for both identities, selecting the certificate
// store rather than TPM NV RAM. The store is the production
// store.MemoryCertStore, not a stand-in, so the CertificateStorer contract is
// exercised as shipped.
func newCertStoreTPM(t *testing.T) *TPM2 {
	t.Helper()

	h := newSimHarness(t, func(c *Config) {
		c.IDevID = &IDevIDConfig{
			CertHandle:         0, // store mode
			CN:                 "idevid-device-001",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			Pad:                false,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
		c.IAK.CertHandle = 0 // store mode
	})

	h.TPM.certStore = store.NewMemoryCertStore(h.Logger)

	// Mint the IDevID key explicitly. Provision() attempts this itself but
	// treats failure as non-fatal, so relying on it would reintroduce exactly
	// the "maybe it is there" ambiguity these tests used to skip on.
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	_, _, err = h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err, "the simulator must be able to create an IDevID key")

	_, err = h.TPM.IDevIDAttributes()
	require.NoError(t, err, "the IDevID key must be present at the configured handle")

	return h.TPM
}

// certForTPMKey issues a certificate whose subject public key is the public key
// of the supplied TPM key, which is what ProvisionIDevIDCert and
// ProvisionIAKCert require before they will store a certificate.
//
// The certificate is signed by a throwaway CA key; only the subject public key
// matters to validateCertPublicKey.
func certForTPMKey(t *testing.T, attrs *types.KeyAttributes, cn string) *x509.Certificate {
	t.Helper()

	require.NotNil(t, attrs.TPMAttributes, "key attributes must carry a TPM public area")

	subjectPub, err := x509.ParsePKIXPublicKey(attrs.TPMAttributes.PublicKeyBytes)
	require.NoError(t, err, "the TPM public area must parse as a PKIX public key")

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, subjectPub, issuerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestProvisionIDevIDCert_NotConfigured tests error when IDevID not configured
func TestProvisionIDevIDCert_NotConfigured(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	// Get internal TPM2 to modify config
	tpm2Impl := tpm.(*TPM2)
	originalConfig := tpm2Impl.config.IDevID
	tpm2Impl.config.IDevID = nil
	defer func() { tpm2Impl.config.IDevID = originalConfig }()

	cert := createTestCertForIDevID(t)
	err := tpm.ProvisionIDevIDCert(nil, cert)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestIDevIDCertificate_NotConfigured tests error when IDevID not configured
func TestIDevIDCertificate_NotConfigured(t *testing.T) {
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	originalConfig := tpm2Impl.config.IAK
	tpm2Impl.config.IAK = nil
	defer func() { tpm2Impl.config.IAK = originalConfig }()

	cert := createTestCertForIDevID(t)
	err := tpm.ProvisionIAKCert(nil, cert)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

// TestIAKCertificate_NotConfigured tests error when IAK not configured
func TestIAKCertificate_NotConfigured(t *testing.T) {
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
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
	err := tpm.ProvisionIDevIDCert(nil, cert)
	// Should fail with key mismatch since cert doesn't match TPM key
	assert.Error(t, err)
}

// TestIDevIDCertificate_NotFound tests certificate not found error.
//
// The store's generic ErrCertNotFound must be translated into the identity
// specific ErrIDevIDCertNotFound, which is what callers match on; the previous
// bare assert.Error would have passed for any failure at all, including a nil
// store panic.
func TestIDevIDCertificate_NotFound(t *testing.T) {
	tpm := newCertStoreTPM(t)

	cert, err := tpm.IDevIDCertificate()
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrIDevIDCertNotFound)
}

// TestIDevIDCertificate_StoreNotConfigured pins the other store-mode failure:
// asking for a certificate in store mode without a store must report
// ErrCertStoreNotConfigured rather than dereferencing the nil store.
func TestIDevIDCertificate_StoreNotConfigured(t *testing.T) {
	tpm := newCertStoreTPM(t)
	tpm.certStore = nil

	cert, err := tpm.IDevIDCertificate()
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrCertStoreNotConfigured)
}

// TestIAKCertificate_NotFound tests certificate not found error.
func TestIAKCertificate_NotFound(t *testing.T) {
	tpm := newCertStoreTPM(t)

	cert, err := tpm.IAKCertificate()
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrIAKCertNotFound)
}

// TestIAKCertificate_StoreNotConfigured is the IAK counterpart of
// TestIDevIDCertificate_StoreNotConfigured.
func TestIAKCertificate_StoreNotConfigured(t *testing.T) {
	tpm := newCertStoreTPM(t)
	tpm.certStore = nil

	cert, err := tpm.IAKCertificate()
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrCertStoreNotConfigured)
}

// TestProvisionIDevIDCert_PublicKeyMismatch tests public key validation.
//
// This used to skip because createSim configures no IDevID section; it now runs
// against a TPM that really has an IDevID key, which is the only configuration
// in which the mismatch check is reachable.
func TestProvisionIDevIDCert_PublicKeyMismatch(t *testing.T) {
	tpm := newCertStoreTPM(t)

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
	err = tpm.ProvisionIDevIDCert(nil, cert)
	assert.ErrorIs(t, err, ErrCertPublicKeyMismatch)

	// A rejected certificate must not be stored.
	stored, getErr := tpm.IDevIDCertificate()
	assert.Nil(t, stored)
	assert.ErrorIs(t, getErr, ErrIDevIDCertNotFound)
}

// TestProvisionIAKCert_PublicKeyMismatch tests public key validation
func TestProvisionIAKCert_PublicKeyMismatch(t *testing.T) {
	_, tpm := createSim(t, false)
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

	err = tpm.ProvisionIAKCert(nil, cert)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCertPublicKeyMismatch)
}

// TestDeleteIDevIDCertificate_StoreMode exercises the whole store-mode IDevID
// certificate lifecycle: provision, read back, delete, and confirm the delete.
//
// The previous version skipped whenever the store was absent and, when it did
// run, discarded the result with "_ = err" after asserting nothing, so it could
// not fail. Provisioning first also means the delete has something to remove,
// which is the case that actually matters.
func TestDeleteIDevIDCertificate_StoreMode(t *testing.T) {
	tpm := newCertStoreTPM(t)

	idevidAttrs, err := tpm.IDevIDAttributes()
	require.NoError(t, err)
	cert := certForTPMKey(t, idevidAttrs, "idevid-device-001")

	require.NoError(t, tpm.ProvisionIDevIDCert(nil, cert),
		"a certificate matching the IDevID key must be accepted")

	stored, err := tpm.IDevIDCertificate()
	require.NoError(t, err, "the provisioned certificate must be readable")
	assert.Equal(t, cert.Raw, stored.Raw, "the stored certificate must round trip intact")

	require.NoError(t, tpm.DeleteIDevIDCertificate())

	after, err := tpm.IDevIDCertificate()
	assert.Nil(t, after)
	assert.ErrorIs(t, err, ErrIDevIDCertNotFound, "the certificate must be gone after deletion")
}

// TestDeleteIDevIDCertificate_StoreNotConfigured pins the guard clause: a
// delete in store mode without a store reports ErrCertStoreNotConfigured.
func TestDeleteIDevIDCertificate_StoreNotConfigured(t *testing.T) {
	tpm := newCertStoreTPM(t)
	tpm.certStore = nil

	assert.ErrorIs(t, tpm.DeleteIDevIDCertificate(), ErrCertStoreNotConfigured)
}

// TestDeleteIAKCertificate_StoreMode is the IAK counterpart of
// TestDeleteIDevIDCertificate_StoreMode.
func TestDeleteIAKCertificate_StoreMode(t *testing.T) {
	tpm := newCertStoreTPM(t)

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)
	cert := certForTPMKey(t, iakAttrs, "device-id-001")

	require.NoError(t, tpm.ProvisionIAKCert(nil, cert),
		"a certificate matching the IAK must be accepted")

	stored, err := tpm.IAKCertificate()
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, stored.Raw)

	require.NoError(t, tpm.DeleteIAKCertificate())

	after, err := tpm.IAKCertificate()
	assert.Nil(t, after)
	assert.ErrorIs(t, err, ErrIAKCertNotFound)
}

// TestDeleteIAKCertificate_StoreNotConfigured is the IAK counterpart of
// TestDeleteIDevIDCertificate_StoreNotConfigured.
func TestDeleteIAKCertificate_StoreNotConfigured(t *testing.T) {
	tpm := newCertStoreTPM(t)
	tpm.certStore = nil

	assert.ErrorIs(t, tpm.DeleteIAKCertificate(), ErrCertStoreNotConfigured)
}

// TestIDevIDAndIAKCertificatesAreStoredSeparately proves the two identities do
// not collide in the certificate store: deleting one must leave the other
// intact. MemoryCertStore keys on the common name, so a configuration that gave
// both identities the same CN would silently share a single slot.
func TestIDevIDAndIAKCertificatesAreStoredSeparately(t *testing.T) {
	tpm := newCertStoreTPM(t)

	idevidAttrs, err := tpm.IDevIDAttributes()
	require.NoError(t, err)
	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	idevidCert := certForTPMKey(t, idevidAttrs, "idevid-device-001")
	iakCert := certForTPMKey(t, iakAttrs, "device-id-001")

	require.NoError(t, tpm.ProvisionIDevIDCert(nil, idevidCert))
	require.NoError(t, tpm.ProvisionIAKCert(nil, iakCert))

	require.NoError(t, tpm.DeleteIDevIDCertificate())

	_, err = tpm.IDevIDCertificate()
	assert.ErrorIs(t, err, ErrIDevIDCertNotFound)

	survivor, err := tpm.IAKCertificate()
	require.NoError(t, err, "deleting the IDevID certificate must not remove the IAK certificate")
	assert.Equal(t, iakCert.Raw, survivor.Raw)
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

// newNVRAMCertTPM returns a simulator-backed TPM provisioned with an IDevID
// key and configured to store both identity certificates in TPM NV RAM rather
// than in the certificate store.
//
// This is the configuration deployed nodes actually run — the consumer config
// sets idevid.cert-handle — and the one no test covered: every existing
// certificate lifecycle test leaves CertHandle at zero and exercises the
// store. The NV path was therefore never executed end to end, which is how an
// index defined as TPM_NT_COUNTER shipped.
//
// The handles are the ones a deployed node uses, in the TCG-reserved range for
// platform-defined NV indices, so the sizes and attributes under test match
// production rather than an arbitrary scratch index.
func newNVRAMCertTPM(t *testing.T) *TPM2 {
	t.Helper()

	const (
		idevidCertHandle = 0x01C90000
		iakCertHandle    = 0x01C90010
	)

	h := newSimHarness(t, func(c *Config) {
		c.IDevID = &IDevIDConfig{
			CertHandle:         idevidCertHandle,
			CN:                 "idevid-device-001",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			Pad:                false,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
		c.IAK.CertHandle = iakCertHandle
	})

	// No certificate store is wired: in NV RAM mode the store must never be
	// consulted, so a nil store proves the NV path carried the whole flow.
	h.TPM.certStore = nil

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	_, _, err = h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err, "the simulator must be able to create an IDevID key")

	_, err = h.TPM.IDevIDAttributes()
	require.NoError(t, err, "the IDevID key must be present at the configured handle")

	return h.TPM
}

// TestProvisionIDevIDCert_NVRAMRoundTrip is the end-to-end form of the defect
// in issue #138: with a cert handle configured, ProvisionIDevIDCert writes the
// certificate into an NV index and IDevIDCertificate must read the same
// certificate back.
//
// Before the fix the NV index was defined as TPM_NT_COUNTER, so
// TPM2_NV_DefineSpace rejected a certificate-sized data area with
// TPM_RC_SIZE and this call never got as far as writing anything.
func TestProvisionIDevIDCert_NVRAMRoundTrip(t *testing.T) {
	tpm := newNVRAMCertTPM(t)

	idevidAttrs, err := tpm.IDevIDAttributes()
	require.NoError(t, err)
	cert := certForTPMKey(t, idevidAttrs, "idevid-device-001")

	require.NoError(t, tpm.ProvisionIDevIDCert(nil, cert))

	stored, err := tpm.IDevIDCertificate()
	require.NoError(t, err, "the certificate must be readable back out of NV RAM")
	require.NotNil(t, stored)
	assert.Equal(t, cert.Raw, stored.Raw, "NV RAM must return the certificate verbatim")

	require.NoError(t, tpm.DeleteIDevIDCertificate())

	_, err = tpm.IDevIDCertificate()
	assert.Error(t, err, "reading an undefined NV index must fail")
}

// TestProvisionIAKCert_NVRAMRoundTrip covers the second caller of
// writeCertToNVRAM. No consumer configures iak.cert-handle today, so this path
// carried the same defect latently; the round trip keeps it honest.
func TestProvisionIAKCert_NVRAMRoundTrip(t *testing.T) {
	tpm := newNVRAMCertTPM(t)

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)
	cert := certForTPMKey(t, iakAttrs, "device-id-001")

	require.NoError(t, tpm.ProvisionIAKCert(nil, cert))

	stored, err := tpm.IAKCertificate()
	require.NoError(t, err, "the certificate must be readable back out of NV RAM")
	require.NotNil(t, stored)
	assert.Equal(t, cert.Raw, stored.Raw)

	require.NoError(t, tpm.DeleteIAKCertificate())

	_, err = tpm.IAKCertificate()
	assert.Error(t, err)
}

// TestProvisionIDevIDCert_NVRAMOversized pins the one case in which a
// certificate write really is a size problem, and that it is reported as a
// typed error rather than the bare TPM_RC_SIZE a wrong index type also
// produced — the two were previously indistinguishable to a caller.
func TestProvisionIDevIDCert_NVRAMOversized(t *testing.T) {
	tpm := newNVRAMCertTPM(t)

	indexMax, err := nvIndexMaxSize(tpm.transport)
	require.NoError(t, err)

	err = tpm.writeCertToNVRAM(tpm2.TPMHandle(tpm.config.IDevID.CertHandle), nil, make([]byte, int(indexMax)+1))
	assert.ErrorIs(t, err, ErrNVCertTooLarge)
}
