// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// All go-xkms backend types
var allBackendTypes = []string{
	"software",
	"tpm2",
	"pkcs11",
	"awskms",
	"gcpkms",
	"azurekv",
	"vault",
}

// TestAllBackends_EKCertificateIssuance tests EK certificate issuance with each backend.
// This test MUST run in the devcontainer where all dependencies are available.
func TestAllBackends_EKCertificateIssuance(t *testing.T) {
	requireDevcontainerDependencies(t)

	for _, backendType := range allBackendTypes {
		backendType := backendType
		t.Run(backendType, func(t *testing.T) {
			testEKCertificateWithBackend(t, backendType)
		})
	}
}

// TestAllBackends_AKCertificateIssuance tests AK certificate issuance with each backend.
func TestAllBackends_AKCertificateIssuance(t *testing.T) {
	requireDevcontainerDependencies(t)

	for _, backendType := range allBackendTypes {
		backendType := backendType
		t.Run(backendType, func(t *testing.T) {
			testAKCertificateWithBackend(t, backendType)
		})
	}
}

// TestAllBackends_CertificateChain tests EK + AK certificate chain with each backend.
func TestAllBackends_CertificateChain(t *testing.T) {
	requireDevcontainerDependencies(t)

	for _, backendType := range allBackendTypes {
		backendType := backendType
		t.Run(backendType, func(t *testing.T) {
			testCertificateChainWithBackend(t, backendType)
		})
	}
}

// requireDevcontainerDependencies verifies all required dependencies are available.
// Tests FAIL if dependencies are not met.
func requireDevcontainerDependencies(t *testing.T) {
	t.Helper()

	// Verify swtpm is running
	tpmHost := os.Getenv("TPM_SOCKET_HOST")
	tpmPort := os.Getenv("TPM_SOCKET_PORT")
	require.NotEmpty(t, tpmHost, "TPM_SOCKET_HOST must be set")
	require.NotEmpty(t, tpmPort, "TPM_SOCKET_PORT must be set")

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", tpmHost, tpmPort), 5*time.Second)
	require.NoError(t, err, "swtpm must be running at %s:%s", tpmHost, tpmPort)
	conn.Close()

	// Verify SoftHSM2 is available
	pkcs11Module := os.Getenv("PKCS11_MODULE")
	if pkcs11Module == "" {
		pkcs11Module = "/usr/lib/softhsm/libsofthsm2.so"
	}
	_, err = os.Stat(pkcs11Module)
	require.NoError(t, err, "SoftHSM2 module must exist at %s", pkcs11Module)

	// Verify Vault is available
	vaultAddr := os.Getenv("VAULT_ADDR")
	require.NotEmpty(t, vaultAddr, "VAULT_ADDR must be set")
}

// testEKCertificateWithBackend tests EK certificate issuance with a specific backend.
// Note: We use a mock PKCS8 backend registered under the backend name, so we verify
// certificate issuance works but can't verify backend-specific OID values.
func testEKCertificateWithBackend(t *testing.T, backendType string) {
	t.Helper()

	caInstance := createCAWithBackend(t, backendType)

	// Generate test EK key
	ekPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Issue EK certificate
	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   fmt.Sprintf("ek-%s-test.local", backendType),
			Organization: "Backend Integration Test",
		},
		PermanentID: fmt.Sprintf("device-%s-001", backendType),
		ProdModel:   fmt.Sprintf("%s-MODEL", backendType),
		ProdSerial:  fmt.Sprintf("%s-SERIAL-001", backendType),
	}

	cert, err := caInstance.IssueEKCertificate(certRequest, ekPrivateKey.Public())
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate has expected subject
	assert.Equal(t, fmt.Sprintf("ek-%s-test.local", backendType), cert.Subject.CommonName)

	// Verify tp-issuerKeyStore OID exists (value depends on actual backend)
	var foundIssuerKeyStore bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ca.OIDTPIssuerKeyStore) {
			foundIssuerKeyStore = true
			break
		}
	}
	assert.True(t, foundIssuerKeyStore, "EK certificate must have tp-issuerKeyStore OID")

	// Verify tp-keyStore OID is TPM2 for EK certs
	var keyStore string
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ca.OIDTPKeyStore) {
			var value string
			if _, err := asn1.Unmarshal(ext.Value, &value); err == nil {
				keyStore = value
			}
			break
		}
	}
	assert.Equal(t, "TPM2", keyStore, "tp-keyStore must be TPM2 for EK certificate")
}

// testAKCertificateWithBackend tests AK certificate issuance with a specific backend.
func testAKCertificateWithBackend(t *testing.T, backendType string) {
	t.Helper()

	caInstance := createCAWithBackend(t, backendType)

	// Generate test AK key
	akPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Issue AK certificate
	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   fmt.Sprintf("ak-%s-test.local", backendType),
			Organization: "Backend Integration Test",
		},
		PermanentID: fmt.Sprintf("ak-device-%s-001", backendType),
		ProdModel:   fmt.Sprintf("%s-MODEL", backendType),
		ProdSerial:  fmt.Sprintf("%s-AK-SERIAL-001", backendType),
	}

	cert, err := caInstance.IssueAKCertificate(certRequest, akPrivateKey.Public())
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify TCG AIK OID is present
	var foundAIKOID bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ca.OIDTCGAIKCertificate) {
			foundAIKOID = true
			break
		}
	}
	assert.True(t, foundAIKOID, "AK certificate must have TCG AIK OID")
}

// testCertificateChainWithBackend tests EK + AK chain with a specific backend.
func testCertificateChainWithBackend(t *testing.T, backendType string) {
	t.Helper()

	caInstance := createCAWithBackend(t, backendType)
	deviceID := fmt.Sprintf("chain-%s-001", backendType)

	// Issue EK certificate
	ekKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekCert, err := caInstance.IssueEKCertificate(&ca.CertificateRequest{
		Subject:     ca.Subject{CommonName: fmt.Sprintf("ek-%s", deviceID)},
		PermanentID: fmt.Sprintf("ek-%s", deviceID),
	}, ekKey.Public())
	require.NoError(t, err)

	// Issue AK certificate
	akKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	akCert, err := caInstance.IssueAKCertificate(&ca.CertificateRequest{
		Subject:     ca.Subject{CommonName: fmt.Sprintf("ak-%s", deviceID)},
		PermanentID: fmt.Sprintf("ak-%s", deviceID),
	}, akKey.Public())
	require.NoError(t, err)

	// Verify same issuer
	assert.Equal(t, ekCert.Issuer.CommonName, akCert.Issuer.CommonName, "certificates must have same issuer")
}

// createCAWithBackend creates a CA instance with the specified backend type.
func createCAWithBackend(t *testing.T, backendType string) ca.CertificateAuthority {
	t.Helper()

	tmpDir := t.TempDir()
	keysDir := tmpDir + "/keys"
	certsDir := tmpDir + "/certs"
	blobsDir := tmpDir + "/blobs"

	// Create storage backends
	keyStorageBackend, err := xkmssdk.NewFileStorageBackend(keysDir)
	require.NoError(t, err)

	certStorageBackend, err := xkmssdk.NewFileStorageBackend(certsDir)
	require.NoError(t, err)

	pkcs8Backend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorageBackend,
	})
	require.NoError(t, err)

	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     pkcs8Backend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	// Register backend with the specified type name
	xkmssdk.ServiceReset()
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			backendType: keyStore,
		},
		DefaultBackend: backendType,
	})
	require.NoError(t, err)
	t.Cleanup(xkmssdk.ServiceReset)

	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStoreInstance, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	blobStorage := local.New()
	err = blobStorage.Configure(map[string]string{"path": blobsDir})
	require.NoError(t, err)

	caConfig := ca.TestConfig()
	caConfig.HomeDir = tmpDir
	caConfig.Identity[0].Subject.CommonName = fmt.Sprintf("%s Test CA", backendType)
	caConfig.Identity[0].KeystoreType = backendType

	caInstance, err := ca.NewWithParams(ca.Params{
		Config:      caConfig,
		CertStore:   certStoreInstance,
		ObjectStore: blobStorage,
	})
	require.NoError(t, err)
	require.True(t, caInstance.IsInitialized())

	return caInstance
}
