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

//go:build local

package ca

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCertificateStore tests certificate store operations
func TestCertificateStore(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("CertificateStore", func(t *testing.T) {
		store := caInstance.CertificateStore()
		require.NotNil(t, store)
	})

	t.Run("PEMRetrieval", func(t *testing.T) {
		request := TestCertificateRequest("pem-test.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		attrs := &xkmssdk.KeyAttributes{
			CN:           "pem-test.example.com",
			KeyAlgorithm: x509.ECDSA,
			StoreType:    xkmssdk.StoreSoftware,
			KeyType:      xkmssdk.KeyTypeTLS,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		pemData, err := caInstance.PEM(attrs)
		require.NoError(t, err)
		require.NotEmpty(t, pemData)

		// Parse PEM to verify
		block, _ := pem.Decode(pemData)
		require.NotNil(t, block)
		parsedCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, cert.SerialNumber, parsedCert.SerialNumber)
	})

	t.Run("CertificatePEM", func(t *testing.T) {
		request := TestCertificateRequest("certpem-test.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		pemData, err := caInstance.CertificatePEM("certpem-test.example.com")
		require.NoError(t, err)
		require.NotEmpty(t, pemData)

		// Parse PEM to verify
		block, _ := pem.Decode(pemData)
		require.NotNil(t, block)
		parsedCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, cert.SerialNumber, parsedCert.SerialNumber)
	})

	t.Run("ImportCertificatePEM", func(t *testing.T) {
		// Generate a certificate
		request := TestCertificateRequest("import-pem.example.com")
		_, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Get its PEM
		pemData, err := caInstance.CertificatePEM("import-pem.example.com")
		require.NoError(t, err)

		// Import under different name
		err = caInstance.ImportCertificatePEM("import-pem-copy.example.com", pemData)
		require.NoError(t, err)

		// Verify we can retrieve it
		retrieved, err := caInstance.CertificatePEM("import-pem-copy.example.com")
		require.NoError(t, err)
		assert.NotEmpty(t, retrieved)
	})

	t.Run("ImportCertificate", func(t *testing.T) {
		request := TestCertificateRequest("import-cert.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Import the certificate again
		err = caInstance.ImportCertificate(cert)
		require.NoError(t, err)
	})

	t.Run("Certificate", func(t *testing.T) {
		request := TestCertificateRequest("get-cert.example.com")
		issuedCert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		attrs := &xkmssdk.KeyAttributes{
			CN:           "get-cert.example.com",
			KeyAlgorithm: x509.ECDSA,
			StoreType:    xkmssdk.StoreSoftware,
			KeyType:      xkmssdk.KeyTypeTLS,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		retrievedCert, err := caInstance.Certificate(attrs)
		require.NoError(t, err)
		assert.Equal(t, issuedCert.SerialNumber, retrievedCert.SerialNumber)
	})
}

// TestTrustChain tests trust chain building methods
func TestTrustChain(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	// Issue a test certificate
	request := TestCertificateRequest("chain-test.example.com")
	cert, err := caInstance.IssueCertificate(request)
	require.NoError(t, err)

	t.Run("TrustedRoot", func(t *testing.T) {
		root, err := caInstance.TrustedRoot()
		require.NoError(t, err)
		require.NotNil(t, root)
		assert.True(t, root.IsCA)
		assert.Equal(t, root.Issuer, root.Subject) // Self-signed
	})

	t.Run("TrustedIntermediate", func(t *testing.T) {
		intermediate, err := caInstance.TrustedIntermediate()
		require.NoError(t, err)
		require.NotNil(t, intermediate)
		assert.True(t, intermediate.IsCA)
	})

	t.Run("TrustedRootCertPool", func(t *testing.T) {
		pool, err := caInstance.TrustedRootCertPool(cert, nil)
		require.NoError(t, err)
		require.NotNil(t, pool)
	})

	t.Run("TrustedIntermediateCertPool", func(t *testing.T) {
		pool, err := caInstance.TrustedIntermediateCertPool(cert, nil)
		require.NoError(t, err)
		require.NotNil(t, pool)
	})

	t.Run("CABundleCertPool", func(t *testing.T) {
		pool, err := caInstance.CABundleCertPool(xkmssdk.StoreSoftware, x509.ECDSA)
		require.NoError(t, err)
		require.NotNil(t, pool)
	})

	t.Run("CABundle", func(t *testing.T) {
		bundle, err := caInstance.CABundle(xkmssdk.StoreSoftware, x509.ECDSA)
		require.NoError(t, err)
		require.NotEmpty(t, bundle)

		// Should contain both intermediate and root
		assert.Contains(t, string(bundle), "BEGIN CERTIFICATE")

		// Count certificates in bundle
		remaining := bundle
		count := 0
		for len(remaining) > 0 {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				count++
			}
			remaining = rest
		}
		assert.True(t, count >= 1, "Bundle should contain at least one certificate")
	})

	t.Run("RootCertificate", func(t *testing.T) {
		root, err := caInstance.RootCertificate(cert)
		require.NoError(t, err)
		require.NotNil(t, root)
		assert.True(t, root.IsCA)
		assert.Equal(t, root.Issuer, root.Subject) // Self-signed root
	})
}

// TestParseBundle tests bundle parsing
func TestParseBundle(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("ParseSingleCertificate", func(t *testing.T) {
		request := TestCertificateRequest("parse-single.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		pemData, err := caInstance.CertificatePEM("parse-single.example.com")
		require.NoError(t, err)

		certs, err := caInstance.ParseBundle(pemData)
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		assert.Equal(t, cert.SerialNumber, certs[0].SerialNumber)
	})

	t.Run("ParseCABundle", func(t *testing.T) {
		bundle, err := caInstance.CABundle(xkmssdk.StoreSoftware, x509.ECDSA)
		require.NoError(t, err)

		certs, err := caInstance.ParseBundle(bundle)
		require.NoError(t, err)
		assert.True(t, len(certs) >= 1, "Should parse at least one certificate from bundle")

		// All should be CA certificates
		for _, cert := range certs {
			assert.True(t, cert.IsCA)
		}
	})

	t.Run("ParseEmptyBundle", func(t *testing.T) {
		certs, err := caInstance.ParseBundle([]byte{})
		// Empty bundle should return an error
		assert.Error(t, err)
		assert.Nil(t, certs)
	})
}

// TestAdvancedSigning tests advanced signing operations
func TestAdvancedSigning(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("SignedBlob", func(t *testing.T) {
		data := []byte("test data to sign")
		signature, err := caInstance.SignedBlob(data)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("SignedBlobWithString", func(t *testing.T) {
		data := "string data to sign"
		signature, err := caInstance.SignedBlob(data)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("CASigner", func(t *testing.T) {
		signer, err := caInstance.CASigner(xkmssdk.StoreSoftware, x509.ECDSA)
		require.NoError(t, err)
		require.NotNil(t, signer)

		// Test signing
		digest := []byte("test digest")
		signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("CAKeyAttributes", func(t *testing.T) {
		attrs, err := caInstance.CAKeyAttributes(xkmssdk.StoreSoftware)
		require.NoError(t, err)
		require.NotNil(t, attrs)
		assert.NotEmpty(t, attrs.CN)
	})
}

// TestCrossSigning tests cross-signing operations
func TestCrossSigning(t *testing.T) {
	// Reset any previous facade state
	xkmssdk.ServiceReset()

	// Create storage backends for both CAs upfront
	keyStorage1, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorageBackend1, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	keyStorage2, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorageBackend2, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	// Create PKCS#8 backends for both
	softwareBackend1, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{KeyStorage: keyStorage1})
	require.NoError(t, err)
	softwareBackend2, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{KeyStorage: keyStorage2})
	require.NoError(t, err)

	// Create keystores for both
	keyStore1, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend1,
		CertStorage: certStorageBackend1,
	})
	require.NoError(t, err)
	keyStore2, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend2,
		CertStorage: certStorageBackend2,
	})
	require.NoError(t, err)

	// Initialize the facade with both backends at once
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software":  keyStore1,
			"pkcs8-ca2": keyStore2,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer xkmssdk.ServiceReset()

	// Create certstore and blobstore for CA1
	certAdapter1 := xkmssdk.NewStorageCertAdapter(certStorageBackend1)
	certStore1, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter1,
	})
	require.NoError(t, err)

	blobStore1 := local.New()
	err = blobStore1.Configure(map[string]string{"path": t.TempDir()})
	require.NoError(t, err)

	// Create CA1
	ca1Config := TestCAConfig()
	ca1, err := ca.New(ca1Config, certStore1, blobStore1)
	require.NoError(t, err)

	// Create certstore and blobstore for CA2
	certAdapter2 := xkmssdk.NewStorageCertAdapter(certStorageBackend2)
	certStore2, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter2,
	})
	require.NoError(t, err)

	blobStore2 := local.New()
	err = blobStore2.Configure(map[string]string{"path": t.TempDir()})
	require.NoError(t, err)

	// Create CA2 with different identity
	ca2Config := TestCAConfig()
	if len(ca2Config.Identity) > 0 {
		ca2Config.Identity[0].Subject.CommonName = "Cross-Sign Root CA"
		ca2Config.Identity[0].KeystoreType = "pkcs8-ca2"
	}
	if len(ca2Config.Identity) > 1 {
		ca2Config.Identity[1].Subject.CommonName = "Cross-Sign Intermediate CA"
		ca2Config.Identity[1].KeystoreType = "pkcs8-ca2"
	}

	ca2, err := ca.New(ca2Config, certStore2, blobStore2)
	require.NoError(t, err)

	t.Run("TLSConfigWithXSigner", func(t *testing.T) {
		// Issue a certificate with CA1
		request := TestCertificateRequest("xsign-test.example.com")
		_, err := ca1.IssueCertificate(request)
		require.NoError(t, err)

		attrs := &xkmssdk.KeyAttributes{
			CN:           "xsign-test.example.com",
			KeyAlgorithm: x509.ECDSA,
			StoreType:    xkmssdk.StoreSoftware,
			KeyType:      xkmssdk.KeyTypeTLS,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Get CA2's signer
		ca2Signer, err := ca2.Signer()
		require.NoError(t, err)

		// Create TLS config with cross-signer
		tlsConfig, err := ca1.TLSConfigWithXSigner(attrs, ca2Signer)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
	})

	t.Run("VerifyWithXSigner", func(t *testing.T) {
		// Issue certificate with CA1
		request := TestCertificateRequest("verify-xsign.example.com")
		cert, err := ca1.IssueCertificate(request)
		require.NoError(t, err)

		// Get CA2's signer for cross-verification
		ca2Signer, err := ca2.Signer()
		require.NoError(t, err)

		// Verify with cross-signer
		chains, err := ca1.Verify(cert, ca2Signer)
		require.NoError(t, err)
		assert.NotEmpty(t, chains)
	})

	t.Run("TrustedRootCertPoolWithXSigner", func(t *testing.T) {
		request := TestCertificateRequest("pool-xsign.example.com")
		cert, err := ca1.IssueCertificate(request)
		require.NoError(t, err)

		ca2Signer, err := ca2.Signer()
		require.NoError(t, err)

		pool, err := ca1.TrustedRootCertPool(cert, ca2Signer)
		require.NoError(t, err)
		require.NotNil(t, pool)
	})

	t.Run("TrustedIntermediateCertPoolWithXSigner", func(t *testing.T) {
		request := TestCertificateRequest("intermediate-pool-xsign.example.com")
		cert, err := ca1.IssueCertificate(request)
		require.NoError(t, err)

		ca2Signer, err := ca2.Signer()
		require.NoError(t, err)

		pool, err := ca1.TrustedIntermediateCertPool(cert, ca2Signer)
		require.NoError(t, err)
		require.NotNil(t, pool)
	})
}

// TestImportIssuingCAs tests automatic AIA import
func TestImportIssuingCAs(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("ImportIssuingCAsWithoutAIA", func(t *testing.T) {
		// Issue a basic certificate without AIA
		request := TestCertificateRequest("no-aia.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Should not error even if no AIA present
		err = caInstance.ImportIssuingCAs(cert)
		require.NoError(t, err)
	})

	t.Run("IsAutoImportingIssuerCAs", func(t *testing.T) {
		autoImport := caInstance.IsAutoImportingIssuerCAs()
		// Just verify the method works
		_ = autoImport
	})
}

// TestImportDistributionCRLs tests CRL import
func TestImportDistributionCRLs(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("ImportDistributionCRLsWithoutCDP", func(t *testing.T) {
		// Issue a certificate without CRL Distribution Points
		request := TestCertificateRequest("no-cdp.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Should not error even if no CDP present
		err = caInstance.ImportDistributionCRLs(cert)
		require.NoError(t, err)
	})
}
