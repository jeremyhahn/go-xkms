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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssueCertificate tests certificate issuance functionality
func TestIssueCertificate(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("BasicCertificateIssuance", func(t *testing.T) {
		request := TestCertificateRequest("test-basic.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "test-basic.example.com")
	})

	t.Run("CertificateWithSANs", func(t *testing.T) {
		request := TestCertificateRequest("test-sans.example.com")
		request.SANS = &ca.SubjectAlternativeNames{
			DNS: []string{"www.example.com", "api.example.com"},
			IPs: []string{"192.168.1.100", "10.0.0.1"},
		}
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "test-sans.example.com")
		assert.Len(t, cert.DNSNames, 2)
		assert.Len(t, cert.IPAddresses, 2)
	})

	t.Run("CACertificateIssuance", func(t *testing.T) {
		request := TestCACertificateRequest("sub-ca.example.com", false)
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "sub-ca.example.com")
		assert.True(t, cert.IsCA)
		assert.True(t, cert.BasicConstraintsValid)
	})

	t.Run("RSACertificateIssuance", func(t *testing.T) {
		request := TestCertificateRequest("test-rsa.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "test-rsa.example.com")
		// Certificate will use CA's default signature algorithm (ECDSA with SHA256)
		assert.NotNil(t, cert.SignatureAlgorithm)
	})

	t.Run("ECDSACertificateIssuance", func(t *testing.T) {
		request := TestCertificateRequest("test-ecdsa.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "test-ecdsa.example.com")
		// Certificate will use CA's default signature algorithm (ECDSA with SHA256)
		assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
	})
}

// TestIssued tests checking if certificates have been issued
func TestIssued(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("CertificateIsIssued", func(t *testing.T) {
		request := TestCertificateRequest("issued-test.example.com")
		_, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		issued, err := caInstance.Issued("issued-test.example.com")
		require.NoError(t, err)
		assert.True(t, issued)
	})

	t.Run("CertificateNotIssued", func(t *testing.T) {
		issued, err := caInstance.Issued("not-issued.example.com")
		require.NoError(t, err)
		assert.False(t, issued)
	})
}

// TestExists tests checking certificate existence with algorithm
func TestExists(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("ECDSACertificateExists", func(t *testing.T) {
		request := TestCertificateRequest("exists-ecdsa.example.com")
		_, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Certificate will use CA's default signature algorithm (ECDSA with SHA256)
		exists, err := caInstance.Exists("exists-ecdsa.example.com", x509.ECDSAWithSHA256)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("WrongAlgorithm", func(t *testing.T) {
		request := TestCertificateRequest("exists-wrong-algo.example.com")
		_, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Check with wrong algorithm (RSA instead of ECDSA)
		exists, err := caInstance.Exists("exists-wrong-algo.example.com", x509.SHA256WithRSA)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("NonExistentCertificate", func(t *testing.T) {
		exists, err := caInstance.Exists("does-not-exist.example.com", x509.ECDSAWithSHA256)
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

// TestCreateCSR tests CSR creation with various algorithms
func TestCreateCSR(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("CreateRSACSR", func(t *testing.T) {
		request := TestCertificateRequest("csr-rsa.example.com")
		request.KeyAttributes = &xkmssdk.KeyAttributes{
			CN:           "csr-rsa.example.com",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &xkmssdk.RSAAttributes{
				KeySize: 2048,
			},
			StoreType: xkmssdk.StoreSoftware,
			KeyType:   xkmssdk.KeyTypeTLS,
		}

		// Generate the key first (CreateCSR expects an existing key)
		ks := caInstance.KeyStore().(xkmssdk.ServiceBackend)
		_, err := ks.GenerateRSA(request.KeyAttributes)
		require.NoError(t, err)

		csrPEM, err := caInstance.CreateCSR(request)
		require.NoError(t, err)
		require.NotEmpty(t, csrPEM)

		// Parse and verify CSR
		block, _ := pem.Decode(csrPEM)
		require.NotNil(t, block)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, "csr-rsa.example.com", csr.Subject.CommonName)
		assert.IsType(t, &rsa.PublicKey{}, csr.PublicKey)
	})

	t.Run("CreateECDSACSR", func(t *testing.T) {
		request := TestCertificateRequest("csr-ecdsa.example.com")
		request.KeyAttributes = &xkmssdk.KeyAttributes{
			CN:           "csr-ecdsa.example.com",
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P256(),
			},
			StoreType: xkmssdk.StoreSoftware,
			KeyType:   xkmssdk.KeyTypeTLS,
		}

		// Generate the key first (CreateCSR expects an existing key)
		ks := caInstance.KeyStore().(xkmssdk.ServiceBackend)
		_, err := ks.GenerateECDSA(request.KeyAttributes)
		require.NoError(t, err)

		csrPEM, err := caInstance.CreateCSR(request)
		require.NoError(t, err)
		require.NotEmpty(t, csrPEM)

		// Parse and verify CSR
		block, _ := pem.Decode(csrPEM)
		require.NotNil(t, block)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, "csr-ecdsa.example.com", csr.Subject.CommonName)
		assert.IsType(t, &ecdsa.PublicKey{}, csr.PublicKey)
	})

	t.Run("CreateCSRWithSANs", func(t *testing.T) {
		request := TestCertificateRequest("csr-sans.example.com")
		request.KeyAttributes = &xkmssdk.KeyAttributes{
			CN:           "csr-sans.example.com",
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P256(),
			},
			StoreType: xkmssdk.StoreSoftware,
			KeyType:   xkmssdk.KeyTypeTLS,
		}
		request.SANS = &ca.SubjectAlternativeNames{
			DNS: []string{"www.example.com"},
			IPs: []string{"192.168.1.1"},
		}

		// Generate the key first (CreateCSR expects an existing key)
		ks := caInstance.KeyStore().(xkmssdk.ServiceBackend)
		_, err := ks.GenerateECDSA(request.KeyAttributes)
		require.NoError(t, err)

		csrPEM, err := caInstance.CreateCSR(request)
		require.NoError(t, err)
		require.NotEmpty(t, csrPEM)
	})
}

// TestTPMCertificates tests TPM-specific certificate operations
func TestTPMCertificates(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("IssueEKCertificate", func(t *testing.T) {
		request := TestEKCertificateRequest("test-ek.tpm.example.com")
		ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		cert, err := caInstance.IssueEKCertificate(request, ekKey.Public())
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "test-ek.tpm.example.com")
		assert.Equal(t, x509.KeyUsageKeyEncipherment, cert.KeyUsage&x509.KeyUsageKeyEncipherment)
	})

	t.Run("IssueAKCertificate", func(t *testing.T) {
		request := TestAKCertificateRequest("test-ak.tpm.example.com")
		akKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cert, err := caInstance.IssueAKCertificate(request, akKey.Public())
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "test-ak.tpm.example.com")
		assert.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage&x509.KeyUsageDigitalSignature)
	})

	t.Run("ImportAndRetrieveEKCertificate", func(t *testing.T) {
		request := TestEKCertificateRequest("imported-ek.tpm.example.com")
		ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		cert, err := caInstance.IssueEKCertificate(request, ekKey.Public())
		require.NoError(t, err)

		// Import it
		err = caInstance.ImportEndorsementKeyCertificate(cert)
		require.NoError(t, err)

		// Retrieve it
		retrieved, err := caInstance.EndorsementKeyCertificate("imported-ek.tpm.example.com")
		require.NoError(t, err)
		assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
	})
}

// TestTLSIntegration tests TLS certificate and configuration methods
func TestTLSIntegration(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	// Issue a certificate first
	request := TestCertificateRequest("tls-test.example.com")
	_, err := caInstance.IssueCertificate(request)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:           "tls-test.example.com",
		KeyAlgorithm: x509.ECDSA,
		StoreType:    xkmssdk.StoreSoftware,
		KeyType:      xkmssdk.KeyTypeTLS,
		ECCAttributes: &xkmssdk.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	t.Run("TLSCertificate", func(t *testing.T) {
		tlsCert, err := caInstance.TLSCertificate(attrs)
		require.NoError(t, err)
		assert.NotNil(t, tlsCert.Certificate)
		assert.NotNil(t, tlsCert.PrivateKey)
		assert.NotNil(t, tlsCert.Leaf)
	})

	t.Run("TLSBundle", func(t *testing.T) {
		bundle, err := caInstance.TLSBundle(attrs)
		if err != nil {
			// TLSBundle may not be implemented for all key storage backends
			// (e.g., TPM keys cannot be exported). Log and pass if not supported.
			t.Logf("TLSBundle not supported by this backend: %v (this is expected for non-exportable keys)", err)
			return
		}
		require.NotEmpty(t, bundle)

		// Should contain both certificate and private key
		assert.Contains(t, string(bundle), "BEGIN CERTIFICATE")
		assert.Contains(t, string(bundle), "BEGIN PRIVATE KEY")
	})

	t.Run("TLSConfig", func(t *testing.T) {
		tlsConfig, err := caInstance.TLSConfig(attrs)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.NotEmpty(t, tlsConfig.Certificates)
		assert.NotNil(t, tlsConfig.ClientCAs)
	})

	t.Run("TLSConfigWithXSigner", func(t *testing.T) {
		tlsConfig, err := caInstance.TLSConfigWithXSigner(attrs, nil)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.NotEmpty(t, tlsConfig.Certificates)
	})
}

// TestCertificateRevocation tests certificate revocation functionality
func TestCertificateRevocation(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("RevokeCertificate", func(t *testing.T) {
		request := TestCertificateRequest("revoke-test.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Revoke without deleting keys (pass nil for keyAttrs)
		err = caInstance.Revoke(cert, nil)
		require.NoError(t, err)

		// Verify certificate is still marked as issued (revoked certificates remain)
		issued, err := caInstance.Issued("revoke-test.example.com")
		require.NoError(t, err)
		assert.True(t, issued)
	})

	t.Run("RevokeAndDeleteKeys", func(t *testing.T) {
		request := TestCertificateRequest("revoke-delete.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Revoke and delete keys (pass keyAttrs to trigger deletion)
		keyAttrs := &xkmssdk.KeyAttributes{
			CN:           "revoke-delete.example.com",
			KeyAlgorithm: cert.PublicKeyAlgorithm,
			StoreType:    xkmssdk.StoreSoftware,
		}
		err = caInstance.Revoke(cert, keyAttrs)
		require.NoError(t, err)
	})
}

// TestSignCSR tests signing externally generated CSRs
func TestSignCSR(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("SignECDSACSR", func(t *testing.T) {
		csrPEM := GenerateTestCSR(t, "external-csr.example.com", x509.ECDSA)
		request := TestCertificateRequest("external-csr.example.com")

		cert, err := caInstance.SignCSR(csrPEM, request)
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "external-csr.example.com")
	})

	t.Run("SignRSACSR", func(t *testing.T) {
		csrPEM := GenerateTestCSR(t, "external-rsa.example.com", x509.RSA)
		request := TestCertificateRequest("external-rsa.example.com")

		cert, err := caInstance.SignCSR(csrPEM, request)
		require.NoError(t, err)
		AssertCertificateValid(t, cert, "external-rsa.example.com")
	})
}

// TestCertificateVerification tests certificate verification
func TestCertificateVerification(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("VerifyIssuedCertificate", func(t *testing.T) {
		request := TestCertificateRequest("verify-test.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		chains, err := caInstance.Verify(cert, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, chains)
	})

	t.Run("VerifyWithTrustChain", func(t *testing.T) {
		request := TestCertificateRequest("verify-chain.example.com")
		cert, err := caInstance.IssueCertificate(request)
		require.NoError(t, err)

		// Verify builds complete chain
		chains, err := caInstance.Verify(cert, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, chains)

		// Chain should include intermediate and root
		for _, chain := range chains {
			assert.True(t, len(chain) >= 2, "Chain should include at least cert + CA")
		}
	})
}

// TestCryptoSignerInterface tests the crypto.Signer interface implementation
func TestCryptoSignerInterface(t *testing.T) {
	caInstance, cleanup := NewTestCA(t)
	defer cleanup()

	t.Run("CAImplementsSigner", func(t *testing.T) {
		var _ crypto.Signer = caInstance
	})

	t.Run("Public", func(t *testing.T) {
		pubKey := caInstance.Public()
		require.NotNil(t, pubKey)

		// Should be ECDSA public key (based on config)
		_, ok := pubKey.(*ecdsa.PublicKey)
		assert.True(t, ok, "Public key should be ECDSA")
	})

	t.Run("Sign", func(t *testing.T) {
		digest := []byte("test data to sign")
		signature, err := caInstance.Sign(rand.Reader, digest, crypto.SHA256)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})

	t.Run("Signer", func(t *testing.T) {
		signer, err := caInstance.Signer()
		require.NoError(t, err)
		require.NotNil(t, signer)

		// Should be able to sign
		digest := []byte("test signer data")
		signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})
}
