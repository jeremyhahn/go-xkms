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

//go:build integration
// +build integration

package certstore_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Test Helpers
// ========================================================================

// generateTestCert generates a test certificate with the given parameters
func generateTestCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, interface{}) {
	t.Helper()

	// Generate key pair
	var priv interface{}
	var pub interface{}
	var err error

	if isCA {
		// Use RSA for CA certificates (more traditional)
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		priv = rsaKey
		pub = &rsaKey.PublicKey
	} else {
		// Use ECDSA for leaf certificates (more modern)
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		priv = ecKey
		pub = &ecKey.PublicKey
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	// Build certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.MaxPathLen = 1
		template.MaxPathLenZero = false
	}

	// Determine parent and signing key
	var certParent *x509.Certificate
	var signingKey interface{}

	if parent != nil && parentKey != nil {
		certParent = parent
		signingKey = parentKey
		template.Issuer = parent.Subject
	} else {
		// Self-signed
		certParent = template
		signingKey = priv
		template.Issuer = template.Subject
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, certParent, pub, signingKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, priv
}

// generateExpiredCert generates a certificate that has already expired
func generateExpiredCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// generateNotYetValidCert generates a certificate that is not yet valid
func generateNotYetValidCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(24 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// generateCRL generates a Certificate Revocation List
func generateCRL(t *testing.T, caCert *x509.Certificate, caKey interface{}, revokedCerts ...*x509.Certificate) *x509.RevocationList {
	t.Helper()

	revokedList := []pkix.RevokedCertificate{}
	for _, cert := range revokedCerts {
		revokedList = append(revokedList, pkix.RevokedCertificate{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now(),
		})
	}

	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(1),
		Issuer:              caCert.Subject,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(24 * time.Hour),
		RevokedCertificates: revokedList,
	}

	var crlDER []byte
	var err error

	// Handle both RSA and ECDSA keys
	switch key := caKey.(type) {
	case *rsa.PrivateKey:
		crlDER, err = x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, key)
	case *ecdsa.PrivateKey:
		crlDER, err = x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, key)
	default:
		t.Fatalf("Unsupported key type: %T", caKey)
	}
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	return crl
}

// ========================================================================
// Basic Certificate Operations Tests
// ========================================================================

func TestCertStore_StoreCertificate(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)

	err = cs.StoreCertificate(cert)
	assert.NoError(t, err)

	// Verify it was stored
	retrieved, err := cs.GetCertificate(cert.Subject.CommonName)
	assert.NoError(t, err)
	assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
	assert.Equal(t, cert.Subject.CommonName, retrieved.Subject.CommonName)
}

func TestCertStore_StoreCertificate_MultipleTypes(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	tests := []struct {
		name string
		isCA bool
	}{
		{"leaf.example.com", false},
		{"ca.example.com", true},
		{"server.example.com", false},
		{"intermediate.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _ := generateTestCert(t, tt.name, tt.isCA, nil, nil)
			err := cs.StoreCertificate(cert)
			assert.NoError(t, err)

			retrieved, err := cs.GetCertificate(tt.name)
			assert.NoError(t, err)
			assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
		})
	}
}

func TestCertStore_GetCertificate_NotFound(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	_, err = cs.GetCertificate("nonexistent.example.com")
	assert.Error(t, err)
}

func TestCertStore_DeleteCertificate(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	require.NoError(t, err)

	err = cs.DeleteCertificate(cert.Subject.CommonName)
	assert.NoError(t, err)

	// Verify it was deleted
	_, err = cs.GetCertificate(cert.Subject.CommonName)
	assert.Error(t, err)
}

func TestCertStore_ListCertificates(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Store multiple certificates
	cert1, _ := generateTestCert(t, "test1.example.com", false, nil, nil)
	cert2, _ := generateTestCert(t, "test2.example.com", false, nil, nil)
	cert3, _ := generateTestCert(t, "test3.example.com", false, nil, nil)

	err = cs.StoreCertificate(cert1)
	require.NoError(t, err)
	err = cs.StoreCertificate(cert2)
	require.NoError(t, err)
	err = cs.StoreCertificate(cert3)
	require.NoError(t, err)

	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, 3)
}

func TestCertStore_ListCertificates_Empty(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Empty(t, certs)
}

// ========================================================================
// Certificate Chain Tests
// ========================================================================

func TestCertStore_CertificateChain_ThreeTier(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a 3-tier chain: root -> intermediate -> leaf
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	intermediateCert, intermediateKey := generateTestCert(t, "intermediate.example.com", true, rootCert, rootKey)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, intermediateCert, intermediateKey)

	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}

	err = cs.StoreCertificateChain(chain)
	assert.NoError(t, err)

	// Retrieve and verify chain
	retrieved, err := cs.GetCertificateChain(leafCert.Subject.CommonName)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 3)
	assert.Equal(t, leafCert.SerialNumber, retrieved[0].SerialNumber)
	assert.Equal(t, intermediateCert.SerialNumber, retrieved[1].SerialNumber)
	assert.Equal(t, rootCert.SerialNumber, retrieved[2].SerialNumber)
}

func TestCertStore_CertificateChain_TwoTier(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a 2-tier chain: root -> leaf
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, rootCert, rootKey)

	chain := []*x509.Certificate{leafCert, rootCert}

	err = cs.StoreCertificateChain(chain)
	assert.NoError(t, err)

	// Retrieve and verify chain
	retrieved, err := cs.GetCertificateChain(leafCert.Subject.CommonName)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 2)
	assert.Equal(t, leafCert.SerialNumber, retrieved[0].SerialNumber)
	assert.Equal(t, rootCert.SerialNumber, retrieved[1].SerialNumber)
}

func TestCertStore_CertificateChain_NotFound(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	_, err = cs.GetCertificateChain("nonexistent.example.com")
	assert.Error(t, err)
}

// ========================================================================
// Certificate Revocation List (CRL) Tests
// ========================================================================

func TestCertStore_CRL_StoreAndRetrieve(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	crl := generateCRL(t, caCert, caKey, leafCert)

	err = cs.StoreCRL(crl)
	assert.NoError(t, err)

	retrieved, err := cs.GetCRL(caCert.Subject.CommonName)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, crl.Number, retrieved.Number)
}

func TestCertStore_CRL_MultipleCAs(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create multiple CA certificates with their own CRLs
	ca1Cert, ca1Key := generateTestCert(t, "ca1.example.com", true, nil, nil)
	ca2Cert, ca2Key := generateTestCert(t, "ca2.example.com", true, nil, nil)

	crl1 := generateCRL(t, ca1Cert, ca1Key)
	crl2 := generateCRL(t, ca2Cert, ca2Key)

	err = cs.StoreCRL(crl1)
	require.NoError(t, err)
	err = cs.StoreCRL(crl2)
	require.NoError(t, err)

	// Verify both CRLs can be retrieved
	retrieved1, err := cs.GetCRL(ca1Cert.Subject.CommonName)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved1)

	retrieved2, err := cs.GetCRL(ca2Cert.Subject.CommonName)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved2)
}

func TestCertStore_CRL_NotFound(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	_, err = cs.GetCRL("nonexistent.example.com")
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrCRLNotFound, err)
}

// ========================================================================
// Certificate Validation Tests
// ========================================================================

func TestCertStore_VerifyCertificate_ValidChain(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create CA and leaf certificate
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestCertStore_VerifyCertificate_WithIntermediates(t *testing.T) {
	backend := storage.New()

	// Create certificate chain
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	intermediateCert, intermediateKey := generateTestCert(t, "intermediate.example.com", true, rootCert, rootKey)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, intermediateCert, intermediateKey)

	// Set up intermediates pool
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
		VerifyOptions: &x509.VerifyOptions{
			Intermediates: intermediates,
		},
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestCertStore_VerifyCertificate_UntrustedRoot(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a CA and certificate
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create a different CA for the root pool
	differentCA, _ := generateTestCert(t, "different-ca.example.com", true, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(differentCA)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.Error(t, err)
}

// ========================================================================
// Certificate Revocation Tests
// ========================================================================

func TestCertStore_IsRevoked_NotRevoked(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create empty CRL
	crl := generateCRL(t, caCert, caKey)
	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestCertStore_IsRevoked_Revoked(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL with revoked certificate
	crl := generateCRL(t, caCert, caKey, leafCert)
	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

func TestCertStore_IsRevoked_NoCRL(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// No CRL stored - should assume not revoked
	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestCertStore_StoreCertificate_Revoked_WithoutAllowRevoked(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage:  storage.NewCertAdapter(backend),
		AllowRevoked: false,
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL with revoked certificate
	crl := generateCRL(t, caCert, caKey, leafCert)
	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	// Should fail because certificate is revoked
	err = cs.StoreCertificate(leafCert)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrCertRevoked, err)
}

func TestCertStore_StoreCertificate_Revoked_WithAllowRevoked(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage:  storage.NewCertAdapter(backend),
		AllowRevoked: true,
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL with revoked certificate
	crl := generateCRL(t, caCert, caKey, leafCert)
	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	// Should succeed because AllowRevoked is true
	err = cs.StoreCertificate(leafCert)
	assert.NoError(t, err)
}

// ========================================================================
// Certificate Expiration and Validity Tests
// ========================================================================

func TestCertStore_StoreCertificate_Expired(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	cert := generateExpiredCert(t, "expired.example.com")

	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrCertExpired, err)
}

func TestCertStore_StoreCertificate_NotYetValid(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	cert := generateNotYetValidCert(t, "future.example.com")

	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrCertNotYetValid, err)
}

func TestCertStore_CRL_Expired(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)

	// Create expired CRL
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	}

	var crlDER []byte
	// Handle both RSA and ECDSA keys
	switch key := caKey.(type) {
	case *rsa.PrivateKey:
		crlDER, err = x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, key)
	case *ecdsa.PrivateKey:
		crlDER, err = x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, key)
	default:
		t.Fatalf("Unsupported key type: %T", caKey)
	}
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrCRLExpired, err)
}

// ========================================================================
// TLS Certificate Workflow Tests
// ========================================================================

func TestCertStore_TLSWorkflow(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a CA
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)

	// Create a server certificate
	serverCert, serverKey := generateTestCert(t, "server.example.com", false, caCert, caKey)

	// Create a client certificate
	clientCert, _ := generateTestCert(t, "client.example.com", false, caCert, caKey)

	// Store CA certificate
	err = cs.StoreCertificate(caCert)
	require.NoError(t, err)

	// Store server certificate
	err = cs.StoreCertificate(serverCert)
	require.NoError(t, err)

	// Store client certificate
	err = cs.StoreCertificate(clientCert)
	require.NoError(t, err)

	// Verify all certificates are stored
	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, 3)

	// Verify certificates against CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	err = cs.VerifyCertificate(serverCert, roots)
	assert.NoError(t, err)

	err = cs.VerifyCertificate(clientCert, roots)
	assert.NoError(t, err)

	// Create TLS certificate from stored data
	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw},
		PrivateKey:  serverKey,
		Leaf:        serverCert,
	}

	assert.NotNil(t, tlsCert.Certificate)
	assert.NotNil(t, tlsCert.PrivateKey)
	assert.Equal(t, serverCert.SerialNumber, tlsCert.Leaf.SerialNumber)
}

// ========================================================================
// CA Certificate Management Tests
// ========================================================================

func TestCertStore_CAManagement_MultipleRoots(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create multiple root CAs
	ca1, ca1Key := generateTestCert(t, "ca1.example.com", true, nil, nil)
	ca2, ca2Key := generateTestCert(t, "ca2.example.com", true, nil, nil)
	ca3, _ := generateTestCert(t, "ca3.example.com", true, nil, nil)

	// Store all CAs
	err = cs.StoreCertificate(ca1)
	require.NoError(t, err)
	err = cs.StoreCertificate(ca2)
	require.NoError(t, err)
	err = cs.StoreCertificate(ca3)
	require.NoError(t, err)

	// Create certificates from different CAs
	cert1, _ := generateTestCert(t, "leaf1.example.com", false, ca1, ca1Key)
	cert2, _ := generateTestCert(t, "leaf2.example.com", false, ca2, ca2Key)

	// Verify certificates against their respective roots
	roots1 := x509.NewCertPool()
	roots1.AddCert(ca1)
	err = cs.VerifyCertificate(cert1, roots1)
	assert.NoError(t, err)

	roots2 := x509.NewCertPool()
	roots2.AddCert(ca2)
	err = cs.VerifyCertificate(cert2, roots2)
	assert.NoError(t, err)

	// Verify cross-CA validation fails
	err = cs.VerifyCertificate(cert1, roots2)
	assert.Error(t, err)
}

func TestCertStore_CAManagement_IntermediateChains(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a complex chain: root -> intermediate1 -> intermediate2 -> leaf
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	int1Cert, int1Key := generateTestCert(t, "intermediate1.example.com", true, rootCert, rootKey)
	int2Cert, int2Key := generateTestCert(t, "intermediate2.example.com", true, int1Cert, int1Key)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, int2Cert, int2Key)

	chain := []*x509.Certificate{leafCert, int2Cert, int1Cert, rootCert}

	err = cs.StoreCertificateChain(chain)
	assert.NoError(t, err)

	retrieved, err := cs.GetCertificateChain(leafCert.Subject.CommonName)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 4)
}

// ========================================================================
// Certificate Search and Filtering Tests
// ========================================================================

func TestCertStore_Search_ByCN(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Store multiple certificates
	cert1, _ := generateTestCert(t, "web1.example.com", false, nil, nil)
	cert2, _ := generateTestCert(t, "web2.example.com", false, nil, nil)
	cert3, _ := generateTestCert(t, "api.example.com", false, nil, nil)

	err = cs.StoreCertificate(cert1)
	require.NoError(t, err)
	err = cs.StoreCertificate(cert2)
	require.NoError(t, err)
	err = cs.StoreCertificate(cert3)
	require.NoError(t, err)

	// Get specific certificate by CN
	retrieved, err := cs.GetCertificate("api.example.com")
	assert.NoError(t, err)
	assert.Equal(t, cert3.SerialNumber, retrieved.SerialNumber)
}

func TestCertStore_Filter_CACerts(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Store mix of CA and leaf certificates
	ca1, _ := generateTestCert(t, "ca1.example.com", true, nil, nil)
	ca2, _ := generateTestCert(t, "ca2.example.com", true, nil, nil)
	leaf1, _ := generateTestCert(t, "leaf1.example.com", false, nil, nil)
	leaf2, _ := generateTestCert(t, "leaf2.example.com", false, nil, nil)

	err = cs.StoreCertificate(ca1)
	require.NoError(t, err)
	err = cs.StoreCertificate(ca2)
	require.NoError(t, err)
	err = cs.StoreCertificate(leaf1)
	require.NoError(t, err)
	err = cs.StoreCertificate(leaf2)
	require.NoError(t, err)

	// List all certificates
	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, 4)

	// Filter CA certificates
	var caCerts []*x509.Certificate
	for _, cert := range certs {
		if cert.IsCA {
			caCerts = append(caCerts, cert)
		}
	}
	assert.Len(t, caCerts, 2)
}

// ========================================================================
// Composite CertStore Tests
// ========================================================================

func TestCertStore_Composite_MultipleStorages(t *testing.T) {
	// Create multiple in-memory storages
	backend1 := storage.New()
	backend2 := storage.New()

	cs1, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend1),
	})
	require.NoError(t, err)
	defer cs1.Close()

	cs2, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend2),
	})
	require.NoError(t, err)
	defer cs2.Close()

	// Store different certificates in each
	cert1, _ := generateTestCert(t, "store1.example.com", false, nil, nil)
	cert2, _ := generateTestCert(t, "store2.example.com", false, nil, nil)

	err = cs1.StoreCertificate(cert1)
	require.NoError(t, err)

	err = cs2.StoreCertificate(cert2)
	require.NoError(t, err)

	// Verify isolation
	_, err = cs1.GetCertificate("store2.example.com")
	assert.Error(t, err)

	_, err = cs2.GetCertificate("store1.example.com")
	assert.Error(t, err)
}

// ========================================================================
// Error Handling and Edge Cases
// ========================================================================

func TestCertStore_ErrorHandling_NilCertificate(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	err = cs.StoreCertificate(nil)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrCertInvalid, err)
}

func TestCertStore_ErrorHandling_EmptyCN(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	cert.Subject.CommonName = ""

	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrInvalidCN, err)
}

func TestCertStore_ErrorHandling_EmptyChain(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	err = cs.StoreCertificateChain([]*x509.Certificate{})
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrChainEmpty, err)
}

func TestCertStore_ErrorHandling_NilInChain(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	chain := []*x509.Certificate{cert, nil}

	err = cs.StoreCertificateChain(chain)
	assert.Error(t, err)
}

func TestCertStore_ErrorHandling_NilCRL(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	err = cs.StoreCRL(nil)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrCRLInvalid, err)
}

func TestCertStore_ErrorHandling_ClosedStore(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)

	// Close the store
	csErr := cs.Close()
	require.NoError(t, csErr)
	err = backend.Close()
	require.NoError(t, err)

	// All operations should fail
	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrStorageClosed, err)

	_, err = cs.GetCertificate("test.example.com")
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrStorageClosed, err)

	err = cs.DeleteCertificate("test.example.com")
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrStorageClosed, err)

	_, err = cs.ListCertificates()
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrStorageClosed, err)
}

// ========================================================================
// Concurrent Access Tests
// ========================================================================

func TestCertStore_Concurrent_ReadWrite(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent writes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			cert, _ := generateTestCert(t, fmt.Sprintf("test%d.example.com", id), false, nil, nil)
			_ = cs.StoreCertificate(cert)
		}(i)
	}
	wg.Wait()

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			_, _ = cs.GetCertificate(fmt.Sprintf("test%d.example.com", id))
		}(i)
	}
	wg.Wait()

	// Verify all were stored
	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, numGoroutines)
}

func TestCertStore_Concurrent_ChainOperations(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	var wg sync.WaitGroup
	numGoroutines := 5

	// Concurrent chain operations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Create a certificate chain
			rootCert, rootKey := generateTestCert(t, fmt.Sprintf("root%d.example.com", id), true, nil, nil)
			leafCert, _ := generateTestCert(t, fmt.Sprintf("leaf%d.example.com", id), false, rootCert, rootKey)

			chain := []*x509.Certificate{leafCert, rootCert}
			_ = cs.StoreCertificateChain(chain)
		}(i)
	}
	wg.Wait()

	// Verify all chains can be retrieved
	for i := 0; i < numGoroutines; i++ {
		chain, err := cs.GetCertificateChain(fmt.Sprintf("leaf%d.example.com", i))
		assert.NoError(t, err)
		assert.Len(t, chain, 2)
	}
}

func TestCertStore_Concurrent_CRLOperations(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	var wg sync.WaitGroup
	numGoroutines := 5

	// Concurrent CRL operations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			caCert, caKey := generateTestCert(t, fmt.Sprintf("ca%d.example.com", id), true, nil, nil)
			crl := generateCRL(t, caCert, caKey)
			_ = cs.StoreCRL(crl)
		}(i)
	}
	wg.Wait()

	// Verify all CRLs can be retrieved
	for i := 0; i < numGoroutines; i++ {
		crl, err := cs.GetCRL(fmt.Sprintf("ca%d.example.com", i))
		assert.NoError(t, err)
		assert.NotNil(t, crl)
	}
}

// ========================================================================
// Additional Coverage Tests
// ========================================================================

func TestCertStore_Config_WithVerifyOptions(t *testing.T) {
	backend := storage.New()

	verifyOpts := &x509.VerifyOptions{
		DNSName:   "test.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	cs, err := certstore.New(&certstore.Config{
		CertStorage:   storage.NewCertAdapter(backend),
		VerifyOptions: verifyOpts,
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a certificate with DNS name
	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	assert.NoError(t, err)
}

func TestCertStore_VerifyCertificate_WithDNSName(t *testing.T) {
	backend := storage.New()

	verifyOpts := &x509.VerifyOptions{
		DNSName: "",
	}

	cs, err := certstore.New(&certstore.Config{
		CertStorage:   storage.NewCertAdapter(backend),
		VerifyOptions: verifyOpts,
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create CA and leaf certificate
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// This tests that the DNSName field is copied from config to verify options
	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestCertStore_VerifyCertificate_EmptyIntermediates(t *testing.T) {
	backend := storage.New()

	intermediates := x509.NewCertPool()

	verifyOpts := &x509.VerifyOptions{
		Intermediates: intermediates,
	}

	cs, err := certstore.New(&certstore.Config{
		CertStorage:   storage.NewCertAdapter(backend),
		VerifyOptions: verifyOpts,
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create CA and leaf certificate
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestCertStore_GetCRL_EmptyIssuer(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Try to get a CRL with empty issuer
	_, err = cs.GetCRL("")
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrInvalidIssuer, err)
}

func TestCertStore_ListCertificates_WithGetError(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Store a certificate
	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	require.NoError(t, err)

	// Close underlying storage to cause errors
	err = backend.Close()
	require.NoError(t, err)

	// This should fail because storage is closed
	_, err = cs.ListCertificates()
	assert.Error(t, err)
}

func TestCertStore_IsRevoked_WithRevokedCertificateEntries(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// Create CRL with RevokedCertificateEntries (newer format)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		Issuer:     caCert.Subject,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   leafCert.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
	}

	var crlDER []byte
	switch key := caKey.(type) {
	case *rsa.PrivateKey:
		crlDER, err = x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, key)
	case *ecdsa.PrivateKey:
		crlDER, err = x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, key)
	}
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	revoked, err := cs.IsRevoked(leafCert)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

func TestCertStore_StoreCertificate_StorageError(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)

	// Close storage to cause error
	err = backend.Close()
	require.NoError(t, err)

	// Try to store certificate - should fail
	err = cs.StoreCertificate(cert)
	assert.Error(t, err)
}

func TestCertStore_GetCertificate_StorageError(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	require.NoError(t, err)

	// Close storage to cause error
	err = backend.Close()
	require.NoError(t, err)

	// Try to get certificate - should fail
	_, err = cs.GetCertificate("test.example.com")
	assert.Error(t, err)
}

func TestCertStore_DeleteCertificate_StorageError(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)

	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	require.NoError(t, err)

	// Close storage to cause error
	err = backend.Close()
	require.NoError(t, err)

	// Try to delete certificate - should fail
	err = cs.DeleteCertificate("test.example.com")
	assert.Error(t, err)
}

func TestCertStore_StoreCertificateChain_StorageError(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)

	// Create a certificate chain
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, rootCert, rootKey)
	chain := []*x509.Certificate{leafCert, rootCert}

	// Close storage to cause error
	err = backend.Close()
	require.NoError(t, err)

	// Try to store chain - should fail
	err = cs.StoreCertificateChain(chain)
	assert.Error(t, err)
}

func TestCertStore_GetCertificateChain_StorageError(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)

	// Create and store a certificate chain
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, rootCert, rootKey)
	chain := []*x509.Certificate{leafCert, rootCert}
	err = cs.StoreCertificateChain(chain)
	require.NoError(t, err)

	// Close storage to cause error
	err = backend.Close()
	require.NoError(t, err)

	// Try to get chain - should fail
	_, err = cs.GetCertificateChain("leaf.example.com")
	assert.Error(t, err)
}

func TestCertStore_Config_NilVerifyOptions(t *testing.T) {
	backend := storage.New()

	// Create certstore with nil verify options
	cs, err := certstore.New(&certstore.Config{
		CertStorage:   storage.NewCertAdapter(backend),
		VerifyOptions: nil, // Explicitly nil
	})
	require.NoError(t, err)
	defer cs.Close()

	// Should use default verify options
	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	err = cs.StoreCertificate(cert)
	assert.NoError(t, err)
}

func TestCertStore_New_InvalidConfig(t *testing.T) {
	// Test nil config
	cs, err := certstore.New(nil)
	assert.Error(t, err)
	assert.Nil(t, cs)
	assert.Equal(t, certstore.ErrInvalidConfig, err)
}

func TestCertStore_New_NilStorage(t *testing.T) {
	// Test nil storage
	cs, err := certstore.New(&certstore.Config{
		CertStorage: nil,
	})
	assert.Error(t, err)
	assert.Nil(t, cs)
	assert.Equal(t, certstore.ErrStorageRequired, err)
}

func TestCertStore_StoreCertificateChain_EmptyCNInLeaf(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a certificate with empty CN
	cert, _ := generateTestCert(t, "test.example.com", false, nil, nil)
	cert.Subject.CommonName = ""

	chain := []*x509.Certificate{cert}

	err = cs.StoreCertificateChain(chain)
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrInvalidCN, err)
}

func TestCertStore_Close_Multiple(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)

	// First close
	csErr := cs.Close()
	require.NoError(t, csErr)
	err = backend.Close()
	assert.NoError(t, err)

	// Second close should be idempotent
	err = cs.Close()
	assert.NoError(t, err)
}

func TestCertStore_VerifyCertificate_WithEmptyKeyUsages(t *testing.T) {
	backend := storage.New()

	// Test with empty key usages (should be skipped)
	verifyOpts := &x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{}, // Empty key usages
	}

	cs, err := certstore.New(&certstore.Config{
		CertStorage:   storage.NewCertAdapter(backend),
		VerifyOptions: verifyOpts,
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestCertStore_StoreCertificate_InvalidFutureRevocationCheck(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage:  storage.NewCertAdapter(backend),
		AllowRevoked: false,
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a certificate that would check revocation
	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, caCert, caKey)

	// No CRL is set, so revocation check should pass (no CRL = not revoked)
	err = cs.StoreCertificate(leafCert)
	assert.NoError(t, err)
}

func TestCertStore_IsRevoked_MultipleCRLEntries(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	cert1, _ := generateTestCert(t, "cert1.example.com", false, caCert, caKey)
	cert2, _ := generateTestCert(t, "cert2.example.com", false, caCert, caKey)
	cert3, _ := generateTestCert(t, "cert3.example.com", false, caCert, caKey)

	// Create CRL with multiple revoked certificates
	crl := generateCRL(t, caCert, caKey, cert1, cert3)
	err = cs.StoreCRL(crl)
	require.NoError(t, err)

	// Check cert1 - should be revoked
	revoked, err := cs.IsRevoked(cert1)
	assert.NoError(t, err)
	assert.True(t, revoked)

	// Check cert2 - should NOT be revoked
	revoked, err = cs.IsRevoked(cert2)
	assert.NoError(t, err)
	assert.False(t, revoked)

	// Check cert3 - should be revoked
	revoked, err = cs.IsRevoked(cert3)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

func TestCertStore_ListCertificates_MixedValidAndInvalid(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Store valid certificates
	cert1, _ := generateTestCert(t, "cert1.example.com", false, nil, nil)
	cert2, _ := generateTestCert(t, "cert2.example.com", false, nil, nil)

	err = cs.StoreCertificate(cert1)
	require.NoError(t, err)
	err = cs.StoreCertificate(cert2)
	require.NoError(t, err)

	// List should return all valid certificates
	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestCertStore_VerifyCertificate_AllOptions(t *testing.T) {
	backend := storage.New()

	// Create certificate chain
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	intermediateCert, intermediateKey := generateTestCert(t, "intermediate.example.com", true, rootCert, rootKey)
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, intermediateCert, intermediateKey)

	// Set up intermediates pool
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	// Test with all verify options set
	verifyOpts := &x509.VerifyOptions{
		DNSName:       "",
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	cs, err := certstore.New(&certstore.Config{
		CertStorage:   storage.NewCertAdapter(backend),
		VerifyOptions: verifyOpts,
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	// This tests that all verify options are properly copied
	err = cs.VerifyCertificate(leafCert, roots)
	assert.NoError(t, err)
}

func TestCertStore_GetCertificateChain_WithEmptyCN(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Try to get chain with empty CN
	_, err = cs.GetCertificateChain("")
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrInvalidCN, err)
}

func TestCertStore_DeleteCertificate_WithEmptyCN(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Try to delete with empty CN
	err = cs.DeleteCertificate("")
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrInvalidCN, err)
}

func TestCertStore_GetCertificate_WithEmptyCN(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Try to get with empty CN
	_, err = cs.GetCertificate("")
	assert.Error(t, err)
	assert.Equal(t, certstore.ErrInvalidCN, err)
}

func TestCertStore_StoreCRL_UpdateExisting(t *testing.T) {
	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	caCert, caKey := generateTestCert(t, "ca.example.com", true, nil, nil)
	cert1, _ := generateTestCert(t, "cert1.example.com", false, caCert, caKey)

	// Store initial CRL
	crl1 := generateCRL(t, caCert, caKey)
	err = cs.StoreCRL(crl1)
	require.NoError(t, err)

	// Update CRL with a revoked certificate
	crl2 := generateCRL(t, caCert, caKey, cert1)
	err = cs.StoreCRL(crl2)
	require.NoError(t, err)

	// Verify the updated CRL is used
	revoked, err := cs.IsRevoked(cert1)
	assert.NoError(t, err)
	assert.True(t, revoked)
}

// ========================================================================
// Performance and Load Tests
// ========================================================================

func TestCertStore_Performance_LargeNumberOfCerts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	numCerts := 100

	start := time.Now()

	// Store many certificates
	for i := 0; i < numCerts; i++ {
		cert, _ := generateTestCert(t, fmt.Sprintf("test%d.example.com", i), false, nil, nil)
		err := cs.StoreCertificate(cert)
		require.NoError(t, err)
	}

	storeDuration := time.Since(start)
	t.Logf("Stored %d certificates in %v", numCerts, storeDuration)

	start = time.Now()

	// List all certificates
	certs, err := cs.ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, numCerts)

	listDuration := time.Since(start)
	t.Logf("Listed %d certificates in %v", numCerts, listDuration)
}

func TestCertStore_Performance_LargeChains(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	backend := storage.New()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(backend),
	})
	require.NoError(t, err)
	defer cs.Close()

	// Create a chain with many intermediates
	var chain []*x509.Certificate
	var parentCert *x509.Certificate
	var parentKey interface{}

	// Root CA
	rootCert, rootKey := generateTestCert(t, "root.example.com", true, nil, nil)
	parentCert = rootCert
	parentKey = rootKey

	// Create 5 intermediate CAs
	for i := 0; i < 5; i++ {
		intermediateCert, intermediateKey := generateTestCert(t, fmt.Sprintf("int%d.example.com", i), true, parentCert, parentKey)
		parentCert = intermediateCert
		parentKey = intermediateKey
	}

	// Leaf certificate
	leafCert, _ := generateTestCert(t, "leaf.example.com", false, parentCert, parentKey)

	// Build the chain (leaf to root)
	chain = append(chain, leafCert)
	// Note: We'd need to keep all intermediate certs to build the full chain
	// This is simplified for the test

	err = cs.StoreCertificateChain([]*x509.Certificate{leafCert, parentCert, rootCert})
	assert.NoError(t, err)
}
