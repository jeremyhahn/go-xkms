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

//go:build local || integration

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/require"
)

// TestCAConfig creates a minimal CA configuration for testing
func TestCAConfig() ca.Config {
	return ca.Config{
		Identity: []ca.Identity{
			{
				Subject: ca.Subject{
					CommonName:   "Test Root CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        10, // 10 years for root CA
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P256",
				KeystoreType: "software",
				IsRoot:       true,
			},
			{
				Subject: ca.Subject{
					CommonName:   "Test Intermediate CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        5, // 5 years for intermediate CA
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P256",
				KeystoreType: "software",
				ParentCA:     "Test Root CA",
			},
		},
		SelectedCA:                1,   // Use intermediate CA for issuing
		DefaultValidityPeriod:     365, // 365 days
		DefaultKeyAlgorithm:       x509.ECDSA,
		DefaultSignatureAlgorithm: x509.ECDSAWithSHA256,
		DefaultHash:               crypto.SHA256,
		LazyInitialization:        false,
	}
}

// NewTestCA creates a new CA instance for testing with in-memory storage
func NewTestCA(t *testing.T) (*ca.CA, func()) {
	// Reset any previous facade state to ensure clean test isolation
	xkmssdk.ServiceReset()

	// Create in-memory storage backends
	keyStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorageBackend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	// Create software backend for key storage
	softwareBackend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	// Create xkms (keystore) with software backend
	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend,
		CertStorage: certStorageBackend,
	})
	require.NoError(t, err)

	// Initialize the XKMSFacade with the software backend as default
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software": keyStore,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	// Create cert adapter and certstore for CA
	certAdapter := xkmssdk.NewStorageCertAdapter(certStorageBackend)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	// Create blob store using go-objstore
	blobStore := local.New()
	err = blobStore.Configure(map[string]string{"path": t.TempDir()})
	require.NoError(t, err)

	// Create CA (gets KeyStore from facade based on config.Identity[0].KeystoreType)
	config := TestCAConfig()
	caInstance, err := ca.New(config, certStore, blobStore)
	require.NoError(t, err)

	cleanup := func() {
		xkmssdk.ServiceReset()
	}

	return caInstance, cleanup
}

// GenerateTestCertificate creates a test certificate signed by the provided signer
func GenerateTestCertificate(t *testing.T, cn string, signer crypto.Signer, caCert *x509.Certificate) *x509.Certificate {
	// Generate a new key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Self-signed if no CA cert provided
	if caCert == nil {
		caCert = template
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// GenerateTestCSR generates a Certificate Signing Request for testing
func GenerateTestCSR(t *testing.T, cn string, keyAlgo x509.PublicKeyAlgorithm) []byte {
	var privateKey crypto.Signer
	var err error
	var sigAlgo x509.SignatureAlgorithm

	switch keyAlgo {
	case x509.RSA:
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		sigAlgo = x509.SHA256WithRSA
	case x509.ECDSA:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sigAlgo = x509.ECDSAWithSHA256
	default:
		t.Fatalf("Unsupported key algorithm: %v", keyAlgo)
	}
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
			Country:      []string{"US"},
		},
		SignatureAlgorithm: sigAlgo,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)

	// Encode to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM
}

// MockTPMData provides mock TPM attestation data for testing
type MockTPMData struct {
	Quote     []byte
	Signature []byte
	PCRs      map[uint][]byte
	EventLog  []byte
}

// NewMockTPMData creates mock TPM attestation data
func NewMockTPMData() *MockTPMData {
	return &MockTPMData{
		Quote:     []byte("mock-tpm-quote-data"),
		Signature: []byte("mock-tpm-signature"),
		PCRs: map[uint][]byte{
			0:  []byte("mock-pcr-0"),
			7:  []byte("mock-pcr-7"),
			14: []byte("mock-pcr-14"),
		},
		EventLog: []byte("mock-event-log-data"),
	}
}

// TestCertificateRequest creates a standard certificate request for testing
func TestCertificateRequest(cn string) *ca.CertificateRequest {
	return &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   cn,
			Organization: "Test Organization",
			Country:      "US",
		},
		Valid:       365,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

// TestCACertificateRequest creates a CA certificate request for testing
func TestCACertificateRequest(cn string, isRoot bool) *ca.CertificateRequest {
	maxPathLen := 1
	if isRoot {
		maxPathLen = 2
	}

	return &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   cn,
			Organization: "Test Organization",
			Country:      "US",
		},
		Valid:      365,
		IsCA:       true,
		MaxPathLen: maxPathLen,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// TestEKCertificateRequest creates an Endorsement Key certificate request
func TestEKCertificateRequest(cn string) *ca.CertificateRequest {
	return &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   cn,
			Organization: "TPM Manufacturer",
			Country:      "US",
		},
		Valid:    0, // Indefinite validity for EK certs
		KeyUsage: x509.KeyUsageKeyEncipherment,
	}
}

// TestAKCertificateRequest creates an Attestation Key certificate request
func TestAKCertificateRequest(cn string) *ca.CertificateRequest {
	return &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   cn,
			Organization: "TPM Owner",
			Country:      "US",
		},
		Valid:    0, // Indefinite validity for AK certs
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
}

// GenerateTestKeyPair generates a test key pair for various algorithms
func GenerateTestKeyPair(t *testing.T, algo x509.PublicKeyAlgorithm) crypto.Signer {
	var signer crypto.Signer
	var err error

	switch algo {
	case x509.RSA:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case x509.ECDSA:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		t.Fatalf("Unsupported algorithm: %v", algo)
	}

	require.NoError(t, err)
	return signer
}

// AssertCertificateValid performs common validation checks on a certificate
func AssertCertificateValid(t *testing.T, cert *x509.Certificate, expectedCN string) {
	require.NotNil(t, cert, "Certificate should not be nil")
	require.Equal(t, expectedCN, cert.Subject.CommonName, "Common name should match")
	require.True(t, time.Now().After(cert.NotBefore), "Certificate should be valid now (NotBefore)")
	require.True(t, time.Now().Before(cert.NotAfter), "Certificate should be valid now (NotAfter)")
	require.NotNil(t, cert.SerialNumber, "Serial number should not be nil")
	require.True(t, cert.SerialNumber.Cmp(big.NewInt(0)) > 0, "Serial number should be positive")
}
