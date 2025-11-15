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

package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// TestCA represents a test Certificate Authority
type TestCA struct {
	// Cert is the CA certificate
	Cert *x509.Certificate
	// Key is the CA private key
	Key *ecdsa.PrivateKey
	// CertPEM is the PEM-encoded CA certificate
	CertPEM []byte
	// KeyPEM is the PEM-encoded CA private key
	KeyPEM []byte
}

// TestCertificate represents a generated test certificate
type TestCertificate struct {
	// Cert is the X.509 certificate
	Cert *x509.Certificate
	// Key is the private key
	Key *ecdsa.PrivateKey
	// CertPEM is the PEM-encoded certificate
	CertPEM []byte
	// KeyPEM is the PEM-encoded private key
	KeyPEM []byte
	// TLSCert is the tls.Certificate ready for use
	TLSCert tls.Certificate
}

// GenerateTestCA generates a test Certificate Authority (CA) for use in tests.
// The CA can sign both server and client certificates.
//
// Returns:
//   - *TestCA: The generated CA with certificate, key, and PEM-encoded data
//   - error: Any error encountered during generation
//
// Example:
//
//	ca, err := testutil.GenerateTestCA()
//	if err != nil {
//	    t.Fatalf("Failed to generate CA: %v", err)
//	}
func GenerateTestCA() (*TestCA, error) {
	// Generate private key for CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour) // Valid for 24 hours

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Encode to PEM
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA key: %w", err)
	}

	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: caKeyBytes,
	})

	return &TestCA{
		Cert:    caCert,
		Key:     caKey,
		CertPEM: caCertPEM,
		KeyPEM:  caKeyPEM,
	}, nil
}

// GenerateTestServerCert generates a server certificate signed by the given CA.
// The certificate is configured for server authentication (TLS server).
//
// Parameters:
//   - ca: The Certificate Authority to sign the certificate
//   - dnsNames: DNS names to include in the certificate (e.g., "localhost", "example.com")
//
// Returns:
//   - *TestCertificate: The generated server certificate
//   - error: Any error encountered during generation
//
// Example:
//
//	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
//	if err != nil {
//	    t.Fatalf("Failed to generate server cert: %v", err)
//	}
func GenerateTestServerCert(ca *TestCA, dnsNames ...string) (*TestCertificate, error) {
	// Generate private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   dnsNames[0],
		},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Create tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &TestCertificate{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		TLSCert: tlsCert,
	}, nil
}

// GenerateTestClientCert generates a client certificate signed by the given CA.
// The certificate is configured for client authentication (TLS client).
//
// Parameters:
//   - ca: The Certificate Authority to sign the certificate
//   - commonName: The common name (CN) for the client certificate (e.g., "test-client")
//
// Returns:
//   - *TestCertificate: The generated client certificate
//   - error: Any error encountered during generation
//
// Example:
//
//	clientCert, err := testutil.GenerateTestClientCert(ca, "test-client")
//	if err != nil {
//	    t.Fatalf("Failed to generate client cert: %v", err)
//	}
func GenerateTestClientCert(ca *TestCA, commonName string) (*TestCertificate, error) {
	// Generate private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	if commonName == "" {
		commonName = "test-client"
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Create tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &TestCertificate{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		TLSCert: tlsCert,
	}, nil
}
