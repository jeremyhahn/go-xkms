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

// Package main demonstrates creating a TLS client using the keychain.
package main

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	// Create a temporary directory
	tmpDir := filepath.Join(os.TempDir(), "keystore-tls-client")
	defer os.RemoveAll(tmpDir)

	// Initialize storage backend
	storage, err := file.New(tmpDir)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	// Create PKCS#8 backend
	pkcs8Backend, err := pkcs8.NewBackend(&pkcs8.Config{
		KeyStorage: storage,
	})
	if err != nil {
		log.Fatalf("Failed to create PKCS#8 backend: %v", err)
	}
	defer pkcs8Backend.Close()

	// Create keystore instance
	ks, err := keychain.New(&keychain.Config{
		Backend:     pkcs8Backend,
		CertStorage: storage,
	})
	if err != nil {
		log.Fatalf("Failed to create keystore: %v", err)
	}
	defer ks.Close()

	fmt.Println("=== TLS Client Example ===")

	// Step 1: Create CA (shared with server)
	fmt.Println("1. Creating Certificate Authority...")
	caCert, caKey := createCA(ks)
	fmt.Printf("   ✓ CA created\n\n")

	// Step 2: Create client certificate
	fmt.Println("2. Creating client certificate...")
	clientCert := createClientCertificate(ks, caCert, caKey)
	fmt.Printf("   ✓ Client certificate created\n\n")

	// Step 3: Get TLS certificate from keystore
	fmt.Println("3. Loading TLS certificate from keychain...")
	tlsCert, err := ks.GetTLSCertificate("client@example.com", &types.KeyAttributes{
		CN:           "client@example.com",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	})
	if err != nil {
		log.Fatalf("Failed to get TLS certificate: %v", err)
	}
	fmt.Printf("   ✓ TLS certificate loaded\n\n")

	// Step 4: Create root CA pool
	fmt.Println("4. Creating trusted CA pool...")
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)
	fmt.Printf("   ✓ CA pool created with root certificate\n\n")

	// Step 5: Create TLS configuration
	fmt.Println("5. Configuring TLS client...")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	fmt.Printf("   ✓ TLS configuration created\n\n")

	// Step 6: Create HTTP client
	fmt.Println("6. Creating HTTPS client...")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}
	fmt.Printf("   ✓ HTTPS client created\n\n")

	// Step 7: Make requests to demonstrate different scenarios
	fmt.Println("=== Making Test Requests ===")

	// Example 1: Simple GET request
	fmt.Println("1. Making GET request to https://example.com...")
	demoRequest(client, "https://example.com")

	// Example 2: POST request with data
	fmt.Println("\n2. Making POST request (simulated)...")
	fmt.Printf("   Note: POST requests work the same way as GET\n")
	fmt.Printf("   The client certificate is automatically presented\n")

	// Example 3: Display connection state
	fmt.Println("\n3. Displaying TLS connection information...")
	displayConnectionInfo(tlsConfig, clientCert)

	// Example 4: Demonstrate certificate verification
	fmt.Println("\n4. Demonstrating certificate verification...")
	demonstrateCertVerification(clientCert, caCert)

	fmt.Println("\n✓ TLS client examples completed successfully!")
	fmt.Printf("\nClient files stored in: %s\n", tmpDir)
}

// createCA creates a Certificate Authority
func createCA(ks keychain.KeyStore) (*x509.Certificate, crypto.Signer) {
	keyAttrs := &types.KeyAttributes{
		CN:           "Example Root CA",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}

	_, err := ks.GenerateECDSA(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate CA key: %v", err)
	}

	// Get signer for the CA key
	caSigner, err := ks.Signer(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to get CA signer: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	caCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Example Root CA",
			Organization: []string{"Example Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		caCertTemplate,
		caCertTemplate,
		caSigner.Public(),
		caSigner,
	)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, _ := x509.ParseCertificate(caCertBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert(keyAttrs.CN, caCert)

	return caCert, caSigner
}

// createClientCertificate creates a client certificate
func createClientCertificate(ks keychain.KeyStore, caCert *x509.Certificate, caSigner crypto.Signer) *x509.Certificate {
	clientKeyAttrs := &types.KeyAttributes{
		CN:           "client@example.com",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	_, err := ks.GenerateECDSA(clientKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate client key: %v", err)
	}

	// Get signer for the client key
	clientSigner, err := ks.Signer(clientKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to get client signer: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	clientCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "client@example.com",
			Organization: []string{"Example Organization"},
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{"client@example.com"},
	}

	clientCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		clientCertTemplate,
		caCert,
		clientSigner.Public(),
		caSigner,
	)
	if err != nil {
		log.Fatalf("Failed to create client certificate: %v", err)
	}

	clientCert, _ := x509.ParseCertificate(clientCertBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert("client@example.com", clientCert)

	return clientCert
}

// demoRequest makes a demo request and displays the response
func demoRequest(client *http.Client, url string) {
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("   Request to %s:\n", url)
		fmt.Printf("   Status: Failed (%v)\n", err)
		fmt.Printf("   Note: This is expected as we're using a self-signed CA\n")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("   Request to %s:\n", url)
	fmt.Printf("   Status: %s\n", resp.Status)
	fmt.Printf("   Body length: %d bytes\n", len(body))

	if resp.TLS != nil {
		fmt.Printf("   TLS Version: %s\n", tlsVersionString(resp.TLS.Version))
		fmt.Printf("   Cipher Suite: %s\n", tls.CipherSuiteName(resp.TLS.CipherSuite))
	}
}

// displayConnectionInfo displays TLS connection information
func displayConnectionInfo(config *tls.Config, cert *x509.Certificate) {
	fmt.Println("   TLS Configuration:")
	fmt.Printf("     Minimum TLS Version: %s\n", tlsVersionString(config.MinVersion))
	fmt.Printf("     Cipher Suites: %d configured\n", len(config.CipherSuites))
	fmt.Printf("     Client Certificates: %d loaded\n", len(config.Certificates))

	fmt.Println("\n   Client Certificate:")
	fmt.Printf("     Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("     Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Printf("     Valid From: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("     Valid Until: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("     Extended Key Usage: %v\n", cert.ExtKeyUsage)
}

// demonstrateCertVerification demonstrates certificate verification
func demonstrateCertVerification(cert, caCert *x509.Certificate) {
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		fmt.Printf("   ✗ Certificate verification failed: %v\n", err)
		return
	}

	fmt.Printf("   ✓ Certificate verified successfully\n")
	fmt.Printf("     Verified %d chain(s)\n", len(chains))
	for i, chain := range chains {
		fmt.Printf("     Chain %d length: %d certificates\n", i+1, len(chain))
	}
}

// tlsVersionString converts TLS version to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
