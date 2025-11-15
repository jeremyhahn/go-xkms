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

// Package main demonstrates creating a TLS server using the keychain.
package main

import (
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
	tmpDir := filepath.Join(os.TempDir(), "keystore-tls-server")
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

	fmt.Println("=== TLS Server Example ===")

	// Step 1: Create CA
	fmt.Println("1. Creating Certificate Authority...")
	caCert, caKey := createCA(ks)
	fmt.Printf("   ✓ CA created\n\n")

	// Step 2: Create server certificate
	fmt.Println("2. Creating server certificate...")
	serverCert := createServerCertificate(ks, caCert, caKey)
	fmt.Printf("   ✓ Server certificate created\n\n")

	// Step 3: Get TLS certificate from keystore
	fmt.Println("3. Loading TLS certificate from keychain...")
	tlsCert, err := ks.GetTLSCertificate("localhost", &types.KeyAttributes{
		CN:           "localhost",
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

	// Step 4: Create TLS configuration
	fmt.Println("4. Configuring TLS server...")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}
	fmt.Printf("   ✓ TLS configuration created\n")
	fmt.Printf("     Minimum TLS version: 1.2\n")
	fmt.Printf("     Cipher suites: %d configured\n\n", len(tlsConfig.CipherSuites))

	// Step 5: Setup HTTP handlers
	fmt.Println("5. Setting up HTTP handlers...")
	mux := http.NewServeMux()

	// Simple handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from TLS server!\n")
		fmt.Fprintf(w, "TLS Version: %s\n", tlsVersionString(r.TLS.Version))
		fmt.Fprintf(w, "Cipher Suite: %s\n", tls.CipherSuiteName(r.TLS.CipherSuite))
		fmt.Fprintf(w, "Server Name: %s\n", r.TLS.ServerName)
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")
	})

	// Certificate info endpoint
	mux.HandleFunc("/cert-info", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Server Certificate Information:\n")
		fmt.Fprintf(w, "  Subject: %s\n", serverCert.Subject.CommonName)
		fmt.Fprintf(w, "  Issuer: %s\n", serverCert.Issuer.CommonName)
		fmt.Fprintf(w, "  Valid From: %s\n", serverCert.NotBefore.Format(time.RFC3339))
		fmt.Fprintf(w, "  Valid Until: %s\n", serverCert.NotAfter.Format(time.RFC3339))
		fmt.Fprintf(w, "  Serial Number: %s\n", serverCert.SerialNumber.String())
	})

	fmt.Printf("   ✓ HTTP handlers configured\n\n")

	// Step 6: Create HTTPS server
	fmt.Println("6. Starting HTTPS server...")
	server := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Println("\n=== Server Information ===")
	fmt.Printf("Server listening on: https://localhost:8443\n")
	fmt.Printf("Available endpoints:\n")
	fmt.Printf("  - https://localhost:8443/\n")
	fmt.Printf("  - https://localhost:8443/health\n")
	fmt.Printf("  - https://localhost:8443/cert-info\n")
	fmt.Println("\nTo test the server (in another terminal):")
	fmt.Printf("  curl -k https://localhost:8443/\n")
	fmt.Printf("  curl -k https://localhost:8443/cert-info\n")
	fmt.Println("\nPress Ctrl+C to stop the server")
	fmt.Println()

	// Start server
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// createCA creates a Certificate Authority
func createCA(ks keychain.KeyStore) (*x509.Certificate, interface{}) {
	keyAttrs := &types.KeyAttributes{
		CN:           "Example Root CA",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}

	caPrivKey, err := ks.GenerateECDSA(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate CA key: %v", err)
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
		caPrivKey.(interface{ Public() interface{} }).Public(),
		caPrivKey,
	)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, _ := x509.ParseCertificate(caCertBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert(keyAttrs.CN, caCert)

	return caCert, caPrivKey
}

// createServerCertificate creates a server certificate
func createServerCertificate(ks keychain.KeyStore, caCert *x509.Certificate, caPrivKey interface{}) *x509.Certificate {
	serverKeyAttrs := &types.KeyAttributes{
		CN:           "localhost",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	serverPrivKey, err := ks.GenerateECDSA(serverKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate server key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serverCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Example Organization"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}

	serverCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		serverCertTemplate,
		caCert,
		serverPrivKey.(interface{ Public() interface{} }).Public(),
		caPrivKey,
	)
	if err != nil {
		log.Fatalf("Failed to create server certificate: %v", err)
	}

	serverCert, _ := x509.ParseCertificate(serverCertBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert("localhost", serverCert)

	return serverCert
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

// testServer performs a simple test of the server
func testServer() {
	time.Sleep(2 * time.Second) // Wait for server to start

	// Create HTTP client with insecure TLS (for testing only)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// #nosec G402 - InsecureSkipVerify is intentionally used in this example
				// to demonstrate self-signed certificates. In production, always verify certificates!
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		log.Printf("Test request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Test response:\n%s\n", body)
}
