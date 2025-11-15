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

// Package main demonstrates issuing certificates signed by a CA.
package main

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
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
	// Create a temporary directory for certificates
	tmpDir := filepath.Join(os.TempDir(), "keystore-issue-cert")
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

	fmt.Println("=== Certificate Issuance Examples ===")

	// Step 1: Create CA first
	fmt.Println("1. Creating Certificate Authority...")
	caCert, caPrivKey := createCA(ks)
	fmt.Printf("   ✓ CA created: %s\n\n", caCert.Subject.CommonName)

	// Step 2: Issue server certificate
	fmt.Println("2. Issuing server certificate...")
	serverCert := issueServerCertificate(ks, caCert, caPrivKey, "server.example.com")
	fmt.Printf("   ✓ Server certificate issued for: server.example.com\n\n")

	// Step 3: Issue client certificate
	fmt.Println("3. Issuing client certificate...")
	clientCert := issueClientCertificate(ks, caCert, caPrivKey, "client@example.com")
	fmt.Printf("   ✓ Client certificate issued for: client@example.com\n\n")

	// Step 4: Issue wildcard certificate
	fmt.Println("4. Issuing wildcard certificate...")
	wildcardCert := issueWildcardCertificate(ks, caCert, caPrivKey, "*.example.com")
	fmt.Printf("   ✓ Wildcard certificate issued for: *.example.com\n\n")

	// Step 5: Verify server certificate chain
	fmt.Println("5. Verifying server certificate...")
	if err := verifyCertificate(serverCert, caCert); err != nil {
		log.Fatalf("Server certificate verification failed: %v", err)
	}
	fmt.Printf("   ✓ Server certificate verified\n\n")

	// Step 6: Verify client certificate chain
	fmt.Println("6. Verifying client certificate...")
	if err := verifyCertificate(clientCert, caCert); err != nil {
		log.Fatalf("Client certificate verification failed: %v", err)
	}
	fmt.Printf("   ✓ Client certificate verified\n\n")

	// Step 7: Export certificates to PEM files
	fmt.Println("7. Exporting certificates to PEM files...")
	exportCertToPEM(filepath.Join(tmpDir, "server.crt"), serverCert)
	exportCertToPEM(filepath.Join(tmpDir, "client.crt"), clientCert)
	exportCertToPEM(filepath.Join(tmpDir, "wildcard.crt"), wildcardCert)
	fmt.Printf("   ✓ Certificates exported\n\n")

	// Step 8: Display certificate information
	fmt.Println("8. Certificate Summary:")
	displayCertInfo("Server", serverCert)
	displayCertInfo("Client", clientCert)
	displayCertInfo("Wildcard", wildcardCert)

	fmt.Println("\n✓ All certificates issued and verified successfully!")
	fmt.Printf("\nCertificates stored in: %s\n", tmpDir)
}

// createCA creates a Certificate Authority
func createCA(ks keychain.KeyStore) (*x509.Certificate, crypto.Signer) {
	// Generate CA key
	caKeyAttrs := &types.KeyAttributes{
		CN:           "Example Root CA",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}

	_, err := ks.GenerateECDSA(caKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate CA key: %v", err)
	}

	// Get signer for the CA key
	caSigner, err := ks.Signer(caKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to get CA signer: %v", err)
	}

	// Create CA certificate
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
	ks.SaveCert(caKeyAttrs.CN, caCert)

	return caCert, caSigner
}

// issueServerCertificate issues a server certificate
func issueServerCertificate(ks keychain.KeyStore, caCert *x509.Certificate, caSigner crypto.Signer, hostname string) *x509.Certificate {
	// Generate server key
	serverKeyAttrs := &types.KeyAttributes{
		CN:           hostname,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	_, err := ks.GenerateECDSA(serverKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate server key: %v", err)
	}

	// Get signer for the server key
	serverSigner, err := ks.Signer(serverKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to get server signer: %v", err)
	}

	// Create server certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

	serverCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Example Organization"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{hostname},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		serverCertTemplate,
		caCert,
		serverSigner.Public(),
		caSigner,
	)
	if err != nil {
		log.Fatalf("Failed to create server certificate: %v", err)
	}

	serverCert, _ := x509.ParseCertificate(serverCertBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert(hostname, serverCert)

	return serverCert
}

// issueClientCertificate issues a client certificate
func issueClientCertificate(ks keychain.KeyStore, caCert *x509.Certificate, caSigner crypto.Signer, email string) *x509.Certificate {
	// Generate client key
	clientKeyAttrs := &types.KeyAttributes{
		CN:           email,
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

	// Create client certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	clientCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{"Example Organization"},
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{email},
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
	ks.SaveCert(email, clientCert)

	return clientCert
}

// issueWildcardCertificate issues a wildcard certificate
func issueWildcardCertificate(ks keychain.KeyStore, caCert *x509.Certificate, caSigner crypto.Signer, domain string) *x509.Certificate {
	// Generate wildcard key
	wildcardKeyAttrs := &types.KeyAttributes{
		CN:           domain,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	_, err := ks.GenerateECDSA(wildcardKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate wildcard key: %v", err)
	}

	// Get signer for the wildcard key
	wildcardSigner, err := ks.Signer(wildcardKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to get wildcard signer: %v", err)
	}

	// Create wildcard certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	wildcardCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Example Organization"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{domain, "example.com"}, // Wildcard + base domain
	}

	wildcardCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		wildcardCertTemplate,
		caCert,
		wildcardSigner.Public(),
		caSigner,
	)
	if err != nil {
		log.Fatalf("Failed to create wildcard certificate: %v", err)
	}

	wildcardCert, _ := x509.ParseCertificate(wildcardCertBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert(domain, wildcardCert)

	return wildcardCert
}

// verifyCertificate verifies a certificate against the CA
func verifyCertificate(cert, caCert *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := cert.Verify(opts)
	return err
}

// exportCertToPEM exports a certificate to a PEM file
func exportCertToPEM(filename string, cert *x509.Certificate) {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	// #nosec G304 - Example code with controlled file paths
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create file %s: %v", filename, err)
	}
	defer f.Close()

	// #nosec G104 - Example code, error handling omitted for clarity
	pem.Encode(f, pemBlock)
}

// displayCertInfo displays certificate information
func displayCertInfo(name string, cert *x509.Certificate) {
	fmt.Printf("\n   %s Certificate:\n", name)
	fmt.Printf("     Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("     Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Printf("     Serial: %s\n", cert.SerialNumber.String())
	fmt.Printf("     Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	if len(cert.DNSNames) > 0 {
		fmt.Printf("     DNS Names: %v\n", cert.DNSNames)
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("     Email Addresses: %v\n", cert.EmailAddresses)
	}
}
