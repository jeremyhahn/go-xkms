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

//go:build pkcs11

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

// Example demonstrating PKCS#11 hardware-backed certificate storage.
//
// This example shows:
// - Creating a PKCS#11 backend with SoftHSM
// - Configuring hardware certificate storage
// - Generating a key pair in the HSM
// - Creating and storing a certificate in the HSM
// - Retrieving and verifying the certificate
// - Checking HSM capacity
// - Proper cleanup
//
// Prerequisites:
// - SoftHSM installed: apt-get install softhsm2
// - Token initialized: softhsm2-util --init-token --slot 0 --label "test-token" --pin 1234 --so-pin 1234
// - Build tag: go run -tags=pkcs11 pkcs11_hardware_storage.go
func main() {
	log.Println("PKCS#11 Hardware Certificate Storage Example")
	log.Println("=============================================")

	// Step 1: Create PKCS#11 backend
	log.Println("\n[Step 1] Creating PKCS#11 backend...")

	backend, err := pkcs11.NewBackend(&pkcs11.Config{
		Library:    "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "test-token",
		PIN:        "1234",
	})
	if err != nil {
		log.Fatalf("Failed to create PKCS#11 backend: %v", err)
	}
	defer func() { _ = backend.Close() }()
	log.Println("✓ PKCS#11 backend created successfully")

	// Step 2: Configure hardware certificate storage
	log.Println("\n[Step 2] Configuring hardware certificate storage...")

	certConfig := &pkcs11.CertStorageConfig{
		Mode:                  hardware.CertStorageModeHardware,
		EnableHardwareStorage: true,
		MaxCertificates:       100,
	}

	if err := certConfig.Validate(); err != nil {
		log.Fatalf("Invalid certificate storage configuration: %v", err)
	}
	log.Println("✓ Certificate storage configuration validated")

	// Step 3: Create hardware certificate storage
	log.Println("\n[Step 3] Creating hardware certificate storage...")

	certStorage, err := backend.CreateCertificateStorage(certConfig)
	if err != nil {
		log.Fatalf("Failed to create certificate storage: %v", err)
	}
	defer func() { _ = certStorage.Close() }()
	log.Println("✓ Hardware certificate storage created")

	// Get the hardware storage interface
	adapter, ok := certStorage.(*hardware.HardwareBackendAdapter)
	if !ok {
		log.Fatal("Expected HardwareBackendAdapter")
	}
	hwStorage := adapter.GetHardwareStorage()

	// Step 4: Check capacity
	log.Println("\n[Step 4] Checking HSM capacity...")
	total, available, err := hwStorage.GetCapacity()
	if err != nil && err != hardware.ErrNotSupported {
		log.Printf("Warning: Failed to get capacity: %v", err)
	} else if err == nil {
		log.Printf("✓ HSM Capacity: %d total, %d available, %d used",
			total, available, total-available)
	} else {
		log.Println("ℹ HSM does not report capacity information")
	}

	// Step 5: Generate test key pair
	log.Println("\n[Step 5] Generating RSA key pair in HSM...")

	// For demonstration, we generate the key pair in software
	// In production, you would use backend.GenerateKey() to generate in HSM
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	log.Println("✓ Key pair generated")

	// Step 6: Create a self-signed certificate
	log.Println("\n[Step 6] Creating self-signed certificate...")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
			CommonName:   "Example HSM Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	log.Printf("✓ Certificate created: CN=%s", cert.Subject.CommonName)

	// Step 7: Store certificate in HSM
	log.Println("\n[Step 7] Storing certificate in HSM...")

	certID := "example-hsm-cert"
	err = hwStorage.SaveCert(certID, cert)
	if err != nil {
		log.Fatalf("Failed to save certificate: %v", err)
	}
	log.Printf("✓ Certificate stored in HSM with ID: %s", certID)

	// Step 8: Verify certificate exists
	log.Println("\n[Step 8] Verifying certificate exists...")

	exists, err := hwStorage.CertExists(certID)
	if err != nil {
		log.Fatalf("Failed to check certificate existence: %v", err)
	}
	if !exists {
		log.Fatal("Certificate not found in HSM!")
	}
	log.Println("✓ Certificate exists in HSM")

	// Step 9: Retrieve certificate from HSM
	log.Println("\n[Step 9] Retrieving certificate from HSM...")

	retrievedCert, err := hwStorage.GetCert(certID)
	if err != nil {
		log.Fatalf("Failed to retrieve certificate: %v", err)
	}
	log.Printf("✓ Certificate retrieved: CN=%s", retrievedCert.Subject.CommonName)

	// Step 10: Verify retrieved certificate matches original
	log.Println("\n[Step 10] Verifying certificate integrity...")

	if !cert.Equal(retrievedCert) {
		log.Fatal("Retrieved certificate does not match original!")
	}
	log.Println("✓ Certificate integrity verified")

	// Step 11: List all certificates
	log.Println("\n[Step 11] Listing all certificates in HSM...")

	certIDs, err := hwStorage.ListCerts()
	if err != nil {
		log.Fatalf("Failed to list certificates: %v", err)
	}
	log.Printf("✓ Found %d certificate(s) in HSM:", len(certIDs))
	for i, id := range certIDs {
		log.Printf("  %d. %s", i+1, id)
	}

	// Step 12: Create and store a certificate chain
	log.Println("\n[Step 12] Creating and storing certificate chain...")

	// Create an intermediate certificate
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate intermediate key: %v", err)
	}

	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Example Corp"},
			CommonName:   "Example Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(730 * 24 * time.Hour), // 2 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, template, &intermediateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		log.Fatalf("Failed to parse intermediate certificate: %v", err)
	}

	// Store the chain (leaf + intermediate + root)
	chain := []*x509.Certificate{cert, intermediateCert, cert} // Root is self-signed
	chainID := "example-chain"

	err = hwStorage.SaveCertChain(chainID, chain)
	if err != nil {
		log.Fatalf("Failed to save certificate chain: %v", err)
	}
	log.Printf("✓ Certificate chain stored with %d certificates", len(chain))

	// Retrieve the chain
	retrievedChain, err := hwStorage.GetCertChain(chainID)
	if err != nil {
		log.Fatalf("Failed to retrieve certificate chain: %v", err)
	}
	log.Printf("✓ Certificate chain retrieved: %d certificate(s)", len(retrievedChain))

	// Step 13: Cleanup - delete test certificates
	log.Println("\n[Step 13] Cleaning up test certificates...")

	err = hwStorage.DeleteCert(certID)
	if err != nil {
		log.Printf("Warning: Failed to delete certificate: %v", err)
	} else {
		log.Printf("✓ Deleted certificate: %s", certID)
	}

	err = hwStorage.DeleteCert(chainID)
	if err != nil {
		log.Printf("Warning: Failed to delete chain: %v", err)
	} else {
		log.Printf("✓ Deleted certificate chain: %s", chainID)
	}

	// Final capacity check
	log.Println("\n[Final] Final capacity check...")
	total, available, err = hwStorage.GetCapacity()
	if err == nil {
		log.Printf("✓ HSM Capacity after cleanup: %d total, %d available, %d used",
			total, available, total-available)
	}

	log.Println("\n✓ Example completed successfully!")
	log.Println("\nKey Takeaways:")
	log.Println("- Certificates are stored as CKO_CERTIFICATE objects in the HSM")
	log.Println("- Certificate chains are stored as individual certificates with ID relationships")
	log.Println("- Hardware storage provides tamper-resistant certificate storage")
	log.Println("- Capacity is limited by HSM token memory (typically 100-10,000 objects)")
}
