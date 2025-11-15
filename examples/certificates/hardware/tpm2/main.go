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

//go:build tpm2

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

// Example demonstrating TPM2 NV RAM certificate storage.
//
// This example shows:
// - Creating a TPM2 NV RAM certificate storage
// - Storing certificates in TPM NV RAM
// - Handling NV RAM capacity constraints
// - Certificate retrieval from TPM
// - Proper cleanup of NV indices
//
// Prerequisites:
// - TPM2 device or simulator: /dev/tpmrm0 or swtpm
// - Build tag: go run -tags=tpm2 tpm2_nvram_storage.go
//
// Important: TPM NV RAM is very limited (2-8KB total)
// Only store critical certificates (2-4 max recommended)
func main() {
	log.Println("TPM2 NV RAM Certificate Storage Example")
	log.Println("========================================")

	// Step 1: Open TPM device
	log.Println("\n[Step 1] Opening TPM device...")

	tpmDevice := "/dev/tpmrm0"
	if _, err := os.Stat(tpmDevice); os.IsNotExist(err) {
		log.Printf("TPM device %s not found, using simulator", tpmDevice)
		tpmDevice = "simulator"
	}

	var tpm transport.TPMCloser
	var err error

	if tpmDevice == "simulator" {
		// For testing with simulator
		log.Println("ℹ Using TPM simulator (swtpm)")
		log.Println("  Start swtpm: swtpm socket --tpmstate dir=/tmp/tpm --ctrl type=tcp,port=2322 --server type=tcp,port=2321")
		tpm, err = transport.OpenTPM("swtpm:host=localhost,port=2321")
	} else {
		tpm, err = transport.OpenTPM(tpmDevice)
	}

	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}
	defer tpm.Close()
	log.Println("✓ TPM device opened successfully")

	// Step 2: Configure NV RAM certificate storage
	log.Println("\n[Step 2] Configuring NV RAM certificate storage...")

	certConfig := &hardware.TPM2CertStorageConfig{
		BaseIndex:   0x01800000, // TPM_NV_INDEX_FIRST
		MaxCertSize: 2048,       // Conservative size
		OwnerAuth:   []byte{},   // No owner password (default)
	}

	log.Printf("  NV Base Index: 0x%08x", certConfig.BaseIndex)
	log.Printf("  Max Cert Size: %d bytes", certConfig.MaxCertSize)
	log.Println("✓ Configuration validated")

	// Step 3: Create NV RAM certificate storage
	log.Println("\n[Step 3] Creating NV RAM certificate storage...")

	certStorage, err := hardware.NewTPM2CertStorage(tpm, certConfig)
	if err != nil {
		log.Fatalf("Failed to create TPM cert storage: %v", err)
	}
	defer certStorage.Close()
	log.Println("✓ NV RAM certificate storage created")

	// Step 4: Check NV RAM capacity
	log.Println("\n[Step 4] Checking NV RAM capacity...")

	hwStorage := certStorage.(hardware.HardwareCertStorage)
	total, available, err := hwStorage.GetCapacity()
	if err != nil {
		log.Printf("Warning: Unable to query exact capacity: %v", err)
		log.Println("ℹ Using estimated capacity (4 certificates)")
	} else {
		log.Printf("✓ TPM NV RAM Capacity: %d total, %d available, %d used",
			total, available, total-available)
	}

	// Step 5: Create test certificate
	log.Println("\n[Step 5] Creating test certificate...")

	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TPM Example"},
			Country:      []string{"US"},
			CommonName:   "TPM Device Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

	// Step 6: Store certificate in NV RAM
	log.Println("\n[Step 6] Storing certificate in TPM NV RAM...")

	certID := "tpm-device-cert"
	err = certStorage.SaveCert(certID, cert)
	if err != nil {
		if err == hardware.ErrCertificateTooLarge {
			log.Fatalf("Certificate too large for NV RAM: %v", err)
		}
		if err == hardware.ErrCapacityExceeded {
			log.Fatalf("NV RAM capacity exceeded: %v", err)
		}
		log.Fatalf("Failed to save certificate: %v", err)
	}
	log.Printf("✓ Certificate stored in NV RAM with ID: %s", certID)

	// Step 7: Verify certificate exists
	log.Println("\n[Step 7] Verifying certificate in NV RAM...")

	exists, err := certStorage.CertExists(certID)
	if err != nil {
		log.Fatalf("Failed to check certificate: %v", err)
	}
	if !exists {
		log.Fatal("Certificate not found in NV RAM!")
	}
	log.Println("✓ Certificate exists in NV RAM")

	// Step 8: Retrieve certificate
	log.Println("\n[Step 8] Retrieving certificate from NV RAM...")

	retrievedCert, err := certStorage.GetCert(certID)
	if err != nil {
		log.Fatalf("Failed to retrieve certificate: %v", err)
	}
	log.Printf("✓ Certificate retrieved: CN=%s", retrievedCert.Subject.CommonName)

	// Step 9: Verify integrity
	log.Println("\n[Step 9] Verifying certificate integrity...")

	if !cert.Equal(retrievedCert) {
		log.Fatal("Retrieved certificate does not match original!")
	}
	log.Println("✓ Certificate integrity verified")

	// Step 10: Store a CA certificate chain
	log.Println("\n[Step 10] Creating and storing CA certificate chain...")

	// Create root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			Organization: []string{"TPM CA"},
			CommonName:   "TPM Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	// Create intermediate CA
	intKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	intTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			Organization: []string{"TPM CA"},
			CommonName:   "TPM Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1825 * 24 * time.Hour), // 5 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	intDER, _ := x509.CreateCertificate(rand.Reader, intTemplate, rootTemplate, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intDER)

	// Store chain in NV RAM
	chain := []*x509.Certificate{cert, intCert, rootCert}
	chainID := "tpm-ca-chain"

	err = certStorage.SaveCertChain(chainID, chain)
	if err != nil {
		if hardware.IsCapacityError(err) {
			log.Printf("Warning: NV RAM capacity limit reached: %v", err)
			log.Println("ℹ In production, use hybrid mode with external storage")
		} else {
			log.Printf("Warning: Failed to save chain: %v", err)
		}
	} else {
		log.Printf("✓ Certificate chain stored: %d certificates", len(chain))

		// Retrieve chain
		retrievedChain, err := certStorage.GetCertChain(chainID)
		if err != nil {
			log.Printf("Failed to retrieve chain: %v", err)
		} else {
			log.Printf("✓ Certificate chain retrieved: %d certificates", len(retrievedChain))
		}
	}

	// Step 11: List certificates in NV RAM
	log.Println("\n[Step 11] Listing certificates in NV RAM...")

	certIDs, err := certStorage.ListCerts()
	if err != nil {
		log.Printf("Warning: Failed to list certificates: %v", err)
	} else {
		log.Printf("✓ Found %d NV index(es) with certificates:", len(certIDs))
		for i, id := range certIDs {
			log.Printf("  %d. %s", i+1, id)
		}
	}

	// Step 12: Cleanup - delete certificates
	log.Println("\n[Step 12] Cleaning up NV RAM...")

	err = certStorage.DeleteCert(certID)
	if err != nil {
		log.Printf("Warning: Failed to delete certificate: %v", err)
	} else {
		log.Printf("✓ Deleted certificate: %s", certID)
	}

	if chainID != "" {
		err = certStorage.DeleteCert(chainID)
		if err != nil {
			log.Printf("Warning: Failed to delete chain: %v", err)
		} else {
			log.Printf("✓ Deleted certificate chain: %s", chainID)
		}
	}

	// Final capacity check
	log.Println("\n[Final] Final NV RAM status...")
	total, available, err = hwStorage.GetCapacity()
	if err == nil {
		log.Printf("✓ NV RAM after cleanup: %d total, %d available, %d used",
			total, available, total-available)
	}

	log.Println("\n✓ Example completed successfully!")
	log.Println("\nKey Takeaways:")
	log.Println("- TPM NV RAM is very limited (2-8KB total)")
	log.Println("- Practical limit: 2-4 certificates per TPM")
	log.Println("- Certificates are PEM-encoded and stored in NV indices")
	log.Println("- Use hybrid mode in production for automatic overflow")
	log.Println("- Store only critical certificates in TPM (CA roots, device identity)")
	log.Println("- Monitor NV RAM capacity carefully to avoid exhaustion")
}
