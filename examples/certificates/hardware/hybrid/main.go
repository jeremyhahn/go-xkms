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
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

// Example demonstrating hybrid certificate storage with automatic failover.
//
// This example shows:
// - Setting up hybrid storage (hardware + external)
// - Automatic failover when hardware is full
// - Certificate migration scenarios
// - Capacity management
// - Best practices for production use
//
// Prerequisites:
// - SoftHSM: apt-get install softhsm2
// - Token initialized: softhsm2-util --init-token --slot 0 --label "hybrid-demo" --pin 1234 --so-pin 1234
// - Build tag: go run -tags=pkcs11 hybrid_storage.go
func main() {
	log.Println("Hybrid Certificate Storage Example")
	log.Println("===================================")

	// Step 1: Create external (file) storage
	log.Println("\n[Step 1] Creating external storage...")

	externalStorage, err := file.New("/tmp/hybrid-certs")
	if err != nil {
		log.Fatalf("Failed to create external storage: %v", err)
	}
	defer externalStorage.Close()
	log.Println("✓ External storage created at /tmp/hybrid-certs")

	// Step 2: Create PKCS#11 backend
	log.Println("\n[Step 2] Creating PKCS#11 backend...")

	backend, err := pkcs11.NewBackend(&pkcs11.Config{
		Library:    "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "hybrid-demo",
		PIN:        "1234",
	})
	if err != nil {
		log.Fatalf("Failed to create PKCS#11 backend: %v", err)
	}
	defer backend.Close()
	log.Println("✓ PKCS#11 backend created")

	// Step 3: Configure hybrid certificate storage
	log.Println("\n[Step 3] Configuring hybrid storage...")

	certConfig := &pkcs11.CertStorageConfig{
		Mode:                  hardware.CertStorageModeHybrid,
		ExternalStorage:       externalStorage,
		EnableHardwareStorage: true,
		MaxCertificates:       10, // Low limit for demonstration
	}

	if err := certConfig.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	log.Println("✓ Hybrid storage configured")
	log.Println("  - Primary: Hardware (HSM)")
	log.Println("  - Fallback: External (filesystem)")
	log.Println("  - Max hardware certs: 10")

	// Step 4: Create hybrid certificate storage
	log.Println("\n[Step 4] Creating hybrid certificate storage...")

	certStorage, err := backend.CreateCertificateStorage(certConfig)
	if err != nil {
		log.Fatalf("Failed to create hybrid storage: %v", err)
	}
	defer certStorage.Close()
	log.Println("✓ Hybrid storage created successfully")

	// Get the hardware storage interface
	adapter, ok := certStorage.(*hardware.HardwareBackendAdapter)
	if !ok {
		log.Fatal("Expected HardwareBackendAdapter")
	}
	hwStorage := adapter.GetHardwareStorage()

	// Step 5: Demonstrate normal operation (hardware storage)
	log.Println("\n[Step 5] Storing certificates (hardware first)...")

	for i := 1; i <= 5; i++ {
		cert := createTestCertificate(fmt.Sprintf("test-cert-%d", i))
		certID := fmt.Sprintf("cert-%d", i)

		err = hwStorage.SaveCert(certID, cert)
		if err != nil {
			log.Fatalf("Failed to save certificate %d: %v", i, err)
		}
		log.Printf("✓ Stored certificate %d: %s", i, certID)
	}

	// Step 6: Verify certificates are in hardware
	log.Println("\n[Step 6] Verifying certificates in hardware...")

	allCerts, err := hwStorage.ListCerts()
	if err != nil {
		log.Fatalf("Failed to list certificates: %v", err)
	}
	log.Printf("✓ Total certificates: %d", len(allCerts))

	// Step 7: Fill hardware to demonstrate failover
	log.Println("\n[Step 7] Demonstrating automatic failover...")
	log.Println("ℹ Filling hardware storage to capacity...")

	for i := 6; i <= 15; i++ {
		cert := createTestCertificate(fmt.Sprintf("overflow-cert-%d", i))
		certID := fmt.Sprintf("cert-%d", i)

		err = hwStorage.SaveCert(certID, cert)
		if err != nil {
			if hardware.IsCapacityError(err) {
				log.Printf("ℹ Hardware full at certificate %d (expected)", i)
				log.Println("✓ Automatic failover to external storage")
			} else {
				log.Fatalf("Unexpected error: %v", err)
			}
		} else {
			log.Printf("✓ Stored certificate %d", i)
		}
	}

	// Step 8: List all certificates (from both storages)
	log.Println("\n[Step 8] Listing all certificates...")

	allCerts, err = hwStorage.ListCerts()
	if err != nil {
		log.Fatalf("Failed to list certificates: %v", err)
	}
	log.Printf("✓ Total certificates (hardware + external): %d", len(allCerts))

	// Step 9: Retrieve certificates (automatic lookup)
	log.Println("\n[Step 9] Retrieving certificates...")

	// Try retrieving from different locations
	testIDs := []string{"cert-1", "cert-10", "cert-15"}
	for _, id := range testIDs {
		cert, err := hwStorage.GetCert(id)
		if err != nil {
			if err == storage.ErrNotFound {
				log.Printf("ℹ Certificate %s not found", id)
			} else {
				log.Printf("Error retrieving %s: %v", id, err)
			}
		} else {
			log.Printf("✓ Retrieved %s: CN=%s", id, cert.Subject.CommonName)
		}
	}

	// Step 10: Migration scenario
	log.Println("\n[Step 10] Migration scenario: External to hybrid...")

	// Create some certificates in external storage first
	log.Println("ℹ Creating certificates in external storage...")
	for i := 20; i <= 22; i++ {
		cert := createTestCertificate(fmt.Sprintf("legacy-cert-%d", i))
		certID := fmt.Sprintf("legacy-%d", i)

		// Encode certificate to PEM
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		// Use storage.SaveCert helper function
		err = storage.SaveCert(externalStorage, certID, pemData)
		if err != nil {
			log.Fatalf("Failed to save legacy cert: %v", err)
		}
	}

	// Now access via hybrid storage (reads from external)
	log.Println("ℹ Accessing legacy certificates via hybrid storage...")
	legacyCert, err := hwStorage.GetCert("legacy-20")
	if err != nil {
		log.Printf("Error: %v", err)
	} else {
		log.Printf("✓ Retrieved legacy certificate: CN=%s", legacyCert.Subject.CommonName)
	}

	// Step 11: Demonstrate delete from both storages
	log.Println("\n[Step 11] Deleting certificates...")

	deleteIDs := []string{"cert-1", "cert-10", "legacy-20"}
	for _, id := range deleteIDs {
		err = hwStorage.DeleteCert(id)
		if err != nil && err != storage.ErrNotFound {
			log.Printf("Warning: Failed to delete %s: %v", id, err)
		} else {
			log.Printf("✓ Deleted: %s", id)
		}
	}

	// Step 12: Final statistics
	log.Println("\n[Step 12] Final statistics...")

	remainingCerts, _ := hwStorage.ListCerts()
	log.Printf("✓ Remaining certificates: %d", len(remainingCerts))

	// Cleanup
	log.Println("\n[Cleanup] Removing remaining test certificates...")
	for _, id := range remainingCerts {
		hwStorage.DeleteCert(id)
	}

	log.Println("\n✓ Example completed successfully!")
	log.Println("\nKey Takeaways:")
	log.Println("- Hybrid mode provides automatic failover between hardware and external storage")
	log.Println("- Writes go to hardware first, fall back to external on capacity errors")
	log.Println("- Reads check hardware first, then external")
	log.Println("- Deletes remove from both storages (idempotent)")
	log.Println("- Perfect for migration scenarios and capacity management")
	log.Println("- Recommended for production deployments requiring high availability")

	log.Println("\nProduction Recommendations:")
	log.Println("- Set MaxCertificates conservatively based on HSM capacity")
	log.Println("- Monitor hardware capacity periodically")
	log.Println("- Use hardware for CA certs and high-value certificates")
	log.Println("- Use external for bulk/frequently-accessed certificates")
	log.Println("- Implement capacity alerts at 80% hardware usage")
}

// createTestCertificate creates a self-signed certificate for testing
func createTestCertificate(cn string) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Hybrid Storage Demo"},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
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

	return cert
}
