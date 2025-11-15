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

// Package main demonstrates creating a Certificate Authority (CA).
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
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
	// Create a temporary directory for the CA
	tmpDir := filepath.Join(os.TempDir(), "keystore-ca")
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

	fmt.Println("=== Certificate Authority Creation ===")

	// Example 1: Generate CA private key (ECDSA P-384 for strong security)
	fmt.Println("1. Generating CA private key (ECDSA P-384)...")
	caKeyAttrs := &types.KeyAttributes{
		CN:           "Example Root CA",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}

	_, err = ks.GenerateECDSA(caKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate CA key: %v", err)
	}
	fmt.Printf("   ✓ CA private key generated\n\n")

	// Get signer for the CA key
	caSigner, err := ks.Signer(caKeyAttrs)
	if err != nil {
		log.Fatalf("Failed to get CA signer: %v", err)
	}

	// Example 2: Create CA certificate template
	fmt.Println("2. Creating CA certificate template...")
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10 years

	caCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "Example Root CA",
			Organization:       []string{"Example Organization"},
			OrganizationalUnit: []string{"Security"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2, // Can sign intermediate CAs
		MaxPathLenZero:        false,
	}

	fmt.Println("   Certificate template:")
	fmt.Printf("     Common Name: %s\n", caCertTemplate.Subject.CommonName)
	fmt.Printf("     Organization: %s\n", caCertTemplate.Subject.Organization[0])
	fmt.Printf("     Valid From: %s\n", notBefore.Format(time.RFC3339))
	fmt.Printf("     Valid Until: %s\n", notAfter.Format(time.RFC3339))
	fmt.Printf("     Is CA: %v\n", caCertTemplate.IsCA)
	fmt.Printf("     Max Path Length: %d\n\n", caCertTemplate.MaxPathLen)

	// Example 3: Self-sign the CA certificate
	fmt.Println("3. Self-signing CA certificate...")
	caCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		caCertTemplate,
		caCertTemplate, // Self-signed
		caSigner.Public(),
		caSigner,
	)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		log.Fatalf("Failed to parse CA certificate: %v", err)
	}
	fmt.Printf("   ✓ CA certificate created and self-signed\n\n")

	// Example 4: Store CA certificate
	fmt.Println("4. Storing CA certificate...")
	err = ks.SaveCert(caKeyAttrs.CN, caCert)
	if err != nil {
		log.Fatalf("Failed to store CA certificate: %v", err)
	}
	fmt.Printf("   ✓ CA certificate stored in keystore\n\n")

	// Example 5: Export CA certificate to PEM file
	fmt.Println("5. Exporting CA certificate to PEM file...")
	caPEMFile := filepath.Join(tmpDir, "ca-cert.pem")
	caPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	}

	// #nosec G304 - Example code with controlled file paths
	f, err := os.Create(caPEMFile)
	if err != nil {
		log.Fatalf("Failed to create PEM file: %v", err)
	}
	defer f.Close()

	err = pem.Encode(f, caPEMBlock)
	if err != nil {
		log.Fatalf("Failed to encode PEM: %v", err)
	}
	fmt.Printf("   ✓ CA certificate exported to: %s\n\n", caPEMFile)

	// Example 6: Verify CA certificate
	fmt.Println("6. Verifying CA certificate...")
	retrievedCert, err := ks.GetCert(caKeyAttrs.CN)
	if err != nil {
		log.Fatalf("Failed to retrieve CA certificate: %v", err)
	}

	if retrievedCert.Subject.CommonName != caCert.Subject.CommonName {
		log.Fatal("Retrieved certificate CN doesn't match")
	}

	if !retrievedCert.IsCA {
		log.Fatal("Retrieved certificate is not marked as CA")
	}

	fmt.Println("   Certificate details:")
	fmt.Printf("     Subject: %s\n", retrievedCert.Subject.String())
	fmt.Printf("     Issuer: %s\n", retrievedCert.Issuer.String())
	fmt.Printf("     Serial: %s\n", retrievedCert.SerialNumber.String())
	fmt.Printf("     Is CA: %v\n", retrievedCert.IsCA)
	fmt.Printf("     Key Usage: %v\n", retrievedCert.KeyUsage)
	fmt.Printf("   ✓ CA certificate verified successfully\n\n")

	// Example 7: Create trust pool with CA
	fmt.Println("7. Creating trust pool...")
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	fmt.Printf("   ✓ Trust pool created with CA certificate\n")
	fmt.Printf("     Subjects: %v\n\n", roots.Subjects())

	// Example 8: Display CA fingerprint
	fmt.Println("8. CA certificate fingerprint:")
	fmt.Printf("   SHA-256: %x\n", caCert.RawSubjectPublicKeyInfo)

	fmt.Println("\n✓ Certificate Authority created successfully!")
	fmt.Printf("\nCA files stored in: %s\n", tmpDir)
	fmt.Println("\nYou can now use this CA to issue certificates for servers and clients.")
}
