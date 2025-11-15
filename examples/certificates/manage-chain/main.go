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

// Package main demonstrates managing certificate chains.
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
	// Create a temporary directory
	tmpDir := filepath.Join(os.TempDir(), "keystore-cert-chain")
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

	fmt.Println("=== Certificate Chain Management ===")

	// Step 1: Create Root CA
	fmt.Println("1. Creating Root CA...")
	rootCert, rootKey := createRootCA(ks, "Example Root CA")
	fmt.Printf("   ✓ Root CA created: %s\n\n", rootCert.Subject.CommonName)

	// Step 2: Create Intermediate CA
	fmt.Println("2. Creating Intermediate CA...")
	intermediateCert, intermediateKey := createIntermediateCA(ks, rootCert, rootKey, "Example Intermediate CA")
	fmt.Printf("   ✓ Intermediate CA created: %s\n\n", intermediateCert.Subject.CommonName)

	// Step 3: Create End-Entity (Leaf) Certificate
	fmt.Println("3. Creating end-entity certificate...")
	leafCert := createLeafCertificate(ks, intermediateCert, intermediateKey, "server.example.com")
	fmt.Printf("   ✓ End-entity certificate created: %s\n\n", leafCert.Subject.CommonName)

	// Step 4: Build and store complete certificate chain
	fmt.Println("4. Building certificate chain (leaf -> intermediate -> root)...")
	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}
	err = ks.SaveCertChain("server.example.com", chain)
	if err != nil {
		log.Fatalf("Failed to save certificate chain: %v", err)
	}
	fmt.Printf("   ✓ Certificate chain stored\n")
	fmt.Printf("     Chain length: %d certificates\n\n", len(chain))

	// Step 5: Retrieve and verify certificate chain
	fmt.Println("5. Retrieving certificate chain...")
	retrievedChain, err := ks.GetCertChain("server.example.com")
	if err != nil {
		log.Fatalf("Failed to retrieve certificate chain: %v", err)
	}
	fmt.Printf("   ✓ Retrieved chain length: %d certificates\n", len(retrievedChain))
	for i, cert := range retrievedChain {
		fmt.Printf("     [%d] %s (issued by: %s)\n", i, cert.Subject.CommonName, cert.Issuer.CommonName)
	}
	fmt.Println()

	// Step 6: Verify the certificate chain
	fmt.Println("6. Verifying certificate chain...")
	if err := verifyChain(leafCert, intermediateCert, rootCert); err != nil {
		log.Fatalf("Chain verification failed: %v", err)
	}
	fmt.Printf("   ✓ Certificate chain verified successfully\n\n")

	// Step 7: Export chain to PEM bundle
	fmt.Println("7. Exporting certificate chain to PEM bundle...")
	chainFile := filepath.Join(tmpDir, "chain.pem")
	if err := exportChainToPEM(chainFile, chain); err != nil {
		log.Fatalf("Failed to export chain: %v", err)
	}
	fmt.Printf("   ✓ Chain exported to: %s\n\n", chainFile)

	// Step 8: Display chain details
	fmt.Println("8. Certificate Chain Details:")
	displayChainInfo(chain)

	// Step 9: Demonstrate path validation
	fmt.Println("\n9. Demonstrating certificate path validation...")
	demonstratePathValidation(leafCert, intermediateCert, rootCert)

	fmt.Println("\n✓ Certificate chain management completed successfully!")
	fmt.Printf("\nChain files stored in: %s\n", tmpDir)
}

// createRootCA creates a root CA certificate
func createRootCA(ks keychain.KeyStore, cn string) (*x509.Certificate, interface{}) {
	keyAttrs := &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}

	privKey, err := ks.GenerateECDSA(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(20 * 365 * 24 * time.Hour) // 20 years

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Example Root Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		privKey.(interface{ Public() interface{} }).Public(),
		privKey,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	cert, _ := x509.ParseCertificate(certBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert(cn, cert)

	return cert, privKey
}

// createIntermediateCA creates an intermediate CA certificate
func createIntermediateCA(ks keychain.KeyStore, issuerCert *x509.Certificate, issuerKey interface{}, cn string) (*x509.Certificate, interface{}) {
	keyAttrs := &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	privKey, err := ks.GenerateECDSA(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10 years

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Example Intermediate Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		issuerCert,
		privKey.(interface{ Public() interface{} }).Public(),
		issuerKey,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	cert, _ := x509.ParseCertificate(certBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert(cn, cert)

	return cert, privKey
}

// createLeafCertificate creates an end-entity (leaf) certificate
func createLeafCertificate(ks keychain.KeyStore, issuerCert *x509.Certificate, issuerKey interface{}, cn string) *x509.Certificate {
	keyAttrs := &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	privKey, err := ks.GenerateECDSA(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Example Organization"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{cn},
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		issuerCert,
		privKey.(interface{ Public() interface{} }).Public(),
		issuerKey,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	cert, _ := x509.ParseCertificate(certBytes)
	// #nosec G104 - Example code, error handling omitted for clarity
	ks.SaveCert(cn, cert)

	return cert
}

// verifyChain verifies a complete certificate chain
func verifyChain(leaf, intermediate, root *x509.Certificate) error {
	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(root)

	// Create intermediate pool
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)

	// Verify options
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	// Verify the chain
	chains, err := leaf.Verify(opts)
	if err != nil {
		return err
	}

	// Display verified chains
	fmt.Printf("   Found %d valid chain(s):\n", len(chains))
	for i, chain := range chains {
		fmt.Printf("     Chain %d: ", i+1)
		for j, cert := range chain {
			if j > 0 {
				fmt.Print(" -> ")
			}
			fmt.Print(cert.Subject.CommonName)
		}
		fmt.Println()
	}

	return nil
}

// exportChainToPEM exports a certificate chain to a PEM file
func exportChainToPEM(filename string, chain []*x509.Certificate) error {
	// #nosec G304 - Example code with controlled file paths
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, cert := range chain {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(f, pemBlock); err != nil {
			return err
		}
	}

	return nil
}

// displayChainInfo displays detailed information about a certificate chain
func displayChainInfo(chain []*x509.Certificate) {
	for i, cert := range chain {
		var certType string
		if cert.IsCA {
			if cert.Subject.CommonName == cert.Issuer.CommonName {
				certType = "Root CA"
			} else {
				certType = "Intermediate CA"
			}
		} else {
			certType = "End-Entity"
		}

		fmt.Printf("\n   Certificate %d (%s):\n", i+1, certType)
		fmt.Printf("     Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("     Issuer: %s\n", cert.Issuer.CommonName)
		fmt.Printf("     Serial: %s\n", cert.SerialNumber.String())
		fmt.Printf("     Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("     Is CA: %v\n", cert.IsCA)
		if cert.IsCA {
			fmt.Printf("     Max Path Length: %d\n", cert.MaxPathLen)
		}
		if len(cert.DNSNames) > 0 {
			fmt.Printf("     DNS Names: %v\n", cert.DNSNames)
		}
	}
}

// demonstratePathValidation shows different path validation scenarios
func demonstratePathValidation(leaf, intermediate, root *x509.Certificate) {
	// Scenario 1: Valid chain with all certificates
	fmt.Println("   Scenario 1: Complete chain (leaf + intermediate + root)")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		fmt.Printf("     ✗ Verification failed (unexpected): %v\n", err)
	} else {
		fmt.Printf("     ✓ Verification succeeded\n")
	}

	// Scenario 2: Missing intermediate certificate
	fmt.Println("   Scenario 2: Missing intermediate certificate")
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots,
		// No intermediates provided
	})
	if err != nil {
		fmt.Printf("     ✓ Verification correctly failed: %v\n", err)
	} else {
		fmt.Printf("     ✗ Verification succeeded (unexpected)\n")
	}

	// Scenario 3: Trust intermediate as root (incorrect)
	fmt.Println("   Scenario 3: Trusting intermediate as root")
	wrongRoots := x509.NewCertPool()
	wrongRoots.AddCert(intermediate)

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: wrongRoots,
	})
	if err != nil {
		fmt.Printf("     ✓ Verification correctly failed: %v\n", err)
	} else {
		fmt.Printf("     ✗ Verification succeeded (unexpected)\n")
	}
}
