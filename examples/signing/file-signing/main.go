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

// Package main demonstrates signing files and verifying file signatures.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	// Create a temporary directory for the keychain
	tmpDir := filepath.Join(os.TempDir(), "keystore-file-signing")
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

	fmt.Println("=== File Signing Examples ===")

	// Create a test file
	testFile := filepath.Join(tmpDir, "test-document.txt")
	testContent := []byte("This is a test document that needs to be signed.\nIt contains multiple lines.\nAnd some important data.\n")
	err = os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		log.Fatalf("Failed to create test file: %v", err)
	}
	fmt.Printf("Created test file: %s (%d bytes)\n\n", testFile, len(testContent))

	// Example 1: Generate signing key
	fmt.Println("1. Generating ECDSA P-256 signing key...")
	ecdsaAttrs := &types.KeyAttributes{
		CN:           "file-signing-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	_, err = ks.GenerateECDSA(ecdsaAttrs)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	fmt.Printf("   ✓ Signing key generated: %s\n\n", ecdsaAttrs.CN)

	// Get signer for public key access
	signer, err := ks.Signer(ecdsaAttrs)
	if err != nil {
		log.Fatalf("Failed to get signer: %v", err)
	}
	pubKey := signer.Public().(*ecdsa.PublicKey)

	// Example 2: Sign a file
	fmt.Println("2. Signing the file...")
	signature, _, err := signFile(ks, ecdsaAttrs, testFile)
	if err != nil {
		log.Fatalf("Failed to sign file: %v", err)
	}

	// Save signature to file
	sigFile := testFile + ".sig"
	err = os.WriteFile(sigFile, signature, 0644)
	if err != nil {
		log.Fatalf("Failed to save signature: %v", err)
	}
	fmt.Printf("   ✓ File signed successfully\n")
	fmt.Printf("   Signature file: %s\n", sigFile)
	fmt.Printf("   Signature (base64): %s\n\n", base64.StdEncoding.EncodeToString(signature))

	// Example 3: Verify the signature
	fmt.Println("3. Verifying file signature...")
	signatureBytes, err := os.ReadFile(sigFile)
	if err != nil {
		log.Fatalf("Failed to read signature file: %v", err)
	}

	valid := verifyFileSignature(pubKey, testFile, signatureBytes)
	if valid {
		fmt.Printf("   ✓ File signature verified successfully\n\n")
	} else {
		log.Fatal("   ✗ File signature verification failed")
	}

	// Example 4: Demonstrate signature failure on tampered file
	fmt.Println("4. Demonstrating tamper detection...")
	tamperedFile := filepath.Join(tmpDir, "test-document-tampered.txt")
	tamperedContent := []byte("This file has been tampered with!\nMalicious content added.\n")
	err = os.WriteFile(tamperedFile, tamperedContent, 0644)
	if err != nil {
		log.Fatalf("Failed to create tampered file: %v", err)
	}

	valid = verifyFileSignature(pubKey, tamperedFile, signatureBytes)
	if !valid {
		fmt.Printf("   ✓ Tampered file correctly rejected\n\n")
	} else {
		log.Fatal("   ✗ Tampered file incorrectly verified!")
	}

	// Example 5: Batch file signing
	fmt.Println("5. Batch signing multiple files...")
	files := []string{
		filepath.Join(tmpDir, "doc1.txt"),
		filepath.Join(tmpDir, "doc2.txt"),
		filepath.Join(tmpDir, "doc3.txt"),
	}

	for i, f := range files {
		content := []byte(fmt.Sprintf("Document %d content\n", i+1))
		err = os.WriteFile(f, content, 0644)
		if err != nil {
			log.Fatalf("Failed to create file %s: %v", f, err)
		}

		sig, _, err := signFile(ks, ecdsaAttrs, f)
		if err != nil {
			log.Fatalf("Failed to sign file %s: %v", f, err)
		}

		err = os.WriteFile(f+".sig", sig, 0644)
		if err != nil {
			log.Fatalf("Failed to save signature for %s: %v", f, err)
		}

		fmt.Printf("   ✓ Signed: %s\n", filepath.Base(f))
	}

	// Verify all signatures
	fmt.Println("\n6. Verifying all batch signatures...")
	for _, f := range files {
		sig, err := os.ReadFile(f + ".sig")
		if err != nil {
			log.Fatalf("Failed to read signature for %s: %v", f, err)
		}

		if verifyFileSignature(pubKey, f, sig) {
			fmt.Printf("   ✓ Verified: %s\n", filepath.Base(f))
		} else {
			log.Fatalf("   ✗ Verification failed for: %s\n", filepath.Base(f))
		}
	}

	fmt.Println("\n✓ All file signing examples completed successfully!")
	fmt.Printf("\nFiles stored in: %s\n", tmpDir)
}

// signFile signs a file and returns the signature and file hash
func signFile(ks keychain.KeyStore, attrs *types.KeyAttributes, filename string) ([]byte, []byte, error) {
	// Open and read the file
	// #nosec G304 - Example code with controlled file paths
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Calculate SHA-256 hash
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, nil, fmt.Errorf("failed to hash file: %w", err)
	}
	hash := hasher.Sum(nil)

	// Get signer
	signer, err := ks.Signer(attrs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signer: %w", err)
	}

	// Sign the hash
	signature, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, hash, nil
}

// verifyFileSignature verifies a file signature using an ECDSA public key
func verifyFileSignature(pubKey *ecdsa.PublicKey, filename string, signature []byte) bool {
	// Open and read the file
	// #nosec G304 - Example code with controlled file paths
	f, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer f.Close()

	// Calculate SHA-256 hash
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return false
	}
	hash := hasher.Sum(nil)

	// Verify signature
	return ecdsa.VerifyASN1(pubKey, hash, signature)
}
