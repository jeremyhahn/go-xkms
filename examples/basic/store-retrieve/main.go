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

// Package main demonstrates storing and retrieving keys from the keychain.
package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
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
	tmpDir := filepath.Join(os.TempDir(), "keystore-store-retrieve")
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

	fmt.Println("=== Store and Retrieve Keys ===")

	// Example 1: Store an RSA key
	fmt.Println("1. Generating and storing RSA key...")
	rsaAttrs := &types.KeyAttributes{
		CN:           "stored-rsa-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = ks.GenerateRSA(rsaAttrs)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	fmt.Printf("   ✓ RSA key generated and stored: %s\n\n", rsaAttrs.CN)

	// Example 2: Retrieve the stored RSA key
	fmt.Println("2. Retrieving stored RSA key...")
	retrievedRSA, err := ks.GetKey(rsaAttrs)
	if err != nil {
		log.Fatalf("Failed to retrieve RSA key: %v", err)
	}
	fmt.Printf("   ✓ RSA key retrieved: %T\n\n", retrievedRSA)

	// Example 3: Store an ECDSA key
	fmt.Println("3. Generating and storing ECDSA key...")
	ecdsaAttrs := &types.KeyAttributes{
		CN:           "stored-ecdsa-key",
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
	fmt.Printf("   ✓ ECDSA key generated and stored: %s\n\n", ecdsaAttrs.CN)

	// Example 4: Retrieve the stored ECDSA key
	fmt.Println("4. Retrieving stored ECDSA key...")
	retrievedECDSA, err := ks.GetKey(ecdsaAttrs)
	if err != nil {
		log.Fatalf("Failed to retrieve ECDSA key: %v", err)
	}
	fmt.Printf("   ✓ ECDSA key retrieved: %T\n\n", retrievedECDSA)

	// Example 5: Store an Ed25519 key
	fmt.Println("5. Generating and storing Ed25519 key...")
	ed25519Attrs := &types.KeyAttributes{
		CN:           "stored-ed25519-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
	}

	_, err = ks.GenerateEd25519(ed25519Attrs)
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	fmt.Printf("   ✓ Ed25519 key generated and stored: %s\n\n", ed25519Attrs.CN)

	// Example 6: Retrieve the stored Ed25519 key
	fmt.Println("6. Retrieving stored Ed25519 key...")
	retrievedEd25519, err := ks.GetKey(ed25519Attrs)
	if err != nil {
		log.Fatalf("Failed to retrieve Ed25519 key: %v", err)
	}
	fmt.Printf("   ✓ Ed25519 key retrieved: %T\n\n", retrievedEd25519)

	// Example 7: List all stored keys
	fmt.Println("7. Listing all stored keys...")
	keys, err := ks.ListKeys()
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}

	fmt.Printf("   Total keys stored: %d\n", len(keys))
	for i, key := range keys {
		fmt.Printf("   %d. CN=%s, Algorithm=%s\n", i+1, key.CN, key.KeyAlgorithm)
	}
	fmt.Println()

	// Example 8: Delete a key
	fmt.Println("8. Deleting ECDSA key...")
	err = ks.DeleteKey(ecdsaAttrs)
	if err != nil {
		log.Fatalf("Failed to delete ECDSA key: %v", err)
	}
	fmt.Printf("   ✓ ECDSA key deleted: %s\n\n", ecdsaAttrs.CN)

	// Example 9: Verify deletion
	fmt.Println("9. Verifying deletion...")
	keys, err = ks.ListKeys()
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}
	fmt.Printf("   Total keys after deletion: %d\n", len(keys))
	for i, key := range keys {
		fmt.Printf("   %d. CN=%s, Algorithm=%s\n", i+1, key.CN, key.KeyAlgorithm)
	}

	fmt.Println("\n✓ All store and retrieve examples completed successfully!")
	fmt.Printf("\nKeys stored in: %s\n", tmpDir)
}
