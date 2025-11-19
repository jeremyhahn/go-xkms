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

// Package main demonstrates basic key generation for RSA, ECDSA, and Ed25519 keys.
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
	tmpDir := filepath.Join(os.TempDir(), "keystore-example")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize storage backend
	storage, err := file.New(tmpDir)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	// Create PKCS#8 backend (software keys)
	pkcs8Backend, err := pkcs8.NewBackend(&pkcs8.Config{
		KeyStorage: storage,
	})
	if err != nil {
		log.Fatalf("Failed to create PKCS#8 backend: %v", err)
	}
	defer func() { _ = pkcs8Backend.Close() }()

	// Create keystore instance
	ks, err := keychain.New(&keychain.Config{
		Backend:     pkcs8Backend,
		CertStorage: storage,
	})
	if err != nil {
		log.Fatalf("Failed to create keystore: %v", err)
	}
	defer func() { _ = ks.Close() }()

	fmt.Println("=== Key Generation Examples ===")

	// Example 1: Generate RSA-2048 key
	fmt.Println("1. Generating RSA-2048 key...")
	rsaAttrs := &types.KeyAttributes{
		CN:           "rsa-example-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	rsaKey, err := ks.GenerateRSA(rsaAttrs)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	fmt.Printf("   ✓ RSA-2048 key generated: %s\n\n", rsaAttrs.CN)

	// Example 2: Generate RSA-4096 key
	fmt.Println("2. Generating RSA-4096 key...")
	rsa4096Attrs := &types.KeyAttributes{
		CN:           "rsa-4096-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 4096,
		},
	}

	_, err = ks.GenerateRSA(rsa4096Attrs)
	if err != nil {
		log.Fatalf("Failed to generate RSA-4096 key: %v", err)
	}
	fmt.Printf("   ✓ RSA-4096 key generated: %s\n\n", rsa4096Attrs.CN)

	// Example 3: Generate ECDSA P-256 key
	fmt.Println("3. Generating ECDSA P-256 key...")
	ecdsaP256Attrs := &types.KeyAttributes{
		CN:           "ecdsa-p256-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	ecdsaKey, err := ks.GenerateECDSA(ecdsaP256Attrs)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA P-256 key: %v", err)
	}
	fmt.Printf("   ✓ ECDSA P-256 key generated: %s\n\n", ecdsaP256Attrs.CN)

	// Example 4: Generate ECDSA P-384 key
	fmt.Println("4. Generating ECDSA P-384 key...")
	ecdsaP384Attrs := &types.KeyAttributes{
		CN:           "ecdsa-p384-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}

	_, err = ks.GenerateECDSA(ecdsaP384Attrs)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA P-384 key: %v", err)
	}
	fmt.Printf("   ✓ ECDSA P-384 key generated: %s\n\n", ecdsaP384Attrs.CN)

	// Example 5: Generate Ed25519 key
	fmt.Println("5. Generating Ed25519 key...")
	ed25519Attrs := &types.KeyAttributes{
		CN:           "ed25519-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
	}

	ed25519Key, err := ks.GenerateEd25519(ed25519Attrs)
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	fmt.Printf("   ✓ Ed25519 key generated: %s\n\n", ed25519Attrs.CN)

	// List all generated keys
	fmt.Println("6. Listing all keys...")
	keys, err := ks.ListKeys()
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}

	fmt.Printf("   Total keys: %d\n", len(keys))
	for i, key := range keys {
		fmt.Printf("   %d. %s (%s)\n", i+1, key.CN, key.KeyAlgorithm)
	}
	fmt.Println()

	// Demonstrate type assertions
	fmt.Println("=== Key Type Information ===")
	fmt.Printf("RSA key type: %T\n", rsaKey)
	fmt.Printf("ECDSA key type: %T\n", ecdsaKey)
	fmt.Printf("Ed25519 key type: %T\n", ed25519Key)

	fmt.Println("\n✓ All key generation examples completed successfully!")
	fmt.Printf("\nKeys stored in: %s\n", tmpDir)
}
