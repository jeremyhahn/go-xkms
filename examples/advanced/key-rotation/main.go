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

// Package main demonstrates key rotation strategies.
package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"log"
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
	tmpDir := filepath.Join(os.TempDir(), "keystore-rotation")
	defer func() { _ = os.RemoveAll(tmpDir) }()

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

	fmt.Println("=== Key Rotation Examples ===")

	// Example 1: Basic key rotation
	fmt.Println("1. Basic Key Rotation")
	demonstrateBasicRotation(ks)

	// Example 2: Scheduled rotation with version tracking
	fmt.Println("\n2. Versioned Key Rotation")
	demonstrateVersionedRotation(ks)

	// Example 3: Blue-green rotation strategy
	fmt.Println("\n3. Blue-Green Rotation Strategy")
	demonstrateBlueGreenRotation(ks)

	// Example 4: Graceful rotation with overlap period
	fmt.Println("\n4. Graceful Rotation with Overlap Period")
	demonstrateGracefulRotation(ks)

	// Example 5: Emergency rotation
	fmt.Println("\n5. Emergency Key Rotation")
	demonstrateEmergencyRotation(ks)

	fmt.Println("\n✓ All key rotation examples completed successfully!")
}

// demonstrateBasicRotation shows a simple key rotation
func demonstrateBasicRotation(ks keychain.KeyStore) {
	keyAttrs := &types.KeyAttributes{
		CN:           "basic-rotation-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	// Generate initial key
	fmt.Println("   a. Generating initial key...")
	key1, err := ks.GenerateECDSA(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Printf("      ✓ Initial key generated: %T\n", key1)

	// Use the key for some time...
	time.Sleep(100 * time.Millisecond)

	// Rotate the key
	fmt.Println("   b. Rotating key...")
	key2, err := ks.RotateKey(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to rotate key: %v", err)
	}
	fmt.Printf("      ✓ Key rotated: %T\n", key2)

	// Verify old key is gone
	fmt.Println("   c. Verifying rotation...")
	currentKey, err := ks.GetKey(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to get current key: %v", err)
	}
	fmt.Printf("      ✓ Current key retrieved: %T\n", currentKey)
	fmt.Printf("      ✓ Rotation completed successfully\n")
}

// demonstrateVersionedRotation shows rotation with version tracking
func demonstrateVersionedRotation(ks keychain.KeyStore) {
	keyBaseName := "versioned-key"
	versions := []string{"v1", "v2", "v3"}

	fmt.Println("   a. Creating versioned keys...")
	for _, version := range versions {
		keyAttrs := &types.KeyAttributes{
			CN:           fmt.Sprintf("%s-%s", keyBaseName, version),
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		_, err := ks.GenerateECDSA(keyAttrs)
		if err != nil {
			log.Fatalf("Failed to generate key %s: %v", version, err)
		}
		fmt.Printf("      ✓ Generated %s-%s\n", keyBaseName, version)

		// Simulate time passing
		time.Sleep(50 * time.Millisecond)
	}

	fmt.Println("   b. Listing all versions...")
	keys, err := ks.ListKeys()
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}

	versionedKeys := 0
	for _, key := range keys {
		if len(key.CN) > len(keyBaseName) && key.CN[:len(keyBaseName)] == keyBaseName {
			fmt.Printf("      - %s\n", key.CN)
			versionedKeys++
		}
	}
	fmt.Printf("      ✓ Found %d versioned keys\n", versionedKeys)

	fmt.Println("   c. Cleaning up old versions (keeping only v3)...")
	for _, version := range []string{"v1", "v2"} {
		keyAttrs := &types.KeyAttributes{
			CN:           fmt.Sprintf("%s-%s", keyBaseName, version),
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}
		err := ks.DeleteKey(keyAttrs)
		if err != nil {
			log.Fatalf("Failed to delete key %s: %v", version, err)
		}
		fmt.Printf("      ✓ Deleted %s-%s\n", keyBaseName, version)
	}
}

// demonstrateBlueGreenRotation shows blue-green deployment style rotation
func demonstrateBlueGreenRotation(ks keychain.KeyStore) {
	fmt.Println("   a. Blue-Green rotation scenario...")

	// Blue key (current production)
	blueAttrs := &types.KeyAttributes{
		CN:           "service-key-blue",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	// Generate blue key
	fmt.Println("      - Generating blue key (active)...")
	_, err := ks.GenerateECDSA(blueAttrs)
	if err != nil {
		log.Fatalf("Failed to generate blue key: %v", err)
	}
	fmt.Printf("        ✓ Blue key active\n")

	// Simulate production usage
	time.Sleep(100 * time.Millisecond)

	// Green key (new key)
	greenAttrs := &types.KeyAttributes{
		CN:           "service-key-green",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	// Generate green key
	fmt.Println("      - Generating green key (standby)...")
	_, err = ks.GenerateECDSA(greenAttrs)
	if err != nil {
		log.Fatalf("Failed to generate green key: %v", err)
	}
	fmt.Printf("        ✓ Green key ready\n")

	// Switch traffic to green
	fmt.Println("      - Switching to green key...")
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("        ✓ Traffic switched to green\n")

	// Verify green is working
	fmt.Println("      - Verifying green key operation...")
	_, err = ks.GetKey(greenAttrs)
	if err != nil {
		log.Fatalf("Failed to get green key: %v", err)
	}
	fmt.Printf("        ✓ Green key operational\n")

	// Delete blue key
	fmt.Println("      - Removing blue key...")
	err = ks.DeleteKey(blueAttrs)
	if err != nil {
		log.Fatalf("Failed to delete blue key: %v", err)
	}
	fmt.Printf("        ✓ Blue key removed\n")
	fmt.Printf("      ✓ Blue-Green rotation completed\n")
}

// demonstrateGracefulRotation shows rotation with an overlap period
func demonstrateGracefulRotation(ks keychain.KeyStore) {
	fmt.Println("   a. Graceful rotation with overlap period...")

	// Current key
	currentAttrs := &types.KeyAttributes{
		CN:           "graceful-key-current",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	fmt.Println("      - Generating current key...")
	_, err := ks.GenerateECDSA(currentAttrs)
	if err != nil {
		log.Fatalf("Failed to generate current key: %v", err)
	}
	fmt.Printf("        ✓ Current key in use\n")

	// Generate next key (overlap begins)
	nextAttrs := &types.KeyAttributes{
		CN:           "graceful-key-next",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	fmt.Println("      - Starting overlap period...")
	fmt.Println("        - Generating next key...")
	_, err = ks.GenerateECDSA(nextAttrs)
	if err != nil {
		log.Fatalf("Failed to generate next key: %v", err)
	}
	fmt.Printf("        ✓ Next key generated\n")

	// Both keys are valid during overlap
	fmt.Println("        - Overlap period: both keys valid...")
	fmt.Println("          * New requests use 'next' key")
	fmt.Println("          * Existing sessions use 'current' key")
	time.Sleep(200 * time.Millisecond) // Simulate overlap period

	// End overlap period
	fmt.Println("      - Ending overlap period...")
	err = ks.DeleteKey(currentAttrs)
	if err != nil {
		log.Fatalf("Failed to delete current key: %v", err)
	}
	fmt.Printf("        ✓ Current key retired\n")
	fmt.Printf("        ✓ Next key is now current\n")
	fmt.Printf("      ✓ Graceful rotation completed\n")
}

// demonstrateEmergencyRotation shows emergency rotation scenario
func demonstrateEmergencyRotation(ks keychain.KeyStore) {
	fmt.Println("   a. Emergency rotation scenario...")

	compromisedAttrs := &types.KeyAttributes{
		CN:           "compromised-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	// Generate key
	fmt.Println("      - Initial key in use...")
	_, err := ks.GenerateECDSA(compromisedAttrs)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Simulate compromise detection
	time.Sleep(100 * time.Millisecond)
	fmt.Println("      - ⚠️  SECURITY ALERT: Key compromise detected!")

	// Immediate rotation
	fmt.Println("      - Executing emergency rotation...")
	startTime := time.Now()

	// Rotate key immediately
	newKey, err := ks.RotateKey(compromisedAttrs)
	if err != nil {
		log.Fatalf("Failed to rotate key: %v", err)
	}

	rotationTime := time.Since(startTime)
	fmt.Printf("        ✓ Key rotated in %v\n", rotationTime)
	fmt.Printf("        ✓ New key type: %T\n", newKey)
	fmt.Printf("        ✓ Compromised key deleted\n")
	fmt.Printf("      ✓ Emergency rotation completed\n")

	// Verify new key
	fmt.Println("      - Verifying new key...")
	_, err = ks.GetKey(compromisedAttrs)
	if err != nil {
		log.Fatalf("Failed to get new key: %v", err)
	}
	fmt.Printf("        ✓ New key operational\n")
}
