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

package kdf_test

import (
	"crypto"
	"crypto/rand"
	_ "crypto/sha256"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/kdf"
)

// Example demonstrates basic HKDF usage for key derivation
func Example_hkdf() {
	// Create HKDF adapter
	adapter := kdf.NewHKDFAdapter()

	// Input key material (e.g., from ECDH key exchange)
	ikm := []byte("shared secret from key exchange")

	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}

	// Application-specific context information
	info := []byte("my-application-v1")

	// Configure parameters
	params := &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Salt:      salt,
		Info:      info,
		KeyLength: 32, // 256-bit key
		Hash:      crypto.SHA256,
	}

	// Derive key
	key, err := adapter.DeriveKey(ikm, params)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Derived key length: %d bytes\n", len(key))
	// Output: Derived key length: 32 bytes
}

// Example demonstrates PBKDF2 usage for password-based key derivation
func Example_pbkdf2() {
	// Create PBKDF2 adapter
	adapter := kdf.NewPBKDF2Adapter()

	// Password
	password := []byte("my-secure-password")

	// Generate a random salt (should be stored with the derived key)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}

	// Configure parameters with recommended settings
	params := &kdf.KDFParams{
		Algorithm:  kdf.AlgorithmPBKDF2,
		Salt:       salt,
		Iterations: 600000, // OWASP recommendation
		KeyLength:  32,     // 256-bit key
		Hash:       crypto.SHA256,
	}

	// Derive key from password
	key, err := adapter.DeriveKey(password, params)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Derived key length: %d bytes\n", len(key))
	// Output: Derived key length: 32 bytes
}

// Example demonstrates Argon2id usage for password-based key derivation
func Example_argon2id() {
	// Create Argon2id adapter (recommended variant)
	adapter := kdf.NewArgon2idAdapter()

	// Password
	password := []byte("my-secure-password")

	// Generate a random salt (should be stored with the derived key)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}

	// Configure parameters with recommended settings
	params := &kdf.KDFParams{
		Algorithm: kdf.AlgorithmArgon2id,
		Salt:      salt,
		Memory:    64 * 1024, // 64 MiB
		Time:      3,         // 3 iterations
		Threads:   4,         // 4 parallel threads
		KeyLength: 32,        // 256-bit key
	}

	// Derive key from password
	key, err := adapter.DeriveKey(password, params)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Derived key length: %d bytes\n", len(key))
	// Output: Derived key length: 32 bytes
}

// Example demonstrates using default parameters
func Example_defaultParams() {
	// Get default parameters for HKDF
	params := kdf.DefaultParams(kdf.AlgorithmHKDF)

	// Add required parameters (salt is optional for HKDF)
	params.Salt = []byte("my-salt-value-16") // 16 bytes

	adapter := kdf.NewHKDFAdapter()
	ikm := []byte("my input key material")

	key, err := adapter.DeriveKey(ikm, params)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Algorithm: %s\n", params.Algorithm)
	fmt.Printf("Derived key length: %d bytes\n", len(key))
	// Output:
	// Algorithm: HKDF
	// Derived key length: 32 bytes
}

// Example demonstrates parameter validation
func Example_validateParams() {
	adapter := kdf.NewPBKDF2Adapter()

	// Invalid parameters - salt too short
	params := &kdf.KDFParams{
		Algorithm:  kdf.AlgorithmPBKDF2,
		Salt:       []byte("short"), // Less than 16 bytes
		Iterations: 600000,
		KeyLength:  32,
		Hash:       crypto.SHA256,
	}

	// Validate parameters before use
	if err := adapter.ValidateParams(params); err != nil {
		fmt.Printf("Validation error: %v\n", err)
	}
	// Output: Validation error: kdf: invalid salt
}

// Example demonstrates deriving multiple keys from the same IKM
func Example_multipleKeys() {
	adapter := kdf.NewHKDFAdapter()
	ikm := []byte("shared secret")
	salt := []byte("common-salt-val1") // 16 bytes

	// Derive encryption key
	encParams := &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Salt:      salt,
		Info:      []byte("encryption-key"),
		KeyLength: 32,
		Hash:      crypto.SHA256,
	}
	encKey, err := adapter.DeriveKey(ikm, encParams)
	if err != nil {
		log.Fatal(err)
	}

	// Derive authentication key (HMAC)
	authParams := &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Salt:      salt,
		Info:      []byte("authentication-key"),
		KeyLength: 32,
		Hash:      crypto.SHA256,
	}
	authKey, err := adapter.DeriveKey(ikm, authParams)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encryption key length: %d bytes\n", len(encKey))
	fmt.Printf("Authentication key length: %d bytes\n", len(authKey))
	// Output:
	// Encryption key length: 32 bytes
	// Authentication key length: 32 bytes
}

// Example demonstrates choosing the right KDF algorithm
func Example_algorithmSelection() {
	// HKDF - Best for high-entropy input (ECDH, random keys)
	hkdfAdapter := kdf.NewHKDFAdapter()
	fmt.Printf("HKDF algorithm: %s\n", hkdfAdapter.Algorithm())

	// PBKDF2 - For password-based derivation (widely supported)
	pbkdf2Adapter := kdf.NewPBKDF2Adapter()
	fmt.Printf("PBKDF2 algorithm: %s\n", pbkdf2Adapter.Algorithm())

	// Argon2id - Best for password-based derivation (most secure)
	argon2Adapter := kdf.NewArgon2idAdapter()
	fmt.Printf("Argon2id algorithm: %s\n", argon2Adapter.Algorithm())

	// Output:
	// HKDF algorithm: HKDF
	// PBKDF2 algorithm: PBKDF2
	// Argon2id algorithm: Argon2id
}
