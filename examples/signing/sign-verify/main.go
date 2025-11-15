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

// Package main demonstrates signing data and verifying signatures.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	tmpDir := filepath.Join(os.TempDir(), "keystore-signing")
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

	fmt.Println("=== Sign and Verify Examples ===")

	// Data to sign
	message := []byte("Hello, go-keychain! This is a test message for signing.")
	fmt.Printf("Message to sign: %s\n\n", message)

	// Example 1: RSA Signing and Verification
	fmt.Println("1. RSA-2048 Signing...")
	rsaAttrs := &types.KeyAttributes{
		CN:           "rsa-signing-key",
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

	// Get signer
	rsaSigner, err := ks.Signer(rsaAttrs)
	if err != nil {
		log.Fatalf("Failed to get RSA signer: %v", err)
	}

	// Hash the message
	hash := sha256.Sum256(message)

	// Sign using crypto.Signer interface
	rsaSignature, err := rsaSigner.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		log.Fatalf("Failed to sign with RSA: %v", err)
	}
	fmt.Printf("   ✓ RSA signature created (%d bytes)\n", len(rsaSignature))

	// Verify RSA signature
	rsaPubKey := rsaSigner.Public().(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hash[:], rsaSignature)
	if err != nil {
		log.Fatalf("RSA signature verification failed: %v", err)
	}
	fmt.Printf("   ✓ RSA signature verified successfully\n\n")

	// Example 2: ECDSA Signing and Verification
	fmt.Println("2. ECDSA P-256 Signing...")
	ecdsaAttrs := &types.KeyAttributes{
		CN:           "ecdsa-signing-key",
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

	// Get signer
	ecdsaSigner, err := ks.Signer(ecdsaAttrs)
	if err != nil {
		log.Fatalf("Failed to get ECDSA signer: %v", err)
	}

	// Sign using crypto.Signer interface
	ecdsaSignature, err := ecdsaSigner.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		log.Fatalf("Failed to sign with ECDSA: %v", err)
	}
	fmt.Printf("   ✓ ECDSA signature created (%d bytes)\n", len(ecdsaSignature))

	// Verify ECDSA signature
	ecdsaPubKey := ecdsaSigner.Public().(*ecdsa.PublicKey)
	valid := ecdsa.VerifyASN1(ecdsaPubKey, hash[:], ecdsaSignature)
	if !valid {
		log.Fatal("ECDSA signature verification failed")
	}
	fmt.Printf("   ✓ ECDSA signature verified successfully\n\n")

	// Example 3: Ed25519 Signing and Verification
	fmt.Println("3. Ed25519 Signing...")
	ed25519Attrs := &types.KeyAttributes{
		CN:           "ed25519-signing-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
	}

	_, err = ks.GenerateEd25519(ed25519Attrs)
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Get signer
	ed25519Signer, err := ks.Signer(ed25519Attrs)
	if err != nil {
		log.Fatalf("Failed to get Ed25519 signer: %v", err)
	}

	// Sign using crypto.Signer interface
	// Note: Ed25519 doesn't require pre-hashing
	ed25519Signature, err := ed25519Signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		log.Fatalf("Failed to sign with Ed25519: %v", err)
	}
	fmt.Printf("   ✓ Ed25519 signature created (%d bytes)\n", len(ed25519Signature))

	// Verify Ed25519 signature
	ed25519PubKey := ed25519Signer.Public().(ed25519.PublicKey)
	valid = ed25519.Verify(ed25519PubKey, message, ed25519Signature)
	if !valid {
		log.Fatal("Ed25519 signature verification failed")
	}
	fmt.Printf("   ✓ Ed25519 signature verified successfully\n\n")

	// Example 4: Demonstrating signature determinism with RSA
	fmt.Println("4. Demonstrating RSA PSS (probabilistic) vs PKCS1v15 (deterministic)...")

	// Sign twice with PSS - should produce different signatures
	sig1, _ := rsaSigner.Sign(rand.Reader, hash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	sig2, _ := rsaSigner.Sign(rand.Reader, hash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})

	fmt.Printf("   RSA-PSS signatures are probabilistic (different each time)\n")
	fmt.Printf("   Signature 1 != Signature 2: %v\n", string(sig1) != string(sig2))

	// Both should verify successfully
	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, hash[:], sig1, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		log.Fatalf("PSS signature 1 verification failed: %v", err)
	}
	err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, hash[:], sig2, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		log.Fatalf("PSS signature 2 verification failed: %v", err)
	}
	fmt.Printf("   ✓ Both PSS signatures verified successfully\n")

	fmt.Println("\n✓ All signing and verification examples completed successfully!")
}
