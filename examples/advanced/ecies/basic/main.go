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

// Package main demonstrates basic ECIES (Elliptic Curve Integrated Encryption Scheme) usage.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/ecies"
)

func main() {
	fmt.Println("=== ECIES Basic Example ===")

	// Example 1: Basic encryption and decryption
	basicExample()

	// Example 2: Using different elliptic curves
	multiCurveExample()

	// Example 3: Large message encryption
	largeMessageExample()
}

// basicExample demonstrates basic ECIES encryption and decryption
func basicExample() {
	fmt.Println("Example 1: Basic Encryption and Decryption")
	fmt.Println("==========================================")

	// Generate a key pair for the recipient
	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate recipient key: %v", err)
	}
	recipientPub := &recipientPriv.PublicKey

	// Message to encrypt
	message := []byte("Hello, ECIES! This is a secret message.")

	// Encrypt the message using the recipient's public key
	ciphertext, err := ecies.Encrypt(rand.Reader, recipientPub, message, nil)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Original message:     %s\n", message)
	fmt.Printf("Message size:         %d bytes\n", len(message))
	fmt.Printf("Ciphertext size:      %d bytes\n", len(ciphertext))
	fmt.Printf("Overhead:             %d bytes (ephemeral key + nonce + tag)\n", len(ciphertext)-len(message))

	// Decrypt the message using the recipient's private key
	decrypted, err := ecies.Decrypt(recipientPriv, ciphertext, nil)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted message:    %s\n", decrypted)
	fmt.Printf("Decryption successful: %v\n\n", string(decrypted) == string(message))
}

// multiCurveExample demonstrates ECIES with different elliptic curves
func multiCurveExample() {
	fmt.Println("Example 2: Different Elliptic Curves")
	fmt.Println("====================================")

	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256 (NIST curve, 256-bit)", elliptic.P256()},
		{"P-384 (NIST curve, 384-bit)", elliptic.P384()},
		{"P-521 (NIST curve, 521-bit)", elliptic.P521()},
	}

	message := []byte("Testing different curves")

	for _, c := range curves {
		fmt.Printf("\nCurve: %s\n", c.name)
		fmt.Println(strings.Repeat("-", len(c.name)+7))

		// Generate key pair for this curve
		priv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate key for %s: %v", c.name, err)
		}

		// Encrypt
		ciphertext, err := ecies.Encrypt(rand.Reader, &priv.PublicKey, message, nil)
		if err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}

		// Decrypt
		decrypted, err := ecies.Decrypt(priv, ciphertext, nil)
		if err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}

		fmt.Printf("  Message size:    %d bytes\n", len(message))
		fmt.Printf("  Ciphertext size: %d bytes\n", len(ciphertext))
		fmt.Printf("  Decryption OK:   %v\n", string(decrypted) == string(message))
	}
	fmt.Println()
}

// largeMessageExample demonstrates encrypting larger data
func largeMessageExample() {
	fmt.Println("Example 3: Encrypting Large Messages")
	fmt.Println("====================================")

	recipientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate recipient key: %v", err)
	}

	// Create messages of different sizes
	sizes := []int{100, 1024, 10 * 1024, 100 * 1024} // 100B, 1KB, 10KB, 100KB

	for _, size := range sizes {
		// Create a message of specified size
		message := make([]byte, size)
		_, err := rand.Read(message)
		if err != nil {
			log.Fatalf("Failed to generate random message: %v", err)
		}

		// Encrypt
		ciphertext, err := ecies.Encrypt(rand.Reader, &recipientPriv.PublicKey, message, nil)
		if err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}

		// Decrypt
		decrypted, err := ecies.Decrypt(recipientPriv, ciphertext, nil)
		if err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}

		overhead := len(ciphertext) - len(message)
		percentOverhead := float64(overhead) / float64(len(message)) * 100

		fmt.Printf("Message size: %7d bytes -> Ciphertext: %7d bytes (%.1f%% overhead)\n",
			len(message), len(ciphertext), percentOverhead)

		if string(decrypted) != string(message) {
			log.Fatal("Decryption mismatch!")
		}
	}
	fmt.Println()
}
