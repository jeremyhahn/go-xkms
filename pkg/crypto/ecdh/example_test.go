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

package ecdh_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/ecdh"
)

// Example demonstrates basic ECDH key agreement between Alice and Bob
func Example() {
	// Alice generates her key pair
	alicePriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Bob generates his key pair
	bobPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Alice and Bob exchange public keys (over an insecure channel)
	// alicePublic := &alicePriv.PublicKey
	// bobPublic := &bobPriv.PublicKey

	// Alice derives shared secret using Bob's public key
	aliceSecret, _ := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)

	// Bob derives shared secret using Alice's public key
	bobSecret, _ := ecdh.DeriveSharedSecret(bobPriv, &alicePriv.PublicKey)

	// Both secrets are identical
	fmt.Printf("Secrets match: %v\n", string(aliceSecret) == string(bobSecret))
	fmt.Printf("Secret length: %d bytes\n", len(aliceSecret))

	// Output:
	// Secrets match: true
	// Secret length: 32 bytes
}

// ExampleDeriveKey demonstrates deriving encryption keys from a shared secret
func ExampleDeriveKey() {
	// Assume Alice and Bob have already performed ECDH
	alicePriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bobPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sharedSecret, _ := ecdh.DeriveSharedSecret(alicePriv, &bobPriv.PublicKey)

	// Derive different keys for different purposes
	encKey, _ := ecdh.DeriveKey(sharedSecret, nil, []byte("encryption"), 32)
	macKey, _ := ecdh.DeriveKey(sharedSecret, nil, []byte("authentication"), 32)

	fmt.Printf("Encryption key length: %d bytes\n", len(encKey))
	fmt.Printf("MAC key length: %d bytes\n", len(macKey))
	fmt.Printf("Keys are different: %v\n", string(encKey) != string(macKey))

	// Output:
	// Encryption key length: 32 bytes
	// MAC key length: 32 bytes
	// Keys are different: true
}
