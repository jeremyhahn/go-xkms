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

package secretsharing_test

import (
	"fmt"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/secretsharing"
)

// ExampleShamir demonstrates basic usage of Shamir's Secret Sharing.
func ExampleShamir() {
	// Create a Shamir instance with threshold=3, total=5
	// This means any 3 of the 5 shares can reconstruct the secret
	shamir, err := secretsharing.NewShamir(&secretsharing.ShareConfig{
		Threshold:   3,
		TotalShares: 5,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Split a secret
	secret := []byte("my secret key")
	shares, err := shamir.Split(secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Secret split into %d shares\n", len(shares))

	// Reconstruct using exactly 3 shares (the threshold)
	reconstructed, err := shamir.Combine(shares[:3])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Secret reconstructed successfully: %v\n", string(reconstructed) == string(secret))

	// Output:
	// Secret split into 5 shares
	// Secret reconstructed successfully: true
}

// ExampleShamir_multipleKeyHolders demonstrates a scenario with multiple key holders.
func ExampleShamir_multipleKeyHolders() {
	// Setup: Company needs 3 of 5 executives to approve a transaction
	shamir, _ := secretsharing.NewShamir(&secretsharing.ShareConfig{
		Threshold:   3,
		TotalShares: 5,
	})

	// The master signing key
	masterKey := []byte("master-signing-key-abc123")

	// Distribute shares to 5 executives
	shares, _ := shamir.Split(masterKey)

	// Scenario: 3 executives come together to sign a transaction
	// Using shares from executives 1, 3, and 5
	executiveShares := []secretsharing.Share{
		shares[0], // Executive 1
		shares[2], // Executive 3
		shares[4], // Executive 5
	}

	// Reconstruct the master key
	reconstructedKey, _ := shamir.Combine(executiveShares)

	fmt.Printf("Master key reconstructed: %v\n", string(reconstructedKey) == string(masterKey))

	// Output:
	// Master key reconstructed: true
}

// ExampleShamir_verifyShares demonstrates share verification.
func ExampleShamir_verifyShares() {
	shamir, _ := secretsharing.NewShamir(&secretsharing.ShareConfig{
		Threshold:   2,
		TotalShares: 3,
	})

	secret := []byte("verification test")
	shares, _ := shamir.Split(secret)

	// Verify shares have valid checksums
	err := shamir.Verify(shares)
	if err != nil {
		fmt.Println("Verification failed:", err)
		return
	}

	fmt.Println("All shares verified successfully")

	// Corrupt a share
	shares[0].Value[0] ^= 0xFF

	// Verification should now fail
	err = shamir.Verify(shares)
	if err != nil {
		fmt.Println("Corrupted share detected")
	}

	// Output:
	// All shares verified successfully
	// Corrupted share detected
}
