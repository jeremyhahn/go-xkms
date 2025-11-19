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

package verification_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/verification"
)

// Example_rsaPKCS1v15 demonstrates RSA PKCS1v15 signature verification
func Example_rsaPKCS1v15() {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Create and hash test data
	data := []byte("important message")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		log.Fatal(err)
	}

	// Create verifier
	verifier := verification.NewVerifier(nil)

	// Verify signature with options
	opts := &verification.VerifyOpts{
		KeyAttributes: &verification.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RSA PKCS1v15 signature verified successfully")
	// Output: RSA PKCS1v15 signature verified successfully
}

// Example_rsaPSS demonstrates RSA-PSS signature verification
func Example_rsaPSS() {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Create and hash test data
	data := []byte("important message")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Configure PSS options
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       hash,
	}

	// Sign the data with PSS
	signature, err := rsa.SignPSS(rand.Reader, privateKey, hash, hashed, pssOpts)
	if err != nil {
		log.Fatal(err)
	}

	// Create verifier
	verifier := verification.NewVerifier(nil)

	// Verify signature with PSS options
	opts := &verification.VerifyOpts{
		KeyAttributes: &verification.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		PSSOptions: pssOpts,
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RSA-PSS signature verified successfully")
	// Output: RSA-PSS signature verified successfully
}

// Example_ecdsa demonstrates ECDSA signature verification
func Example_ecdsa() {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Create and hash test data
	data := []byte("important message")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashed)
	if err != nil {
		log.Fatal(err)
	}

	// Create verifier
	verifier := verification.NewVerifier(nil)

	// Verify signature with options
	opts := &verification.VerifyOpts{
		KeyAttributes: &verification.KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
		},
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("ECDSA signature verified successfully")
	// Output: ECDSA signature verified successfully
}

// Example_ed25519 demonstrates Ed25519 signature verification
func Example_ed25519() {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Create test data (Ed25519 doesn't require pre-hashing)
	data := []byte("important message")

	// Sign the data
	signature := ed25519.Sign(privateKey, data)

	// Create verifier
	verifier := verification.NewVerifier(nil)

	// Verify signature
	opts := &verification.VerifyOpts{
		KeyAttributes: &verification.KeyAttributes{
			KeyAlgorithm: x509.Ed25519,
		},
	}

	err = verifier.Verify(publicKey, crypto.SHA256, data, signature, opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Ed25519 signature verified successfully")
	// Output: Ed25519 signature verified successfully
}

// mockChecksumStore demonstrates a simple checksum storage implementation
type mockChecksumStore struct {
	checksums map[string][]byte
}

func (m *mockChecksumStore) Checksum(opts *verification.VerifyOpts) ([]byte, error) {
	/* Convert to string */
	checksum, exists := m.checksums[string(opts.BlobCN)]
	if !exists {
		return nil, verification.ErrChecksumNotFound
	}
	return checksum, nil
}

// Example_integrityCheck demonstrates signature verification with integrity checking
func Example_integrityCheck() {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Create and hash test data
	data := []byte("important message")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		log.Fatal(err)
	}

	// Setup checksum store with the expected checksum
	checksumStore := &mockChecksumStore{
		checksums: make(map[string][]byte),
	}
	blobName := "my-blob"
	checksumStore.checksums[blobName] = []byte(hex.EncodeToString(hashed))

	// Create verifier with checksum provider
	verifier := verification.NewVerifier(checksumStore)

	// Verify signature with integrity check enabled
	opts := &verification.VerifyOpts{
		KeyAttributes: &verification.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		BlobCN:         []byte(blobName),
		IntegrityCheck: true,
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Signature and integrity check verified successfully")
	// Output: Signature and integrity check verified successfully
}

// Example_simpleVerification demonstrates basic signature verification without options
func Example_simpleVerification() {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Create and hash test data
	data := []byte("simple message")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		log.Fatal(err)
	}

	// Create verifier
	verifier := verification.NewVerifier(nil)

	// Verify without options (defaults to PKCS1v15 for RSA)
	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Simple verification successful")
	// Output: Simple verification successful
}
