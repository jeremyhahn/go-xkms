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

// Package main demonstrates basic key attestation for proving that
// cryptographic keys were generated in hardware (TPM or HSM) and
// never left the secure boundary.
//
// This example shows:
//  1. Generating a hardware-backed key
//  2. Creating an attestation statement proving the key is hardware-backed
//  3. Verifying the attestation to confirm the key's authenticity
//
// Key attestation is critical for:
//   - Zero-trust security architectures
//   - FIPS 140-2 and Common Criteria compliance
//   - Supply chain security
//   - Proving hardware-backed key provenance
package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/attestation"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	fmt.Println("Key Attestation Example")
	fmt.Println("=======================")
	fmt.Println()

	// In a real scenario, you would initialize a hardware backend (TPM2 or PKCS#11)
	// For demonstration, we'll show the API flow

	// Step 1: Define key attributes for a hardware-backed signing key
	keyAttrs := &types.KeyAttributes{
		CN:                 "hardware-signing-key",
		KeyAlgorithm:       x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyType:            types.KeyTypeSigning,
		StoreType:          types.StoreTPM2, // Could also be PKCS11 for HSM
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	fmt.Println("Step 1: Key Definition")
	fmt.Println("---------------------")
	fmt.Printf("Common Name: %s\n", keyAttrs.CN)
	fmt.Printf("Algorithm: %s\n", keyAttrs.KeyAlgorithm)
	fmt.Printf("Backend: %s\n", keyAttrs.StoreType)
	fmt.Println()

	// Step 2: Create attestation (simulated - would require actual hardware)
	// In a real scenario:
	//   backend := tpm2.NewTPM2KeyStore(...)  // or PKCS#11
	//   attestStmt, err := backend.AttestKey(keyAttrs, nonce)
	//   if err != nil { /* handle error */ }

	fmt.Println("Step 2: Key Attestation")
	fmt.Println("----------------------")
	fmt.Println("In production, hardware backend would:")
	fmt.Println("  1. Get the key from hardware")
	fmt.Println("  2. Use hardware's attestation key to sign attestation data")
	fmt.Println("  3. Include certificate chain proving attestation key")
	fmt.Println("  4. Include nonce and PCR values for freshness")
	fmt.Println()

	// Step 3: Demonstrate attestation verification
	fmt.Println("Step 3: Attestation Verification")
	fmt.Println("--------------------------------")
	fmt.Println("Using attestation.Verifier to validate:")
	fmt.Println("  1. Certificate chain authenticity")
	fmt.Println("  2. Signature over attestation data")
	fmt.Println("  3. Freshness (timestamp and nonce)")
	fmt.Println("  4. PCR values (for TPM2 attestations)")
	fmt.Println()

	// Step 4: Verification options
	fmt.Println("Step 4: Security Considerations")
	fmt.Println("-------------------------------")

	// Secure verification options (production recommended)
	secureOpts := attestation.DefaultVerifyOptions()
	fmt.Println("Secure verification (production recommended):")
	fmt.Printf("  Check freshness: %v (prevents replay attacks)\n", secureOpts.CheckFreshness)
	fmt.Printf("  Freshness window: %d seconds\n", secureOpts.FreshnessWindow)
	fmt.Printf("  Allow self-signed: %v\n", secureOpts.AllowSelfSigned)
	fmt.Println()

	// Insecure verification options (testing only)
	insecureOpts := attestation.InsecureVerifyOptions()
	fmt.Println("Insecure verification (testing/lab only):")
	fmt.Printf("  Check freshness: %v (no replay protection)\n", insecureOpts.CheckFreshness)
	fmt.Printf("  Allow self-signed: %v (risky for production)\n", insecureOpts.AllowSelfSigned)
	fmt.Println()

	// Step 5: Use cases and benefits
	fmt.Println("Step 5: Key Attestation Benefits")
	fmt.Println("--------------------------------")
	fmt.Println("Attestation enables:")
	fmt.Println("  • Proof that keys are hardware-backed")
	fmt.Println("  • Verification of key generation location")
	fmt.Println("  • Supply chain security validation")
	fmt.Println("  • Zero-trust architecture support")
	fmt.Println("  • Compliance with security standards (FIPS 140-2, CC)")
	fmt.Println()

	// Step 6: Integration with keychain
	fmt.Println("Step 6: Integration with go-keychain")
	fmt.Println("------------------------------------")
	fmt.Println("Typical workflow:")
	fmt.Println("  1. Initialize hardware backend (TPM2 or PKCS#11)")
	fmt.Println("  2. Generate key with backend.GenerateKey()")
	fmt.Println("  3. Attest key with backend.AttestKey()")
	fmt.Println("  4. Verify attestation with attestation.Verifier")
	fmt.Println("  5. Store attestation with key metadata")
	fmt.Println("  6. Periodically re-attest for ongoing validation")
	fmt.Println()

	// Step 7: Code example
	fmt.Println("Step 7: Code Example (pseudocode)")
	fmt.Println("---------------------------------")
	fmt.Print(`
// Initialize hardware backend
backend := tpm2.NewTPM2KeyStore(config, ...)
defer func() { _ = backend.Close() }()

// Generate key
privKey, err := backend.GenerateKey(keyAttrs)
if err != nil { log.Fatal(err) }

// Attest key (proves it's hardware-backed)
attestStmt, err := backend.AttestKey(keyAttrs, nonce)
if err != nil { log.Fatal(err) }

// Verify attestation
verifier := attestation.NewVerifier(trustedRoots)
opts := attestation.DefaultVerifyOptions()
err = verifier.Verify(attestStmt.(*attestation.AttestationStatement), opts)
if err != nil { log.Fatal("attestation verification failed:", err) }

// Attestation is valid - key is proven to be hardware-backed
fmt.Println("Key attestation verified successfully")
`)
	fmt.Println()

	log.Println("Example complete - review code for integration details")
}
