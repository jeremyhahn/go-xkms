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

//go:build tpm2

// Package tpm2 provides a TPM 2.0 backend implementation for secure key management.
//
// # Overview
//
// This package integrates Trusted Platform Module 2.0 hardware or simulators to provide
// hardware-backed cryptographic key storage and operations. Keys stored in the TPM never
// expose their private key material, ensuring maximum security for cryptographic operations.
//
// # Architecture
//
// The TPM 2.0 keystore uses a hierarchical key structure:
//
//	Endorsement Key (EK) - TPM vendor-provisioned root
//	        |
//	Storage Root Key (SRK) - Application-specific root under EK
//	        |
//	Application Keys - Child keys under SRK (RSA, ECDSA)
//
// # Supported Algorithms
//
// RSA: 2048, 3072, 4096 bit keys
//
// ECDSA: P-256, P-384, P-521 curves
//
// Ed25519: Not supported (TPM 2.0 limitation)
//
// # Key Features
//
//   - Hardware-backed key storage with TPM 2.0
//   - Private keys never leave the TPM in plaintext
//   - Storage Root Key (SRK) hierarchy under Endorsement Key
//   - TPM-native signing operations
//   - Password sealing using TPM keyed hash objects
//   - Platform PCR policy support for measured boot integration
//   - Thread-safe concurrent operations
//   - Support for both hardware TPM devices and simulators
//
// # Configuration
//
// The TPM backend requires configuration specifying the TPM device path,
// Storage Root Key handle, and optional platform policy settings:
//
//	config := tpm2.DefaultConfig()
//	config.CN = "my-srk"
//	config.DevicePath = "/dev/tpmrm0"
//	config.SRKHandle = 0x81000001
//
// For simulator testing:
//
//	config.UseSimulator = true
//	config.SimulatorHost = "localhost"
//	config.SimulatorPort = 2321
//
// # Usage Example
//
//	// Create storage backend for TPM blob storage
//	opts := &storage.Options{
//		Path:        "/var/lib/keystore",
//		Permissions: 0600,
//	}
//	backend, err := file.New(opts)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Configure TPM keystore
//	config := tpm2.DefaultConfig()
//	config.CN = "app-srk"
//
//	// Create TPM keystore
//	ks, err := tpm2.NewTPM2KeyStore(config, backend)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer ks.Close()
//
//	// Initialize (first time only)
//	soPIN := keychain.NewClearPassword([]byte("security-officer-pin"))
//	userPIN := keychain.NewClearPassword([]byte("user-pin"))
//	err = ks.Initialize(soPIN, userPIN)
//	if err != nil && !errors.Is(err, keychain.ErrAlreadyInitialized) {
//		log.Fatal(err)
//	}
//
//	// Generate RSA key
//	attrs := &types.KeyAttributes{
//		CN:           "my-signing-key",
//		KeyAlgorithm: x509.RSA,
//		KeyType:      keychain.KeyTypeSigning,
//		StoreType:    keychain.StoreTPM2,
//		RSAAttributes: &types.RSAAttributes{
//			KeySize: 2048,
//		},
//	}
//	opaqueKey, err := ks.GenerateKey(attrs)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Get signer for TPM-backed signing
//	signer, err := ks.Signer(attrs)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Sign data (private key never leaves TPM)
//	digest := sha256.Sum256([]byte("data to sign"))
//	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Thread Safety
//
// All keystore operations are thread-safe and can be called concurrently from
// multiple goroutines. Internal synchronization uses read-write mutexes to allow
// maximum concurrency for read operations while ensuring safety for write operations.
//
// # Integration Tests
//
// Full TPM operations require actual hardware or a simulator (SWTPM). Unit tests
// focus on configuration validation, error handling, and helper functions that
// don't require TPM access. Integration tests should be run in Docker with SWTPM:
//
//	make integration-test
//
// # Security Considerations
//
//   - Private keys are sealed in TPM blobs and never exposed
//   - SRK handle should be in persistent range (0x81000000-0x81FFFFFF)
//   - Platform policy binds keys to specific PCR values for measured boot
//   - User PINs are sealed to TPM keyed hash objects for secure storage
//   - Session encryption protects data in transit to/from TPM
//
// # Limitations
//
//   - Ed25519 not supported by TPM 2.0 specification
//   - Some operations require hardware/simulator access
//   - TPM performance is lower than software-only operations
//   - Key generation is TPM-dependent and may be slow
//
// # References
//
// TPM 2.0 Specification: https://trustedcomputinggroup.org/resource/tpm-library-specification/
//
// go-tpm Library: https://github.com/google/go-tpm
//
// TCG PC Client Platform TPM Profile: https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/
package tpm2
