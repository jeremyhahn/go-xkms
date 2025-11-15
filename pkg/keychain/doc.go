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

// Package keystore provides a unified interface for secure cryptographic key management
// across multiple backend implementations including software (PKCS#8), hardware security
// modules (PKCS#11), and Trusted Platform Modules (TPM 2.0).
//
// # Overview
//
// The keystore package abstracts the complexity of different key storage mechanisms
// while maintaining consistent behavior and security guarantees. It supports RSA,
// ECDSA, and Ed25519 key algorithms with flexible configuration options.
//
// # Key Concepts
//
// KeyStore: The primary interface for all key operations. Implementations handle
// the details of interacting with specific backends.
//
// OpaqueKey: A private key whose material is managed by a backend. Implements
// crypto.Signer, crypto.Decrypter, and crypto.PrivateKey interfaces.
//
// Backend: The underlying storage mechanism. Can be file-based, hardware-backed,
// or TPM-based.
//
// KeyAttributes: Configuration describing a key's algorithm, purpose, and storage
// parameters.
//
// # Supported Backends
//
// PKCS#8: Software keys stored as encrypted files in the filesystem. Suitable for
// development and scenarios where hardware security isn't required.
//
// PKCS#11: Hardware-backed keys in HSMs, smart cards, or USB tokens. Provides
// hardware-level security with the private key never leaving the device.
//
// TPM 2.0: Keys stored in a Trusted Platform Module. Provides hardware-based
// security and attestation capabilities.
//
// # Basic Usage
//
// Create a keystore and generate a key:
//
//	cfg := &keychain.Config{
//	    StoreType: keychain.StorePKCS8,
//	    RootDir:   "/var/lib/keystore",
//	}
//
//	store, err := pkcs8.NewKeyStore(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer store.Close()
//
//	attrs := &types.KeyAttributes{
//	    CN:                 "my-signing-key",
//	    KeyAlgorithm:       x509.RSA,
//	    SignatureAlgorithm: x509.SHA256WithRSA,
//	    RSAAttributes:      &types.RSAAttributes{KeySize: 2048},
//	    KeyType:            keychain.KeyTypeSigning,
//	    StoreType:          keychain.StorePKCS8,
//	    Hash:               crypto.SHA256,
//	}
//
//	key, err := store.GenerateRSA(attrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Sign data with a key:
//
//	signer, err := store.Signer(attrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	data := []byte("message to sign")
//	hashed := sha256.Sum256(data)
//	signature, err := signer.Sign(rand.Reader, hashed[:], crypto.SHA256)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Verify a signature:
//
//	verifier := store.Verifier(attrs)
//	err = verifier.Verify(key.Public(), crypto.SHA256, hashed[:], signature, nil)
//	if err != nil {
//	    log.Fatal("signature verification failed:", err)
//	}
//
// # Security Considerations
//
// Password Protection: Keys can be protected with passwords. Use strong passwords
// and consider using a secure password manager or vault.
//
// Key Rotation: Regularly rotate keys to minimize exposure from potential compromise.
//
// Hardware Backing: Use PKCS#11 or TPM backends for production systems requiring
// higher security assurances.
//
// Access Control: Implement appropriate file system permissions for PKCS#8 stores
// and use PIN policies for PKCS#11/TPM stores.
//
// # Thread Safety
//
// KeyStore implementations are expected to be safe for concurrent use. However,
// individual OpaqueKey instances are not guaranteed to be thread-safe and should
// not be used concurrently without external synchronization.
//
// # Error Handling
//
// All errors returned by this package can be compared using errors.Is() and errors.As().
// Check for specific error conditions using the package-level error variables:
//
//	if errors.Is(err, keychain.ErrKeyNotFound) {
//	    // Handle missing key
//	}
//
// # Performance
//
// Performance varies significantly by backend:
//
// PKCS#8: Fast for generation and signing. Limited by filesystem I/O.
//
// PKCS#11: Slower than software but provides hardware security. Speed depends
// on the HSM/token implementation.
//
// TPM 2.0: Generally slower than software but provides attestation and platform
// binding. Speed varies by TPM version and implementation.
//
// For high-throughput scenarios, consider:
//   - Caching OpaqueKey instances
//   - Using connection pooling for PKCS#11
//   - Pre-generating keys during initialization
//
// # Testing
//
// For testing, use the PKCS#8 backend with a temporary directory:
//
//	tempDir, _ := os.MkdirTemp("", "keystore-test")
//	defer os.RemoveAll(tempDir)
//
//	cfg := &keychain.Config{
//	    StoreType: keychain.StorePKCS8,
//	    RootDir:   tempDir,
//	}
//
//	store, _ := pkcs8.NewKeyStore(cfg)
//	defer store.Close()
package keychain
