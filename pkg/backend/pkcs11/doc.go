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

//go:build pkcs11

// Package pkcs11 implements a backend for PKCS#11 hardware security modules (HSMs).
//
// PKCS#11 is a standard for cryptographic token interfaces, allowing applications
// to work with various HSM hardware without vendor-specific code. This package
// provides a backend implementation that stores private keys securely in HSMs where
// they cannot be exported or accessed directly.
//
// # Key Features
//
// - Hardware-backed key storage with PKCS#11 compatible HSMs
// - Support for RSA, ECDSA, and Ed25519 key algorithms
// - Ed25519 support requires PKCS#11 v3.0+ and HSM support (SoftHSM v2.6+)
// - Context caching to prevent re-initialization overhead
// - Thread-safe operations with mutex protection
// - SoftHSM support for testing and development
//
// # Supported HSMs
//
// This backend works with any PKCS#11 compatible HSM, including:
//
//   - SoftHSM (software HSM for testing)
//   - YubiKey HSM
//   - Thales nShield
//   - Gemalto SafeNet
//   - AWS CloudHSM
//   - Any PKCS#11 2.x compatible device
//
// # Usage Example
//
//	// Create configuration
//	config := &pkcs11.Config{
//		CN:         "my-app",
//		Library:    "/usr/lib/softhsm/libsofthsm2.so",
//		TokenLabel: "my-token",
//		PIN:        "user1234",
//		SOPIN:      "admin5678",
//	}
//
//	// Create backend
//	backend, err := pkcs11.NewBackend(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Initialize token (first time only)
//	err = backend.Initialize("admin5678", "user1234")
//	if err != nil && err != pkcs11.ErrAlreadyInitialized {
//		log.Fatal(err)
//	}
//
//	// Login to token
//	if err := backend.Login(); err != nil {
//		log.Fatal(err)
//	}
//
// # Security Considerations
//
// Private keys stored in a PKCS#11 HSM cannot be exported. This is by design
// and provides strong security guarantees. Keys can only be used for cryptographic
// operations through the HSM's API.
//
// PINs should be stored securely and never hardcoded. Consider using environment
// variables, secure key management services, or prompting the user at runtime.
//
// # Testing with SoftHSM
//
// For development and testing, SoftHSM provides a software implementation:
//
//	# Install SoftHSM
//	apt-get install softhsm2  # Debian/Ubuntu
//	yum install softhsm       # RHEL/CentOS
//	brew install softhsm      # macOS
//
//	# Initialize a token
//	softhsm2-util --init-token --slot 0 --label "test-token" \
//		--so-pin "admin1234" --pin "user1234"
//
// # Integration Tests
//
// Full integration tests that interact with actual HSMs (or SoftHSM) should be
// run in Docker containers to avoid modifying the host system. Unit tests focus
// on configuration validation, error handling, and logic that doesn't require
// real HSM interaction.
//
// # Thread Safety
//
// All operations are protected by read-write mutexes, making the backend safe
// for concurrent use from multiple goroutines. Context caching ensures that
// multiple backend instances using the same token share a single PKCS#11 session.
//
// # Error Handling
//
// The package defines several specific error types:
//
//   - ErrNotInitialized: Token needs initialization
//   - ErrAlreadyInitialized: Token is already initialized
//   - ErrInvalidSOPIN: Security Officer PIN is invalid
//   - ErrInvalidUserPIN: User PIN is invalid
//   - ErrInvalidTokenLabel: Token label is missing or invalid
//   - ErrUnsupportedOperation: Operation not supported by PKCS#11
//
// Always check for specific errors to handle different failure scenarios appropriately.
package pkcs11
