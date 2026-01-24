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

// Package authenticator provides a native FIDO2 authenticator implementation.
//
// This package implements a software-based FIDO2 authenticator conforming to
// the CTAP2 (Client to Authenticator Protocol) specification. It supports the
// core WebAuthn operations including credential creation and assertion, as well
// as optional extensions like hmac-secret and credProtect.
//
// # Features
//
// The authenticator supports:
//   - ECDSA P-256 (ES256, COSE algorithm -7)
//   - ECDSA P-384 (ES384, COSE algorithm -35)
//   - ECDSA P-521 (ES512, COSE algorithm -36)
//   - Ed25519 (EdDSA, COSE algorithm -8)
//   - Discoverable credentials (resident keys)
//   - User verification via PIN
//   - Self-attestation
//   - hmac-secret extension
//   - credProtect extension
//
// # Architecture
//
// The authenticator is designed with clean separation of concerns:
//   - Credential storage is abstracted via the CredentialStorage interface
//   - Cryptographic operations use Go's standard crypto packages
//   - State management is thread-safe using atomic operations
//
// # Usage
//
// Create a new authenticator with default configuration:
//
//	auth, err := authenticator.New(authenticator.WithAAGUID(myAAGUID))
//	if err != nil {
//	    return err
//	}
//
//	// Create a credential
//	resp, err := auth.MakeCredential(ctx, options)
//	if err != nil {
//	    return err
//	}
//
//	// Get an assertion
//	assertion, err := auth.GetAssertion(ctx, rpID, challenge, allowList)
//	if err != nil {
//	    return err
//	}
//
// # Security Considerations
//
// This is a software authenticator and does not provide the same security
// guarantees as hardware authenticators. Private keys are stored in memory
// or in the configured credential store. For production use cases requiring
// hardware-backed security, consider integrating with TPM 2.0 or hardware
// security modules.
//
// PIN handling follows CTAP2 specifications with retry limiting and lockout
// protection. The PIN is never stored directly; only a salted hash is retained.
package authenticator
