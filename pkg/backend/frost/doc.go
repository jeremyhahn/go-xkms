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

// Package frost provides FROST threshold signature support for go-keychain.
//
// This package implements RFC 9591 FROST (Flexible Round-Optimized Schnorr
// Threshold Signatures) as a go-keychain backend. FROST enables threshold
// signing where any M-of-N participants can collaboratively sign messages
// without ever reconstructing the private key.
//
// # Build Requirements
//
// This package requires the "frost" build tag:
//
//	go build -tags frost
//
// Without this tag, a stub implementation is compiled that returns
// ErrNotCompiled for all operations.
//
// # Supported Ciphersuites
//
// All RFC 9591 ciphersuites are supported:
//
//   - FROST-Ed25519-SHA512 (default, recommended)
//   - FROST-ristretto255-SHA512
//   - FROST-Ed448-SHAKE256
//   - FROST-P256-SHA256
//   - FROST-secp256k1-SHA256
//
// # Architecture
//
// The FROST backend separates public and secret storage:
//
//   - PublicStorage: Stores non-sensitive data (group public key,
//     verification shares, metadata) using any storage.Backend
//   - SecretBackend: Stores the secret key share using any types.Backend
//     (TPM2, PKCS#11, Cloud KMS, Vault, etc.)
//
// This separation allows secret shares to be protected by hardware security
// modules while keeping public components easily accessible.
//
// # Key Generation
//
// Keys can be generated using:
//
//   - TrustedDealer (default): A single party generates all key shares.
//     Suitable for controlled environments.
//   - Custom DKG: Implement KeyGenerator for distributed key generation
//     where no single party sees the full key.
//
// # Signing Modes
//
// Two signing modes are available:
//
// Orchestrated Mode (crypto.Signer interface):
// The Signer() method returns a crypto.Signer that internally coordinates
// the FROST protocol rounds. For threshold=1 scenarios, signing completes
// in a single call. For threshold>1, external coordination is required.
//
// Explicit Round Mode (GenerateNonces, SignRound, Aggregate):
// For distributed scenarios, use the explicit round API:
//
//  1. Each participant calls GenerateNonces to get a NoncePackage
//  2. Participants exchange commitments
//  3. Each participant calls SignRound with all commitments to get a SignatureShare
//  4. Any party collects threshold shares and calls Aggregate to produce the signature
//
// # Security Considerations
//
// Nonce Reuse Prevention:
// NONCE REUSE IS CATASTROPHIC in FROST - it reveals the private key.
// Enable EnableNonceTracking (default: true) to prevent reuse. Each nonce
// commitment is hashed and stored; reuse attempts return ErrNonceAlreadyUsed.
//
// Secret Share Protection:
// Configure SecretBackend with a hardware-backed backend (TPM2, PKCS#11,
// Cloud KMS) for production deployments.
//
// Session Management:
// Signing sessions expire after DefaultSessionTimeout (5 minutes).
// Always complete signing sessions promptly.
//
// # Basic Usage
//
//	// Create configuration
//	config := &frost.Config{
//	    PublicStorage:       publicStorageBackend,
//	    SecretBackend:       secretStorageBackend,
//	    Algorithm:           types.FrostAlgorithmEd25519,
//	    DefaultThreshold:    2,
//	    DefaultTotal:        3,
//	    ParticipantID:       1,
//	    EnableNonceTracking: true,
//	}
//
//	// Create backend
//	backend, err := frost.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Generate key
//	attrs := &types.KeyAttributes{
//	    CN:        "my-frost-key",
//	    StoreType: types.StoreFrost,
//	}
//	key, err := backend.GenerateKey(attrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get signer
//	signer, err := backend.Signer(attrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Sign message (for threshold=1)
//	digest := sha256.Sum256([]byte("message"))
//	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
//
// # Explicit Round API Usage
//
//	// Round 1: Generate nonces
//	nonces, err := backend.GenerateNonces("my-frost-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Exchange commitments with other participants...
//	allCommitments := []*frost.Commitment{
//	    {ParticipantID: 1, Commitments: nonces.Commitments},
//	    // ... commitments from other participants
//	}
//
//	// Round 2: Generate signature share
//	share, err := backend.SignRound("my-frost-key", message, nonces, allCommitments)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Collect threshold shares and aggregate
//	allShares := []*frost.SignatureShare{share /* ... */}
//	signature, err := backend.Aggregate("my-frost-key", message, allCommitments, allShares)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify
//	if err := backend.Verify("my-frost-key", message, signature); err != nil {
//	    log.Fatal("verification failed:", err)
//	}
//
// For more information, see the RFC 9591 specification and the go-frost library.
package frost
