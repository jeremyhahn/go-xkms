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

// Package tpm2 provides a types.Backend implementation for TPM 2.0 hardware security modules.
//
// This package wraps the low-level pkg/tpm2 library to provide a unified Backend interface
// that can be used interchangeably with other backends (software, PKCS#11, cloud KMS).
//
// Key Features:
//   - Hardware-backed key storage with private keys never leaving the TPM
//   - RSA and ECDSA key generation
//   - Cryptographic signing operations using TPM
//   - Key attestation support via AttestingBackend interface
//   - Platform PCR-based policy authorization
//
// Thread Safety:
// All operations are protected by mutexes, making the backend safe for concurrent access.
//
// Usage:
//
//	config := &tpm2.Config{
//	    Device:         "/dev/tpmrm0",
//	    KeyDir:         "/var/lib/keychain/tpm2",
//	    UseSimulator:   false,
//	    EncryptSession: true,
//	}
//	backend, err := tpm2.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Generate a key
//	attrs := &types.KeyAttributes{
//	    CN:           "my-signing-key",
//	    KeyType:      types.KeyTypeSigning,
//	    KeyAlgorithm: x509.RSA,
//	    RSAAttributes: &types.RSAAttributes{KeySize: 2048},
//	}
//	key, err := backend.GenerateKey(attrs)
package tpm2
