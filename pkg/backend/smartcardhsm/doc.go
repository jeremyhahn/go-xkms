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

// Package smartcardhsm provides a backend implementation for SmartCard-HSM devices.
//
// SmartCard-HSM is a lightweight, affordable hardware security module that provides:
//   - PKCS#11 interface for standard cryptographic operations
//   - DKEK (Device Key Encryption Key) protocol for secure key backup/restore
//   - Support for RSA, ECDSA, and Ed25519 key operations
//   - Symmetric encryption (AES-GCM)
//   - Hardware-backed key storage
//
// # DKEK Protocol
//
// The DKEK protocol enables secure key backup and restore operations using
// Shamir's Secret Sharing scheme. A master DKEK is split into N shares, where
// any M shares can reconstruct the original key (M-of-N threshold scheme).
//
// This is useful for:
//   - Distributing key management across multiple administrators
//   - Creating secure backups of HSM keys
//   - Migrating keys between SmartCard-HSM devices
//   - Distributed key management in raft clusters (e.g., go-dragondb)
//
// # Usage Example
//
//	// Create PKCS#11 config for SmartCard-HSM
//	pkcs11Config := &pkcs11.Config{
//		Library:    "/usr/lib/opensc-pkcs11.so",
//		TokenLabel: "SmartCard-HSM",
//		PIN:        "648219",
//		KeyStorage: keyStorage,
//		CertStorage: certStorage,
//	}
//
//	// Create SmartCard-HSM backend with DKEK
//	config := &smartcardhsm.Config{
//		PKCS11Config:  pkcs11Config,
//		DKEKShares:    5, // Create 5 shares
//		DKEKThreshold: 3, // Need any 3 to reconstruct
//		DKEKStorage:   dkekStorage,
//	}
//
//	backend, err := smartcardhsm.NewBackend(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Initialize and login
//	if err := backend.Initialize(); err != nil {
//		log.Fatal(err)
//	}
//	if err := backend.Login("648219"); err != nil {
//		log.Fatal(err)
//	}
//
//	// Use like any other backend
//	pubKey, err := backend.GenerateRSA([]byte("my-key"), 2048, attrs)
//
// # DKEK Operations
//
// Generate DKEK shares:
//
//	shares, err := backend.DKEK().Generate()
//	// Distribute shares to N administrators
//
// Reconstruct DKEK from shares:
//
//	// Collect M shares from administrators
//	dkek, err := backend.DKEK().Reconstruct(shares)
//
// # Security Considerations
//
// - DKEK shares should be stored securely and distributed to different administrators
// - The threshold should be chosen to balance security and availability
// - Shares can be stored offline, on paper, or in secure vaults
// - The reconstructed DKEK should never be stored; regenerate when needed
// - This backend requires the PKCS#11 library for SmartCard-HSM
//
// # Build Tags
//
// This package requires the 'pkcs11' build tag:
//
//	go build -tags=pkcs11
//
// # Supported Devices
//
// - SmartCard-HSM (Nitrokey HSM, CardContact SmartCard-HSM)
// - Any PKCS#11 device that supports similar DKEK protocol
//
// # References
//
//   - SmartCard-HSM: https://www.smartcard-hsm.com/
//   - PKCS#11: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/
//   - Shamir's Secret Sharing: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
package smartcardhsm
