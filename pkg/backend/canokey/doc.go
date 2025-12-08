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

// Package canokey provides a backend implementation for CanoKey hardware tokens
// using the PIV (Personal Identity Verification) application.
//
// # CanoKey PIV Backend
//
// The CanoKey backend is a specialized adapter that provides optimized support
// for CanoKey open-source security keys while maintaining compatibility with the
// standard backend.Backend interface. It wraps PKCS#11 operations with CanoKey-specific
// features and constraints.
//
// CanoKey is an open-source PIV-compatible security key that works with standard
// PKCS#11 libraries like OpenSC. It supports the same PIV slots as YubiKey and
// provides comparable cryptographic functionality.
//
// Key Features:
//
//   - PIV slot management (9a, 9c, 9d, 9e, 82-95)
//   - Hardware and virtual (QEMU) device support
//   - Automatic token detection and configuration
//   - CanoKey-specific firmware version handling
//   - Hardware-backed key storage and operations (except QEMU virtual mode)
//   - Ed25519/X25519 support on firmware 3.0.0+
//
// PIV Slots:
//
// CanoKey PIV supports the same slots as YubiKey for key storage:
//
//   - 0x9a: PIV Authentication - General authentication, requires PIN
//   - 0x9c: Digital Signature - Always requires PIN for operations
//   - 0x9d: Key Management - Used for encryption/decryption, requires PIN
//   - 0x9e: Card Authentication - No PIN required for operations
//   - 0x82-0x95: Retired Key Management - 20 additional storage slots
//
// Firmware Versions:
//
// CanoKey uses semantic versioning (e.g., 1.0.0, 2.0.0, 3.0.0) unlike YubiKey's
// encoded format. Feature support by version:
//
//   - 2.0+: RSA 2048/4096, ECDSA P-256/P-384
//   - 3.0+: Ed25519/X25519 support
//
// Hardware vs Virtual:
//
// CanoKey can run in two modes:
//
//   - Hardware: Physical CanoKey device (HardwareBacked = true)
//   - Virtual (QEMU): Software emulation for testing (HardwareBacked = false)
//
// Set Config.IsVirtual = true when using CanoKey QEMU for CI/CD pipelines.
//
// Usage Example:
//
//	import "github.com/jeremyhahn/go-keychain/pkg/backend/canokey"
//
//	// Create CanoKey backend for physical device
//	config := &canokey.Config{
//		PIN: "123456",  // Default CanoKey PIN
//	}
//
//	backend, err := canokey.NewBackend(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer backend.Close()
//
//	// Initialize backend
//	err = backend.Initialize()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Generate RSA key in PIV Authentication slot
//	attrs := &types.KeyAttributes{
//		CN:           "my-canokey-key",
//		KeyAlgorithm: x509.RSA,
//		RSAAttributes: &types.RSAAttributes{
//			KeySize: 2048,
//		},
//	}
//
//	// Specify PIV slot using KeyID
//	attrs.KeyID = canokey.SlotAuthentication
//
//	key, err := backend.GenerateRSA(attrs)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Virtual Mode (CanoKey QEMU):
//
// For CI/CD testing without physical hardware:
//
//	config := &canokey.Config{
//		PIN:       "123456",
//		IsVirtual: true,  // Marks as software emulation
//	}
//
// Compatibility:
//
// The CanoKey backend implements the standard backend.Backend interface,
// making it fully compatible with existing code that uses the backend
// abstraction. It can be used as a drop-in replacement for other PIV backends.
//
// Requirements:
//
//   - CanoKey device (hardware or QEMU virtual)
//   - OpenSC PKCS#11 library (opensc-pkcs11.so)
//   - Appropriate USB permissions for CanoKey access (hardware only)
//
// See also:
//
//   - https://github.com/canokeys/canokey-core
//   - https://github.com/canokeys/canokey-qemu
//   - https://www.canokeys.org/
package canokey
