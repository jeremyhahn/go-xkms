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

// Package yubikey provides a backend implementation for YubiKey hardware tokens
// using the PIV (Personal Identity Verification) application.
//
// # YubiKey PIV Backend
//
// The YubiKey backend is a specialized adapter that provides optimized support
// for YubiKey hardware tokens while maintaining compatibility with the standard
// backend.Backend interface. It wraps PKCS#11 operations with YubiKey-specific
// features and constraints.
//
// Key Features:
//
//   - PIV slot management (9a, 9c, 9d, 9e, 82-95)
//   - Management key authentication for administrative operations
//   - Automatic token detection and configuration
//   - YubiKey-specific error messages and diagnostics
//   - Hardware-backed key storage and operations
//
// PIV Slots:
//
// YubiKey PIV supports specific slots for key storage:
//
//   - 0x9a: PIV Authentication - General authentication, requires PIN
//   - 0x9c: Digital Signature - Always requires PIN for operations
//   - 0x9d: Key Management - Used for encryption/decryption, requires PIN
//   - 0x9e: Card Authentication - No PIN required for operations
//   - 0x82-0x95: Retired Key Management - 20 additional storage slots
//
// Management Key:
//
// Administrative operations (key generation, deletion) require authentication
// with the management key. The default management key is:
//
//	010203040506070801020304050607080102030405060708 (hex)
//
// Usage Example:
//
//	import "github.com/jeremyhahn/go-keychain/pkg/backend/yubikey"
//
//	// Create YubiKey backend
//	config := &yubikey.Config{
//		PIN:           "123456",              // Default YubiKey PIN
//		ManagementKey: yubikey.DefaultMgmtKey, // Or custom management key
//	}
//
//	backend, err := yubikey.NewBackend(config)
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
//		CN:           "my-yubikey-key",
//		KeyAlgorithm: x509.RSA,
//		RSAAttributes: &types.RSAAttributes{
//			KeySize: 2048,
//		},
//	}
//
//	// Specify PIV slot using KeyID
//	attrs.KeyID = yubikey.SlotAuthentication
//
//	key, err := backend.GenerateRSA(attrs)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Compatibility:
//
// The YubiKey backend implements the standard backend.Backend interface,
// making it fully compatible with existing code that uses the backend
// abstraction. It can be used as a drop-in replacement for other backends.
//
// Requirements:
//
//   - YubiKey 4 or later (PIV application support)
//   - Yubico PIV Tool and libykcs11.so library installed
//   - Appropriate USB permissions for YubiKey access
//
// See also:
//
//   - https://developers.yubico.com/PIV/Introduction/
//   - https://github.com/Yubico/yubico-piv-tool
package yubikey
