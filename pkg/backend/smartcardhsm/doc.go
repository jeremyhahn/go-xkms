// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package smartcardhsm provides a backend for SmartCard-HSM devices.
//
// SmartCard-HSM is a lightweight hardware security module available as a
// USB token (Nitrokey HSM) or smart card (CardContact SmartCard-HSM).
// It provides secure key storage with support for M-of-N key splitting
// using DKEK (Device Key Encryption Key).
//
// # Features
//
//   - Standard PKCS#11 operations via embedded pkcs11.Backend
//   - M-of-N DKEK key splitting using Shamir's Secret Sharing
//   - Secure key backup/restore with DKEK-wrapped keys
//   - Key migration between devices with matching DKEK
//   - Device initialization with configurable PIN retry counter
//
// # Build Tags
//
// This package requires the "smartcardhsm" build tag:
//
//	go build -tags smartcardhsm
//
// Without this tag, stub implementations are provided that return errors.
//
// # DKEK (Device Key Encryption Key)
//
// DKEK enables secure key export/import between SmartCard-HSM devices.
// The DKEK can be split into N shares where M shares are required to
// reconstruct it (M-of-N threshold scheme).
//
// Example: 3-of-5 DKEK setup
//
//	// Generate 5 shares, require 3 to reconstruct
//	shares, err := smartcardhsm.GenerateDKEKShares(5, 3)
//
//	// Initialize device with DKEK
//	backend.InitializeDevice(soPin, userPin, 3, 5, 3)
//
//	// Import shares (need 3 of 5)
//	backend.ImportDKEKShare(shares[0])
//	backend.ImportDKEKShare(shares[2])
//	backend.ImportDKEKShare(shares[4])
//
//	// Now can wrap/unwrap keys
//	wrapped, _ := backend.WrapKey(keyRef)
//	backend.UnwrapKey(keyRef, wrapped)
//
// # Dependencies
//
// This package requires:
//   - github.com/ebfe/scard - PC/SC smart card communication
//   - OpenSC PKCS#11 library installed on the system
//
// On Debian/Ubuntu:
//
//	apt install opensc pcscd libpcsclite-dev
//
// On macOS:
//
//	brew install opensc
package smartcardhsm
