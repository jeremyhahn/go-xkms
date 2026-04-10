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

// Package yubikey provides a backend for YubiKey PIV devices.
//
// YubiKey PIV provides hardware-backed key storage conforming to the
// PIV (Personal Identity Verification) standard (FIPS 201).
//
// # Features
//
//   - Standard PKCS#11 operations via embedded pkcs11.Backend
//   - Key attestation using slot 0xF9 (Yubico-specific)
//   - Hardware-backed key generation and storage
//   - Support for RSA and EC keys
//
// # PIV Slots
//
// YubiKey PIV provides the following key slots:
//
//   - 0x9A: PIV Authentication
//   - 0x9C: Digital Signature
//   - 0x9D: Key Management
//   - 0x9E: Card Authentication
//   - 0xF9: Attestation (Yubico-specific)
//
// # Key Attestation
//
// YubiKey supports key attestation which proves that a key was generated
// on genuine YubiKey hardware. The attestation certificate chains to
// Yubico's attestation CA.
//
// Example:
//
//	certs, err := backend.GenerateAttestationStatement(yubikey.SlotAuthentication)
//	// certs[0] = attestation certificate for the key
//	// certs[1] = Yubico intermediate CA (if available)
//
// # Build Tags
//
// This package requires the "pkcs11" build tag:
//
//	go build -tags pkcs11
//
// # Dependencies
//
// This package requires libykcs11 (YubiKey PKCS#11 library):
//
// On Debian/Ubuntu:
//
//	apt install ykcs11
//
// On macOS:
//
//	brew install yubico-piv-tool
package yubikey
