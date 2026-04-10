// Copyright (c) 2025 Jeremy Hahn, Automate The Things, LLC. All rights reserved.
// Dual-licensed under the AGPL-3.0 and commercial licenses.
// See LICENSE.md for details.

// Package phone implements a xkmsd backend that proxies cryptographic
// operations to a phone's secure hardware.
//
// The phone backend provides hardware-backed key storage via platform-specific
// secure elements (e.g., Android TEE/StrongBox, iOS Secure Enclave). All
// private keys remain on the phone's secure hardware - the backend acts as a
// transparent proxy for cryptographic operations.
//
// Communication between xkmsd and the phone occurs over BLE (Bluetooth Low
// Energy) or USB with TCP tunneling via ADB (Android Debug Bridge). All
// communication is encrypted using the Noise XX protocol to ensure
// confidentiality and integrity.
//
// Attestation verification is delegated to platform-specific verifiers via the
// PlatformVerifier interface. Platform packages register themselves using
// RegisterPlatform and are activated via blank imports:
//
//	import _ "github.com/jeremyhahn/go-xkms/pkg/backend/phone/android"
//
// The backend implements the following interfaces:
//   - types.KeyProvider: Standard key lifecycle and signature operations
//   - types.AttestingKeyProvider: Key attestation and chain of custody
//   - types.SymmetricKeyProvider: Symmetric encryption operations
//   - types.KeyAgreementProvider: ECDH and key agreement operations
//
// Operations may require biometric authentication (fingerprint, face) on the
// phone to authorize sensitive cryptographic operations, providing additional
// security through user presence verification.
package phone
