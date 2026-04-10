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

package nativemsg

import "errors"

var (
	// ErrHandshakeRequired indicates an operation was attempted before the
	// X25519 ECDH handshake was completed.
	ErrHandshakeRequired = errors.New("nativemsg: handshake not completed")

	// ErrHandshakeFailed indicates the ECDH key exchange could not be completed.
	ErrHandshakeFailed = errors.New("nativemsg: handshake failed")

	// ErrInvalidPublicKey indicates the peer supplied a malformed or
	// incorrectly-sized public key.
	ErrInvalidPublicKey = errors.New("nativemsg: invalid public key")

	// ErrEncryptionFailed indicates AES-256-GCM encryption failed.
	ErrEncryptionFailed = errors.New("nativemsg: encryption failed")

	// ErrDecryptionFailed indicates AES-256-GCM decryption failed, which may
	// signal tampered or corrupted ciphertext.
	ErrDecryptionFailed = errors.New("nativemsg: decryption failed")

	// ErrReplayDetected indicates a message with a previously-seen or
	// out-of-order nonce counter was received.
	ErrReplayDetected = errors.New("nativemsg: replay attack detected")

	// ErrMessageTooLarge indicates the message exceeds the maximum allowed size.
	ErrMessageTooLarge = errors.New("nativemsg: message exceeds maximum size")

	// ErrReadFailed indicates a failure reading from the native messaging channel.
	ErrReadFailed = errors.New("nativemsg: read failed")

	// ErrWriteFailed indicates a failure writing to the native messaging channel.
	ErrWriteFailed = errors.New("nativemsg: write failed")

	// ErrInvalidManifest indicates the native messaging manifest configuration
	// is invalid.
	ErrInvalidManifest = errors.New("nativemsg: invalid manifest configuration")

	// ErrManifestInstall indicates the native messaging manifest could not be
	// installed.
	ErrManifestInstall = errors.New("nativemsg: manifest installation failed")

	// ErrManifestNotFound indicates the native messaging manifest was not found
	// at the expected path.
	ErrManifestNotFound = errors.New("nativemsg: manifest not found")

	// ErrIPCConnection indicates the IPC connection to the native messaging
	// host could not be established.
	ErrIPCConnection = errors.New("nativemsg: IPC connection failed")

	// ErrPairingRequired indicates the extension has not been paired with the host.
	ErrPairingRequired = errors.New("nativemsg: extension pairing required")

	// ErrPairingRejected indicates the pairing attempt was rejected.
	ErrPairingRejected = errors.New("nativemsg: pairing rejected")

	// ErrPairingInvalidCode indicates the pairing code did not match.
	ErrPairingInvalidCode = errors.New("nativemsg: invalid pairing code")

	// ErrPairingLocked indicates pairing is locked due to too many failures.
	ErrPairingLocked = errors.New("nativemsg: pairing locked due to too many failures")

	// ErrPairingExpired indicates the pairing code has expired.
	ErrPairingExpired = errors.New("nativemsg: pairing code expired")

	// ErrIdentityMismatch indicates the Ed25519 identity key does not match
	// the paired extension.
	ErrIdentityMismatch = errors.New("nativemsg: identity key does not match paired extension")

	// ErrIdentitySignature indicates the Ed25519 identity signature verification
	// failed.
	ErrIdentitySignature = errors.New("nativemsg: identity signature verification failed")

	// ErrIdentityOriginMismatch indicates the extension origin does not match
	// the paired extension's origin.
	ErrIdentityOriginMismatch = errors.New("nativemsg: extension origin mismatch")

	// ErrIdentityLocked indicates identity verification is locked due to too
	// many failures.
	ErrIdentityLocked = errors.New("nativemsg: identity verification locked due to too many failures")

	// ErrParentProcessInvalid indicates the parent process is not a supported
	// browser binary.
	ErrParentProcessInvalid = errors.New("nativemsg: parent process is not a supported browser")

	// ErrPairingRevoked indicates the pairing was revoked while a session was
	// active, typically because the user clicked Unpair in the GUI.
	ErrPairingRevoked = errors.New("nativemsg: pairing revoked")
)
