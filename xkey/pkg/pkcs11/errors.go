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

// Package pkcs11 provides typed errors for the xkey PKCS#11 embedded transport.
package pkcs11

import "errors"

var (
	// ErrServiceNotInitialized indicates the xkms service is not initialized.
	ErrServiceNotInitialized = errors.New("xkey/pkcs11: xkms service not initialized")

	// ErrBackendNotFound indicates the requested backend does not exist.
	ErrBackendNotFound = errors.New("xkey/pkcs11: backend not found")

	// ErrKeyNotFound indicates the requested key does not exist.
	ErrKeyNotFound = errors.New("xkey/pkcs11: key not found")

	// ErrNilRequest indicates a nil request was provided.
	ErrNilRequest = errors.New("xkey/pkcs11: request is nil")

	// ErrSigningFailed indicates a signing operation failed.
	ErrSigningFailed = errors.New("xkey/pkcs11: signing failed")

	// ErrVerifyFailed indicates a verification operation failed.
	ErrVerifyFailed = errors.New("xkey/pkcs11: verification failed")

	// ErrEncryptionFailed indicates an encryption operation failed.
	ErrEncryptionFailed = errors.New("xkey/pkcs11: encryption failed")

	// ErrDecryptionFailed indicates a decryption operation failed.
	ErrDecryptionFailed = errors.New("xkey/pkcs11: decryption failed")

	// ErrDerivationFailed indicates a key derivation operation failed.
	ErrDerivationFailed = errors.New("xkey/pkcs11: key derivation failed")

	// ErrWrappingFailed indicates a key wrapping/unwrapping operation failed.
	ErrWrappingFailed = errors.New("xkey/pkcs11: key wrapping failed")

	// ErrExportFailed indicates a key material export operation failed.
	ErrExportFailed = errors.New("xkey/pkcs11: key export failed")

	// ErrIPCConnectionFailed indicates the IPC transport could not connect
	// to the xkey daemon socket.
	ErrIPCConnectionFailed = errors.New("xkey/pkcs11: ipc connection failed")

	// ErrIPCNotImplemented indicates the operation is not yet supported
	// via the IPC transport MVP.
	ErrIPCNotImplemented = errors.New("xkey/pkcs11: operation not implemented in ipc transport")
)
