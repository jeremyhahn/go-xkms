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

	// ErrKeyGenerationFailed indicates a key generation operation failed.
	ErrKeyGenerationFailed = errors.New("xkey/pkcs11: key generation failed")

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

	// ErrImportFailed indicates externally generated key material could not be
	// imported into the backend.
	ErrImportFailed = errors.New("xkey/pkcs11: key import failed")

	// ErrGetImportParamsFailed indicates the wrapping key and import token for
	// a key-import ceremony could not be obtained from the backend.
	ErrGetImportParamsFailed = errors.New("xkey/pkcs11: get import parameters failed")

	// ErrImportKeyFailed indicates the backend rejected the wrapped key
	// material. It wraps the backend's cause so a bad import token is
	// distinguishable from malformed material.
	ErrImportKeyFailed = errors.New("pkcs11: import key failed")

	// ErrIPCConnectionFailed indicates the IPC transport could not connect
	// to the xkey daemon socket.
	ErrIPCConnectionFailed = errors.New("xkey/pkcs11: ipc connection failed")

	// ErrIPCRequestCanceled indicates the caller's context ended before the
	// xkey instance answered: an already-ended context sends nothing, and one
	// ending mid-exchange abandons the connection, which cancels the request
	// on the xkey side.
	ErrIPCRequestCanceled = errors.New("xkey/pkcs11: ipc request canceled")
)

// DetailError appends detail text directly after a wrapped error while
// preserving errors.Is / errors.As matching of the wrapped error through
// Unwrap. The detail text carries its own leading separator.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
