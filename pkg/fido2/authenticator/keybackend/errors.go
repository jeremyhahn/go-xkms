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

package keybackend

import "errors"

// Key backend errors.
var (
	// ErrKeyNotFound indicates the requested key does not exist.
	ErrKeyNotFound = errors.New("keybackend: key not found")

	// ErrUnsupportedAlgorithm indicates the algorithm is not supported by this backend.
	ErrUnsupportedAlgorithm = errors.New("keybackend: unsupported algorithm")

	// ErrExportNotSupported indicates private key export is not supported.
	ErrExportNotSupported = errors.New("keybackend: export not supported")

	// ErrImportNotSupported indicates private key import is not supported.
	ErrImportNotSupported = errors.New("keybackend: import not supported")

	// ErrInvalidKeyHandle indicates the key handle is invalid or corrupt.
	ErrInvalidKeyHandle = errors.New("keybackend: invalid key handle")

	// ErrKeyGenerationFailed indicates key generation failed.
	ErrKeyGenerationFailed = errors.New("keybackend: key generation failed")

	// ErrSigningFailed indicates the signing operation failed.
	ErrSigningFailed = errors.New("keybackend: signing failed")

	// ErrAttestationNotSupported indicates attestation is not supported.
	ErrAttestationNotSupported = errors.New("keybackend: attestation not supported")

	// ErrBackendClosed indicates the backend has been closed.
	ErrBackendClosed = errors.New("keybackend: backend closed")

	// ErrInvalidCredentialID indicates the credential ID is invalid.
	ErrInvalidCredentialID = errors.New("keybackend: invalid credential ID")

	// ErrInvalidPKCS8Key indicates the PKCS#8 key data is invalid.
	ErrInvalidPKCS8Key = errors.New("keybackend: invalid PKCS#8 key")

	// ErrBackendNotFound indicates the requested backend does not exist in the composite.
	ErrBackendNotFound = errors.New("keybackend: backend not found")

	// ErrUserVerificationUnavailable indicates a UserVerifier could not
	// reach a decision about the user, for an operational reason such as a
	// lost connection, an exchange that timed out or a revocation source
	// that could not be read. It is not a failed verification, so it spends
	// no uvRetries. Verifiers wrap the cause with SentinelCauseError.
	ErrUserVerificationUnavailable = errors.New("keybackend: user verification unavailable")
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

// MessageError is a typed error that carries a preformatted message. It
// replaces inline formatted-error constructions that do not wrap a cause.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
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

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
