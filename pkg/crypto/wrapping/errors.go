// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package wrapping

// NilInputError is returned when a required input pointer is nil.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string {
	return "wrapping: nil input: " + e.Field
}

// EmptyInputError is returned when a required input slice is empty.
type EmptyInputError struct {
	Field string
}

// Error implements the error interface.
func (e *EmptyInputError) Error() string {
	return "wrapping: empty input: " + e.Field
}

// UnsupportedAlgorithmError is returned when a wrap/unwrap request
// uses an algorithm this package does not implement.
type UnsupportedAlgorithmError struct {
	Algorithm string
}

// Error implements the error interface.
func (e *UnsupportedAlgorithmError) Error() string {
	return "wrapping: unsupported algorithm: " + e.Algorithm
}

// InvalidKeySizeError is returned when a wrapping key size is not
// valid for the requested algorithm (e.g., an AES key length other
// than 16, 24, or 32 bytes).
type InvalidKeySizeError struct {
	Algorithm string
	Size      int
}

// Error implements the error interface.
func (e *InvalidKeySizeError) Error() string {
	return "wrapping: invalid key size for " + e.Algorithm
}

// MalformedWrappedKeyError is returned when a wrapped key payload is
// structurally invalid — truncated, wrong AIV, bad MLI, etc.
type MalformedWrappedKeyError struct {
	Reason string
}

// Error implements the error interface.
func (e *MalformedWrappedKeyError) Error() string {
	return "wrapping: malformed wrapped key: " + e.Reason
}

// CryptoError wraps an underlying crypto-library failure. Op names
// the operation ("rsa.EncryptOAEP", "aes.NewCipher", ...) so callers
// get precise diagnostics without brittle string matching.
type CryptoError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *CryptoError) Error() string {
	return "wrapping: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying crypto error.
func (e *CryptoError) Unwrap() error { return e.Err }
