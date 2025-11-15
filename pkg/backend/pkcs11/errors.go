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

package pkcs11

import "errors"

var (
	// ErrUnsupportedKeyAlgorithm is returned when an unsupported key algorithm is requested.
	ErrUnsupportedKeyAlgorithm = errors.New("pkcs11: unsupported key algorithm")

	// ErrUnsupportedOperation is returned when an operation is not supported by the PKCS#11 backend.
	ErrUnsupportedOperation = errors.New("pkcs11: unsupported operation")

	// ErrInvalidSOPIN is returned when the Security Officer PIN is invalid.
	ErrInvalidSOPIN = errors.New("pkcs11: invalid security officer pin")

	// ErrInvalidUserPIN is returned when the user PIN is invalid.
	ErrInvalidUserPIN = errors.New("pkcs11: invalid user pin")

	// ErrInvalidTokenLabel is returned when the token label is invalid or empty.
	ErrInvalidTokenLabel = errors.New("pkcs11: invalid token label")

	// ErrInvalidSOPINLength is returned when the SO PIN is too short.
	// PKCS#11 typically requires PINs to be at least 4 characters.
	ErrInvalidSOPINLength = errors.New("pkcs11: invalid SO pin length, must be at least 4 characters")

	// ErrInvalidPINLength is returned when the user PIN is too short.
	// PKCS#11 typically requires PINs to be at least 4 characters.
	ErrInvalidPINLength = errors.New("pkcs11: invalid pin length, must be at least 4 characters")

	// ErrNotInitialized is returned when the token has not been initialized.
	ErrNotInitialized = errors.New("pkcs11: token not initialized")

	// ErrAlreadyInitialized is returned when attempting to initialize an already initialized token.
	ErrAlreadyInitialized = errors.New("pkcs11: token already initialized")

	// ErrContextNotFound is returned when a context is not found in the cache.
	ErrContextNotFound = errors.New("pkcs11: context not found in cache")

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("pkcs11: invalid configuration")

	// ErrLibraryNotFound is returned when the PKCS#11 library cannot be found.
	ErrLibraryNotFound = errors.New("pkcs11: library not found")

	// ErrTokenNotFound is returned when the specified token cannot be found.
	ErrTokenNotFound = errors.New("pkcs11: token not found")
)
