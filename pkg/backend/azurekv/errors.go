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

//go:build azurekv

package azurekv

import "errors"

var (
	// ErrNotInitialized is returned when the Azure Key Vault client is not initialized.
	ErrNotInitialized = errors.New("azurekv: client not initialized")

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("azurekv: invalid configuration")

	// ErrKeyNotFound is returned when a key is not found in Azure Key Vault.
	ErrKeyNotFound = errors.New("azurekv: key not found")

	// ErrUnsupportedKeyType is returned when an unsupported key type is requested.
	ErrUnsupportedKeyType = errors.New("azurekv: unsupported key type")

	// ErrInvalidVaultURL is returned when an invalid vault URL is specified.
	ErrInvalidVaultURL = errors.New("azurekv: invalid vault URL")

	// ErrInvalidKeySize is returned when an invalid key size is provided.
	ErrInvalidKeySize = errors.New("azurekv: invalid key size")

	// ErrKeyAlreadyExists is returned when attempting to create a key that already exists.
	ErrKeyAlreadyExists = errors.New("azurekv: key already exists")

	// ErrInvalidAlgorithm is returned when an invalid algorithm is specified.
	ErrInvalidAlgorithm = errors.New("azurekv: invalid algorithm")

	// ErrSignatureFailed is returned when signature verification fails.
	ErrSignatureFailed = errors.New("azurekv: signature verification failed")

	// ErrInvalidCurve is returned when an invalid elliptic curve is specified.
	ErrInvalidCurve = errors.New("azurekv: invalid elliptic curve")

	// ErrInvalidCredentials is returned when Azure credentials are invalid.
	ErrInvalidCredentials = errors.New("azurekv: invalid credentials")

	// ErrUnsupportedOperation is returned when an operation is not supported.
	ErrUnsupportedOperation = errors.New("azurekv: unsupported operation")
)
