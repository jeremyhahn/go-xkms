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

//go:build vault

package vault

import "errors"

var (
	// ErrKeyNotFound is returned when a key doesn't exist in Vault
	ErrKeyNotFound = errors.New("vault: key not found")

	// ErrInvalidAlgorithm is returned when an unsupported algorithm is specified
	ErrInvalidAlgorithm = errors.New("vault: invalid algorithm")

	// ErrInvalidKeyType is returned when an unsupported key type is specified
	ErrInvalidKeyType = errors.New("vault: invalid key type")

	// ErrOperationNotSupported is returned when an operation is not supported
	ErrOperationNotSupported = errors.New("vault: operation not supported")

	// ErrVaultConnection is returned when unable to connect to Vault
	ErrVaultConnection = errors.New("vault: connection failed")

	// ErrInvalidResponse is returned when Vault returns an unexpected response
	ErrInvalidResponse = errors.New("vault: invalid response")
)
