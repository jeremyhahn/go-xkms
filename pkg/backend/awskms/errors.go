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

//go:build awskms

package awskms

import "errors"

var (
	// ErrNotInitialized is returned when the KMS client is not initialized.
	ErrNotInitialized = errors.New("awskms: client not initialized")

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("awskms: invalid configuration")

	// ErrKeyNotFound is returned when a key is not found in KMS.
	ErrKeyNotFound = errors.New("awskms: key not found")

	// ErrUnsupportedKeyType is returned when an unsupported key type is requested.
	ErrUnsupportedKeyType = errors.New("awskms: unsupported key type")

	// ErrInvalidRegion is returned when an invalid AWS region is specified.
	ErrInvalidRegion = errors.New("awskms: invalid region")

	// ErrInvalidKeySpec is returned when an invalid key spec is provided.
	ErrInvalidKeySpec = errors.New("awskms: invalid key spec")

	// ErrKeyAlreadyExists is returned when attempting to create a key that already exists.
	ErrKeyAlreadyExists = errors.New("awskms: key already exists")

	// ErrInvalidAlgorithm is returned when an invalid algorithm is specified.
	ErrInvalidAlgorithm = errors.New("awskms: invalid algorithm")

	// ErrSignatureFailed is returned when signature verification fails.
	ErrSignatureFailed = errors.New("awskms: signature verification failed")

	// ErrMetadataStorage is returned when metadata storage operations fail.
	ErrMetadataStorage = errors.New("awskms: metadata storage failed")

	// ErrInvalidKeyID is returned when the key ID format is invalid.
	ErrInvalidKeyID = errors.New("awskms: invalid key ID")
)
