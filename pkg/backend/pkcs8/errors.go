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

package pkcs8

import "errors"

var (
	// ErrKeyNotFound is returned when a key does not exist in storage.
	ErrKeyNotFound = errors.New("pkcs8: key not found")

	// ErrKeyAlreadyExists is returned when attempting to generate a key that already exists.
	ErrKeyAlreadyExists = errors.New("pkcs8: key already exists")

	// ErrInvalidKeyType is returned when an unsupported key type is requested.
	ErrInvalidKeyType = errors.New("pkcs8: invalid or unsupported key type")

	// ErrInvalidPassword is returned when password decryption fails.
	ErrInvalidPassword = errors.New("pkcs8: invalid password")

	// ErrStorageClosed is returned when attempting to use a closed backend.
	ErrStorageClosed = errors.New("pkcs8: storage is closed")

	// ErrKeyEncodingFailed is returned when PKCS#8 encoding fails.
	ErrKeyEncodingFailed = errors.New("pkcs8: key encoding failed")

	// ErrKeyDecodingFailed is returned when PKCS#8 decoding fails.
	ErrKeyDecodingFailed = errors.New("pkcs8: key decoding failed")

	// ErrUnsupportedAlgorithm is returned when an unsupported algorithm is requested.
	ErrUnsupportedAlgorithm = errors.New("pkcs8: unsupported algorithm")

	// ErrInvalidAttributes is returned when key attributes are invalid or incomplete.
	ErrInvalidAttributes = errors.New("pkcs8: invalid key attributes")

	// ErrKeyNotSigner is returned when a key doesn't support signing operations.
	ErrKeyNotSigner = errors.New("pkcs8: key does not support signing")

	// ErrKeyNotDecrypter is returned when a key doesn't support decryption operations.
	ErrKeyNotDecrypter = errors.New("pkcs8: key does not support decryption")
)
