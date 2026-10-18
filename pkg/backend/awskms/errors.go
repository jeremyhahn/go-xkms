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

//go:build awskms

package awskms

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

var (
	// ErrNotInitialized is returned when the KMS client is not initialized.
	ErrNotInitialized = errors.New("awskms: client not initialized")

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("awskms: invalid configuration")

	// ErrKeyNotFound is returned when a key is not found in KMS. It is an
	// alias of backend.ErrKeyNotFound so errors.Is(err, backend.ErrKeyNotFound)
	// recognizes it without any wrapping, matching every other backend.
	ErrKeyNotFound = backend.ErrKeyNotFound

	// ErrKeyRetrievalFailed is returned when DescribeKey fails for a reason
	// other than the key genuinely not existing -- throttling, a network
	// fault, or an IAM/authorization failure. It must not satisfy
	// errors.Is(err, backend.ErrKeyNotFound): callers use that distinction
	// to decide whether generating a replacement key is safe.
	ErrKeyRetrievalFailed = errors.New("awskms: key retrieval failed")

	// ErrMalformedResponse indicates AWS KMS returned a success response
	// missing a field the backend depends on (e.g. CreateKey without
	// KeyMetadata.KeyId).
	ErrMalformedResponse = errors.New("awskms: malformed AWS KMS response")

	// ErrUnsupportedKeyType is returned when an unsupported key type is requested.
	ErrUnsupportedKeyType = errors.New("awskms: unsupported key type")

	// ErrInvalidRegion is returned when an invalid AWS region is specified.
	ErrInvalidRegion = errors.New("awskms: invalid region")

	// ErrInvalidKeySpec is returned when an invalid key spec is provided.
	ErrInvalidKeySpec = errors.New("awskms: invalid key spec")

	// ErrKeyAlreadyExists is returned when attempting to create a key that
	// already exists. It is an alias of backend.ErrKeyAlreadyExists so a
	// get-or-generate caller recognizes a lost generate race with
	// errors.Is(err, backend.ErrKeyAlreadyExists), matching every other
	// backend (go-xkms#1599).
	ErrKeyAlreadyExists = backend.ErrKeyAlreadyExists

	// ErrInvalidAlgorithm is returned when an invalid algorithm is specified.
	ErrInvalidAlgorithm = errors.New("awskms: invalid algorithm")

	// ErrSignatureFailed is returned when signature verification fails.
	ErrSignatureFailed = errors.New("awskms: signature verification failed")

	// ErrMetadataStorage is returned when metadata storage operations fail.
	ErrMetadataStorage = errors.New("awskms: metadata storage failed")

	// ErrInvalidKeyID is returned when the key ID format is invalid.
	ErrInvalidKeyID = errors.New("awskms: invalid key ID")
)
