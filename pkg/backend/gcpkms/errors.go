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

//go:build gcpkms

package gcpkms

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

var (
	// ErrNotInitialized is returned when the KMS client is not initialized.
	ErrNotInitialized = errors.New("gcpkms: client not initialized")

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("gcpkms: invalid configuration")

	// ErrKeyNotFound is returned when the specified key cannot be found. It
	// is an alias of backend.ErrKeyNotFound so
	// errors.Is(err, backend.ErrKeyNotFound) recognizes it without any
	// wrapping, matching every other backend.
	ErrKeyNotFound = backend.ErrKeyNotFound

	// ErrKeyRetrievalFailed is returned when GetCryptoKey (or the local
	// metadata lookup that precedes it) fails for a reason other than the
	// key genuinely not existing -- a gRPC transport fault, throttling, or
	// an IAM/authorization denial. It must not satisfy
	// errors.Is(err, backend.ErrKeyNotFound): callers use that distinction
	// to decide whether generating a replacement key is safe.
	ErrKeyRetrievalFailed = errors.New("gcpkms: key retrieval failed")

	// ErrUnsupportedKeyType is returned when an unsupported key type is requested.
	ErrUnsupportedKeyType = errors.New("gcpkms: unsupported key type")

	// ErrUnsupportedOperation is returned when an operation is not supported.
	ErrUnsupportedOperation = errors.New("gcpkms: unsupported operation")

	// ErrInvalidProjectID is returned when the project ID is invalid or empty.
	ErrInvalidProjectID = errors.New("gcpkms: invalid project ID")

	// ErrInvalidLocationID is returned when the location ID is invalid or empty.
	ErrInvalidLocationID = errors.New("gcpkms: invalid location ID")

	// ErrInvalidKeyRingID is returned when the key ring ID is invalid or empty.
	ErrInvalidKeyRingID = errors.New("gcpkms: invalid key ring ID")

	// ErrInvalidCredentials is returned when credentials are invalid or cannot be loaded.
	ErrInvalidCredentials = errors.New("gcpkms: invalid credentials")

	// ErrKeyAlreadyExists is returned when attempting to create a key that already exists.
	ErrKeyAlreadyExists = errors.New("gcpkms: key already exists")

	// ErrInvalidKeyAttributes is returned when key attributes are invalid.
	ErrInvalidKeyAttributes = errors.New("gcpkms: invalid key attributes")

	// ErrUnsupportedKeySize is returned when an unsupported RSA key size is requested.
	ErrUnsupportedKeySize = errors.New("gcpkms: unsupported key size")

	// ErrUnsupportedCurve is returned when an unsupported elliptic curve is requested.
	ErrUnsupportedCurve = errors.New("gcpkms: unsupported elliptic curve")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("gcpkms: invalid signature")

	// ErrInvalidDigest is returned when the digest is invalid or has an incorrect length.
	ErrInvalidDigest = errors.New("gcpkms: invalid digest")

	// ErrNoPrimaryVersion is returned when a crypto key has no primary
	// version, so no key version can be resolved for signing, decryption,
	// or public key retrieval.
	ErrNoPrimaryVersion = errors.New("gcpkms: crypto key has no primary version")
)
