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

//go:build azurekv

package azurekv

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

var (
	// ErrNotInitialized is returned when the Azure Key Vault client is not initialized.
	ErrNotInitialized = errors.New("azurekv: client not initialized")

	// ErrInvalidConfig is returned when the configuration is invalid.
	ErrInvalidConfig = errors.New("azurekv: invalid configuration")

	// ErrKeyNotFound is returned when a key is not found in Azure Key Vault.
	// It is an alias of backend.ErrKeyNotFound so
	// errors.Is(err, backend.ErrKeyNotFound) recognizes it without any
	// wrapping, matching every other backend.
	ErrKeyNotFound = backend.ErrKeyNotFound

	// ErrKeyRetrievalFailed is returned when the Key Vault client's GetKey
	// call fails for a reason other than the key genuinely not existing --
	// a transport fault, throttling, or an RBAC/authorization denial. It
	// must not satisfy errors.Is(err, backend.ErrKeyNotFound): callers use
	// that distinction to decide whether generating a replacement key is
	// safe.
	ErrKeyRetrievalFailed = errors.New("azurekv: key retrieval failed")

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

	// ErrRawECDSADigestUnsupported is returned when a raw ECDSA signature
	// (no named hash, PKCS#11's CKM_ECDSA) is requested over a digest Azure
	// Key Vault cannot sign: Key Vault pairs each curve with one algorithm
	// (P-256/ES256, P-384/ES384, P-521/ES512) and requires the digest to be
	// exactly that algorithm's hash size, so it cannot truncate a digest of
	// another length to the curve order as raw ECDSA allows.
	ErrRawECDSADigestUnsupported = errors.New("azurekv: raw ECDSA digest length does not match the key's curve")

	// ErrSignatureFailed is returned when signature verification fails.
	ErrSignatureFailed = errors.New("azurekv: signature verification failed")

	// ErrInvalidCurve is returned when an invalid elliptic curve is specified.
	ErrInvalidCurve = errors.New("azurekv: invalid elliptic curve")

	// ErrInvalidCredentials is returned when Azure credentials are invalid.
	ErrInvalidCredentials = errors.New("azurekv: invalid credentials")

	// ErrUnsupportedOperation is returned when an operation is not supported.
	ErrUnsupportedOperation = errors.New("azurekv: unsupported operation")

	// ErrInvalidKeyID is returned when a key identifier returned by Azure Key
	// Vault cannot be parsed to extract its version.
	ErrInvalidKeyID = errors.New("azurekv: invalid key identifier")

	// ErrLocalVaultURLNotAllowed is returned when the vault URL names
	// localhost or 127.0.0.1 but the configuration does not opt into
	// AllowLocalVaultURL. Off by default: a production build must not
	// silently accept a fake vault endpoint.
	ErrLocalVaultURLNotAllowed = errors.New("azurekv: local vault URL not allowed")

	// ErrMetadataStorage is returned when Config.KeyStorage operations
	// against this backend's CN -> key metadata records fail for a reason
	// other than the record genuinely not existing (go-xkms#1098, mirroring
	// awskms.ErrMetadataStorage from go-xkms#839).
	ErrMetadataStorage = errors.New("azurekv: metadata storage failed")

	// ErrCiphertextRejected is returned, joined with the AEAD's own error
	// where it produced one, when an AES-GCM ciphertext does not authenticate
	// under the key: its tag or nonce is not the length the construction
	// requires, or gcm.Open refuses it because it was tampered with,
	// truncated or extended, produced under another key, or sealed under
	// different additional authenticated data. Failures to build the cipher
	// itself (an unusable key, a construction the process's FIPS mode
	// refuses) are not this error.
	ErrCiphertextRejected = errors.New("azurekv: AES-GCM ciphertext failed authentication")
)
