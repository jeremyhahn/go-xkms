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

//go:build vault

package vault

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

var (
	// ErrKeyNotFound is returned when a key doesn't exist in Vault. It is
	// an alias of backend.ErrKeyNotFound so
	// errors.Is(err, backend.ErrKeyNotFound) recognizes it without any
	// wrapping, matching every other backend.
	ErrKeyNotFound = backend.ErrKeyNotFound

	// ErrKeyRetrievalFailed is returned when a key lookup fails for a
	// reason other than the key genuinely not existing -- a network fault,
	// an unavailable metadata store, or an ACL/authorization denial. It
	// must not satisfy errors.Is(err, backend.ErrKeyNotFound): callers use
	// that distinction to decide whether generating a replacement key is
	// safe.
	ErrKeyRetrievalFailed = errors.New("vault: key retrieval failed")

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

	// ErrAsymmetricImportNotSupported is returned by GetImportParameters and
	// ImportKey for a key whose attributes describe an asymmetric algorithm.
	// Vault Transit's BYOK ceremony this backend implements is wired for
	// aes256-gcm96 symmetric keys only; asymmetric import would need a
	// different "type" value and public-key handling this backend does not
	// yet send, so it is refused with this typed error rather than attempted.
	ErrAsymmetricImportNotSupported = errors.New("vault: BYOK import is implemented for symmetric keys only")

	// ErrWrappingKeyNotRSA is returned when Vault's transit/wrapping_key
	// endpoint returns a public key that does not parse as RSA. Every Vault
	// release has used an RSA-4096 wrapping key for Transit's BYOK ceremony;
	// this guards the type assertion WrapKey depends on rather than assuming
	// it silently.
	ErrWrappingKeyNotRSA = errors.New("vault: wrapping key is not RSA")

	// ErrWrappedExportNotSupported is returned by ExportKey. Vault Transit's
	// wrapping_key exists to receive BYOK material, not to hand key material
	// out wrapped for an arbitrary third-party recipient -- there is no
	// server-side primitive to wrap FROM Vault the way there is one to wrap
	// INTO it. A key created with Exportable=true can still be read directly
	// with ExportKeyMaterial; this error names that alternative.
	ErrWrappedExportNotSupported = errors.New("vault: wrapped export has no Vault-native equivalent; use ExportKeyMaterial for exportable keys")
)
