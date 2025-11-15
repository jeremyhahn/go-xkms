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

package opaque

import "errors"

var (
	// ErrKeyStoreRequired indicates a nil keystore was provided
	ErrKeyStoreRequired = errors.New("opaque: keystore is required")

	// ErrInvalidKeyAttributes indicates invalid key attributes
	ErrInvalidKeyAttributes = errors.New("opaque: invalid key attributes")

	// ErrInvalidPublicKey indicates an invalid public key
	ErrInvalidPublicKey = errors.New("opaque: invalid public key")

	// ErrSignerNotSupported indicates the backend doesn't support signing
	ErrSignerNotSupported = errors.New("opaque: signer not supported by backend")

	// ErrDecrypterNotSupported indicates the backend doesn't support decryption
	ErrDecrypterNotSupported = errors.New("opaque: decrypter not supported by backend")

	// ErrInvalidHashFunction indicates an invalid or unavailable hash function
	ErrInvalidHashFunction = errors.New("opaque: invalid or unavailable hash function")

	// ErrEqualNotSupported indicates equality check is not supported
	ErrEqualNotSupported = errors.New("opaque: equality check not supported")
)
