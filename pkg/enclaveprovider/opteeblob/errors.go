// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package opteeblob

import "errors"

// Key errors.
var (
	// ErrKeyLength is returned by Seal and Unseal for a sealing key that is
	// not KeySize bytes long.
	ErrKeyLength = errors.New("opteeblob: sealing key must be 32 bytes")

	// ErrTAUniqueKeyLength is returned by DeriveKey for a TA unique key that
	// is not exactly TAUniqueKeySize bytes.
	ErrTAUniqueKeyLength = errors.New("opteeblob: TA unique key must be 32 bytes")

	// ErrSealFailed is returned by Seal when the blob could not be produced.
	ErrSealFailed = errors.New("opteeblob: could not seal")

	// ErrDeriveFailed is returned by DeriveKey when HKDF refuses its inputs.
	ErrDeriveFailed = errors.New("opteeblob: could not derive the sealing key")
)

// Blob errors, returned by Unseal. Each names the first rule the blob breaks,
// in the order docs/optee-sealed-blob/README.md lists them.
var (
	// ErrTruncated reports a blob that ends inside a CBOR item, or whose
	// ciphertext is shorter than the GCM tag.
	ErrTruncated = errors.New("opteeblob: blob is truncated")

	// ErrMalformed reports a blob that is not a tagged COSE_Encrypt0 in the
	// one encoding this format allows: another CBOR tag or structure,
	// trailing bytes, or an encoding that is not core deterministic.
	ErrMalformed = errors.New("opteeblob: blob is not a sealed-blob COSE_Encrypt0")

	// ErrVersion reports a protected header whose version is not Version.
	ErrVersion = errors.New("opteeblob: unsupported blob version")

	// ErrAlgorithm reports a protected header whose algorithm is not
	// A256GCM.
	ErrAlgorithm = errors.New("opteeblob: algorithm is not A256GCM")

	// ErrHeader reports a protected or unprotected header that is not the
	// one this format defines: a missing, extra or mistyped parameter, or a
	// nonce that is not NonceSize bytes.
	ErrHeader = errors.New("opteeblob: bad header")

	// ErrAuthentication reports a blob whose GCM tag does not verify under
	// the key and the TA identity: the wrong key, the wrong TA, or an
	// altered protected header, nonce, ciphertext or tag.
	ErrAuthentication = errors.New("opteeblob: blob does not authenticate")
)
