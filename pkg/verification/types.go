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

package verification

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
)

// KeyAttributes contains the minimal key attributes needed for verification.
// This is a subset of types.KeyAttributes to avoid import cycles.
type KeyAttributes struct {
	// KeyAlgorithm specifies the public key algorithm (RSA, ECDSA, Ed25519)
	KeyAlgorithm x509.PublicKeyAlgorithm

	// Hash specifies the hash function to use with this key
	Hash crypto.Hash
}

// VerifyOpts contains optional parameters for signature verification operations.
type VerifyOpts struct {
	// KeyAttributes specifies the key algorithm and other key properties
	KeyAttributes *KeyAttributes

	// BlobCN is the common name identifier for the blob being verified
	BlobCN []byte

	// IntegrityCheck enables verification of the digest against a stored checksum
	IntegrityCheck bool

	// PSSOptions specifies RSA-PSS specific parameters (salt length, hash function)
	// If nil when verifying RSA signatures, PKCS1v15 is used instead
	PSSOptions *rsa.PSSOptions
}
