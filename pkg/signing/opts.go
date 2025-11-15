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

package signing

import (
	"crypto"
	"crypto/rsa"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// SignerOpts extends crypto.SignerOpts with additional options for
// flexible signing operations. It supports:
//   - Standard hash-based signing
//   - Blob-based signing with automatic digest creation
//   - RSA PSS padding options
//   - Custom key attribute specification
type SignerOpts struct {
	// BlobCN is the common name for the blob being signed.
	// When set, the signature may be stored with this identifier.
	BlobCN string

	// BlobData is the raw data to sign.
	// If set, the signer will compute the digest automatically
	// using the configured hash function.
	BlobData []byte

	// KeyAttributes specifies which key to use for signing.
	// If nil, the signer's default key is used.
	KeyAttributes *types.KeyAttributes

	// Hash is the hash function to use for signing.
	// This is used both for digest creation (if BlobData is set)
	// and for the signature algorithm.
	Hash crypto.Hash

	// PSSOptions specifies RSA-PSS padding options.
	// Only used for RSA-PSS signature algorithms.
	// If nil, PKCS#1 v1.5 padding is used for RSA.
	PSSOptions *rsa.PSSOptions
}

// HashFunc returns the hash function for this signing operation.
// Implements crypto.SignerOpts.
func (opts *SignerOpts) HashFunc() crypto.Hash {
	return opts.Hash
}

// NewSignerOpts creates a new SignerOpts with the specified hash function.
// This is a convenience constructor for simple signing operations.
func NewSignerOpts(hash crypto.Hash) *SignerOpts {
	return &SignerOpts{
		Hash: hash,
	}
}

// WithBlobCN sets the blob common name and returns the opts for chaining.
func (opts *SignerOpts) WithBlobCN(cn string) *SignerOpts {
	opts.BlobCN = cn
	return opts
}

// WithBlobData sets the blob data and returns the opts for chaining.
func (opts *SignerOpts) WithBlobData(data []byte) *SignerOpts {
	opts.BlobData = data
	return opts
}

// WithKeyAttributes sets the key attributes and returns the opts for chaining.
func (opts *SignerOpts) WithKeyAttributes(attrs *types.KeyAttributes) *SignerOpts {
	opts.KeyAttributes = attrs
	return opts
}

// WithPSSOptions sets the RSA-PSS options and returns the opts for chaining.
func (opts *SignerOpts) WithPSSOptions(pss *rsa.PSSOptions) *SignerOpts {
	opts.PSSOptions = pss
	return opts
}

// IsPSS returns true if this is an RSA-PSS signing operation.
func (opts *SignerOpts) IsPSS() bool {
	return opts.PSSOptions != nil
}

// GetDigest returns the digest to sign. If BlobData is set, it computes
// the digest using the configured hash function. Otherwise, it returns
// the provided pre-computed digest.
func (opts *SignerOpts) GetDigest(precomputed []byte) ([]byte, error) {
	if opts.BlobData != nil {
		// For Ed25519 (hash == 0), return the blob data directly
		if opts.Hash == 0 {
			return opts.BlobData, nil
		}
		// Compute digest from blob data
		if !opts.Hash.Available() {
			return nil, ErrInvalidHashFunction
		}
		hasher := opts.Hash.New()
		if _, err := hasher.Write(opts.BlobData); err != nil {
			return nil, err
		}
		return hasher.Sum(nil), nil
	}
	// Use pre-computed digest
	return precomputed, nil
}
