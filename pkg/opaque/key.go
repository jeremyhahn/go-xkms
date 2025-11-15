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

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyStorer defines the minimal interface required for opaque key operations.
// This avoids circular dependencies with the keychain package.
type KeyStorer interface {
	// GetKey retrieves an existing private key by its attributes.
	GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error)

	// Signer returns a crypto.Signer for the specified key.
	Signer(attrs *types.KeyAttributes) (crypto.Signer, error)

	// Decrypter returns a crypto.Decrypter for the specified key.
	Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error)
}

// OpaqueKey provides a unified interface for cryptographic operations
// that wraps backend-specific key operations. It implements crypto.PrivateKey,
// crypto.Signer, and crypto.Decrypter interfaces while keeping the actual
// key material opaque (hidden from direct access).
//
// This design allows keys stored in hardware backends (HSM, TPM) or cloud
// KMS services to be used transparently through standard Go crypto interfaces.
type OpaqueKey interface {
	// Digest creates a hash of the provided data using the key's configured hash function.
	Digest(data []byte) ([]byte, error)

	// Equal compares this key with another for equality.
	// This may not be supported by all backends.
	Equal(x crypto.PrivateKey) bool

	// KeyAttributes returns the attributes that identify this key.
	KeyAttributes() *types.KeyAttributes

	// Embeds standard crypto interfaces
	crypto.PrivateKey
	crypto.Signer
	crypto.Decrypter
}

// Opaque is the concrete implementation of OpaqueKey that wraps
// a keystore backend and provides opaque key operations.
type Opaque struct {
	keyStore KeyStorer
	attrs    *types.KeyAttributes
	pub      crypto.PublicKey
}

// NewOpaqueKey creates a new opaque private key backed by the provided keychain.
//
// Parameters:
//   - keyStore: The keystore backend that manages the actual key material
//   - attrs: Key attributes that identify the key in the backend
//   - pub: The public key corresponding to this private key
//
// The returned OpaqueKey can be used anywhere a crypto.PrivateKey, crypto.Signer,
// or crypto.Decrypter is required, enabling transparent use of hardware-backed keys.
func NewOpaqueKey(
	keyStore KeyStorer,
	attrs *types.KeyAttributes,
	pub crypto.PublicKey) (OpaqueKey, error) {

	if keyStore == nil {
		return nil, ErrKeyStoreRequired
	}
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if pub == nil {
		return nil, ErrInvalidPublicKey
	}

	return &Opaque{
		keyStore: keyStore,
		attrs:    attrs,
		pub:      pub,
	}, nil
}

// Public returns the public key corresponding to this opaque private key.
// Implements the crypto.Signer interface.
//
// See: https://pkg.go.dev/crypto#Signer
func (o *Opaque) Public() crypto.PublicKey {
	return o.pub
}

// Sign signs the provided digest using this opaque key.
// Implements the crypto.Signer interface.
//
// The opts parameter can be:
//   - nil: Uses default signing options
//   - crypto.SignerOpts: Standard Go signing options
//   - Custom signing options that the backend understands
//
// The rand parameter is provided for compatibility with the crypto.Signer
// interface but may be ignored by deterministic signing schemes or hardware backends.
//
// See: https://pkg.go.dev/crypto#Signer
func (o *Opaque) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	signer, err := o.keyStore.Signer(o.attrs)
	if err != nil {
		return nil, err
	}

	return signer.Sign(rand, digest, opts)
}

// Decrypt decrypts the provided ciphertext using this opaque key.
// Implements the crypto.Decrypter interface.
//
// The opts parameter can specify decryption options specific to the
// key algorithm (e.g., *rsa.PKCS1v15DecryptOptions, *rsa.OAEPOptions).
//
// The rand parameter is provided for compatibility with the crypto.Decrypter
// interface but may be ignored by some backends.
//
// See: https://pkg.go.dev/crypto#Decrypter
func (o *Opaque) Decrypt(
	rand io.Reader,
	ciphertext []byte,
	opts crypto.DecrypterOpts) (plaintext []byte, err error) {

	decrypter, err := o.keyStore.Decrypter(o.attrs)
	if err != nil {
		return nil, err
	}

	return decrypter.Decrypt(rand, ciphertext, opts)
}

// Equal compares this opaque key with another private key for equality.
// Implements the crypto.PrivateKey interface.
//
// Note: This operation may not be supported by all backends, especially
// hardware-backed keys that don't allow key material export.
//
// See: https://pkg.go.dev/crypto#PrivateKey
func (o *Opaque) Equal(x crypto.PrivateKey) bool {
	// Try to get the actual private key from the backend
	key, err := o.keyStore.GetKey(o.attrs)
	if err != nil {
		return false
	}

	// If the key implements Equal, use it
	if equalKey, ok := key.(interface{ Equal(crypto.PrivateKey) bool }); ok {
		return equalKey.Equal(x)
	}

	// Otherwise, compare public keys as a fallback
	if xKey, ok := x.(crypto.Signer); ok {
		xPub := xKey.Public()
		return o.pub == xPub || publicKeysEqual(o.pub, xPub)
	}

	return false
}

// Digest creates a cryptographic hash of the provided data using the
// hash function configured in the key's attributes.
//
// This is a convenience method for signing operations that require
// pre-hashed data.
func (o *Opaque) Digest(data []byte) ([]byte, error) {
	// Use the Hash from KeyAttributes which is already crypto.Hash
	hash := o.attrs.Hash
	if !hash.Available() {
		return nil, ErrInvalidHashFunction
	}
	hasher := hash.New()
	n, err := hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to hasher: %w", err)
	}
	if n != len(data) {
		return nil, fmt.Errorf("incomplete write to hasher: wrote %d of %d bytes", n, len(data))
	}
	return hasher.Sum(nil), nil
}

// KeyAttributes returns the key attributes that identify this opaque key.
// This includes information about the key type, algorithm, and backend storage.
func (o *Opaque) KeyAttributes() *types.KeyAttributes {
	return o.attrs
}

// publicKeysEqual performs a deep comparison of two public keys.
// This handles different types of public keys and compares their actual values.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}

	switch aPub := a.(type) {
	case *rsa.PublicKey:
		bPub, ok := b.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return aPub.N.Cmp(bPub.N) == 0 && aPub.E == bPub.E

	case *ecdsa.PublicKey:
		bPub, ok := b.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return aPub.Curve == bPub.Curve &&
			aPub.X.Cmp(bPub.X) == 0 &&
			aPub.Y.Cmp(bPub.Y) == 0

	case ed25519.PublicKey:
		bPub, ok := b.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return bytes.Equal(aPub, bPub)

	default:
		// Fallback to direct comparison for unknown types
		return a == b
	}
}
