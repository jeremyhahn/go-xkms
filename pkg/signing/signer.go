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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
)

// Signer wraps a crypto.Signer and provides enhanced signing capabilities
// including support for RSA PKCS#1 v1.5, RSA PSS, ECDSA, and Ed25519.
//
// This wrapper adds:
//   - Automatic digest computation from blob data
//   - RSA-PSS padding support
//   - Algorithm-specific signing optimizations
//   - Enhanced error messages
type Signer struct {
	signer crypto.Signer
}

// NewSigner creates a new enhanced signer wrapping the provided crypto.Signer.
func NewSigner(signer crypto.Signer) (*Signer, error) {
	if signer == nil {
		return nil, ErrSignerRequired
	}
	return &Signer{
		signer: signer,
	}, nil
}

// Public returns the public key corresponding to the wrapped signer.
// Implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.signer.Public()
}

// Sign signs the provided digest using the wrapped signer.
// Implements crypto.Signer.
//
// The opts parameter can be:
//   - *SignerOpts: Enhanced options with blob support
//   - *rsa.PSSOptions: RSA-PSS specific options
//   - crypto.Hash: Simple hash-based signing
//   - nil: Uses default signing options
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Handle SignerOpts for enhanced features
	if signerOpts, ok := opts.(*SignerOpts); ok {
		return s.signWithOpts(rand, digest, signerOpts)
	}

	// Fallback to standard signing
	return s.signer.Sign(rand, digest, opts)
}

// signWithOpts performs signing with enhanced SignerOpts.
func (s *Signer) signWithOpts(rand io.Reader, digest []byte, opts *SignerOpts) ([]byte, error) {
	// Get the actual digest (may be computed from BlobData)
	actualDigest, err := opts.GetDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}

	// Determine signing options based on key type
	pub := s.signer.Public()
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return s.signRSA(rand, actualDigest, opts)
	case *ecdsa.PublicKey:
		return s.signECDSA(rand, actualDigest, opts)
	case ed25519.PublicKey:
		return s.signEd25519(rand, actualDigest, opts)
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedAlgorithm, key)
	}
}

// signRSA performs RSA signing with support for PKCS#1 v1.5 and PSS padding.
func (s *Signer) signRSA(rand io.Reader, digest []byte, opts *SignerOpts) ([]byte, error) {
	if opts.IsPSS() {
		// Use RSA-PSS padding
		return s.signer.Sign(rand, digest, opts.PSSOptions)
	}
	// Use PKCS#1 v1.5 padding (default)
	return s.signer.Sign(rand, digest, opts.Hash)
}

// signECDSA performs ECDSA signing.
func (s *Signer) signECDSA(rand io.Reader, digest []byte, opts *SignerOpts) ([]byte, error) {
	return s.signer.Sign(rand, digest, opts.Hash)
}

// signEd25519 performs Ed25519 signing.
// Note: Ed25519 signatures are deterministic and don't use a hash function.
func (s *Signer) signEd25519(rand io.Reader, digest []byte, opts *SignerOpts) ([]byte, error) {
	// Ed25519 signs the message directly, not a hash
	if opts.BlobData != nil {
		return s.signer.Sign(rand, opts.BlobData, crypto.Hash(0))
	}
	return s.signer.Sign(rand, digest, crypto.Hash(0))
}

// GetKeyAlgorithm returns the public key algorithm of the wrapped signer.
func (s *Signer) GetKeyAlgorithm() x509.PublicKeyAlgorithm {
	switch s.signer.Public().(type) {
	case *rsa.PublicKey:
		return x509.RSA
	case *ecdsa.PublicKey:
		return x509.ECDSA
	case ed25519.PublicKey:
		return x509.Ed25519
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// SupportsHashAlgorithm checks if the signer's key type supports the given hash algorithm.
func (s *Signer) SupportsHashAlgorithm(hash crypto.Hash) bool {
	switch s.signer.Public().(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return hash.Available()
	case ed25519.PublicKey:
		// Ed25519 doesn't use external hash functions
		return hash == 0 || hash == crypto.Hash(0)
	default:
		return false
	}
}
