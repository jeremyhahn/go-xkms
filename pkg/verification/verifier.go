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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
)

// ChecksumProvider defines the interface for retrieving stored checksums
// for integrity verification. Implementations should return the checksum
// associated with the blob name specified in VerifyOpts.
type ChecksumProvider interface {
	// Checksum retrieves the stored checksum for the given verification options.
	// Returns ErrChecksumNotFound if no checksum exists for the blob.
	Checksum(opts *VerifyOpts) ([]byte, error)
}

// Verifier defines the interface for signature verification operations.
// It supports RSA (PKCS1v15 and PSS), ECDSA, and Ed25519 signature schemes
// with optional integrity checking.
type Verifier interface {
	// Verify validates a signature against the provided public key and digest.
	// The hash parameter specifies the hash algorithm used to create the digest.
	// Optional verification options can be provided for algorithm-specific
	// settings and integrity checking.
	Verify(
		pub crypto.PublicKey,
		hash crypto.Hash,
		hashed, signature []byte,
		opts *VerifyOpts) error
}

// verify implements the Verifier interface with support for multiple
// signature algorithms and optional integrity checking.
type verify struct {
	checksumProvider ChecksumProvider
}

// NewVerifier creates a new Verifier instance with the provided checksum provider.
// The checksumProvider is optional and only required if integrity checking will be used.
func NewVerifier(checksumProvider ChecksumProvider) Verifier {
	return &verify{
		checksumProvider: checksumProvider,
	}
}

// Verify validates a signature against the provided public key and digest.
// It supports RSA (PKCS1v15 and PSS), ECDSA, and Ed25519 signature schemes.
//
// When opts is nil, the function performs basic signature verification:
//   - RSA signatures use PKCS1v15 padding
//   - ECDSA signatures use ASN.1 encoding
//   - Ed25519 signatures use standard verification
//
// When opts is provided, the function uses the KeyAttributes to determine
// the algorithm and can perform integrity checking if enabled.
func (v *verify) Verify(
	pub crypto.PublicKey,
	hash crypto.Hash,
	hashed, signature []byte,
	opts *VerifyOpts) error {

	// If opts provided, use algorithm-specific verification
	if opts != nil && opts.KeyAttributes != nil {
		return v.verifyWithOpts(pub, hash, hashed, signature, opts)
	}

	// Default verification without opts
	return v.verifyDefault(pub, hash, hashed, signature)
}

// verifyWithOpts performs verification using the provided options
func (v *verify) verifyWithOpts(
	pub crypto.PublicKey,
	hash crypto.Hash,
	hashed, signature []byte,
	opts *VerifyOpts) error {

	keyAttrs := opts.KeyAttributes
	var err error

	// Verify signature based on key algorithm
	switch keyAttrs.KeyAlgorithm {
	case x509.RSA:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKeyRSA
		}

		if opts.PSSOptions != nil {
			err = rsa.VerifyPSS(rsaPub, hash, hashed, signature, opts.PSSOptions)
		} else {
			err = rsa.VerifyPKCS1v15(rsaPub, hash, hashed, signature)
		}

	case x509.ECDSA:
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKeyECDSA
		}

		if !ecdsa.VerifyASN1(ecdsaPub, hashed, signature) {
			err = ErrSignatureVerification
		}

	case x509.Ed25519:
		ed25519Pub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return ErrInvalidPublicKeyEd25519
		}

		if !ed25519.Verify(ed25519Pub, hashed, signature) {
			err = ErrSignatureVerification
		}

	default:
		return ErrInvalidSignatureAlgorithm
	}

	if err != nil {
		return err
	}

	// Perform integrity check if enabled
	if opts.IntegrityCheck {
		return v.verifyIntegrity(hashed, opts)
	}

	return nil
}

// verifyDefault performs basic verification without options
func (v *verify) verifyDefault(
	pub crypto.PublicKey,
	hash crypto.Hash,
	hashed, signature []byte) error {

	// Try RSA first
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		return rsa.VerifyPKCS1v15(rsaPub, hash, hashed, signature)
	}

	// Try ECDSA
	if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
		if !ecdsa.VerifyASN1(ecdsaPub, hashed, signature) {
			return ErrSignatureVerification
		}
		return nil
	}

	// Try Ed25519
	if ed25519Pub, ok := pub.(ed25519.PublicKey); ok {
		if !ed25519.Verify(ed25519Pub, hashed, signature) {
			return ErrSignatureVerification
		}
		return nil
	}

	return ErrInvalidSignatureAlgorithm
}

// verifyIntegrity checks the digest against a stored checksum
func (v *verify) verifyIntegrity(hashed []byte, opts *VerifyOpts) error {
	if opts.BlobCN == nil {
		return ErrInvalidBlobName
	}

	if v.checksumProvider == nil {
		return ErrChecksumNotFound
	}

	checksum, err := v.checksumProvider.Checksum(opts)
	if err != nil {
		return err
	}

	// Convert hashed to hex string for comparison
	newSum := hex.EncodeToString(hashed)

	// Compare checksums
	if !bytes.Equal(checksum, []byte(newSum)) {
		return ErrFileIntegrityCheckFailed
	}

	return nil
}
