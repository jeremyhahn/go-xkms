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

package xkms

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ========================================================================
// Crypto Operations (delegated to key provider)
// ========================================================================

// Signer returns a crypto.Signer for the specified key.
// The returned signer can be used for signing operations without
// exposing the private key material.
func (c *compositeBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Get signer from key provider
	signer, err := c.backend.Signer(attrs)
	if err != nil {
		return nil, &ErrCryptoOperation{Operation: "signer", Err: err}
	}

	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the specified key.
// The returned decrypter can be used for decryption operations without
// exposing the private key material.
func (c *compositeBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Get decrypter from key provider
	decrypter, err := c.backend.Decrypter(attrs)
	if err != nil {
		return nil, &ErrCryptoOperation{Operation: "decrypter", Err: err}
	}

	return decrypter, nil
}

// ========================================================================
// TLS Helpers (convenience methods)
// ========================================================================

// GetTLSCertificate returns a complete tls.Certificate ready for use.
// This combines the private key from the key provider with the certificate
// from storage into a single tls.Certificate structure.
//
// The keyID is used to locate both the key (via attrs) and certificate.
func (c *compositeBackend) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	if keyID == "" {
		return tls.Certificate{}, ErrInvalidKeyID
	}
	if attrs == nil {
		return tls.Certificate{}, ErrInvalidKeyAttributes
	}

	// Get the private key
	privateKey, err := c.GetKey(attrs)
	if err != nil {
		return tls.Certificate{}, &ErrKeyOperation{Operation: "get private key", Err: err}
	}

	// Get the certificate
	cert, err := c.GetCert(keyID)
	if err != nil {
		return tls.Certificate{}, &ErrCertOperation{Operation: "get certificate", Err: err}
	}

	// Try to get the certificate chain (optional)
	var chain []*x509.Certificate
	chain, err = c.GetCertChain(keyID)
	if err != nil {
		// Chain is optional, just use the leaf certificate
		chain = []*x509.Certificate{cert}
	} else if len(chain) == 0 {
		// Empty chain, use just the leaf certificate
		chain = []*x509.Certificate{cert}
	}

	// Build the tls.Certificate
	tlsCert := tls.Certificate{
		PrivateKey:  privateKey,
		Certificate: make([][]byte, len(chain)),
		Leaf:        cert,
	}

	// Copy the raw certificate bytes
	for i, c := range chain {
		tlsCert.Certificate[i] = c.Raw
	}

	return tlsCert, nil
}
