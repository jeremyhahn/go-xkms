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

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

var (
	ErrInvalidSignatureAlgorithm = errors.New("jwt: invalid signature algorithm")
	ErrInvalidKey                = errors.New("jwt: invalid key type")
)

// SigningMethodSigner implements jwt.SigningMethod for crypto.Signer keys.
// This enables JWT signing with hardware-backed keys (TPM, PKCS11, PKCS8)
// that implement the crypto.Signer interface.
type SigningMethodSigner struct {
	algorithm     string
	hash          crypto.Hash
	keyAttributes *types.KeyAttributes
	isPSS         bool
}

// NewSigningMethodSigner creates a new SigningMethod for crypto.Signer keys.
// The signing algorithm is determined from the key attributes.
func NewSigningMethodSigner(keyAttrs *types.KeyAttributes) (*SigningMethodSigner, error) {
	isPSS := false
	algorithm, err := AlgorithmFromKeyAttributes(keyAttrs)
	if err != nil {
		return nil, err
	}
	if len(algorithm) > 0 && algorithm[0] == 'P' {
		isPSS = true
	}
	return &SigningMethodSigner{
		algorithm:     algorithm,
		hash:          keyAttrs.Hash,
		keyAttributes: keyAttrs,
		isPSS:         isPSS,
	}, nil
}

// Alg returns the JWT algorithm string (RS256, ES256, EdDSA, etc.)
func (sm *SigningMethodSigner) Alg() string {
	return sm.algorithm
}

// Digest computes the hash digest of the signing string.
// For Ed25519, returns the raw message (Ed25519 signs unhashed).
func (sm *SigningMethodSigner) Digest(signingString string) ([]byte, error) {
	// Ed25519 signs raw message
	if sm.keyAttributes.KeyAlgorithm == x509.Ed25519 {
		return []byte(signingString), nil
	}
	hash := sm.hash.New()
	hash.Reset()
	_, err := hash.Write([]byte(signingString))
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

// Sign signs the signing string using the provided crypto.Signer key.
// The key must implement crypto.Signer interface.
func (sm *SigningMethodSigner) Sign(signingString string, key interface{}) ([]byte, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidKey
	}

	// Ed25519 signs raw message (unhashed)
	if sm.keyAttributes.KeyAlgorithm == x509.Ed25519 {
		return signer.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
	}

	// For other algorithms, hash first
	hash := sm.hash.New()
	_, err := hash.Write([]byte(signingString))
	if err != nil {
		return nil, err
	}
	digest := hash.Sum(nil)

	var opts crypto.SignerOpts
	if sm.isPSS {
		opts = &rsa.PSSOptions{
			Hash:       sm.hash,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
	} else {
		opts = sm.hash
	}
	return signer.Sign(rand.Reader, digest, opts)
}

// Verify verifies the signature of the signing string using the provided public key.
func (sm *SigningMethodSigner) Verify(signingString string, signature []byte, key interface{}) error {
	publicKey, ok := key.(crypto.PublicKey)
	if !ok {
		return ErrInvalidKey
	}

	// Ed25519 verifies raw message (unhashed)
	if sm.keyAttributes.KeyAlgorithm == x509.Ed25519 {
		edKey, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return ErrInvalidKey
		}
		if !ed25519.Verify(edKey, []byte(signingString), signature) {
			return jwt.ErrSignatureInvalid
		}
		return nil
	}

	// For other algorithms, hash first
	h := sm.hash.New()
	h.Write([]byte(signingString))
	digest := h.Sum(nil)

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if sm.isPSS {
			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       sm.hash,
			}
			return rsa.VerifyPSS(pub, sm.hash, digest, signature, opts)
		}
		return rsa.VerifyPKCS1v15(pub, sm.hash, digest, signature)

	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return jwt.ErrSignatureInvalid
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// AlgorithmFromKeyAttributes determines the JWT algorithm string from key attributes.
func AlgorithmFromKeyAttributes(keyAttrs *types.KeyAttributes) (string, error) {
	switch keyAttrs.SignatureAlgorithm {
	case x509.PureEd25519:
		return "EdDSA", nil
	case x509.SHA256WithRSAPSS:
		return "PS256", nil
	case x509.SHA384WithRSAPSS:
		return "PS384", nil
	case x509.SHA512WithRSAPSS:
		return "PS512", nil
	case x509.ECDSAWithSHA256:
		return "ES256", nil
	case x509.ECDSAWithSHA384:
		return "ES384", nil
	case x509.ECDSAWithSHA512:
		return "ES512", nil
	case x509.SHA256WithRSA:
		return "RS256", nil
	case x509.SHA384WithRSA:
		return "RS384", nil
	case x509.SHA512WithRSA:
		return "RS512", nil
	default:
		return "", ErrInvalidSignatureAlgorithm
	}
}

// SignWithSigner creates and signs a JWT using a crypto.Signer.
// This is a convenience function that handles the full signing process.
func (s *Signer) SignWithSigner(signer crypto.Signer, claims jwt.Claims, keyAttrs *types.KeyAttributes) (string, error) {
	method, err := NewSigningMethodSigner(keyAttrs)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(signer)
}

// SignWithSignerAndKID creates and signs a JWT with a Key ID using a crypto.Signer.
func (s *Signer) SignWithSignerAndKID(signer crypto.Signer, claims jwt.Claims, keyAttrs *types.KeyAttributes, kid string) (string, error) {
	method, err := NewSigningMethodSigner(keyAttrs)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	return token.SignedString(signer)
}
