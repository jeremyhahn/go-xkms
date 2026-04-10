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

package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"hash"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// DPoP implements RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession.
// DPoP binds access tokens to a specific client by requiring the client
// to prove possession of a private key when making token requests.

// DPoPKey represents an EC P-256 key pair for DPoP proofs.
type DPoPKey struct {
	PrivateKey *ecdsa.PrivateKey
}

// DPoPProofOptions contains options for generating a DPoP proof.
type DPoPProofOptions struct {
	// HTTPMethod is the HTTP method of the request (e.g., "POST").
	HTTPMethod string

	// HTTPUri is the HTTP URI of the request.
	HTTPUri string

	// AccessToken is the access token to bind (optional, for resource requests).
	// If provided, an 'ath' claim is included with the SHA-256 hash of the token.
	AccessToken string

	// Nonce is a server-provided nonce (optional).
	Nonce string
}

// DPoPJWK represents the JWK public key in the DPoP JWT header.
type DPoPJWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

// dpopClaims represents the claims in a DPoP proof JWT.
type dpopClaims struct {
	jwt.RegisteredClaims
	HTTPMethod      string `json:"htm"`
	HTTPUri         string `json:"htu"`
	AccessTokenHash string `json:"ath,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
}

// GenerateDPoPKey generates a new EC P-256 key pair for DPoP proofs.
func GenerateDPoPKey() (*DPoPKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrDPoPKeyGeneration
	}
	return &DPoPKey{PrivateKey: privateKey}, nil
}

// GenerateProof generates a DPoP proof JWT for the given request.
func (k *DPoPKey) GenerateProof(opts *DPoPProofOptions) (string, error) {
	if k.PrivateKey == nil {
		return "", ErrDPoPKeyGeneration
	}

	if opts.HTTPMethod == "" || opts.HTTPUri == "" {
		return "", ErrDPoPInvalidProof
	}

	// Build JWK for the header
	jwk := DPoPJWK{
		KeyType: "EC",
		Curve:   "P-256",
		X:       base64.RawURLEncoding.EncodeToString(k.PrivateKey.PublicKey.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(k.PrivateKey.PublicKey.Y.Bytes()),
	}

	// Pad X and Y coordinates to 32 bytes (P-256 requirement)
	xBytes := k.PrivateKey.PublicKey.X.Bytes()
	yBytes := k.PrivateKey.PublicKey.Y.Bytes()
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}
	jwk.X = base64.RawURLEncoding.EncodeToString(xBytes)
	jwk.Y = base64.RawURLEncoding.EncodeToString(yBytes)

	// Build claims
	now := time.Now()
	claims := dpopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       uuid.New().String(),
			IssuedAt: jwt.NewNumericDate(now),
		},
		HTTPMethod: opts.HTTPMethod,
		HTTPUri:    opts.HTTPUri,
	}

	// Add access token hash if provided (for resource requests)
	if opts.AccessToken != "" {
		claims.AccessTokenHash = computeAccessTokenHash(opts.AccessToken)
	}

	// Add nonce if provided
	if opts.Nonce != "" {
		claims.Nonce = opts.Nonce
	}

	// Create token with custom header
	token := jwt.NewWithClaims(&dpopSigningMethod{}, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["alg"] = "ES256"
	token.Header["jwk"] = jwk

	// Sign the token
	return token.SignedString(k.PrivateKey)
}

// PublicJWK returns the public key as a JWK.
func (k *DPoPKey) PublicJWK() *DPoPJWK {
	if k.PrivateKey == nil {
		return nil
	}

	xBytes := k.PrivateKey.PublicKey.X.Bytes()
	yBytes := k.PrivateKey.PublicKey.Y.Bytes()

	// Pad to 32 bytes
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}

	return &DPoPJWK{
		KeyType: "EC",
		Curve:   "P-256",
		X:       base64.RawURLEncoding.EncodeToString(xBytes),
		Y:       base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

// SerializePrivateKey serializes the private key to PEM format for storage.
func (k *DPoPKey) SerializePrivateKey() (string, error) {
	if k.PrivateKey == nil {
		return "", ErrDPoPKeyGeneration
	}

	der, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		return "", ErrDPoPKeyGeneration
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// DeserializeDPoPKey deserializes a PEM-encoded private key.
func DeserializeDPoPKey(pemData string) (*DPoPKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, ErrDPoPInvalidProof
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrDPoPInvalidProof
	}

	// Verify it's P-256
	if privateKey.Curve != elliptic.P256() {
		return nil, ErrDPoPInvalidProof
	}

	return &DPoPKey{PrivateKey: privateKey}, nil
}

// computeAccessTokenHash computes the SHA-256 hash of an access token for the 'ath' claim.
func computeAccessTokenHash(accessToken string) string {
	hash := sha256Hash([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash)
}

// newSHA256 returns a new SHA-256 hash.
func newSHA256() hash.Hash {
	return sha256.New()
}

// sha256Hash computes the SHA-256 hash of data.
func sha256Hash(data []byte) []byte {
	h := newSHA256()
	h.Write(data)
	return h.Sum(nil)
}

// dpopSigningMethod wraps ES256 for DPoP-specific signing.
type dpopSigningMethod struct{}

func (m *dpopSigningMethod) Alg() string {
	return "ES256"
}

func (m *dpopSigningMethod) Verify(signingString string, sig []byte, key interface{}) error {
	return jwt.SigningMethodES256.Verify(signingString, sig, key)
}

func (m *dpopSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	return jwt.SigningMethodES256.Sign(signingString, key)
}

// DPoPKeyFromCoordinates creates a DPoP key from raw X and Y coordinates.
// This is useful for reconstructing keys from JWK format.
func DPoPKeyFromCoordinates(x, y []byte, d []byte) (*DPoPKey, error) {
	curve := elliptic.P256()

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	privateKey := &ecdsa.PrivateKey{
		PublicKey: *pubKey,
		D:         new(big.Int).SetBytes(d),
	}

	return &DPoPKey{PrivateKey: privateKey}, nil
}
