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

	// Build JWK for the header using the fixed-width P-256 coordinates.
	xBytes, yBytes := dpopCoordinates(&k.PrivateKey.PublicKey)
	jwk := DPoPJWK{
		KeyType: "EC",
		Curve:   "P-256",
		X:       base64.RawURLEncoding.EncodeToString(xBytes),
		Y:       base64.RawURLEncoding.EncodeToString(yBytes),
	}

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

	xBytes, yBytes := dpopCoordinates(&k.PrivateKey.PublicKey)

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

// dpopCoordinates returns the fixed-width 32-byte P-256 X and Y coordinates of
// pub. It uses the SEC1 uncompressed encoding (0x04 || X || Y) returned by
// PublicKey.Bytes, which already left-pads each coordinate to the curve's byte
// size, avoiding the deprecated math/big field accessors.
func dpopCoordinates(pub *ecdsa.PublicKey) (x, y []byte) {
	uncompressed, err := pub.Bytes()
	if err != nil {
		return nil, nil
	}
	// For P-256 the encoding is 65 bytes: a 0x04 prefix followed by two
	// 32-byte coordinates.
	const coordLen = 32
	if len(uncompressed) != 1+2*coordLen {
		return nil, nil
	}
	x = uncompressed[1 : 1+coordLen]
	y = uncompressed[1+coordLen:]
	return x, y
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

// ErrInvalidDPoPKey reports a JWK whose coordinates do not describe a valid
// P-256 key, or whose x/y do not match the point the private scalar derives.
type ErrInvalidDPoPKey struct {
	Reason string
	Err    error
}

func (e *ErrInvalidDPoPKey) Error() string {
	if e.Err != nil {
		return "oidc: invalid DPoP key: " + e.Reason + ": " + e.Err.Error()
	}
	return "oidc: invalid DPoP key: " + e.Reason
}

func (e *ErrInvalidDPoPKey) Unwrap() error { return e.Err }

// DPoPKeyFromCoordinates creates a DPoP key from raw X, Y and D values, as
// carried by a JWK.
//
// The scalar is parsed with ecdsa.ParseRawPrivateKey, which derives the public
// key and rejects a value outside the curve order — the previous code assigned
// D directly, so a malformed JWK produced a key that silently could not sign.
//
// The scalar is LEFT-PADDED to the curve size first. JWK base64url values carry
// no leading zeros, so a d whose high byte is zero arrives short, and
// ParseRawPrivateKey requires exactly the field size. Appending or passing the
// short slice rejects perfectly valid keys at roughly 1 in 256 — the same trap
// fixed in pkg/backend/pkcs11 (#191) and pkg/tpm2 (#226).
//
// x and y are then checked against the derived point rather than trusted: a JWK
// whose public coordinates disagree with its private scalar is malformed, and
// accepting it would let the caller sign with one key while advertising another.
func DPoPKeyFromCoordinates(x, y []byte, d []byte) (*DPoPKey, error) {
	curve := elliptic.P256()
	size := (curve.Params().BitSize + 7) / 8

	if len(d) > size {
		return nil, &ErrInvalidDPoPKey{Reason: "private scalar is longer than the P-256 field"}
	}
	scalar := make([]byte, size)
	copy(scalar[size-len(d):], d)

	privateKey, err := ecdsa.ParseRawPrivateKey(curve, scalar)
	if err != nil {
		return nil, &ErrInvalidDPoPKey{Reason: "private scalar is not a valid P-256 key", Err: err}
	}

	if len(x) > size || len(y) > size {
		return nil, &ErrInvalidDPoPKey{Reason: "public coordinates are longer than the P-256 field"}
	}
	if len(x) > 0 || len(y) > 0 {
		gotX, gotY := privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes() //nolint:staticcheck // comparing the derived point against the supplied JWK coordinates; no key is constructed from these.
		if !bytesEqualUnpadded(gotX, x) || !bytesEqualUnpadded(gotY, y) {
			return nil, &ErrInvalidDPoPKey{Reason: "public coordinates do not match the private scalar"}
		}
	}

	return &DPoPKey{PrivateKey: privateKey}, nil
}

// bytesEqualUnpadded compares two big-endian integers that may differ only in
// leading zeros, which JWK encoding does not preserve.
func bytesEqualUnpadded(a, b []byte) bool {
	for len(a) > 0 && a[0] == 0 {
		a = a[1:]
	}
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
