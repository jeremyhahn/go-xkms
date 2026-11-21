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

package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// JWK represents a JSON Web Key as defined in RFC 7517.
// It supports RSA, ECDSA, Ed25519, and symmetric (oct) key types.
type JWK struct {
	// Common fields (all key types)
	Kty string `json:"kty"`           // Key Type (required)
	Use string `json:"use,omitempty"` // Public Key Use (sig, enc)
	Alg string `json:"alg,omitempty"` // Algorithm
	Kid string `json:"kid,omitempty"` // Key ID

	// RSA public key fields (RFC 7518 Section 6.3.1)
	N string `json:"n,omitempty"` // Modulus (base64url)
	E string `json:"e,omitempty"` // Exponent (base64url)

	// RSA private key fields (RFC 7518 Section 6.3.2)
	D  string `json:"d,omitempty"`  // Private Exponent
	P  string `json:"p,omitempty"`  // First Prime Factor
	Q  string `json:"q,omitempty"`  // Second Prime Factor
	DP string `json:"dp,omitempty"` // First Factor CRT Exponent
	DQ string `json:"dq,omitempty"` // Second Factor CRT Exponent
	QI string `json:"qi,omitempty"` // First CRT Coefficient

	// EC public key fields (RFC 7518 Section 6.2.1)
	Crv string `json:"crv,omitempty"` // Curve (P-256, P-384, P-521, Ed25519)
	X   string `json:"x,omitempty"`   // X Coordinate (base64url)
	Y   string `json:"y,omitempty"`   // Y Coordinate (base64url)

	// Symmetric key field (RFC 7518 Section 6.4)
	K string `json:"k,omitempty"` // Key Value (base64url)

	// Key Operations (optional)
	KeyOps []string `json:"key_ops,omitempty"` // Key Operations
}

// KeyType represents the key type (kty) parameter values
type KeyType string

const (
	KeyTypeRSA KeyType = "RSA"
	KeyTypeEC  KeyType = "EC"
	KeyTypeOKP KeyType = "OKP" // Octet Key Pair (Ed25519, Ed448)
	KeyTypeOct KeyType = "oct" // Symmetric key
)

// Curve represents EC curve names
type Curve string

const (
	CurveP256    Curve = "P-256"
	CurveP384    Curve = "P-384"
	CurveP521    Curve = "P-521"
	CurveEd25519 Curve = "Ed25519"
	CurveX25519  Curve = "X25519"
	CurveEd448   Curve = "Ed448" // For future support
	CurveX448    Curve = "X448"  // For future support
)

// FromPublicKey creates a JWK from a crypto.PublicKey.
// Supports RSA, ECDSA, Ed25519, and X25519 public keys.
func FromPublicKey(pub crypto.PublicKey) (*JWK, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return fromRSAPublicKey(key)
	case *ecdsa.PublicKey:
		return fromECDSAPublicKey(key)
	case ed25519.PublicKey:
		return fromEd25519PublicKey(key)
	case *ecdh.PublicKey:
		// Check if it's X25519
		if key.Curve() == ecdh.X25519() {
			return fromX25519PublicKey(key)
		}
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported ECDH curve: %v", key.Curve())}
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported public key type: %T", pub)}
	}
}

// FromPrivateKey creates a JWK from a crypto.PrivateKey.
// Supports RSA, ECDSA, Ed25519, and X25519 private keys.
// The resulting JWK includes private key parameters.
func FromPrivateKey(priv crypto.PrivateKey) (*JWK, error) {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return fromRSAPrivateKey(key)
	case *ecdsa.PrivateKey:
		return fromECDSAPrivateKey(key)
	case ed25519.PrivateKey:
		return fromEd25519PrivateKey(key)
	case *ecdh.PrivateKey:
		// Check if it's X25519
		if key.Curve() == ecdh.X25519() {
			return fromX25519PrivateKey(key)
		}
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported ECDH curve: %v", key.Curve())}
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported private key type: %T", priv)}
	}
}

// FromSymmetricKey creates a JWK from symmetric key bytes.
// The key parameter should be the raw symmetric key material.
func FromSymmetricKey(key []byte, alg string) (*JWK, error) {
	if len(key) == 0 {
		return nil, &errs.Message{Msg: "symmetric key cannot be empty"}
	}

	return &JWK{
		Kty: string(KeyTypeOct),
		K:   base64.RawURLEncoding.EncodeToString(key),
		Alg: alg,
	}, nil
}

// ToPublicKey converts the JWK to a crypto.PublicKey.
// Returns an error if the JWK doesn't represent a public key.
func (jwk *JWK) ToPublicKey() (crypto.PublicKey, error) {
	switch jwk.Kty {
	case string(KeyTypeRSA):
		return jwk.toRSAPublicKey()
	case string(KeyTypeEC):
		return jwk.toECDSAPublicKey()
	case string(KeyTypeOKP):
		switch jwk.Crv {
		case string(CurveEd25519):
			return jwk.toEd25519PublicKey()
		case string(CurveX25519):
			return jwk.toX25519PublicKey()
		default:
			return nil, &errs.Message{Msg: fmt.Sprintf("unsupported OKP curve: %s", jwk.Crv)}
		}
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key type: %s", jwk.Kty)}
	}
}

// ToPrivateKey converts the JWK to a crypto.PrivateKey.
// Returns an error if the JWK doesn't contain private key parameters.
func (jwk *JWK) ToPrivateKey() (crypto.PrivateKey, error) {
	switch jwk.Kty {
	case string(KeyTypeRSA):
		if jwk.D == "" {
			return nil, &errs.Message{Msg: "JWK does not contain RSA private key parameters"}
		}
		return jwk.toRSAPrivateKey()
	case string(KeyTypeEC):
		if jwk.D == "" {
			return nil, &errs.Message{Msg: "JWK does not contain EC private key parameters"}
		}
		return jwk.toECDSAPrivateKey()
	case string(KeyTypeOKP):
		if jwk.D == "" {
			return nil, &errs.Message{Msg: "JWK does not contain OKP private key parameters"}
		}
		switch jwk.Crv {
		case string(CurveEd25519):
			return jwk.toEd25519PrivateKey()
		case string(CurveX25519):
			return jwk.toX25519PrivateKey()
		default:
			return nil, &errs.Message{Msg: fmt.Sprintf("unsupported OKP curve: %s", jwk.Crv)}
		}
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key type: %s", jwk.Kty)}
	}
}

// ToSymmetricKey extracts the symmetric key bytes from the JWK.
// Returns an error if the JWK doesn't represent a symmetric key.
func (jwk *JWK) ToSymmetricKey() ([]byte, error) {
	if jwk.Kty != string(KeyTypeOct) {
		return nil, &errs.Message{Msg: fmt.Sprintf("JWK is not a symmetric key (kty=%s)", jwk.Kty)}
	}
	if jwk.K == "" {
		return nil, &errs.Message{Msg: "JWK does not contain symmetric key value"}
	}
	return base64.RawURLEncoding.DecodeString(jwk.K)
}

// Marshal returns the JSON encoding of the JWK.
func (jwk *JWK) Marshal() ([]byte, error) {
	return json.Marshal(jwk)
}

// MarshalIndent returns the indented JSON encoding of the JWK.
func (jwk *JWK) MarshalIndent(prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(jwk, prefix, indent)
}

// Unmarshal parses the JSON-encoded data and stores the result in a JWK.
func Unmarshal(data []byte) (*JWK, error) {
	var jwk JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unmarshal JWK", Err: err}
	}
	return &jwk, nil
}

// IsPrivate returns true if the JWK contains private key parameters.
func (jwk *JWK) IsPrivate() bool {
	return jwk.D != "" || jwk.K != ""
}

// IsPublic returns true if the JWK represents a public key.
func (jwk *JWK) IsPublic() bool {
	return !jwk.IsPrivate() && (jwk.N != "" || jwk.X != "" || jwk.Crv != "")
}

// IsSymmetric returns true if the JWK represents a symmetric key.
func (jwk *JWK) IsSymmetric() bool {
	return jwk.Kty == string(KeyTypeOct)
}

// Helper functions for RSA keys

func fromRSAPublicKey(key *rsa.PublicKey) (*JWK, error) {
	return &JWK{
		Kty: string(KeyTypeRSA),
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}, nil
}

func fromRSAPrivateKey(key *rsa.PrivateKey) (*JWK, error) {
	// Ensure CRT values are precomputed
	if key.Precomputed.Dp == nil {
		key.Precompute()
	}

	jwk := &JWK{
		Kty: string(KeyTypeRSA),
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		D:   base64.RawURLEncoding.EncodeToString(key.D.Bytes()),
	}

	// Add prime factors and CRT parameters if available
	if len(key.Primes) >= 2 {
		jwk.P = base64.RawURLEncoding.EncodeToString(key.Primes[0].Bytes())
		jwk.Q = base64.RawURLEncoding.EncodeToString(key.Primes[1].Bytes())
	}

	if key.Precomputed.Dp != nil {
		jwk.DP = base64.RawURLEncoding.EncodeToString(key.Precomputed.Dp.Bytes())
		jwk.DQ = base64.RawURLEncoding.EncodeToString(key.Precomputed.Dq.Bytes())
		jwk.QI = base64.RawURLEncoding.EncodeToString(key.Precomputed.Qinv.Bytes())
	}

	return jwk, nil
}

func (jwk *JWK) toRSAPublicKey() (*rsa.PublicKey, error) {
	if jwk.N == "" {
		return nil, &errs.Message{Msg: "RSA JWK missing required field: n"}
	}
	if jwk.E == "" {
		return nil, &errs.Message{Msg: "RSA JWK missing required field: e"}
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode RSA modulus", Err: err}
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode RSA exponent", Err: err}
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, &errs.Message{Msg: "RSA exponent too large"}
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func (jwk *JWK) toRSAPrivateKey() (*rsa.PrivateKey, error) {
	pubKey, err := jwk.toRSAPublicKey()
	if err != nil {
		return nil, err
	}

	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode RSA private exponent", Err: err}
	}

	privKey := &rsa.PrivateKey{
		PublicKey: *pubKey,
		D:         new(big.Int).SetBytes(dBytes),
	}

	// Decode prime factors if present
	if jwk.P != "" && jwk.Q != "" {
		pBytes, err := base64.RawURLEncoding.DecodeString(jwk.P)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to decode RSA prime P", Err: err}
		}
		qBytes, err := base64.RawURLEncoding.DecodeString(jwk.Q)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to decode RSA prime Q", Err: err}
		}
		privKey.Primes = []*big.Int{
			new(big.Int).SetBytes(pBytes),
			new(big.Int).SetBytes(qBytes),
		}
	}

	// Precompute CRT values
	privKey.Precompute()

	return privKey, nil
}

// Helper functions for ECDSA keys

func fromECDSAPublicKey(key *ecdsa.PublicKey) (*JWK, error) {
	crv, err := getCurveName(key.Curve)
	if err != nil {
		return nil, err
	}

	// RFC 7518 Sections 6.2.1.2 and 6.2.1.3 require x and y to be the full
	// coordinate size, leading zero octets included. The SEC 1 uncompressed
	// point 0x04 || X || Y carries each coordinate at that size; encoding the
	// big-integer coordinates instead drops a zero high byte from about one
	// key in 128. Bytes also rejects a point that is not on the curve.
	point, err := key.Bytes()
	if err != nil {
		return nil, &errs.Detail{Err: ecpoint.ErrInvalidPoint, Detail: err.Error()}
	}
	size := ecpoint.CoordinateSize(key.Curve)

	return &JWK{
		Kty: string(KeyTypeEC),
		Crv: string(crv),
		X:   base64.RawURLEncoding.EncodeToString(point[1 : 1+size]),
		Y:   base64.RawURLEncoding.EncodeToString(point[1+size:]),
	}, nil
}

func fromECDSAPrivateKey(key *ecdsa.PrivateKey) (*JWK, error) {
	jwk, err := fromECDSAPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	// RFC 7518 Section 6.2.2.1 requires d to be the full
	// ceiling(log-base-2(n)/8) octets. Bytes returns the scalar at that
	// fixed length (SEC 1 Section 2.3.6) and rejects an invalid scalar.
	d, err := key.Bytes()
	if err != nil {
		return nil, &errs.Detail{Err: ecpoint.ErrInvalidScalar, Detail: err.Error()}
	}
	jwk.D = base64.RawURLEncoding.EncodeToString(d)
	return jwk, nil
}

func (jwk *JWK) toECDSAPublicKey() (*ecdsa.PublicKey, error) {
	if jwk.Crv == "" {
		return nil, &errs.Message{Msg: "EC JWK missing required field: crv"}
	}
	if jwk.X == "" {
		return nil, &errs.Message{Msg: "EC JWK missing required field: x"}
	}
	if jwk.Y == "" {
		return nil, &errs.Message{Msg: "EC JWK missing required field: y"}
	}

	curve, err := getCurve(jwk.Crv)
	if err != nil {
		return nil, err
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode EC X coordinate", Err: err}
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode EC Y coordinate", Err: err}
	}

	// ecpoint left-pads the coordinates and validates that the point lies on
	// the curve. RFC 7518 Section 6.2.1.2 requires x and y to be the full
	// field size, but encoders that route the value through a big integer
	// drop leading zero bytes; a short member must still decode.
	pubKey, err := ecpoint.PublicKey(curve, xBytes, yBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode EC public key", Err: err}
	}
	return pubKey, nil
}

func (jwk *JWK) toECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	pubKey, err := jwk.toECDSAPublicKey()
	if err != nil {
		return nil, err
	}

	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode EC private key", Err: err}
	}

	privKey, err := ecpoint.PrivateKey(pubKey.Curve, dBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "invalid EC private key scalar", Err: err}
	}

	// The public key derived from d is authoritative. Refuse a JWK whose x/y
	// members describe a different point than its d member, rather than
	// returning a private key whose PublicKey field contradicts its scalar.
	if !privKey.PublicKey.Equal(pubKey) {
		return nil, &errs.Message{Msg: "EC JWK private key does not match its x and y coordinates"}
	}

	return privKey, nil
}

// Helper functions for Ed25519 keys

func fromEd25519PublicKey(key ed25519.PublicKey) (*JWK, error) {
	return &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveEd25519),
		X:   base64.RawURLEncoding.EncodeToString(key),
	}, nil
}

func fromEd25519PrivateKey(key ed25519.PrivateKey) (*JWK, error) {
	pubKey := key.Public().(ed25519.PublicKey)

	return &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveEd25519),
		X:   base64.RawURLEncoding.EncodeToString(pubKey),
		D:   base64.RawURLEncoding.EncodeToString(key.Seed()),
	}, nil
}

func (jwk *JWK) toEd25519PublicKey() (ed25519.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode Ed25519 public key", Err: err}
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid Ed25519 public key size: %d", len(xBytes))}
	}

	return ed25519.PublicKey(xBytes), nil
}

func (jwk *JWK) toEd25519PrivateKey() (ed25519.PrivateKey, error) {
	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode Ed25519 private key", Err: err}
	}

	if len(dBytes) != ed25519.SeedSize {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid Ed25519 seed size: %d", len(dBytes))}
	}

	return ed25519.NewKeyFromSeed(dBytes), nil
}

// Helper functions for X25519 keys

func fromX25519PublicKey(key *ecdh.PublicKey) (*JWK, error) {
	return &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveX25519),
		X:   base64.RawURLEncoding.EncodeToString(key.Bytes()),
	}, nil
}

func fromX25519PrivateKey(key *ecdh.PrivateKey) (*JWK, error) {
	pubKey := key.PublicKey()

	return &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveX25519),
		X:   base64.RawURLEncoding.EncodeToString(pubKey.Bytes()),
		D:   base64.RawURLEncoding.EncodeToString(key.Bytes()),
	}, nil
}

func (jwk *JWK) toX25519PublicKey() (*ecdh.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode X25519 public key", Err: err}
	}

	if len(xBytes) != 32 {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid X25519 public key size: %d (expected 32)", len(xBytes))}
	}

	return ecdh.X25519().NewPublicKey(xBytes)
}

func (jwk *JWK) toX25519PrivateKey() (*ecdh.PrivateKey, error) {
	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode X25519 private key", Err: err}
	}

	if len(dBytes) != 32 {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid X25519 private key size: %d (expected 32)", len(dBytes))}
	}

	return ecdh.X25519().NewPrivateKey(dBytes)
}

// Curve helper functions

func getCurveName(curve elliptic.Curve) (Curve, error) {
	switch curve {
	case elliptic.P256():
		return CurveP256, nil
	case elliptic.P384():
		return CurveP384, nil
	case elliptic.P521():
		return CurveP521, nil
	default:
		return "", &errs.Message{Msg: fmt.Sprintf("unsupported elliptic curve: %s", curve.Params().Name)}
	}
}

func getCurve(name string) (elliptic.Curve, error) {
	switch name {
	case string(CurveP256):
		return elliptic.P256(), nil
	case string(CurveP384):
		return elliptic.P384(), nil
	case string(CurveP521):
		return elliptic.P521(), nil
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported curve: %s", name)}
	}
}
