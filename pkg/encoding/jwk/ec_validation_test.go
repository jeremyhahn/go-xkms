// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
)

// ecJWKCurves are the EC curves RFC 7518 Section 6.2.1.1 defines.
var ecJWKCurves = []struct {
	name  string
	crv   Curve
	curve elliptic.Curve
	size  int
}{
	{"P-256", CurveP256, elliptic.P256(), 32},
	{"P-384", CurveP384, elliptic.P384(), 48},
	{"P-521", CurveP521, elliptic.P521(), 66},
}

// shortCoordinateECKey returns the first key on curve, walking private scalars
// upward from one, whose X or Y coordinate has a zero high byte. Deterministic:
// no RNG, identical on every run.
func shortCoordinateECKey(t *testing.T, curve elliptic.Curve, size int) *ecdsa.PrivateKey {
	t.Helper()
	scalar := make([]byte, size)
	for i := 1; i < 4096; i++ {
		new(big.Int).SetInt64(int64(i)).FillBytes(scalar)
		key, err := ecdsa.ParseRawPrivateKey(curve, scalar)
		if err != nil {
			t.Fatalf("ParseRawPrivateKey(%d): %v", i, err)
		}
		if len(key.X.Bytes()) < size || len(key.Y.Bytes()) < size {
			return key
		}
	}
	t.Fatalf("no short-coordinate key found on %s within 4096 scalars", curve.Params().Name)
	return nil
}

// TestToECDSAPublicKeyAcceptsShortCoordinateMembers covers the left-padding
// trap on the JWK surface. RFC 7518 requires x and y to be the full field
// size, but encoders that route the value through a big integer drop leading
// zero bytes, so roughly one member in 256 arrives short. Parsing without
// left-padding rejects a perfectly valid key.
func TestToECDSAPublicKeyAcceptsShortCoordinateMembers(t *testing.T) {
	for _, tc := range ecJWKCurves {
		t.Run(tc.name, func(t *testing.T) {
			key := shortCoordinateECKey(t, tc.curve, tc.size)
			x := key.X.Bytes()
			y := key.Y.Bytes()
			if len(x) == tc.size && len(y) == tc.size {
				t.Fatal("fixture is not short: both coordinates are full width")
			}

			jwk := &JWK{
				Kty: string(KeyTypeEC),
				Crv: string(tc.crv),
				X:   base64.RawURLEncoding.EncodeToString(x),
				Y:   base64.RawURLEncoding.EncodeToString(y),
			}

			pub, err := jwk.ToPublicKey()
			if err != nil {
				t.Fatalf("ToPublicKey rejected a valid short-member JWK: %v", err)
			}
			ecPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
			}
			if !ecPub.Equal(&key.PublicKey) {
				t.Fatal("decoded public key does not equal the original")
			}
		})
	}
}

func TestToECDSAPublicKeyRejectsOffCurvePoint(t *testing.T) {
	for _, tc := range ecJWKCurves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			x := make([]byte, tc.size)
			y := make([]byte, tc.size)
			key.X.FillBytes(x)
			key.Y.FillBytes(y)
			y[tc.size-1] ^= 0x01

			jwk := &JWK{
				Kty: string(KeyTypeEC),
				Crv: string(tc.crv),
				X:   base64.RawURLEncoding.EncodeToString(x),
				Y:   base64.RawURLEncoding.EncodeToString(y),
			}

			if _, err := jwk.ToPublicKey(); !errors.Is(err, ecpoint.ErrInvalidPoint) {
				t.Fatalf("off-curve JWK: got %v, want ecpoint.ErrInvalidPoint", err)
			}
		})
	}
}

func TestToECDSAPublicKeyRejectsOversizedCoordinate(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeEC),
		Crv: string(CurveP256),
		X:   base64.RawURLEncoding.EncodeToString(make([]byte, 33)),
		Y:   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	if _, err := jwk.ToPublicKey(); !errors.Is(err, ecpoint.ErrCoordinateTooLong) {
		t.Fatalf("oversized coordinate: got %v, want ecpoint.ErrCoordinateTooLong", err)
	}
}

func TestToECDSAPrivateKeyRoundTripsEveryCurve(t *testing.T) {
	for _, tc := range ecJWKCurves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			jwk, err := FromPrivateKey(key)
			if err != nil {
				t.Fatalf("FromPrivateKey: %v", err)
			}
			got, err := jwk.ToPrivateKey()
			if err != nil {
				t.Fatalf("ToPrivateKey: %v", err)
			}
			priv, ok := got.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PrivateKey, got %T", got)
			}
			if !priv.Equal(key) {
				t.Fatal("decoded private key does not equal the original")
			}
		})
	}
}

// TestToECDSAPrivateKeyAcceptsShortScalarMember covers the left-padding trap
// on the "d" member: a scalar with a zero high byte decodes short, and
// crypto/ecdsa's raw-scalar parser wants a fixed-length value.
func TestToECDSAPrivateKeyAcceptsShortScalarMember(t *testing.T) {
	for _, tc := range ecJWKCurves {
		t.Run(tc.name, func(t *testing.T) {
			key := shortCoordinateECKey(t, tc.curve, tc.size)

			jwk, err := FromPrivateKey(key)
			if err != nil {
				t.Fatalf("FromPrivateKey: %v", err)
			}
			// FromPrivateKey encodes D via big.Int.Bytes(), which for these
			// small deterministic scalars is a single byte.
			d, err := base64.RawURLEncoding.DecodeString(jwk.D)
			if err != nil {
				t.Fatalf("decode d: %v", err)
			}
			if len(d) == tc.size {
				t.Fatalf("fixture scalar is full width (%d bytes); it no longer proves the trap", len(d))
			}

			got, err := jwk.ToPrivateKey()
			if err != nil {
				t.Fatalf("ToPrivateKey rejected a valid short-scalar JWK: %v", err)
			}
			priv, ok := got.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PrivateKey, got %T", got)
			}
			if !priv.Equal(key) {
				t.Fatal("decoded private key does not equal the original")
			}
		})
	}
}

// TestToECDSAPrivateKeyRejectsMismatchedScalar covers a JWK whose d member
// belongs to a different key than its x/y members. Assigning D and the
// coordinates independently produced a private key whose PublicKey field
// contradicted its own scalar.
func TestToECDSAPrivateKeyRejectsMismatchedScalar(t *testing.T) {
	first, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwk, err := FromPrivateKey(first)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}
	jwk.D = base64.RawURLEncoding.EncodeToString(second.D.Bytes()) //nolint:staticcheck // building a deliberately inconsistent JWK

	if _, err := jwk.ToPrivateKey(); err == nil {
		t.Fatal("a JWK whose d does not match its x/y was accepted")
	}
}

func TestToECDSAPrivateKeyRejectsInvalidScalar(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk, err := FromPrivateKey(key)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}
	jwk.D = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	if _, err := jwk.ToPrivateKey(); !errors.Is(err, ecpoint.ErrInvalidScalar) {
		t.Fatalf("zero scalar: got %v, want ecpoint.ErrInvalidScalar", err)
	}
}
