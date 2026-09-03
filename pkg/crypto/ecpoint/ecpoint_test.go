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

package ecpoint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
)

// namedCurves are the curves the TPM, PKCS#11 and JWK surfaces produce.
var namedCurves = []struct {
	name  string
	curve elliptic.Curve
	size  int
}{
	{"P-256", elliptic.P256(), 32},
	{"P-384", elliptic.P384(), 48},
	{"P-521", elliptic.P521(), 66},
}

// trimLeadingZeros strips leading zero bytes exactly the way a TPM
// TPM2B_ECC_PARAMETER buffer, a PKCS#11 EC point or a big.Int.Bytes() call
// does. It is the transformation that makes a valid coordinate arrive short.
func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

// shortCoordinateKey returns the first key on curve, walking private scalars
// upward from one, whose X or Y coordinate has a zero high byte and therefore
// serializes short. Deterministic: no RNG, identical on every run.
func shortCoordinateKey(t *testing.T, curve elliptic.Curve, size int) *ecdsa.PrivateKey {
	t.Helper()
	scalar := make([]byte, size)
	for i := 1; i < 4096; i++ {
		new(big.Int).SetInt64(int64(i)).FillBytes(scalar)
		key, err := ecdsa.ParseRawPrivateKey(curve, scalar)
		if err != nil {
			t.Fatalf("ParseRawPrivateKey(%d): %v", i, err)
		}
		if len(key.X.Bytes()) < size || len(key.Y.Bytes()) < size { //nolint:staticcheck // the test's subject is the short raw coordinate
			return key
		}
	}
	t.Fatalf("no short-coordinate key found on %s within 4096 scalars", curve.Params().Name)
	return nil
}

func TestPublicKeyRoundTripsEveryNamedCurve(t *testing.T) {
	for _, tc := range namedCurves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			got, err := PublicKey(tc.curve, key.X.Bytes(), key.Y.Bytes()) //nolint:staticcheck // exercising the raw-coordinate entry point
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			if !got.Equal(&key.PublicKey) {
				t.Fatal("reconstructed public key does not equal the original")
			}
		})
	}
}

// TestPublicKeyAcceptsShortCoordinateBuffers is the regression test for the
// left-padding trap. A coordinate with a zero high byte arrives shorter than
// the field size; assembling 0x04 || X || Y without left-padding produces a
// point of the wrong length and the stdlib parser rejects a perfectly valid
// key. The rate is roughly 1-in-256 per coordinate, so a test built only from
// randomly generated keys passes ~99.2% of the time and hides this.
func TestPublicKeyAcceptsShortCoordinateBuffers(t *testing.T) {
	for _, tc := range namedCurves {
		t.Run(tc.name, func(t *testing.T) {
			key := shortCoordinateKey(t, tc.curve, tc.size)

			x := trimLeadingZeros(key.X.Bytes()) //nolint:staticcheck // the test's subject is the short raw coordinate
			y := trimLeadingZeros(key.Y.Bytes()) //nolint:staticcheck // the test's subject is the short raw coordinate
			if len(x) == tc.size && len(y) == tc.size {
				t.Fatal("fixture is not short: neither coordinate lost a leading zero")
			}

			// The naive assembly this package exists to replace rejects the key.
			naive := make([]byte, 0, 1+len(x)+len(y))
			naive = append(naive, 4)
			naive = append(naive, x...)
			naive = append(naive, y...)
			if _, err := ecdsa.ParseUncompressedPublicKey(tc.curve, naive); err == nil {
				t.Fatal("naive unpadded assembly was accepted; fixture no longer proves the trap")
			}

			got, err := PublicKey(tc.curve, x, y)
			if err != nil {
				t.Fatalf("PublicKey rejected a valid key with a short coordinate: %v", err)
			}
			if !got.Equal(&key.PublicKey) {
				t.Fatal("reconstructed public key does not equal the original")
			}
		})
	}
}

func TestPublicKeyRejectsOffCurvePoint(t *testing.T) {
	for _, tc := range namedCurves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			x := make([]byte, tc.size)
			y := make([]byte, tc.size)
			key.X.FillBytes(x) //nolint:staticcheck // building a deliberately invalid point
			key.Y.FillBytes(y) //nolint:staticcheck // building a deliberately invalid point
			y[tc.size-1] ^= 0x01

			if _, err := PublicKey(tc.curve, x, y); !errors.Is(err, ErrInvalidPoint) {
				t.Fatalf("off-curve point: got %v, want ErrInvalidPoint", err)
			}
		})
	}
}

func TestPublicKeyRejectsPointAtInfinity(t *testing.T) {
	zeros := make([]byte, 32)
	if _, err := PublicKey(elliptic.P256(), zeros, zeros); !errors.Is(err, ErrInvalidPoint) {
		t.Fatalf("point at infinity: got %v, want ErrInvalidPoint", err)
	}
}

func TestPublicKeyRejectsOversizedCoordinates(t *testing.T) {
	big33 := make([]byte, 33)
	ok32 := make([]byte, 32)

	if _, err := PublicKey(elliptic.P256(), big33, ok32); !errors.Is(err, ErrCoordinateTooLong) {
		t.Fatalf("oversized X: got %v, want ErrCoordinateTooLong", err)
	}
	if _, err := PublicKey(elliptic.P256(), ok32, big33); !errors.Is(err, ErrCoordinateTooLong) {
		t.Fatalf("oversized Y: got %v, want ErrCoordinateTooLong", err)
	}
}

func TestPublicKeyRejectsNilCurve(t *testing.T) {
	if _, err := PublicKey(nil, []byte{1}, []byte{2}); !errors.Is(err, ErrNilCurve) {
		t.Fatalf("nil curve: got %v, want ErrNilCurve", err)
	}
}

// TestPublicKeyRejectsUnsupportedCurve covers a curve crypto/ecdsa's parser
// does not accept, which must surface as ErrInvalidPoint rather than a panic.
func TestPublicKeyRejectsUnsupportedCurve(t *testing.T) {
	unsupported := elliptic.CurveParams{
		Name:    "unsupported-256",
		BitSize: 256,
		P:       big.NewInt(23),
		N:       big.NewInt(29),
		B:       big.NewInt(1),
		Gx:      big.NewInt(3),
		Gy:      big.NewInt(10),
	}
	zeros := make([]byte, 32)
	if _, err := PublicKey(&unsupported, zeros, zeros); !errors.Is(err, ErrInvalidPoint) {
		t.Fatalf("unsupported curve: got %v, want ErrInvalidPoint", err)
	}
}

func TestPrivateKeyRoundTripsEveryNamedCurve(t *testing.T) {
	for _, tc := range namedCurves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			got, err := PrivateKey(tc.curve, key.D.Bytes()) //nolint:staticcheck // exercising the raw-scalar entry point
			if err != nil {
				t.Fatalf("PrivateKey: %v", err)
			}
			if !got.Equal(key) {
				t.Fatal("reconstructed private key does not equal the original")
			}
		})
	}
}

// TestPrivateKeyAcceptsShortScalarBuffer is the left-padding trap on the
// private-scalar side: ParseRawPrivateKey wants a fixed-length scalar, and a
// JWK "d" member whose high byte is zero decodes short.
func TestPrivateKeyAcceptsShortScalarBuffer(t *testing.T) {
	for _, tc := range namedCurves {
		t.Run(tc.name, func(t *testing.T) {
			short := []byte{0x2a}
			if _, err := ecdsa.ParseRawPrivateKey(tc.curve, short); err == nil {
				t.Fatal("stdlib accepted a short scalar; fixture no longer proves the trap")
			}

			key, err := PrivateKey(tc.curve, short)
			if err != nil {
				t.Fatalf("PrivateKey rejected a valid short scalar: %v", err)
			}
			if key.D.Cmp(big.NewInt(0x2a)) != 0 { //nolint:staticcheck // asserting the recovered scalar
				t.Fatalf("scalar = %v, want 42", key.D) //nolint:staticcheck // asserting the recovered scalar
			}
		})
	}
}

func TestPrivateKeyRejectsInvalidScalars(t *testing.T) {
	curve := elliptic.P256()
	size := CoordinateSize(curve)

	zero := make([]byte, size)
	if _, err := PrivateKey(curve, zero); !errors.Is(err, ErrInvalidScalar) {
		t.Fatalf("zero scalar: got %v, want ErrInvalidScalar", err)
	}

	order := make([]byte, size)
	curve.Params().N.FillBytes(order)
	if _, err := PrivateKey(curve, order); !errors.Is(err, ErrInvalidScalar) {
		t.Fatalf("scalar equal to the group order: got %v, want ErrInvalidScalar", err)
	}
}

func TestPrivateKeyRejectsOversizedScalar(t *testing.T) {
	if _, err := PrivateKey(elliptic.P256(), make([]byte, 33)); !errors.Is(err, ErrCoordinateTooLong) {
		t.Fatalf("oversized scalar: got %v, want ErrCoordinateTooLong", err)
	}
}

func TestPrivateKeyRejectsNilCurve(t *testing.T) {
	if _, err := PrivateKey(nil, []byte{1}); !errors.Is(err, ErrNilCurve) {
		t.Fatalf("nil curve: got %v, want ErrNilCurve", err)
	}
}

func TestCoordinateSize(t *testing.T) {
	for _, tc := range namedCurves {
		if got := CoordinateSize(tc.curve); got != tc.size {
			t.Errorf("CoordinateSize(%s) = %d, want %d", tc.name, got, tc.size)
		}
	}
}

func BenchmarkPublicKeyP256(b *testing.B) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	x, y := key.X.Bytes(), key.Y.Bytes() //nolint:staticcheck // benchmarking the raw-coordinate entry point
	b.ResetTimer()
	for b.Loop() {
		if _, err := PublicKey(elliptic.P256(), x, y); err != nil {
			b.Fatalf("PublicKey: %v", err)
		}
	}
}
