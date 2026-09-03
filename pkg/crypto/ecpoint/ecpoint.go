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

// Package ecpoint reconstructs ECDSA keys from the raw big-endian affine
// coordinates carried by hardware and wire formats — TPM 2.0
// TPM2B_ECC_PARAMETER buffers, PKCS#11 EC points, JWK x/y/d members and
// COSE_Key coordinates.
//
// Assigning those coordinates straight into an ecdsa.PublicKey performs no
// validation: a point that is not on the curve, or the point at infinity, is
// accepted and then used as a signing or attestation identity. Every function
// here routes through crypto/ecdsa's parsers, which reject those points.
//
// The parsers require fixed-length coordinates. The formats above are not
// required to carry leading zero bytes, so a coordinate whose high byte is
// zero arrives short — roughly one value in 256. Each function left-pads to
// the curve's field size before parsing, so a short buffer reconstructs
// correctly instead of being rejected at random.
package ecpoint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

var (
	// ErrNilCurve reports a missing elliptic curve.
	ErrNilCurve = errors.New("ecpoint: nil elliptic curve")

	// ErrCoordinateTooLong reports a coordinate or scalar wider than the
	// curve's field size, which no left-padding can repair.
	ErrCoordinateTooLong = errors.New("ecpoint: value wider than the curve field size")

	// ErrInvalidPoint reports a point that is not on the curve, or is the
	// point at infinity.
	ErrInvalidPoint = errors.New("ecpoint: public point is not a valid point on the curve")

	// ErrInvalidScalar reports a private scalar that is zero or not reduced
	// modulo the curve order.
	ErrInvalidScalar = errors.New("ecpoint: private scalar is not valid for the curve")
)

// CoordinateSize returns the fixed byte length of a single affine coordinate
// on curve. It is 32 for P-256, 48 for P-384 and 66 for P-521.
func CoordinateSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// PublicKey reconstructs an ECDSA public key from the big-endian affine
// coordinates x and y, which may be short of the curve's field size.
// It returns ErrInvalidPoint if the point does not lie on the curve.
func PublicKey(curve elliptic.Curve, x, y []byte) (*ecdsa.PublicKey, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	size := CoordinateSize(curve)
	if len(x) > size || len(y) > size {
		return nil, ErrCoordinateTooLong
	}

	// SEC 1 uncompressed point: 0x04 || X || Y, each coordinate left-padded
	// to the field size.
	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1+size-len(x):1+size], x)
	copy(point[1+2*size-len(y):], y)

	key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidPoint, Detail: err.Error()}
	}
	return key, nil
}

// PrivateKey reconstructs an ECDSA private key from the big-endian private
// scalar d, which may be short of the curve's field size. The public key is
// derived from d rather than taken on trust. It returns ErrInvalidScalar if
// d is zero or is not reduced modulo the curve order.
func PrivateKey(curve elliptic.Curve, d []byte) (*ecdsa.PrivateKey, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	size := CoordinateSize(curve)
	if len(d) > size {
		return nil, ErrCoordinateTooLong
	}

	scalar := make([]byte, size)
	copy(scalar[size-len(d):], d)

	key, err := ecdsa.ParseRawPrivateKey(curve, scalar)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidScalar, Detail: err.Error()}
	}
	return key, nil
}
