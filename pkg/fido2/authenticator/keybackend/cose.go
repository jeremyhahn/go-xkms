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

package keybackend

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// COSE algorithm constants (IANA COSE Algorithms registry).
const (
	COSEAlgES256 = -7
	COSEAlgES384 = -35
	COSEAlgES512 = -36
	COSEAlgEdDSA = -8

	// RSASSA-PKCS1-v1_5 with SHA-2. Only ever produced by an attesting key an
	// authenticator does not choose itself -- a TPM's Initial Attestation Key
	// provisioned as RSA -- never as a FIDO2 credential key algorithm.
	COSEAlgRS256 = -257
	COSEAlgRS384 = -258
	COSEAlgRS512 = -259

	// RSASSA-PSS with SHA-2, for the same restricted use as the RS* family.
	COSEAlgPS256 = -37
	COSEAlgPS384 = -38
	COSEAlgPS512 = -39
)

// COSE key type and curve constants.
const (
	COSEKeyTypeEC2 = 2
	COSEKeyTypeOKP = 1
	COSEKeyTypeRSA = 3

	COSECurveP256    = 1
	COSECurveP384    = 2
	COSECurveP521    = 3
	COSECurveEd25519 = 6
)

// coseCBOREncMode is a CBOR encoder configured for CTAP2 canonical encoding.
// CTAP2 requires map keys sorted in ascending order of their CBOR encoding.
var coseCBOREncMode cbor.EncMode

func init() {
	em, err := cbor.EncOptions{
		Sort: cbor.SortCanonical,
	}.EncMode()
	if err != nil {
		panic("keybackend: failed to create COSE CBOR encoder: " + err.Error())
	}
	coseCBOREncMode = em
}

// EncodeCOSEPublicKey encodes a crypto.PublicKey as a COSE key structure
// using CTAP2 canonical CBOR encoding. The algorithm parameter is a COSE
// algorithm identifier (e.g., COSEAlgES256).
func EncodeCOSEPublicKey(publicKey crypto.PublicKey, algorithm int) ([]byte, error) {
	switch algorithm {
	case COSEAlgES256, COSEAlgES384, COSEAlgES512:
		ecKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, ErrUnsupportedAlgorithm
		}
		return encodeCOSEEC2Key(ecKey, algorithm)
	case COSEAlgEdDSA:
		edKey, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return nil, ErrUnsupportedAlgorithm
		}
		return encodeCOSEOKPKey(edKey)
	case COSEAlgRS256, COSEAlgRS384, COSEAlgRS512, COSEAlgPS256, COSEAlgPS384, COSEAlgPS512:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, ErrUnsupportedAlgorithm
		}
		return encodeCOSERSAKey(rsaKey, algorithm)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// encodeCOSEEC2Key encodes an ECDSA public key as a COSE EC2 key.
func encodeCOSEEC2Key(publicKey *ecdsa.PublicKey, algorithm int) ([]byte, error) {
	var curve int
	switch algorithm {
	case COSEAlgES256:
		curve = COSECurveP256
	case COSEAlgES384:
		curve = COSECurveP384
	case COSEAlgES512:
		curve = COSECurveP521
	}

	keySize := (publicKey.Curve.Params().BitSize + 7) / 8
	x := make([]byte, keySize)
	y := make([]byte, keySize)
	xBytes := publicKey.X.Bytes() //nolint:staticcheck // CTAP2/COSE/ECDH protocol uses crypto/elliptic raw EC coords + ScalarMult; ecdsa big.Int access is deprecated but functional. Migrating to crypto/ecdh is a separate behavior-sensitive change.
	yBytes := publicKey.Y.Bytes() //nolint:staticcheck // CTAP2/COSE/ECDH protocol uses crypto/elliptic raw EC coords + ScalarMult; ecdsa big.Int access is deprecated but functional. Migrating to crypto/ecdh is a separate behavior-sensitive change.
	copy(x[keySize-len(xBytes):], xBytes)
	copy(y[keySize-len(yBytes):], yBytes)

	coseKey := map[int]interface{}{
		1:  COSEKeyTypeEC2, // kty: EC2
		3:  algorithm,      // alg
		-1: curve,          // crv
		-2: x,              // x
		-3: y,              // y
	}

	return coseCBOREncMode.Marshal(coseKey)
}

// encodeCOSERSAKey encodes an RSA public key as a COSE RSA key (RFC 8230),
// used only for a TPM Initial Attestation Key's public key: no FIDO2
// credential key algorithm in this package is RSA.
func encodeCOSERSAKey(publicKey *rsa.PublicKey, algorithm int) ([]byte, error) {
	e := big.NewInt(int64(publicKey.E)).Bytes()

	coseKey := map[int]interface{}{
		1:  COSEKeyTypeRSA,      // kty: RSA
		3:  algorithm,           // alg
		-1: publicKey.N.Bytes(), // n
		-2: e,                   // e
	}

	return coseCBOREncMode.Marshal(coseKey)
}

// encodeCOSEOKPKey encodes an Ed25519 public key as a COSE OKP key.
func encodeCOSEOKPKey(publicKey ed25519.PublicKey) ([]byte, error) {
	coseKey := map[int]interface{}{
		1:  COSEKeyTypeOKP,    // kty: OKP
		3:  COSEAlgEdDSA,      // alg
		-1: COSECurveEd25519,  // crv
		-2: []byte(publicKey), // x
	}

	return coseCBOREncMode.Marshal(coseKey)
}

// ecdsaSignature is the ASN.1 structure for an ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}

// NormalizeLowS normalizes an ASN.1 DER ECDSA signature to low-S form
// per BIP-62 / WebAuthn requirements. If S > n/2, S is replaced with n - S.
func NormalizeLowS(derSig []byte, curve elliptic.Curve) ([]byte, error) {
	var sig ecdsaSignature
	rest, err := asn1.Unmarshal(derSig, &sig)
	if err != nil || len(rest) > 0 {
		return nil, ErrSigningFailed
	}

	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if sig.S.Cmp(halfN) > 0 {
		sig.S = new(big.Int).Sub(n, sig.S)
	}

	return asn1.Marshal(sig)
}
