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

package authenticator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// cryptoCBOREncMode is a CBOR encoder configured for canonical encoding.
// CTAP2 requires deterministic CBOR with keys sorted in ascending order.
var cryptoCBOREncMode cbor.EncMode

func init() {
	em, err := cbor.EncOptions{
		Sort: cbor.SortCanonical,
	}.EncMode()
	if err != nil {
		panic("failed to create crypto CBOR encoder: " + err.Error())
	}
	cryptoCBOREncMode = em
}

// COSE algorithm constants from IANA COSE Algorithms registry.
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
const (
	COSEAlgES256 = -7   // ECDSA w/ SHA-256 on P-256
	COSEAlgES384 = -35  // ECDSA w/ SHA-384 on P-384
	COSEAlgES512 = -36  // ECDSA w/ SHA-512 on P-521
	COSEAlgRS256 = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256 (not implemented)
	COSEAlgEdDSA = -8   // EdDSA (Ed25519)
)

// COSE key type constants.
const (
	COSEKeyTypeOKP = 1 // Octet Key Pair (Ed25519)
	COSEKeyTypeEC2 = 2 // Elliptic Curve (P-256, P-384, P-521)
	COSEKeyTypeRSA = 3 // RSA (not implemented)
)

// COSE curve constants.
const (
	COSECurveP256    = 1 // NIST P-256
	COSECurveP384    = 2 // NIST P-384
	COSECurveP521    = 3 // NIST P-521
	COSECurveEd25519 = 6 // Ed25519
)

// COSE key parameter labels.
const (
	coseKeyLabelKty = 1  // Key type
	coseKeyLabelAlg = 3  // Algorithm
	coseKeyLabelCrv = -1 // Curve (EC2 and OKP)
	coseKeyLabelX   = -2 // X coordinate (EC2) or public key (OKP)
	coseKeyLabelY   = -3 // Y coordinate (EC2 only)
	coseKeyLabelD   = -4 // Private key (not used in public keys)
)

// Credential ID and key sizes
const (
	CredentialIDSize  = 32 // Random credential ID size
	HMACSecretKeySize = 32 // hmac-secret key size
)

// Cryptographic errors
var (
	ErrUnsupportedCryptoAlgorithm = errors.New("authenticator: unsupported algorithm")
	ErrInvalidPublicKey           = errors.New("authenticator: invalid public key")
	ErrInvalidPrivateKey          = errors.New("authenticator: invalid private key")
	ErrInvalidCOSEKey             = errors.New("authenticator: invalid COSE key encoding")
	ErrKeyGenerationFailed        = errors.New("authenticator: key generation failed")
	ErrSigningFailed              = errors.New("authenticator: signing failed")
	ErrInvalidSignature           = errors.New("authenticator: invalid signature")
	ErrRandomGenerationFailed     = errors.New("authenticator: random generation failed")
	ErrMissingKeyParameter        = errors.New("authenticator: missing required key parameter")
	ErrInvalidCurve               = errors.New("authenticator: invalid or unsupported curve")
)

// GenerateCredentialKey generates a new key pair for the given COSE algorithm.
// Returns the private key and CBOR-encoded COSE public key.
func GenerateCredentialKey(algorithm int) (crypto.PrivateKey, []byte, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey

	switch algorithm {
	case COSEAlgES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, ErrKeyGenerationFailed
		}
		privateKey = key
		publicKey = &key.PublicKey

	case COSEAlgES384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, ErrKeyGenerationFailed
		}
		privateKey = key
		publicKey = &key.PublicKey

	case COSEAlgES512:
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, ErrKeyGenerationFailed
		}
		privateKey = key
		publicKey = &key.PublicKey

	case COSEAlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, ErrKeyGenerationFailed
		}
		privateKey = priv
		publicKey = pub

	default:
		return nil, nil, ErrUnsupportedCryptoAlgorithm
	}

	coseKey, err := EncodeCOSEPublicKey(publicKey, algorithm)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, coseKey, nil
}

// EncodeCOSEPublicKey encodes a public key in COSE_Key format (CBOR).
// The encoding uses integer keys as specified in RFC 8152.
func EncodeCOSEPublicKey(pub crypto.PublicKey, algorithm int) ([]byte, error) {
	if pub == nil {
		return nil, ErrInvalidPublicKey
	}

	var coseKey map[int]interface{}

	switch algorithm {
	case COSEAlgES256:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, ErrInvalidPublicKey
		}
		coseKey = encodeEC2Key(ecKey, algorithm, COSECurveP256, 32)

	case COSEAlgES384:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, ErrInvalidPublicKey
		}
		coseKey = encodeEC2Key(ecKey, algorithm, COSECurveP384, 48)

	case COSEAlgES512:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, ErrInvalidPublicKey
		}
		coseKey = encodeEC2Key(ecKey, algorithm, COSECurveP521, 66)

	case COSEAlgEdDSA:
		edKey, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, ErrInvalidPublicKey
		}
		coseKey = map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeOKP,
			coseKeyLabelAlg: algorithm,
			coseKeyLabelCrv: COSECurveEd25519,
			coseKeyLabelX:   []byte(edKey),
		}

	default:
		return nil, ErrUnsupportedCryptoAlgorithm
	}

	// Use canonical CBOR encoding with keys sorted in ascending order
	// as required by CTAP2 specification
	return cryptoCBOREncMode.Marshal(coseKey)
}

// encodeEC2Key creates a COSE EC2 key map with proper coordinate padding.
func encodeEC2Key(key *ecdsa.PublicKey, algorithm, curve, coordSize int) map[int]interface{} {
	xBytes := padCoordinate(key.X.Bytes(), coordSize)
	yBytes := padCoordinate(key.Y.Bytes(), coordSize)

	return map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: algorithm,
		coseKeyLabelCrv: curve,
		coseKeyLabelX:   xBytes,
		coseKeyLabelY:   yBytes,
	}
}

// padCoordinate pads a coordinate to the required size with leading zeros.
func padCoordinate(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// DecodeCOSEPublicKey decodes a COSE_Key from CBOR and returns the public key
// and its algorithm identifier.
func DecodeCOSEPublicKey(data []byte) (crypto.PublicKey, int, error) {
	if len(data) == 0 {
		return nil, 0, ErrInvalidCOSEKey
	}

	var coseKey map[int]interface{}
	if err := cbor.Unmarshal(data, &coseKey); err != nil {
		return nil, 0, ErrInvalidCOSEKey
	}

	ktyRaw, ok := coseKey[coseKeyLabelKty]
	if !ok {
		return nil, 0, ErrMissingKeyParameter
	}
	kty, err := toInt(ktyRaw)
	if err != nil {
		return nil, 0, ErrInvalidCOSEKey
	}

	algRaw, ok := coseKey[coseKeyLabelAlg]
	if !ok {
		return nil, 0, ErrMissingKeyParameter
	}
	alg, err := toInt(algRaw)
	if err != nil {
		return nil, 0, ErrInvalidCOSEKey
	}

	switch kty {
	case COSEKeyTypeEC2:
		return decodeEC2Key(coseKey, alg)
	case COSEKeyTypeOKP:
		return decodeOKPKey(coseKey, alg)
	default:
		return nil, 0, ErrUnsupportedCryptoAlgorithm
	}
}

// decodeEC2Key decodes an EC2 (elliptic curve) public key from COSE.
func decodeEC2Key(coseKey map[int]interface{}, alg int) (crypto.PublicKey, int, error) {
	crvRaw, ok := coseKey[coseKeyLabelCrv]
	if !ok {
		return nil, 0, ErrMissingKeyParameter
	}
	crv, err := toInt(crvRaw)
	if err != nil {
		return nil, 0, ErrInvalidCOSEKey
	}

	xRaw, ok := coseKey[coseKeyLabelX]
	if !ok {
		return nil, 0, ErrMissingKeyParameter
	}
	xBytes, ok := xRaw.([]byte)
	if !ok {
		return nil, 0, ErrInvalidCOSEKey
	}

	yRaw, ok := coseKey[coseKeyLabelY]
	if !ok {
		return nil, 0, ErrMissingKeyParameter
	}
	yBytes, ok := yRaw.([]byte)
	if !ok {
		return nil, 0, ErrInvalidCOSEKey
	}

	var curve elliptic.Curve
	switch crv {
	case COSECurveP256:
		curve = elliptic.P256()
	case COSECurveP384:
		curve = elliptic.P384()
	case COSECurveP521:
		curve = elliptic.P521()
	default:
		return nil, 0, ErrInvalidCurve
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	if !curve.IsOnCurve(x, y) {
		return nil, 0, ErrInvalidPublicKey
	}

	return pubKey, alg, nil
}

// decodeOKPKey decodes an OKP (Ed25519) public key from COSE.
func decodeOKPKey(coseKey map[int]interface{}, alg int) (crypto.PublicKey, int, error) {
	crvRaw, ok := coseKey[coseKeyLabelCrv]
	if !ok {
		return nil, 0, ErrMissingKeyParameter
	}
	crv, err := toInt(crvRaw)
	if err != nil {
		return nil, 0, ErrInvalidCOSEKey
	}

	if crv != COSECurveEd25519 {
		return nil, 0, ErrInvalidCurve
	}

	xRaw, ok := coseKey[coseKeyLabelX]
	if !ok {
		return nil, 0, ErrMissingKeyParameter
	}
	xBytes, ok := xRaw.([]byte)
	if !ok {
		return nil, 0, ErrInvalidCOSEKey
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, 0, ErrInvalidPublicKey
	}

	return ed25519.PublicKey(xBytes), alg, nil
}

// toInt converts CBOR integer types to int.
func toInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int8:
		return int(n), nil
	case int16:
		return int(n), nil
	case int32:
		return int(n), nil
	case int64:
		return int(n), nil
	case uint:
		return int(n), nil
	case uint8:
		return int(n), nil
	case uint16:
		return int(n), nil
	case uint32:
		return int(n), nil
	case uint64:
		return int(n), nil
	default:
		return 0, ErrInvalidCOSEKey
	}
}

// Sign signs data with the given private key using the specified algorithm.
// For ECDSA algorithms, this produces a fixed-length signature (r || s).
// For EdDSA, this produces the raw Ed25519 signature.
func Sign(key crypto.PrivateKey, algorithm int, data []byte) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidPrivateKey
	}

	switch algorithm {
	case COSEAlgES256:
		return signECDSA(key, data, 32)
	case COSEAlgES384:
		return signECDSA(key, data, 48)
	case COSEAlgES512:
		return signECDSA(key, data, 66)
	case COSEAlgEdDSA:
		return signEdDSA(key, data)
	default:
		return nil, ErrUnsupportedCryptoAlgorithm
	}
}

// ecdsaSignature is the ASN.1 structure for an ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}

// signECDSA signs data using ECDSA with the appropriate hash based on coordSize.
// Returns the signature in ASN.1/DER format as required by the WebAuthn specification
// (W3C WebAuthn Level 2, Section 6.5.5). The signature is normalized to "low-S"
// form where S <= n/2 to prevent signature malleability.
func signECDSA(key crypto.PrivateKey, data []byte, coordSize int) ([]byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}

	// Hash the data using the appropriate hash function for the curve
	var digest []byte
	switch coordSize {
	case 32: // P-256 uses SHA-256
		h := sha256.Sum256(data)
		digest = h[:]
	case 48: // P-384 uses SHA-384
		h := sha512.Sum384(data)
		digest = h[:]
	case 66: // P-521 uses SHA-512
		h := sha512.Sum512(data)
		digest = h[:]
	default:
		return nil, ErrUnsupportedCryptoAlgorithm
	}

	r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest)
	if err != nil {
		return nil, ErrSigningFailed
	}

	// Normalize S to low-S form: if S > n/2, use S' = n - S
	// This prevents signature malleability as required by WebAuthn/CTAP2
	n := ecKey.Curve.Params().N
	halfN := new(big.Int).Rsh(n, 1) // n/2
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(n, s)
	}

	// Encode as ASN.1/DER (SEQUENCE { INTEGER r, INTEGER s })
	// WebAuthn spec mandates DER-encoded ECDSA signatures, not P1363.
	sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return nil, ErrSigningFailed
	}

	return sig, nil
}

// signEdDSA signs data using Ed25519.
func signEdDSA(key crypto.PrivateKey, data []byte) ([]byte, error) {
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}

	return ed25519.Sign(edKey, data), nil
}

// GenerateCredentialID generates a random credential ID.
func GenerateCredentialID() ([]byte, error) {
	id := make([]byte, CredentialIDSize)
	if _, err := rand.Read(id); err != nil {
		return nil, ErrRandomGenerationFailed
	}
	return id, nil
}

// GenerateHMACSecretKey generates a random key for the hmac-secret extension.
func GenerateHMACSecretKey() ([]byte, error) {
	key := make([]byte, HMACSecretKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, ErrRandomGenerationFailed
	}
	return key, nil
}

// AlgorithmName returns a human-readable name for a COSE algorithm.
func AlgorithmName(algorithm int) string {
	switch algorithm {
	case COSEAlgES256:
		return "ES256"
	case COSEAlgES384:
		return "ES384"
	case COSEAlgES512:
		return "ES512"
	case COSEAlgRS256:
		return "RS256"
	case COSEAlgEdDSA:
		return "EdDSA"
	default:
		return "unknown"
	}
}

// CurveForAlgorithm returns the elliptic curve for an ECDSA algorithm.
func CurveForAlgorithm(algorithm int) (elliptic.Curve, error) {
	switch algorithm {
	case COSEAlgES256:
		return elliptic.P256(), nil
	case COSEAlgES384:
		return elliptic.P384(), nil
	case COSEAlgES512:
		return elliptic.P521(), nil
	default:
		return nil, ErrUnsupportedCryptoAlgorithm
	}
}
