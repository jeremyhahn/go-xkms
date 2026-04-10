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

package autofill

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
)

// Assertion verifier errors.
var (
	ErrVerifierInvalidAuthData   = errors.New("autofill: authenticator data too short")
	ErrVerifierRPIDMismatch      = errors.New("autofill: RP ID hash mismatch")
	ErrVerifierMissingUP         = errors.New("autofill: user presence flag not set")
	ErrVerifierMissingUV         = errors.New("autofill: user verification flag not set")
	ErrVerifierSignCountRegress  = errors.New("autofill: signature counter regression detected")
	ErrVerifierInvalidSignature  = errors.New("autofill: signature verification failed")
	ErrVerifierInvalidPublicKey  = errors.New("autofill: invalid COSE public key")
	ErrVerifierNilAuthData       = errors.New("autofill: nil authenticator data")
	ErrVerifierNilSignature      = errors.New("autofill: nil signature")
	ErrVerifierNilClientDataHash = errors.New("autofill: nil client data hash")
	ErrVerifierEmptyRPID         = errors.New("autofill: empty RP ID")
	ErrVerifierNilCOSEKey        = errors.New("autofill: nil COSE public key")
)

// Authenticator data flag constants (matching CTAP2 spec section 6.1).
const (
	flagUP uint8 = 0x01 // User Present
	flagUV uint8 = 0x04 // User Verified
)

// minAuthDataLength is the minimum authenticator data length:
// rpIdHash(32) + flags(1) + signCount(4) = 37 bytes.
const minAuthDataLength = 37

// COSE key type and algorithm identifiers for ES256 (ECDSA with SHA-256 on P-256).
const (
	coseKeyTypeEC2 = 2  // EC2 key type
	coseAlgES256   = -7 // ES256 algorithm
	coseCurveP256  = 1  // P-256 curve
)

// COSE key map labels.
const (
	coseLabel_kty = 1  // Key type
	coseLabel_alg = 3  // Algorithm
	coseLabel_crv = -1 // Curve
	coseLabel_x   = -2 // X coordinate
	coseLabel_y   = -3 // Y coordinate
)

// p256CoordLen is the length in bytes of a P-256 coordinate (32 bytes for a 256-bit field).
const p256CoordLen = 32

// AssertionVerifier verifies CTAP2 assertion responses for autofill operations.
// It validates the authenticator data structure, checks user presence and
// verification flags, enforces signature counter monotonicity for replay
// detection, and verifies ECDSA signatures against a registered public key.
//
// The verifier is safe for concurrent use.
type AssertionVerifier struct {
	rpID          string
	rpIDHash      [32]byte
	publicKey     *ecdsa.PublicKey
	lastSignCount atomic.Uint32
}

// NewAssertionVerifier creates a verifier bound to the given RP ID with a
// COSE-encoded ES256 public key. The COSE key is decoded from the CBOR map
// format used in WebAuthn attestation responses.
//
// Returns ErrVerifierEmptyRPID if rpID is empty, ErrVerifierNilCOSEKey if
// publicKeyCOSE is nil, or ErrVerifierInvalidPublicKey if the key is
// malformed or not a valid ES256 key.
func NewAssertionVerifier(rpID string, publicKeyCOSE []byte) (*AssertionVerifier, error) {
	if rpID == "" {
		return nil, ErrVerifierEmptyRPID
	}
	if publicKeyCOSE == nil {
		return nil, ErrVerifierNilCOSEKey
	}

	pubKey, err := parseCOSEPublicKey(publicKeyCOSE)
	if err != nil {
		return nil, err
	}

	v := &AssertionVerifier{
		rpID:      rpID,
		rpIDHash:  sha256.Sum256([]byte(rpID)),
		publicKey: pubKey,
	}
	return v, nil
}

// Verify performs the complete CTAP2 assertion verification chain:
//
//  1. Validate that authData, signature, and clientDataHash are non-nil
//  2. Parse authenticator data (rpIdHash, flags, signCount)
//  3. Verify rpIdHash matches SHA-256(rpID)
//  4. Check UP (user presence) flag is set
//  5. Check UV (user verification) flag is set
//  6. Check signCount > lastSignCount (replay detection)
//  7. Reconstruct signedData = authData || clientDataHash
//  8. Verify ECDSA signature over SHA-256(signedData)
//
// On success, the internal sign counter is updated to the value from authData.
func (v *AssertionVerifier) Verify(authData, signature, clientDataHash []byte) error {
	if authData == nil {
		return ErrVerifierNilAuthData
	}
	if signature == nil {
		return ErrVerifierNilSignature
	}
	if clientDataHash == nil {
		return ErrVerifierNilClientDataHash
	}

	// Parse authenticator data.
	rpIDHash, flags, signCount, err := parseAuthData(authData)
	if err != nil {
		return err
	}

	// Verify RP ID hash.
	if rpIDHash != v.rpIDHash {
		return ErrVerifierRPIDMismatch
	}

	// Check user presence flag.
	if flags&flagUP == 0 {
		return ErrVerifierMissingUP
	}

	// Check user verification flag.
	if flags&flagUV == 0 {
		return ErrVerifierMissingUV
	}

	// Enforce signature counter monotonicity. A counter of 0 from both
	// sides means the authenticator does not support counters, which is
	// acceptable per the WebAuthn spec.
	lastCount := v.lastSignCount.Load()
	if signCount != 0 || lastCount != 0 {
		if signCount <= lastCount {
			return ErrVerifierSignCountRegress
		}
	}

	// Build the signed message: authData || clientDataHash, then hash it.
	signedData := make([]byte, len(authData)+len(clientDataHash))
	copy(signedData, authData)
	copy(signedData[len(authData):], clientDataHash)
	digest := sha256.Sum256(signedData)

	// Verify ECDSA signature.
	if !ecdsa.VerifyASN1(v.publicKey, digest[:], signature) {
		return ErrVerifierInvalidSignature
	}

	// Update the stored sign count on successful verification.
	v.lastSignCount.Store(signCount)

	return nil
}

// parseAuthData extracts the RP ID hash, flags byte, and signature counter
// from raw authenticator data. Returns ErrVerifierInvalidAuthData if the
// data is shorter than the minimum 37 bytes.
func parseAuthData(data []byte) (rpIDHash [32]byte, flags uint8, signCount uint32, err error) {
	if len(data) < minAuthDataLength {
		err = ErrVerifierInvalidAuthData
		return
	}
	copy(rpIDHash[:], data[:32])
	flags = data[32]
	signCount = binary.BigEndian.Uint32(data[33:37])
	return
}

// parseCOSEPublicKey decodes a COSE_Key encoded ES256 public key from CBOR.
// The expected COSE key map structure for ES256 is:
//
//	{1: 2, 3: -7, -1: 1, -2: <x bytes>, -3: <y bytes>}
//
// where kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256), and -2/-3 are the
// uncompressed X/Y coordinates. Returns ErrVerifierInvalidPublicKey if the
// key is malformed, has wrong type/algorithm/curve, or the point is not on
// the P-256 curve.
func parseCOSEPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	var coseMap map[int]cbor.RawMessage
	if err := cbor.Unmarshal(data, &coseMap); err != nil {
		return nil, ErrVerifierInvalidPublicKey
	}

	// Extract and validate key type.
	kty, err := decodeCOSEInt(coseMap, coseLabel_kty)
	if err != nil || kty != coseKeyTypeEC2 {
		return nil, ErrVerifierInvalidPublicKey
	}

	// Extract and validate algorithm.
	alg, err := decodeCOSEInt(coseMap, coseLabel_alg)
	if err != nil || alg != coseAlgES256 {
		return nil, ErrVerifierInvalidPublicKey
	}

	// Extract and validate curve.
	crv, err := decodeCOSEInt(coseMap, coseLabel_crv)
	if err != nil || crv != coseCurveP256 {
		return nil, ErrVerifierInvalidPublicKey
	}

	// Extract X and Y coordinates.
	xBytes, err := decodeCOSEBytes(coseMap, coseLabel_x)
	if err != nil || len(xBytes) == 0 || len(xBytes) > p256CoordLen {
		return nil, ErrVerifierInvalidPublicKey
	}

	yBytes, err := decodeCOSEBytes(coseMap, coseLabel_y)
	if err != nil || len(yBytes) == 0 || len(yBytes) > p256CoordLen {
		return nil, ErrVerifierInvalidPublicKey
	}

	// Left-pad coordinates to 32 bytes if shorter (some encoders strip leading zeros).
	xPadded := padCoordinate(xBytes, p256CoordLen)
	yPadded := padCoordinate(yBytes, p256CoordLen)

	// Build uncompressed point format (0x04 || X || Y) and parse via stdlib.
	// ParseUncompressedPublicKey validates the point lies on the curve.
	uncompressed := make([]byte, 1+p256CoordLen+p256CoordLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+p256CoordLen], xPadded)
	copy(uncompressed[1+p256CoordLen:], yPadded)

	pubKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, ErrVerifierInvalidPublicKey
	}

	return pubKey, nil
}

// decodeCOSEInt extracts an integer value from a COSE key map for the given label.
func decodeCOSEInt(m map[int]cbor.RawMessage, label int) (int, error) {
	raw, ok := m[label]
	if !ok {
		return 0, ErrVerifierInvalidPublicKey
	}
	var val int
	if err := cbor.Unmarshal(raw, &val); err != nil {
		return 0, ErrVerifierInvalidPublicKey
	}
	return val, nil
}

// decodeCOSEBytes extracts a byte slice value from a COSE key map for the given label.
func decodeCOSEBytes(m map[int]cbor.RawMessage, label int) ([]byte, error) {
	raw, ok := m[label]
	if !ok {
		return nil, ErrVerifierInvalidPublicKey
	}
	var val []byte
	if err := cbor.Unmarshal(raw, &val); err != nil {
		return nil, ErrVerifierInvalidPublicKey
	}
	return val, nil
}

// padCoordinate left-pads a coordinate byte slice to the specified length.
// If the slice is already the correct length or longer, it is returned as-is.
func padCoordinate(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}
	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return padded
}
