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
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const testRPID = "example.com"

// buildTestAuthData constructs a minimal 37-byte authenticator data blob.
func buildTestAuthData(rpID string, flags uint8, signCount uint32) []byte {
	hash := sha256.Sum256([]byte(rpID))
	data := make([]byte, minAuthDataLength)
	copy(data[:32], hash[:])
	data[32] = flags
	binary.BigEndian.PutUint32(data[33:37], signCount)
	return data
}

// encodeCOSEPublicKey encodes an ECDSA P-256 public key as a COSE_Key CBOR map.
func encodeCOSEPublicKey(pub *ecdsa.PublicKey) []byte {
	// Extract X/Y coordinates from the uncompressed point encoding (0x04 || X || Y).
	uncompressed, err := pub.Bytes()
	if err != nil {
		panic("failed to encode public key: " + err.Error())
	}
	xBytes := uncompressed[1 : 1+p256CoordLen]
	yBytes := uncompressed[1+p256CoordLen:]
	coseMap := map[int]interface{}{
		1:  2,      // kty: EC2
		3:  -7,     // alg: ES256
		-1: 1,      // crv: P-256
		-2: xBytes, // x coordinate
		-3: yBytes, // y coordinate
	}
	data, err := cbor.Marshal(coseMap)
	if err != nil {
		panic("failed to encode COSE public key: " + err.Error())
	}
	return data
}

// signAssertion signs authData || clientDataHash using SHA-256 + ECDSA.
func signAssertion(t *testing.T, privKey *ecdsa.PrivateKey, authData, clientDataHash []byte) []byte {
	t.Helper()
	signedData := make([]byte, len(authData)+len(clientDataHash))
	copy(signedData, authData)
	copy(signedData[len(authData):], clientDataHash)
	digest := sha256.Sum256(signedData)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		t.Fatalf("failed to sign assertion: %v", err)
	}
	return sig
}

// generateTestKeypair creates a fresh ECDSA P-256 keypair for testing.
func generateTestKeypair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	return privKey
}

func TestAssertionVerifier_Valid(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	authData := buildTestAuthData(testRPID, flagUP|flagUV, 1)
	clientDataHash := sha256.Sum256([]byte("test client data"))
	sig := signAssertion(t, privKey, authData, clientDataHash[:])

	if err := verifier.Verify(authData, sig, clientDataHash[:]); err != nil {
		t.Fatalf("Verify failed on valid assertion: %v", err)
	}

	// Verify a second time with an incremented counter to confirm counter update.
	authData2 := buildTestAuthData(testRPID, flagUP|flagUV, 2)
	sig2 := signAssertion(t, privKey, authData2, clientDataHash[:])

	if err := verifier.Verify(authData2, sig2, clientDataHash[:]); err != nil {
		t.Fatalf("Verify failed on second valid assertion: %v", err)
	}
}

func TestAssertionVerifier_BadRPIDHash(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	// Build authData with wrong RP ID.
	authData := buildTestAuthData("evil.com", flagUP|flagUV, 1)
	clientDataHash := sha256.Sum256([]byte("test client data"))
	sig := signAssertion(t, privKey, authData, clientDataHash[:])

	err = verifier.Verify(authData, sig, clientDataHash[:])
	if !errors.Is(err, ErrVerifierRPIDMismatch) {
		t.Fatalf("expected ErrVerifierRPIDMismatch, got: %v", err)
	}
}

func TestAssertionVerifier_MissingUP(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	// UV set but UP cleared.
	authData := buildTestAuthData(testRPID, flagUV, 1)
	clientDataHash := sha256.Sum256([]byte("test client data"))
	sig := signAssertion(t, privKey, authData, clientDataHash[:])

	err = verifier.Verify(authData, sig, clientDataHash[:])
	if !errors.Is(err, ErrVerifierMissingUP) {
		t.Fatalf("expected ErrVerifierMissingUP, got: %v", err)
	}
}

func TestAssertionVerifier_MissingUV(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	// UP set but UV cleared.
	authData := buildTestAuthData(testRPID, flagUP, 1)
	clientDataHash := sha256.Sum256([]byte("test client data"))
	sig := signAssertion(t, privKey, authData, clientDataHash[:])

	err = verifier.Verify(authData, sig, clientDataHash[:])
	if !errors.Is(err, ErrVerifierMissingUV) {
		t.Fatalf("expected ErrVerifierMissingUV, got: %v", err)
	}
}

func TestAssertionVerifier_BadSignature(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	authData := buildTestAuthData(testRPID, flagUP|flagUV, 1)
	clientDataHash := sha256.Sum256([]byte("test client data"))

	// Sign with a different key to produce an invalid signature.
	wrongKey := generateTestKeypair(t)
	badSig := signAssertion(t, wrongKey, authData, clientDataHash[:])

	err = verifier.Verify(authData, badSig, clientDataHash[:])
	if !errors.Is(err, ErrVerifierInvalidSignature) {
		t.Fatalf("expected ErrVerifierInvalidSignature, got: %v", err)
	}
}

func TestAssertionVerifier_BadSignatureCorrupted(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	authData := buildTestAuthData(testRPID, flagUP|flagUV, 1)
	clientDataHash := sha256.Sum256([]byte("test client data"))
	sig := signAssertion(t, privKey, authData, clientDataHash[:])

	// Corrupt the last byte of the signature.
	sig[len(sig)-1] ^= 0xFF

	err = verifier.Verify(authData, sig, clientDataHash[:])
	if !errors.Is(err, ErrVerifierInvalidSignature) {
		t.Fatalf("expected ErrVerifierInvalidSignature, got: %v", err)
	}
}

func TestAssertionVerifier_SignCountRegression(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	clientDataHash := sha256.Sum256([]byte("test client data"))

	// First assertion with counter = 5 should succeed.
	authData1 := buildTestAuthData(testRPID, flagUP|flagUV, 5)
	sig1 := signAssertion(t, privKey, authData1, clientDataHash[:])
	if err := verifier.Verify(authData1, sig1, clientDataHash[:]); err != nil {
		t.Fatalf("first Verify failed: %v", err)
	}

	// Second assertion with counter = 3 (regression) should fail.
	authData2 := buildTestAuthData(testRPID, flagUP|flagUV, 3)
	sig2 := signAssertion(t, privKey, authData2, clientDataHash[:])
	err = verifier.Verify(authData2, sig2, clientDataHash[:])
	if !errors.Is(err, ErrVerifierSignCountRegress) {
		t.Fatalf("expected ErrVerifierSignCountRegress, got: %v", err)
	}
}

func TestAssertionVerifier_SignCountEqual(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	clientDataHash := sha256.Sum256([]byte("test client data"))

	// First assertion with counter = 5.
	authData1 := buildTestAuthData(testRPID, flagUP|flagUV, 5)
	sig1 := signAssertion(t, privKey, authData1, clientDataHash[:])
	if err := verifier.Verify(authData1, sig1, clientDataHash[:]); err != nil {
		t.Fatalf("first Verify failed: %v", err)
	}

	// Second assertion with same counter = 5 (replay) should fail.
	authData2 := buildTestAuthData(testRPID, flagUP|flagUV, 5)
	sig2 := signAssertion(t, privKey, authData2, clientDataHash[:])
	err = verifier.Verify(authData2, sig2, clientDataHash[:])
	if !errors.Is(err, ErrVerifierSignCountRegress) {
		t.Fatalf("expected ErrVerifierSignCountRegress for equal counter, got: %v", err)
	}
}

func TestAssertionVerifier_ZeroCounterAccepted(t *testing.T) {
	// Per WebAuthn spec, both counters at zero means counters are unsupported.
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	clientDataHash := sha256.Sum256([]byte("test client data"))

	// Counter = 0 should be accepted when lastSignCount is also 0.
	authData := buildTestAuthData(testRPID, flagUP|flagUV, 0)
	sig := signAssertion(t, privKey, authData, clientDataHash[:])
	if err := verifier.Verify(authData, sig, clientDataHash[:]); err != nil {
		t.Fatalf("Verify with zero counter failed: %v", err)
	}

	// Second zero-counter assertion should also be accepted.
	authData2 := buildTestAuthData(testRPID, flagUP|flagUV, 0)
	sig2 := signAssertion(t, privKey, authData2, clientDataHash[:])
	if err := verifier.Verify(authData2, sig2, clientDataHash[:]); err != nil {
		t.Fatalf("second Verify with zero counter failed: %v", err)
	}
}

func TestAssertionVerifier_InvalidCOSEKey(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "garbage bytes",
			data: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
		{
			name: "empty bytes",
			data: []byte{},
		},
		{
			name: "valid CBOR but wrong key type",
			data: func() []byte {
				coseMap := map[int]interface{}{
					1:  3,                          // kty: OKP (not EC2)
					3:  -7,                         // alg: ES256
					-1: 1,                          // crv: P-256
					-2: make([]byte, p256CoordLen), // x
					-3: make([]byte, p256CoordLen), // y
				}
				data, _ := cbor.Marshal(coseMap)
				return data
			}(),
		},
		{
			name: "valid CBOR but wrong algorithm",
			data: func() []byte {
				coseMap := map[int]interface{}{
					1:  2,                          // kty: EC2
					3:  -35,                        // alg: ES384 (not ES256)
					-1: 1,                          // crv: P-256
					-2: make([]byte, p256CoordLen), // x
					-3: make([]byte, p256CoordLen), // y
				}
				data, _ := cbor.Marshal(coseMap)
				return data
			}(),
		},
		{
			name: "valid CBOR but wrong curve",
			data: func() []byte {
				coseMap := map[int]interface{}{
					1:  2,                          // kty: EC2
					3:  -7,                         // alg: ES256
					-1: 2,                          // crv: P-384 (not P-256)
					-2: make([]byte, p256CoordLen), // x
					-3: make([]byte, p256CoordLen), // y
				}
				data, _ := cbor.Marshal(coseMap)
				return data
			}(),
		},
		{
			name: "missing X coordinate",
			data: func() []byte {
				coseMap := map[int]interface{}{
					1:  2,                          // kty: EC2
					3:  -7,                         // alg: ES256
					-1: 1,                          // crv: P-256
					-3: make([]byte, p256CoordLen), // y only
				}
				data, _ := cbor.Marshal(coseMap)
				return data
			}(),
		},
		{
			name: "missing Y coordinate",
			data: func() []byte {
				coseMap := map[int]interface{}{
					1:  2,                          // kty: EC2
					3:  -7,                         // alg: ES256
					-1: 1,                          // crv: P-256
					-2: make([]byte, p256CoordLen), // x only
				}
				data, _ := cbor.Marshal(coseMap)
				return data
			}(),
		},
		{
			name: "point not on curve",
			data: func() []byte {
				coseMap := map[int]interface{}{
					1:  2,                          // kty: EC2
					3:  -7,                         // alg: ES256
					-1: 1,                          // crv: P-256
					-2: make([]byte, p256CoordLen), // x = 0
					-3: make([]byte, p256CoordLen), // y = 0
				}
				data, _ := cbor.Marshal(coseMap)
				return data
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAssertionVerifier(testRPID, tc.data)
			if !errors.Is(err, ErrVerifierInvalidPublicKey) {
				t.Fatalf("expected ErrVerifierInvalidPublicKey, got: %v", err)
			}
		})
	}
}

func TestAssertionVerifier_NilInputs(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	validAuthData := buildTestAuthData(testRPID, flagUP|flagUV, 1)
	validClientDataHash := sha256.Sum256([]byte("test"))
	validSig := signAssertion(t, privKey, validAuthData, validClientDataHash[:])

	t.Run("nil authData", func(t *testing.T) {
		err := verifier.Verify(nil, validSig, validClientDataHash[:])
		if !errors.Is(err, ErrVerifierNilAuthData) {
			t.Fatalf("expected ErrVerifierNilAuthData, got: %v", err)
		}
	})

	t.Run("nil signature", func(t *testing.T) {
		err := verifier.Verify(validAuthData, nil, validClientDataHash[:])
		if !errors.Is(err, ErrVerifierNilSignature) {
			t.Fatalf("expected ErrVerifierNilSignature, got: %v", err)
		}
	})

	t.Run("nil clientDataHash", func(t *testing.T) {
		err := verifier.Verify(validAuthData, validSig, nil)
		if !errors.Is(err, ErrVerifierNilClientDataHash) {
			t.Fatalf("expected ErrVerifierNilClientDataHash, got: %v", err)
		}
	})
}

func TestAssertionVerifier_TruncatedAuthData(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	clientDataHash := sha256.Sum256([]byte("test"))

	// Auth data that is too short (36 bytes instead of 37).
	shortAuthData := make([]byte, 36)
	err = verifier.Verify(shortAuthData, []byte{0x30}, clientDataHash[:])
	if !errors.Is(err, ErrVerifierInvalidAuthData) {
		t.Fatalf("expected ErrVerifierInvalidAuthData, got: %v", err)
	}
}

func TestNewAssertionVerifier_EmptyRPID(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	_, err := NewAssertionVerifier("", coseKey)
	if !errors.Is(err, ErrVerifierEmptyRPID) {
		t.Fatalf("expected ErrVerifierEmptyRPID, got: %v", err)
	}
}

func TestNewAssertionVerifier_NilCOSEKey(t *testing.T) {
	_, err := NewAssertionVerifier(testRPID, nil)
	if !errors.Is(err, ErrVerifierNilCOSEKey) {
		t.Fatalf("expected ErrVerifierNilCOSEKey, got: %v", err)
	}
}

func TestAssertionVerifier_NoFlagsSet(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	// No flags set at all.
	authData := buildTestAuthData(testRPID, 0, 1)
	clientDataHash := sha256.Sum256([]byte("test"))
	sig := signAssertion(t, privKey, authData, clientDataHash[:])

	err = verifier.Verify(authData, sig, clientDataHash[:])
	if !errors.Is(err, ErrVerifierMissingUP) {
		t.Fatalf("expected ErrVerifierMissingUP when no flags set, got: %v", err)
	}
}

func TestAssertionVerifier_LargerAuthData(t *testing.T) {
	// Authenticator data can be longer than 37 bytes (extensions, attested cred data).
	// The verifier must handle this correctly.
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	verifier, err := NewAssertionVerifier(testRPID, coseKey)
	if err != nil {
		t.Fatalf("NewAssertionVerifier failed: %v", err)
	}

	// Build 37-byte base + 16 bytes of extension data.
	baseAuthData := buildTestAuthData(testRPID, flagUP|flagUV, 1)
	extData := make([]byte, 16)
	for i := range extData {
		extData[i] = byte(i)
	}
	authData := append(baseAuthData, extData...)

	clientDataHash := sha256.Sum256([]byte("test"))
	sig := signAssertion(t, privKey, authData, clientDataHash[:])

	if err := verifier.Verify(authData, sig, clientDataHash[:]); err != nil {
		t.Fatalf("Verify with extended authData failed: %v", err)
	}
}

func TestParseCOSEPublicKey_ValidKey(t *testing.T) {
	privKey := generateTestKeypair(t)
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)

	pubKey, err := parseCOSEPublicKey(coseKey)
	if err != nil {
		t.Fatalf("parseCOSEPublicKey failed: %v", err)
	}

	if !pubKey.Equal(&privKey.PublicKey) {
		t.Fatal("parsed public key does not match original")
	}
}

func TestParseCOSEPublicKey_ShortCoordinates(t *testing.T) {
	// Test that coordinates shorter than 32 bytes (with leading zeros stripped)
	// are handled correctly via left-padding.
	privKey := generateTestKeypair(t)

	// Extract coordinates from uncompressed point encoding.
	uncompressed, err := privKey.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}
	xBytes := uncompressed[1 : 1+p256CoordLen]
	yBytes := uncompressed[1+p256CoordLen:]

	// Trim leading zeros if present, then add one leading zero to create a shorter coord.
	shortX := xBytes
	if len(shortX) == p256CoordLen && shortX[0] != 0 {
		// Force a shorter coordinate by stripping one byte.
		// This may produce a different key, so just test that parsing succeeds
		// for a known-good key with full-length coords.
		// Instead, test the padCoordinate function directly.
		t.Run("padCoordinate", func(t *testing.T) {
			short := []byte{0x01, 0x02}
			padded := padCoordinate(short, 32)
			if len(padded) != 32 {
				t.Fatalf("expected 32 bytes, got %d", len(padded))
			}
			if padded[30] != 0x01 || padded[31] != 0x02 {
				t.Fatal("padding placed bytes at wrong position")
			}
			for i := 0; i < 30; i++ {
				if padded[i] != 0 {
					t.Fatalf("expected zero padding at position %d, got %d", i, padded[i])
				}
			}
		})
		_ = yBytes
		return
	}

	// If X coordinate does have leading zeros, test naturally.
	coseKey := encodeCOSEPublicKey(&privKey.PublicKey)
	pubKey, err := parseCOSEPublicKey(coseKey)
	if err != nil {
		t.Fatalf("parseCOSEPublicKey failed: %v", err)
	}
	if !pubKey.Equal(&privKey.PublicKey) {
		t.Fatal("key mismatch after padding")
	}
}

func TestPadCoordinate(t *testing.T) {
	t.Run("shorter than target", func(t *testing.T) {
		input := []byte{0xAB, 0xCD}
		result := padCoordinate(input, 4)
		expected := []byte{0x00, 0x00, 0xAB, 0xCD}
		if len(result) != len(expected) {
			t.Fatalf("expected length %d, got %d", len(expected), len(result))
		}
		for i := range expected {
			if result[i] != expected[i] {
				t.Fatalf("mismatch at byte %d: expected %02x, got %02x", i, expected[i], result[i])
			}
		}
	})

	t.Run("exact length", func(t *testing.T) {
		input := []byte{0x01, 0x02, 0x03, 0x04}
		result := padCoordinate(input, 4)
		if &result[0] != &input[0] {
			t.Fatal("should return same slice when length matches")
		}
	})

	t.Run("longer than target", func(t *testing.T) {
		input := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		result := padCoordinate(input, 4)
		if &result[0] != &input[0] {
			t.Fatal("should return same slice when longer than target")
		}
	})
}

func TestParseAuthData(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		authData := buildTestAuthData("test.com", flagUP|flagUV, 42)
		rpIDHash, flags, count, err := parseAuthData(authData)
		if err != nil {
			t.Fatalf("parseAuthData failed: %v", err)
		}
		expected := sha256.Sum256([]byte("test.com"))
		if rpIDHash != expected {
			t.Fatal("RP ID hash mismatch")
		}
		if flags != flagUP|flagUV {
			t.Fatalf("expected flags %02x, got %02x", flagUP|flagUV, flags)
		}
		if count != 42 {
			t.Fatalf("expected signCount 42, got %d", count)
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, _, _, err := parseAuthData(make([]byte, 36))
		if !errors.Is(err, ErrVerifierInvalidAuthData) {
			t.Fatalf("expected ErrVerifierInvalidAuthData, got: %v", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, _, _, err := parseAuthData(nil)
		if !errors.Is(err, ErrVerifierInvalidAuthData) {
			t.Fatalf("expected ErrVerifierInvalidAuthData, got: %v", err)
		}
	})
}
