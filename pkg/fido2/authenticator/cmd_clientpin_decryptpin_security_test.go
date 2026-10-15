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

package authenticator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// This file covers go-xkms#1149: decryptPIN checked only a minimum length
// before calling cipher.CBCDecrypter.CryptBlocks, which panics when its
// input is not a whole number of AES blocks, and nothing on the CTAP/uhid
// path recovered. A 65-byte (protocol 1) or 81-byte (protocol 2) newPinEnc
// in setPIN/changePIN crashed the daemon. Separately, a first plaintext byte
// of 0x00 made the old pinLen==0 check fall through to treating the entire
// 64-byte buffer as the PIN instead of an empty one.

// buildPaddedPIN returns a 64-byte CTAP PIN plaintext buffer: pin followed by
// an implicit 0x00 terminator and zero padding filling the rest of the
// block, exactly as encryptNewPIN builds one for a real ceremony.
func buildPaddedPIN(pin string) []byte {
	buf := make([]byte, EncryptedPINMinLength)
	if len(pin) >= len(buf) {
		panic("buildPaddedPIN: pin too long for the padded buffer")
	}
	copy(buf, pin)
	return buf
}

// encryptCBCZeroIV encrypts a block-aligned plaintext with AES-256-CBC and a
// zero IV, as CTAP 2.1 PIN protocol 1 requires. It panics on a setup failure,
// which only a malformed key length in a test fixture could cause.
func encryptCBCZeroIV(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, AESBlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

// encryptCBCRandomIV encrypts a block-aligned plaintext with AES-256-CBC and
// a random IV, prepending the IV as CTAP 2.1 PIN protocol 2 requires.
func encryptCBCRandomIV(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, AESBlockSize)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return append(iv, ciphertext...)
}

// TestDecryptPINRejectsWrongLength is a table test over the lengths that hit
// the go-xkms#1149 panic (65 and 81, one byte past a whole-block ciphertext)
// and the lengths that were already caught by the old minimum-length check
// (63 and 0), verifying that decryptPIN never panics on any exact-length
// mismatch and that every one is reported as ErrInvalidParameter
// (CTAP1_ERR_INVALID_PARAMETER).
func TestDecryptPINRejectsWrongLength(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tests := []struct {
		name     string
		protocol uint8
		size     int
	}{
		{"protocol 1, 65 bytes (one past the required 64, panics CryptBlocks without the guard)", PINProtocol1, 65},
		{"protocol 2, 81 bytes (one past the required 80, panics CryptBlocks without the guard)", PINProtocol2, 81},
		{"protocol 1, 63 bytes (one short of the required 64)", PINProtocol1, 63},
		{"protocol 1, 0 bytes (empty newPinEnc)", PINProtocol1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := make([]byte, tt.size)
			_, err := rand.Read(encrypted)
			require.NoError(t, err)

			var decryptErr error
			require.NotPanics(t, func() {
				_, decryptErr = auth.decryptPIN(key, tt.protocol, encrypted)
			})
			require.ErrorIs(t, decryptErr, ErrInvalidParameter)
		})
	}
}

// TestDecryptPINRejectsBadPadding verifies that an exact-length newPinEnc
// (so it passes the length guard and reaches CryptBlocks) whose decrypted
// plaintext has a non-zero byte after the 0x00 terminator is rejected as
// ErrPINPolicyViolation (CTAP2_ERR_PIN_POLICY_VIOLATION) rather than
// accepted or misparsed.
func TestDecryptPINRejectsBadPadding(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	plaintext := buildPaddedPIN("1234")
	plaintext[10] = 0x41 // stray non-zero byte after the terminator at index 4

	encrypted := encryptCBCZeroIV(key, plaintext)
	require.Len(t, encrypted, EncryptedPINMinLength)

	var decryptErr error
	require.NotPanics(t, func() {
		_, decryptErr = auth.decryptPIN(key, PINProtocol1, encrypted)
	})
	require.ErrorIs(t, decryptErr, ErrPINPolicyViolation)
}

// TestDecryptPINNoTerminatorIsPolicyViolation verifies that a decrypted
// plaintext with no 0x00 byte anywhere -- which has no room left for a
// terminator, so it would represent a 64-byte PIN exceeding the 63-byte
// maximum -- is rejected as ErrPINPolicyViolation instead of falling through
// to using the whole buffer as the PIN.
func TestDecryptPINNoTerminatorIsPolicyViolation(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	plaintext := make([]byte, EncryptedPINMinLength)
	for i := range plaintext {
		plaintext[i] = 'A'
	}

	encrypted := encryptCBCZeroIV(key, plaintext)

	_, err = auth.decryptPIN(key, PINProtocol1, encrypted)
	require.ErrorIs(t, err, ErrPINPolicyViolation)
}

// TestDecryptPINLeadingZeroIsPolicyViolation verifies the go-xkms#1149
// pinLen==0 bug directly: a plaintext whose first byte is 0x00 must extract
// an empty PIN and be rejected as ErrPINPolicyViolation, not silently fall
// through to treating the entire 64-byte buffer as the PIN.
func TestDecryptPINLeadingZeroIsPolicyViolation(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	// All-zero plaintext: byte 0 is the terminator, so the extracted PIN is
	// empty.
	plaintext := make([]byte, EncryptedPINMinLength)
	encrypted := encryptCBCZeroIV(key, plaintext)

	_, err = auth.decryptPIN(key, PINProtocol1, encrypted)
	require.ErrorIs(t, err, ErrPINPolicyViolation)
}

// TestDecryptPINValidPINRoundTrips is the positive case for both protocols:
// a correctly encrypted, correctly padded PIN still decrypts to exactly the
// original PIN bytes.
func TestDecryptPINValidPINRoundTrips(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	plaintext := buildPaddedPIN("correct-horse")

	t.Run("protocol 1", func(t *testing.T) {
		encrypted := encryptCBCZeroIV(key, plaintext)
		pin, err := auth.decryptPIN(key, PINProtocol1, encrypted)
		require.NoError(t, err)
		require.Equal(t, "correct-horse", string(pin))
	})

	t.Run("protocol 2", func(t *testing.T) {
		encrypted := encryptCBCRandomIV(key, plaintext)
		pin, err := auth.decryptPIN(key, PINProtocol2, encrypted)
		require.NoError(t, err)
		require.Equal(t, "correct-horse", string(pin))
	})
}

// FuzzDecryptPIN fuzzes decryptPIN directly over arbitrary protocol/length
// combinations. The only contract under fuzzing is "never panic" --
// decryptPIN must always return an error for malformed input instead of
// crashing the process, which is exactly the go-xkms#1149 regression.
func FuzzDecryptPIN(f *testing.F) {
	config := &Config{
		UserPresenceHandler: NewAutoGrantHandler(),
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       8,
		SupportedAlgorithms: []int{COSEAlgES256},
	}
	auth, err := NewAuthenticator(config)
	if err != nil {
		f.Fatalf("failed to create authenticator: %v", err)
	}
	f.Cleanup(func() { _ = auth.Close() })

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Seed with every case go-xkms#1149 identified.
	f.Add(uint8(PINProtocol1), make([]byte, 65)) // panics CryptBlocks pre-fix (V1)
	f.Add(uint8(PINProtocol2), make([]byte, 81)) // panics CryptBlocks pre-fix (V2)
	f.Add(uint8(PINProtocol1), make([]byte, 63)) // one short
	f.Add(uint8(PINProtocol1), []byte{})         // empty

	badPadding := buildPaddedPIN("1234")
	badPadding[10] = 0x41
	f.Add(uint8(PINProtocol1), encryptCBCZeroIV(key, badPadding))

	f.Add(uint8(PINProtocol1), encryptCBCZeroIV(key, make([]byte, EncryptedPINMinLength))) // leading 0x00

	noTerminator := make([]byte, EncryptedPINMinLength)
	for i := range noTerminator {
		noTerminator[i] = 'A'
	}
	f.Add(uint8(PINProtocol1), encryptCBCZeroIV(key, noTerminator))

	f.Add(uint8(PINProtocol1), encryptCBCZeroIV(key, buildPaddedPIN("1234")))
	f.Add(uint8(PINProtocol2), encryptCBCRandomIV(key, buildPaddedPIN("1234")))

	f.Fuzz(func(t *testing.T, protocol uint8, encrypted []byte) {
		require.NotPanics(t, func() {
			_, _ = auth.decryptPIN(key, protocol, encrypted)
		})
	})
}

// TestRecoverCommandPanicMapsToOther verifies dispatchCommand's recover
// boundary: a handler that panics must not crash ProcessCBORWithContext's
// caller, and errorToStatus must map the recovered error to CTAP2_ERR_OTHER
// (StatusOtherError), the status CTAP2.1 reserves for a fault the platform
// cannot resolve by retrying with corrected parameters.
func TestRecoverCommandPanicMapsToOther(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	var response []byte
	var err error
	require.NotPanics(t, func() {
		response, err = auth.recoverCommandPanic(CmdClientPIN, func() ([]byte, error) {
			panic("simulated handler bug")
		})
	})

	require.Nil(t, response)
	require.ErrorIs(t, err, ErrCommandPanicked)
	require.Equal(t, byte(StatusOtherError), errorToStatus(err))
}

// TestRecoverCommandPanicPassesThroughOnSuccess verifies the recover
// boundary is transparent when fn does not panic: it returns fn's result
// unchanged.
func TestRecoverCommandPanicPassesThroughOnSuccess(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	want := []byte{StatusOK, 0x01, 0x02}
	response, err := auth.recoverCommandPanic(CmdGetInfo, func() ([]byte, error) {
		return want, nil
	})

	require.NoError(t, err)
	require.Equal(t, want, response)
}
