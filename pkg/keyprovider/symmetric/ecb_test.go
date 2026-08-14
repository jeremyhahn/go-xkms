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

package symmetric

import (
	"bytes"
	"crypto/aes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ecbOracle enciphers plaintext with crypto/aes one block at a time, which is
// the definition of ECB and is computed here entirely independently of the
// implementation under test.
func ecbOracle(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	out := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}
	return out
}

// TestEncryptECB_MatchesCryptoAES proves types.CipherModeECB is genuinely ECB.
//
// The oracle is crypto/aes driven block by block. Two properties are asserted
// together because either alone can be satisfied by the wrong mode: the output
// must equal the oracle's byte for byte, AND two identical plaintext blocks
// must produce two identical ciphertext blocks. A chained mode such as CBC, or
// a counter mode such as GCM's, fails both -- which is exactly how
// CKM_AES_ECB behaved when the mechanism carried no mode and the backend fell
// through to its default AEAD.
func TestEncryptECB_MatchesCryptoAES(t *testing.T) {
	enc, key := newTagSizeFixture(t, types.SymmetricAES256GCM)

	// Two identical blocks: the structure leak that identifies ECB.
	oneBlock := bytes.Repeat([]byte{0xa5}, aes.BlockSize)
	plaintext := append(append([]byte{}, oneBlock...), oneBlock...)

	encrypted, err := enc.Encrypt(plaintext, &types.EncryptOptions{Mode: types.CipherModeECB})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	expected := ecbOracle(t, key, plaintext)
	if !bytes.Equal(encrypted.Ciphertext, expected) {
		t.Fatalf("ECB encrypt produced %x, crypto/aes computes %x", encrypted.Ciphertext, expected)
	}

	first := encrypted.Ciphertext[:aes.BlockSize]
	second := encrypted.Ciphertext[aes.BlockSize:]
	if !bytes.Equal(first, second) {
		t.Fatalf("identical plaintext blocks enciphered to %x and %x; this is not ECB", first, second)
	}

	// ECB has no IV and no tag; anything here means some other mode ran.
	if len(encrypted.IV) != 0 {
		t.Fatalf("ECB produced a %d-byte IV", len(encrypted.IV))
	}
	if len(encrypted.Tag) != 0 {
		t.Fatalf("ECB produced a %d-byte authentication tag", len(encrypted.Tag))
	}
	if len(encrypted.Nonce) != 0 {
		t.Fatalf("ECB produced a %d-byte nonce", len(encrypted.Nonce))
	}
}

// TestDecryptECB_RecoversOracleCiphertext proves the decrypt half inverts real
// ECB rather than only inverting this package's own encrypt: the input is the
// ciphertext crypto/aes produced, not anything Encrypt returned.
func TestDecryptECB_RecoversOracleCiphertext(t *testing.T) {
	enc, key := newTagSizeFixture(t, types.SymmetricAES256GCM)

	plaintext := bytes.Repeat([]byte{0x3c}, 3*aes.BlockSize)
	ciphertext := ecbOracle(t, key, plaintext)

	recovered, err := enc.Decrypt(
		&types.EncryptedData{Ciphertext: ciphertext},
		&types.DecryptOptions{Mode: types.CipherModeECB})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("ECB decrypt recovered %x, want %x", recovered, plaintext)
	}
}

// TestECB_RejectsBadInput proves every input ECB cannot honour is refused with
// a typed error instead of being ignored. Silently dropping an IV or an AAD
// would report success for an operation the caller did not get, and a
// non-block-aligned input would panic inside crypto/cipher rather than
// returning an error.
func TestECB_RejectsBadInput(t *testing.T) {
	enc, _ := newTagSizeFixture(t, types.SymmetricAES256GCM)
	aligned := bytes.Repeat([]byte{0x11}, aes.BlockSize)

	t.Run("plaintext not block aligned", func(t *testing.T) {
		_, err := enc.Encrypt(bytes.Repeat([]byte{0x11}, aes.BlockSize+1),
			&types.EncryptOptions{Mode: types.CipherModeECB})
		if !errors.Is(err, ErrPlaintextNotBlockAligned) {
			t.Fatalf("err = %v, want ErrPlaintextNotBlockAligned", err)
		}
	})

	t.Run("empty plaintext", func(t *testing.T) {
		_, err := enc.Encrypt(nil, &types.EncryptOptions{Mode: types.CipherModeECB})
		if !errors.Is(err, ErrPlaintextNotBlockAligned) {
			t.Fatalf("err = %v, want ErrPlaintextNotBlockAligned", err)
		}
	})

	t.Run("additional data", func(t *testing.T) {
		_, err := enc.Encrypt(aligned, &types.EncryptOptions{
			Mode: types.CipherModeECB, AdditionalData: []byte("aad")})
		if !errors.Is(err, ErrAdditionalDataNotSupported) {
			t.Fatalf("err = %v, want ErrAdditionalDataNotSupported", err)
		}
	})

	t.Run("tag size", func(t *testing.T) {
		_, err := enc.Encrypt(aligned, &types.EncryptOptions{
			Mode: types.CipherModeECB, TagSize: 12})
		if !errors.Is(err, ErrTagSizeNotSupported) {
			t.Fatalf("err = %v, want ErrTagSizeNotSupported", err)
		}
	})

	t.Run("iv on encrypt", func(t *testing.T) {
		_, err := enc.Encrypt(aligned, &types.EncryptOptions{
			Mode: types.CipherModeECB, IV: bytes.Repeat([]byte{0x22}, aes.BlockSize)})
		if !errors.Is(err, ErrIVNotSupported) {
			t.Fatalf("err = %v, want ErrIVNotSupported", err)
		}
	})

	t.Run("ciphertext not block aligned", func(t *testing.T) {
		_, err := enc.Decrypt(
			&types.EncryptedData{Ciphertext: bytes.Repeat([]byte{0x33}, aes.BlockSize-1)},
			&types.DecryptOptions{Mode: types.CipherModeECB})
		if !errors.Is(err, ErrCiphertextNotBlockAligned) {
			t.Fatalf("err = %v, want ErrCiphertextNotBlockAligned", err)
		}
	})

	t.Run("iv on decrypt", func(t *testing.T) {
		_, err := enc.Decrypt(
			&types.EncryptedData{
				Ciphertext: bytes.Repeat([]byte{0x33}, aes.BlockSize),
				IV:         bytes.Repeat([]byte{0x44}, aes.BlockSize),
			},
			&types.DecryptOptions{Mode: types.CipherModeECB})
		if !errors.Is(err, ErrIVNotSupported) {
			t.Fatalf("err = %v, want ErrIVNotSupported", err)
		}
	})

	t.Run("tag on decrypt", func(t *testing.T) {
		_, err := enc.Decrypt(
			&types.EncryptedData{
				Ciphertext: bytes.Repeat([]byte{0x33}, aes.BlockSize),
				Tag:        bytes.Repeat([]byte{0x55}, 16),
			},
			&types.DecryptOptions{Mode: types.CipherModeECB})
		if err == nil {
			t.Fatal("a tag accompanying an ECB ciphertext was accepted")
		}
	})
}

// TestECB_RequiresAESKey proves a stream AEAD key is refused: ChaCha20-Poly1305
// has no block-cipher form, so there is no ECB to run and returning the AEAD
// output instead would be a silent substitution.
func TestECB_RequiresAESKey(t *testing.T) {
	enc, _ := newTagSizeFixture(t, types.SymmetricChaCha20Poly1305)
	aligned := bytes.Repeat([]byte{0x11}, aes.BlockSize)

	_, err := enc.Encrypt(aligned, &types.EncryptOptions{Mode: types.CipherModeECB})
	if !errors.Is(err, ErrECBRequiresAES) {
		t.Fatalf("Encrypt err = %v, want ErrECBRequiresAES", err)
	}

	_, err = enc.Decrypt(&types.EncryptedData{Ciphertext: aligned},
		&types.DecryptOptions{Mode: types.CipherModeECB})
	if !errors.Is(err, ErrECBRequiresAES) {
		t.Fatalf("Decrypt err = %v, want ErrECBRequiresAES", err)
	}
}
