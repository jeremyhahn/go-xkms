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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newTagSizeFixture builds a backend holding one symmetric key of the given
// algorithm and returns its encrypter alongside the raw key, so a test can
// recompute the expected ciphertext with crypto/cipher rather than trusting
// this package's own Decrypt to confirm its own Encrypt.
func newTagSizeFixture(t *testing.T, alg types.SymmetricAlgorithm) (types.SymmetricEncrypter, []byte) {
	t.Helper()

	b, err := NewBackend(&Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	attrs := &types.KeyAttributes{
		CN:                 "tagsize-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: alg,
	}

	key, err := b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}
	raw, err := key.Raw()
	if err != nil {
		t.Fatalf("key.Raw: %v", err)
	}

	enc, err := b.SymmetricEncrypter(context.Background(), attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter: %v", err)
	}
	return enc, raw
}

// fixedNonce returns a deterministic 12-byte GCM nonce so the ciphertext this
// package produces can be compared byte for byte against crypto/cipher.
func fixedNonce() []byte {
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	return nonce
}

// TestEncrypt_TagSize_MatchesCryptoCipher checks every tag length NIST
// SP 800-38D section 5.2.1.2 approves against crypto/cipher computed in the
// test with the same truncation.
//
// The comparison is exact, not just a length check: SP 800-38D defines the
// t-bit tag as the leading t bits of the full 128-bit tag, so a backend that
// truncated some other way -- trailing bits, or a separately computed shorter
// MAC -- would produce a tag of the right length that no conforming peer
// accepts.
func TestEncrypt_TagSize_MatchesCryptoCipher(t *testing.T) {
	plaintext := []byte("plaintext that is not a multiple of the block size")
	aad := []byte("additional authenticated data")

	for _, tagSize := range []int{12, 13, 14, 15, 16} {
		t.Run(fmt.Sprintf("tagSize=%d", tagSize), func(t *testing.T) {
			enc, rawKey := newTagSizeFixture(t, types.SymmetricAES256GCM)
			nonce := fixedNonce()

			got, err := enc.Encrypt(plaintext, &types.EncryptOptions{
				Nonce:          nonce,
				AdditionalData: aad,
				TagSize:        tagSize,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			block, err := aes.NewCipher(rawKey)
			if err != nil {
				t.Fatalf("aes.NewCipher: %v", err)
			}
			gcm, err := cipher.NewGCMWithTagSize(block, tagSize)
			if err != nil {
				t.Fatalf("cipher.NewGCMWithTagSize: %v", err)
			}
			sealed := gcm.Seal(nil, nonce, plaintext, aad)
			wantCiphertext := sealed[:len(sealed)-tagSize]
			wantTag := sealed[len(sealed)-tagSize:]

			if !bytes.Equal(got.Ciphertext, wantCiphertext) {
				t.Errorf("ciphertext = %x, want %x", got.Ciphertext, wantCiphertext)
			}
			if !bytes.Equal(got.Tag, wantTag) {
				t.Errorf("tag = %x, want %x", got.Tag, wantTag)
			}
			if len(got.Tag) != tagSize {
				t.Errorf("tag is %d bytes, want %d", len(got.Tag), tagSize)
			}
		})
	}
}

// TestEncryptDecrypt_TagSize_RoundTrip is the both-halves-agree check. A
// decrypt that verified at the full length would reject every truncated tag as
// a forgery, which presents as an authentication failure rather than as the
// parameter mismatch it is.
func TestEncryptDecrypt_TagSize_RoundTrip(t *testing.T) {
	plaintext := []byte("round trip at every approved tag length")
	aad := []byte("bound context")

	for _, tagSize := range []int{0, 12, 13, 14, 15, 16} {
		t.Run(fmt.Sprintf("tagSize=%d", tagSize), func(t *testing.T) {
			enc, _ := newTagSizeFixture(t, types.SymmetricAES256GCM)

			encrypted, err := enc.Encrypt(plaintext, &types.EncryptOptions{
				Nonce:          fixedNonce(),
				AdditionalData: aad,
				TagSize:        tagSize,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			recovered, err := enc.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: aad,
				TagSize:        tagSize,
			})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(recovered, plaintext) {
				t.Fatalf("recovered %q, want %q", recovered, plaintext)
			}
		})
	}
}

// TestDecrypt_TagSize_MismatchIsRejected covers the three ways a tag can be
// the wrong length or the wrong value.
func TestDecrypt_TagSize_MismatchIsRejected(t *testing.T) {
	plaintext := []byte("authenticate me")
	enc, _ := newTagSizeFixture(t, types.SymmetricAES256GCM)

	encrypted, err := enc.Encrypt(plaintext, &types.EncryptOptions{
		Nonce:   fixedNonce(),
		TagSize: 12,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("decrypting a 96-bit tag at the full length is refused", func(t *testing.T) {
		if _, err := enc.Decrypt(encrypted, &types.DecryptOptions{}); err == nil {
			t.Fatal("Decrypt accepted a 12-byte tag while verifying at 16")
		}
	})

	t.Run("decrypting at a different truncated length is refused", func(t *testing.T) {
		if _, err := enc.Decrypt(encrypted, &types.DecryptOptions{TagSize: 14}); err == nil {
			t.Fatal("Decrypt accepted a 12-byte tag while verifying at 14")
		}
	})

	t.Run("a tampered tag of the right length fails authentication", func(t *testing.T) {
		tampered := &types.EncryptedData{
			Ciphertext: encrypted.Ciphertext,
			Nonce:      encrypted.Nonce,
			Tag:        append([]byte(nil), encrypted.Tag...),
		}
		tampered.Tag[0] ^= 0xFF
		if _, err := enc.Decrypt(tampered, &types.DecryptOptions{TagSize: 12}); err == nil {
			t.Fatal("Decrypt accepted a tampered 12-byte tag")
		}
	})
}

// TestTagSize_InvalidLengthsAreRefused is the bad-input case for the tag
// length itself. Rounding an unapproved length to the nearest permitted one
// would produce a tag the caller's peer cannot verify, with no error to say so.
func TestTagSize_InvalidLengthsAreRefused(t *testing.T) {
	for _, tagSize := range []int{1, 4, 8, 11, 17, 32, -1} {
		t.Run(fmt.Sprintf("tagSize=%d", tagSize), func(t *testing.T) {
			enc, _ := newTagSizeFixture(t, types.SymmetricAES256GCM)

			_, err := enc.Encrypt([]byte("data"), &types.EncryptOptions{
				Nonce:   fixedNonce(),
				TagSize: tagSize,
			})
			if err == nil {
				t.Fatal("Encrypt accepted an unapproved tag size")
			}
			if !errors.Is(err, ErrInvalidTagSize) {
				t.Fatalf("Encrypt error = %v, want ErrInvalidTagSize", err)
			}

			_, err = enc.Decrypt(&types.EncryptedData{
				Ciphertext: []byte("x"),
				Nonce:      fixedNonce(),
				Tag:        make([]byte, 16),
			}, &types.DecryptOptions{TagSize: tagSize})
			if err == nil {
				t.Fatal("Decrypt accepted an unapproved tag size")
			}
			if !errors.Is(err, ErrInvalidTagSize) {
				t.Fatalf("Decrypt error = %v, want ErrInvalidTagSize", err)
			}
		})
	}
}

// TestTagSize_Poly1305IsRefused pins the honest refusal. Poly1305 is a
// one-time MAC (RFC 8439 section 2.5) with no leading-bits truncation of the
// kind SP 800-38D defines for GCM, so returning its full 16-byte tag to a
// caller that asked for 12 would report a request as honoured that was not.
func TestTagSize_Poly1305IsRefused(t *testing.T) {
	for _, alg := range []types.SymmetricAlgorithm{
		types.SymmetricChaCha20Poly1305,
		types.SymmetricXChaCha20Poly1305,
	} {
		t.Run(string(alg), func(t *testing.T) {
			enc, _ := newTagSizeFixture(t, alg)

			_, err := enc.Encrypt([]byte("data"), &types.EncryptOptions{TagSize: 12})
			if err == nil {
				t.Fatal("Encrypt accepted a truncated tag request for Poly1305")
			}
			if !errors.Is(err, ErrTagSizeNotSupported) {
				t.Fatalf("Encrypt error = %v, want ErrTagSizeNotSupported", err)
			}

			// The full length must still work: the refusal is about
			// truncation, not about the field being present.
			encrypted, err := enc.Encrypt([]byte("data"), &types.EncryptOptions{TagSize: 16})
			if err != nil {
				t.Fatalf("Encrypt with the full 16-byte tag failed: %v", err)
			}
			if _, err := enc.Decrypt(encrypted, &types.DecryptOptions{TagSize: 16}); err != nil {
				t.Fatalf("Decrypt with the full 16-byte tag failed: %v", err)
			}
		})
	}
}

// TestTagSize_CBCRefusesATagLength covers the non-AEAD modes. AES-CBC produces
// no authentication tag at all, so accepting and ignoring a tag length would
// report success for something the caller did not get -- the same reasoning
// that already refuses AdditionalData there.
func TestTagSize_CBCRefusesATagLength(t *testing.T) {
	for _, mode := range []types.CipherMode{types.CipherModeCBC, types.CipherModeCBCPad} {
		t.Run(string(mode), func(t *testing.T) {
			enc, _ := newTagSizeFixture(t, types.SymmetricAES256GCM)

			_, err := enc.Encrypt(make([]byte, 16), &types.EncryptOptions{
				Mode:    mode,
				IV:      make([]byte, aes.BlockSize),
				TagSize: 16,
			})
			if err == nil {
				t.Fatal("encryptCBC accepted a tag length")
			}
			if !errors.Is(err, ErrTagSizeNotSupported) {
				t.Fatalf("Encrypt error = %v, want ErrTagSizeNotSupported", err)
			}

			_, err = enc.Decrypt(&types.EncryptedData{
				Ciphertext: make([]byte, 16),
				IV:         make([]byte, aes.BlockSize),
			}, &types.DecryptOptions{Mode: mode, TagSize: 16})
			if err == nil {
				t.Fatal("decryptCBC accepted a tag length")
			}
			if !errors.Is(err, ErrTagSizeNotSupported) {
				t.Fatalf("Decrypt error = %v, want ErrTagSizeNotSupported", err)
			}
		})
	}
}
