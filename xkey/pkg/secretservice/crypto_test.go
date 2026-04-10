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

package secretservice

import (
	"bytes"
	"testing"
)

func TestGenerateDHKeyPair(t *testing.T) {
	kp, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateDHKeyPair() error = %v", err)
	}

	if kp.Private == nil {
		t.Error("private key is nil")
	}
	if kp.Public == nil {
		t.Error("public key is nil")
	}
	if kp.Private.Sign() <= 0 {
		t.Error("private key should be positive")
	}
	if kp.Public.Sign() <= 0 {
		t.Error("public key should be positive")
	}
}

func TestDHKeyExchange(t *testing.T) {
	// Simulate Alice and Bob key exchange
	alice, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateDHKeyPair (alice) error = %v", err)
	}

	bob, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateDHKeyPair (bob) error = %v", err)
	}

	// Compute shared secrets
	aliceSecret := ComputeSharedSecret(alice.Private, bob.Public)
	bobSecret := ComputeSharedSecret(bob.Private, alice.Public)

	// They should be equal
	if aliceSecret.Cmp(bobSecret) != 0 {
		t.Error("shared secrets do not match")
	}

	// Derive AES keys
	aliceKey := DeriveAESKey(aliceSecret)
	bobKey := DeriveAESKey(bobSecret)

	if !bytes.Equal(aliceKey, bobKey) {
		t.Error("derived AES keys do not match")
	}

	if len(aliceKey) != 16 {
		t.Errorf("AES key length = %d, want 16", len(aliceKey))
	}
}

func TestSessionCrypto_EncryptDecrypt(t *testing.T) {
	// Generate a shared secret for testing
	alice, _ := GenerateDHKeyPair()
	bob, _ := GenerateDHKeyPair()
	sharedSecret := ComputeSharedSecret(alice.Private, bob.Public)

	crypto := NewSessionCrypto(sharedSecret)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "short text",
			plaintext: []byte("hello"),
		},
		{
			name:      "exact block size",
			plaintext: []byte("sixteen bytes!!"),
		},
		{
			name:      "longer text",
			plaintext: []byte("this is a longer piece of text that spans multiple AES blocks"),
		},
		{
			name:      "empty",
			plaintext: []byte{},
		},
		{
			name:      "single byte",
			plaintext: []byte("x"),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iv, ciphertext, err := crypto.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			if len(iv) != 16 {
				t.Errorf("IV length = %d, want 16", len(iv))
			}

			decrypted, err := crypto.Decrypt(iv, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestSessionCrypto_DecryptInvalidIV(t *testing.T) {
	alice, _ := GenerateDHKeyPair()
	bob, _ := GenerateDHKeyPair()
	sharedSecret := ComputeSharedSecret(alice.Private, bob.Public)
	crypto := NewSessionCrypto(sharedSecret)

	plaintext := []byte("test data")
	_, ciphertext, _ := crypto.Encrypt(plaintext)

	// Try with wrong IV length
	_, err := crypto.Decrypt([]byte("short"), ciphertext)
	if err != ErrDecryptionFailed {
		t.Errorf("Decrypt(short IV) error = %v, want ErrDecryptionFailed", err)
	}
}

func TestSessionCrypto_DecryptInvalidCiphertext(t *testing.T) {
	alice, _ := GenerateDHKeyPair()
	bob, _ := GenerateDHKeyPair()
	sharedSecret := ComputeSharedSecret(alice.Private, bob.Public)
	crypto := NewSessionCrypto(sharedSecret)

	iv := make([]byte, 16)

	// Empty ciphertext
	_, err := crypto.Decrypt(iv, []byte{})
	if err != ErrDecryptionFailed {
		t.Errorf("Decrypt(empty) error = %v, want ErrDecryptionFailed", err)
	}

	// Non-block-aligned ciphertext
	_, err = crypto.Decrypt(iv, []byte("odd length"))
	if err != ErrDecryptionFailed {
		t.Errorf("Decrypt(odd length) error = %v, want ErrDecryptionFailed", err)
	}
}

func TestPublicKeyConversion(t *testing.T) {
	kp, _ := GenerateDHKeyPair()

	// Convert to bytes and back
	bytes := PublicKeyToBytes(kp.Public)
	restored := PublicKeyFromBytes(bytes)

	if kp.Public.Cmp(restored) != 0 {
		t.Error("public key round-trip failed")
	}
}

func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		wantLen   int
	}{
		{
			name:      "empty",
			input:     []byte{},
			blockSize: 16,
			wantLen:   16,
		},
		{
			name:      "one byte",
			input:     []byte("x"),
			blockSize: 16,
			wantLen:   16,
		},
		{
			name:      "15 bytes",
			input:     make([]byte, 15),
			blockSize: 16,
			wantLen:   16,
		},
		{
			name:      "16 bytes (full block)",
			input:     make([]byte, 16),
			blockSize: 16,
			wantLen:   32, // Adds full block of padding
		},
		{
			name:      "17 bytes",
			input:     make([]byte, 17),
			blockSize: 16,
			wantLen:   32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.input, tt.blockSize)
			if len(padded) != tt.wantLen {
				t.Errorf("pkcs7Pad() len = %d, want %d", len(padded), tt.wantLen)
			}

			if len(padded)%tt.blockSize != 0 {
				t.Errorf("pkcs7Pad() result not block-aligned")
			}

			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("pkcs7Unpad() error = %v", err)
			}

			if !bytes.Equal(unpadded, tt.input) {
				t.Errorf("pkcs7Unpad() = %v, want %v", unpadded, tt.input)
			}
		})
	}
}

func TestPKCS7UnpadInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty",
			input: []byte{},
		},
		{
			name:  "padding zero",
			input: []byte{1, 2, 3, 0},
		},
		{
			name:  "padding too large",
			input: []byte{1, 2, 3, 20},
		},
		{
			name:  "inconsistent padding",
			input: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 3, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tt.input)
			if err != ErrDecryptionFailed {
				t.Errorf("pkcs7Unpad() error = %v, want ErrDecryptionFailed", err)
			}
		})
	}
}
