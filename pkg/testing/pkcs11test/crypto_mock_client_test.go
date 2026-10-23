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

package pkcs11test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestCryptoMockClient_Decrypt_OAEPRoundTrip verifies that a Decrypt request
// carrying Padding "oaep" runs RSA-OAEP against the same asymmetric key
// EncryptAsym encrypted under, rather than always running AES-GCM against
// getOrCreateSymKey. This is the regression test for the bug where Decrypt
// ignored req.Padding entirely: every OAEP decrypt silently created an
// unrelated AES key and failed.
func TestCryptoMockClient_Decrypt_OAEPRoundTrip(t *testing.T) {
	c := NewCryptoMockClient()
	ctx := context.Background()
	plaintext := []byte("mock pkcs11 OAEP plaintext")

	encResp, err := c.EncryptAsym(ctx, &transport.EncryptAsymRequest{
		KeyID:     "oaep-key",
		Plaintext: plaintext,
		Hash:      "SHA-256",
	})
	if err != nil {
		t.Fatalf("EncryptAsym() error = %v", err)
	}

	decResp, err := c.Decrypt(ctx, &transport.DecryptRequest{
		KeyID:      "oaep-key",
		Ciphertext: encResp.Ciphertext,
		Padding:    "oaep",
		Hash:       "SHA-256",
	})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decResp.Plaintext, plaintext) {
		t.Errorf("Decrypt() plaintext = %q, want %q", decResp.Plaintext, plaintext)
	}
}

// TestCryptoMockClient_Decrypt_OAEPWrongLabel verifies that decrypting under
// a different OAEP label than the ciphertext was encrypted under fails,
// rather than recovering the wrong plaintext or panicking.
func TestCryptoMockClient_Decrypt_OAEPWrongLabel(t *testing.T) {
	c := NewCryptoMockClient()
	ctx := context.Background()

	encResp, err := c.EncryptAsym(ctx, &transport.EncryptAsymRequest{
		KeyID:     "oaep-label-key",
		Plaintext: []byte("label-bound plaintext"),
		Hash:      "SHA-256",
		Label:     []byte("encrypt-label"),
	})
	if err != nil {
		t.Fatalf("EncryptAsym() error = %v", err)
	}

	_, err = c.Decrypt(ctx, &transport.DecryptRequest{
		KeyID:      "oaep-label-key",
		Ciphertext: encResp.Ciphertext,
		Padding:    "oaep",
		Hash:       "SHA-256",
		Label:      []byte("decrypt-label"),
	})
	if err == nil {
		t.Fatal("Decrypt() with a mismatched OAEP label should return an error")
	}
}

// TestCryptoMockClient_Decrypt_OAEPNonRSAKey verifies that an OAEP decrypt
// against a key id already bound to a non-RSA asymmetric key is refused with
// ErrUnsupportedKeyType rather than run as though it were RSA.
func TestCryptoMockClient_Decrypt_OAEPNonRSAKey(t *testing.T) {
	c := NewCryptoMockClient()
	ctx := context.Background()

	if _, err := c.GenerateKey(ctx, &transport.GenerateKeyRequest{KeyID: "ec-key", KeyType: "ecdsa"}); err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	_, err := c.Decrypt(ctx, &transport.DecryptRequest{
		KeyID:      "ec-key",
		Ciphertext: []byte("irrelevant"),
		Padding:    "oaep",
	})
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Errorf("Decrypt() error = %v, want ErrUnsupportedKeyType", err)
	}
}

// TestCryptoMockClient_Decrypt_UnsupportedPadding verifies that a padding
// name Decrypt does not recognize is refused rather than silently run
// through AES-GCM against a key id that was never meant to be symmetric.
func TestCryptoMockClient_Decrypt_UnsupportedPadding(t *testing.T) {
	c := NewCryptoMockClient()
	ctx := context.Background()

	_, err := c.Decrypt(ctx, &transport.DecryptRequest{
		KeyID:      "any-key",
		Ciphertext: []byte("irrelevant"),
		Padding:    "raw",
	})
	if !errors.Is(err, ErrUnsupportedPadding) {
		t.Errorf("Decrypt() error = %v, want ErrUnsupportedPadding", err)
	}
}

// requireMockEncrypt runs CryptoMockClient.Encrypt for a test that needs the
// result to exercise further behavior. Its requests leave the IV empty, so
// the mock generates it with the random-nonce AEAD and the seal succeeds
// under fips140=only as well.
func requireMockEncrypt(t *testing.T, c *CryptoMockClient, ctx context.Context, req *transport.EncryptRequest) *transport.EncryptResponse {
	t.Helper()
	resp, err := c.Encrypt(ctx, req)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	return resp
}

// TestCryptoMockClient_EncryptDecrypt verifies the round trip works and
// returns a nonce/tag of the expected AES-GCM sizes.
func TestCryptoMockClient_EncryptDecrypt(t *testing.T) {
	c := NewCryptoMockClient()
	ctx := context.Background()

	encResp := requireMockEncrypt(t, c, ctx, &transport.EncryptRequest{
		KeyID:     "test-key",
		Plaintext: []byte("mock pkcs11 plaintext"),
	})
	if len(encResp.Nonce) != 12 {
		t.Fatalf("Nonce length = %d, want 12", len(encResp.Nonce))
	}

	// The nonce mode travels back with the ciphertext, as the module does:
	// it selects the AEAD construction that sealed it.
	decResp, err := c.Decrypt(ctx, &transport.DecryptRequest{
		KeyID:        "test-key",
		Ciphertext:   encResp.Ciphertext,
		Nonce:        encResp.Nonce,
		Tag:          encResp.Tag,
		GCMNonceMode: encResp.GCMNonceMode,
	})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decResp.Plaintext, []byte("mock pkcs11 plaintext")) {
		t.Error("decrypted plaintext does not match original")
	}
}

// TestCryptoMockClient_Decrypt_WrongNonceLength verifies that Decrypt
// returns an error instead of panicking when the request carries a nonce
// that is not exactly the GCM nonce size. This reproduces the class of bug
// where a caller-controlled 16-byte AES-CBC-style IV reaching gcm.Open
// panics the process; this test would have caught it.
func TestCryptoMockClient_Decrypt_WrongNonceLength(t *testing.T) {
	c := NewCryptoMockClient()
	ctx := context.Background()

	encResp := requireMockEncrypt(t, c, ctx, &transport.EncryptRequest{
		KeyID:     "test-key",
		Plaintext: []byte("mock pkcs11 plaintext"),
	})

	tests := []struct {
		name      string
		nonceSize int
	}{
		{name: "16-byte AES-CBC-style IV", nonceSize: 16},
		{name: "empty nonce", nonceSize: 0},
		{name: "single byte nonce", nonceSize: 1},
		{name: "oversized nonce", nonceSize: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Decrypt(ctx, &transport.DecryptRequest{
				KeyID:        "test-key",
				Ciphertext:   encResp.Ciphertext,
				Nonce:        make([]byte, tt.nonceSize),
				Tag:          encResp.Tag,
				GCMNonceMode: encResp.GCMNonceMode,
			})
			if err == nil {
				t.Fatalf("Decrypt() with %d-byte nonce should return an error, not panic", tt.nonceSize)
			}
			if !errors.Is(err, ErrInvalidNonceSize) {
				t.Errorf("Decrypt() error = %v, want ErrInvalidNonceSize", err)
			}
		})
	}
}
