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
	"crypto/fips140"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// requireMockEncrypt runs CryptoMockClient.Encrypt for a test that needs the
// result to exercise further behavior, and reports whether the caller can
// continue using it. The mock always builds its AES-GCM AEAD with
// crypto/cipher's classic, arbitrary-IV-capable constructor -- see
// newGCMWithTagSize in crypto_mock_client.go -- which GODEBUG=fips140=only
// refuses outright regardless of whether this particular call supplied its
// own nonce or let the mock generate one; only cipher.NewGCMWithRandomNonce
// is usable in that mode, and the mock does not use it (see
// docs/fips/README.md "AEAD construction").
func requireMockEncrypt(t *testing.T, c *CryptoMockClient, ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, bool) {
	t.Helper()
	resp, err := c.Encrypt(ctx, req)
	if err != nil {
		if fips140.Enforced() {
			return nil, false
		}
		t.Fatalf("Encrypt() error = %v", err)
	}
	return resp, true
}

// TestCryptoMockClient_EncryptDecrypt verifies the round trip works and
// returns a nonce/tag of the expected AES-GCM sizes.
func TestCryptoMockClient_EncryptDecrypt(t *testing.T) {
	c := NewCryptoMockClient()
	ctx := context.Background()

	encResp, ok := requireMockEncrypt(t, c, ctx, &transport.EncryptRequest{
		KeyID:     "test-key",
		Plaintext: []byte("mock pkcs11 plaintext"),
	})
	if !ok {
		return
	}
	if len(encResp.Nonce) != 12 {
		t.Fatalf("Nonce length = %d, want 12", len(encResp.Nonce))
	}

	decResp, err := c.Decrypt(ctx, &transport.DecryptRequest{
		KeyID:      "test-key",
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		Tag:        encResp.Tag,
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

	encResp, ok := requireMockEncrypt(t, c, ctx, &transport.EncryptRequest{
		KeyID:     "test-key",
		Plaintext: []byte("mock pkcs11 plaintext"),
	})
	if !ok {
		return
	}

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
				KeyID:      "test-key",
				Ciphertext: encResp.Ciphertext,
				Nonce:      make([]byte, tt.nonceSize),
				Tag:        encResp.Tag,
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
