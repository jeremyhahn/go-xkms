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

package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

// Test vectors from RFC 7638 Appendix A
// https://tools.ietf.org/html/rfc7638#appendix-A

func TestRFC7638_RSA_Example(t *testing.T) {
	// RFC 7638 Example RSA Key
	jwk := &JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}

	// Expected thumbprint from RFC 7638
	expected := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	thumbprint, err := jwk.ThumbprintSHA256()
	if err != nil {
		t.Fatalf("ThumbprintSHA256 failed: %v", err)
	}

	if thumbprint != expected {
		t.Errorf("Thumbprint doesn't match RFC 7638 example\nGot:      %s\nExpected: %s", thumbprint, expected)
	}
}

func TestRFC7638_EC_P256_Example(t *testing.T) {
	// RFC 7638 doesn't include an EC example, but we can verify the thumbprint format
	// Create a known EC key
	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
		Y:   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
	}

	thumbprint, err := jwk.ThumbprintSHA256()
	if err != nil {
		t.Fatalf("ThumbprintSHA256 failed: %v", err)
	}

	// Verify it's valid base64url
	_, err = base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		t.Errorf("Thumbprint is not valid base64url: %v", err)
	}

	// Verify length (SHA-256 produces 32 bytes, base64url encoded is 43 chars)
	if len(thumbprint) != 43 {
		t.Errorf("Expected thumbprint length 43, got %d", len(thumbprint))
	}
}

func TestThumbprintConsistency(t *testing.T) {
	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Compute thumbprint multiple times
	tp1, err := ThumbprintSHA256(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("First thumbprint failed: %v", err)
	}

	tp2, err := ThumbprintSHA256(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("Second thumbprint failed: %v", err)
	}

	if tp1 != tp2 {
		t.Error("Thumbprint should be consistent for the same key")
	}

	// Create JWK and compute thumbprint
	jwk, err := FromPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	tp3, err := jwk.ThumbprintSHA256()
	if err != nil {
		t.Fatalf("JWK thumbprint failed: %v", err)
	}

	if tp1 != tp3 {
		t.Error("Thumbprint should match between direct key and JWK")
	}
}

func TestThumbprintDifferentKeys(t *testing.T) {
	// Generate two different keys
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	tp1, _ := ThumbprintSHA256(&key1.PublicKey)
	tp2, _ := ThumbprintSHA256(&key2.PublicKey)

	if tp1 == tp2 {
		t.Error("Different keys should have different thumbprints")
	}
}

func TestThumbprintHashFunctions(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Test different hash functions
	tpSHA1, err := ThumbprintSHA1(&rsaKey.PublicKey)
	if err != nil {
		t.Errorf("ThumbprintSHA1 failed: %v", err)
	}

	tpSHA256, err := ThumbprintSHA256(&rsaKey.PublicKey)
	if err != nil {
		t.Errorf("ThumbprintSHA256 failed: %v", err)
	}

	tpSHA512, err := ThumbprintSHA512(&rsaKey.PublicKey)
	if err != nil {
		t.Errorf("ThumbprintSHA512 failed: %v", err)
	}

	// Verify different hash functions produce different results
	if tpSHA1 == tpSHA256 || tpSHA256 == tpSHA512 || tpSHA1 == tpSHA512 {
		t.Error("Different hash functions should produce different thumbprints")
	}

	// Verify lengths (after base64url encoding)
	// SHA-1: 20 bytes -> 27 chars, SHA-256: 32 bytes -> 43 chars, SHA-512: 64 bytes -> 86 chars
	if len(tpSHA1) != 27 {
		t.Errorf("SHA-1 thumbprint should be 27 chars, got %d", len(tpSHA1))
	}
	if len(tpSHA256) != 43 {
		t.Errorf("SHA-256 thumbprint should be 43 chars, got %d", len(tpSHA256))
	}
	if len(tpSHA512) != 86 {
		t.Errorf("SHA-512 thumbprint should be 86 chars, got %d", len(tpSHA512))
	}
}

func TestThumbprintAllKeyTypes(t *testing.T) {
	tests := []struct {
		name   string
		keyGen func() crypto.PublicKey
	}{
		{
			name: "RSA-2048",
			keyGen: func() crypto.PublicKey {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return &key.PublicKey
			},
		},
		{
			name: "ECDSA-P256",
			keyGen: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &key.PublicKey
			},
		},
		{
			name: "ECDSA-P384",
			keyGen: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return &key.PublicKey
			},
		},
		{
			name: "ECDSA-P521",
			keyGen: func() crypto.PublicKey {
				key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return &key.PublicKey
			},
		},
		{
			name: "Ed25519",
			keyGen: func() crypto.PublicKey {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				return pub
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.keyGen()

			thumbprint, err := ThumbprintSHA256(key)
			if err != nil {
				t.Fatalf("ThumbprintSHA256 failed: %v", err)
			}

			// Verify valid base64url
			_, err = base64.RawURLEncoding.DecodeString(thumbprint)
			if err != nil {
				t.Errorf("Thumbprint is not valid base64url: %v", err)
			}

			// Verify length (SHA-256 = 32 bytes = 43 chars in base64url)
			if len(thumbprint) != 43 {
				t.Errorf("Expected thumbprint length 43, got %d", len(thumbprint))
			}
		})
	}
}

func TestKeyAuthorization(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := "test_token_12345"

	keyAuth, err := KeyAuthorization(token, &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("KeyAuthorization failed: %v", err)
	}

	// Verify format: token.thumbprint
	thumbprint, err := ThumbprintSHA256(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ThumbprintSHA256 failed: %v", err)
	}

	expected := token + "." + thumbprint
	if keyAuth != expected {
		t.Errorf("KeyAuthorization format incorrect\nGot:      %s\nExpected: %s", keyAuth, expected)
	}
}

func TestThumbprintLexicographicOrdering(t *testing.T) {
	// Create a JWK with all fields to verify lexicographic ordering
	// The required fields for RSA are: e, kty, n (in that order)
	jwk := &JWK{
		Kty: "RSA",
		// Add fields that shouldn't be included in thumbprint
		Use: "sig",
		Alg: "RS256",
		Kid: "test-key-id",
		// Required fields
		E: "AQAB",
		N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	}

	// Compute thumbprint
	thumbprint, err := jwk.ThumbprintSHA256()
	if err != nil {
		t.Fatalf("ThumbprintSHA256 failed: %v", err)
	}

	// The thumbprint should only use required fields in lexicographic order
	// {"e":"AQAB","kty":"RSA","n":"..."}
	// The optional fields (use, alg, kid) should not affect the thumbprint

	// Create another JWK without optional fields
	jwk2 := &JWK{
		Kty: "RSA",
		E:   "AQAB",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	}

	thumbprint2, err := jwk2.ThumbprintSHA256()
	if err != nil {
		t.Fatalf("ThumbprintSHA256 failed: %v", err)
	}

	if thumbprint != thumbprint2 {
		t.Error("Thumbprint should be the same regardless of optional fields")
	}
}

func TestThumbprintRequiredFieldsOnly(t *testing.T) {
	// Test that thumbprint computation fails when required fields are missing
	tests := []struct {
		name string
		jwk  *JWK
	}{
		{
			name: "RSA missing N",
			jwk: &JWK{
				Kty: "RSA",
				E:   "AQAB",
			},
		},
		{
			name: "RSA missing E",
			jwk: &JWK{
				Kty: "RSA",
				N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			},
		},
		{
			name: "EC missing X",
			jwk: &JWK{
				Kty: "EC",
				Crv: "P-256",
				Y:   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
			},
		},
		{
			name: "EC missing Y",
			jwk: &JWK{
				Kty: "EC",
				Crv: "P-256",
				X:   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
			},
		},
		{
			name: "EC missing Crv",
			jwk: &JWK{
				Kty: "EC",
				X:   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
				Y:   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.jwk.ThumbprintSHA256()
			if err == nil {
				t.Error("Expected error when computing thumbprint with missing required fields")
			}
		})
	}
}

func TestSymmetricKeyThumbprint(t *testing.T) {
	// Create symmetric key
	keyBytes := make([]byte, 32)
	_, _ = rand.Read(keyBytes)

	jwk, err := FromSymmetricKey(keyBytes, "A256GCM")
	if err != nil {
		t.Fatalf("FromSymmetricKey failed: %v", err)
	}

	// Compute thumbprint
	thumbprint, err := jwk.ThumbprintSHA256()
	if err != nil {
		t.Fatalf("ThumbprintSHA256 failed: %v", err)
	}

	// Verify valid base64url
	_, err = base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		t.Errorf("Thumbprint is not valid base64url: %v", err)
	}

	// Verify length
	if len(thumbprint) != 43 {
		t.Errorf("Expected thumbprint length 43, got %d", len(thumbprint))
	}
}

// Benchmark thumbprint computation
func BenchmarkThumbprintSHA256_RSA(b *testing.B) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk, _ := FromPublicKey(&key.PublicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = jwk.ThumbprintSHA256()
	}
}

func BenchmarkThumbprintSHA256_ECDSA(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := FromPublicKey(&key.PublicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = jwk.ThumbprintSHA256()
	}
}

func BenchmarkThumbprintSHA256_Ed25519(b *testing.B) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk, _ := FromPublicKey(pub)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = jwk.ThumbprintSHA256()
	}
}

// Test custom RSA key to verify thumbprint calculation
func TestCustomRSAThumbprint(t *testing.T) {
	// Create a specific RSA key for reproducible testing
	n, _ := new(big.Int).SetString("23456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", 10)
	e := 65537

	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	// Compute thumbprint
	tp1, err := ThumbprintSHA256(pubKey)
	if err != nil {
		t.Fatalf("ThumbprintSHA256 failed: %v", err)
	}

	// Compute again to verify consistency
	tp2, err := ThumbprintSHA256(pubKey)
	if err != nil {
		t.Fatalf("ThumbprintSHA256 failed: %v", err)
	}

	if tp1 != tp2 {
		t.Error("Thumbprint should be consistent for same key")
	}
}

func TestThumbprintUnsupportedHashFunction(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	// Try using an unsupported hash function
	_, err = jwk.Thumbprint(crypto.MD5) // MD5 is not supported
	if err == nil {
		t.Error("Expected error for unsupported hash function")
	}
}

func TestThumbprintSHA1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	thumbprint, err := ThumbprintSHA1(&key.PublicKey)
	if err != nil {
		t.Fatalf("ThumbprintSHA1 failed: %v", err)
	}

	if len(thumbprint) == 0 {
		t.Error("Thumbprint should not be empty")
	}
}

func TestThumbprintSHA512(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	thumbprint, err := ThumbprintSHA512(&key.PublicKey)
	if err != nil {
		t.Fatalf("ThumbprintSHA512 failed: %v", err)
	}

	if len(thumbprint) == 0 {
		t.Error("Thumbprint should not be empty")
	}
}

func TestThumbprintInvalidKey(t *testing.T) {
	type unsupportedKey struct{}
	key := unsupportedKey{}

	_, err := ThumbprintSHA256(key)
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

func TestKeyAuthorizationError(t *testing.T) {
	type unsupportedKey struct{}
	key := unsupportedKey{}

	_, err := KeyAuthorization("test-token", key)
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

func TestSerializeForThumbprintErrors(t *testing.T) {
	// This is an internal function, but we can test it indirectly
	// by creating a JWK with missing required fields
	jwk := &JWK{
		Kty: string(KeyTypeRSA),
		// Missing N and E
	}

	_, err := jwk.ThumbprintSHA256()
	if err == nil {
		t.Error("Expected error for JWK missing required fields")
	}
}
