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

package jwk

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestFromRSAPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	if jwk.Kty != string(KeyTypeRSA) {
		t.Errorf("Expected kty=RSA, got %s", jwk.Kty)
	}
	if jwk.N == "" {
		t.Error("N (modulus) should not be empty")
	}
	if jwk.E == "" {
		t.Error("E (exponent) should not be empty")
	}
	if jwk.D != "" {
		t.Error("D (private exponent) should be empty for public key")
	}
}

func TestFromRSAPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwk, err := FromPrivateKey(key)
	if err != nil {
		t.Fatalf("FromPrivateKey failed: %v", err)
	}

	if jwk.Kty != string(KeyTypeRSA) {
		t.Errorf("Expected kty=RSA, got %s", jwk.Kty)
	}
	if jwk.N == "" {
		t.Error("N should not be empty")
	}
	if jwk.E == "" {
		t.Error("E should not be empty")
	}
	if jwk.D == "" {
		t.Error("D should not be empty for private key")
	}
	if jwk.P == "" {
		t.Error("P should not be empty for private key")
	}
	if jwk.Q == "" {
		t.Error("Q should not be empty for private key")
	}
}

func TestRSARoundTrip(t *testing.T) {
	// Generate original key
	originalKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to JWK and back
	jwk, err := FromPrivateKey(originalKey)
	if err != nil {
		t.Fatalf("FromPrivateKey failed: %v", err)
	}

	recoveredKey, err := jwk.ToPrivateKey()
	if err != nil {
		t.Fatalf("ToPrivateKey failed: %v", err)
	}

	rsaKey, ok := recoveredKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Recovered key is not *rsa.PrivateKey")
	}

	// Compare key parameters
	if originalKey.N.Cmp(rsaKey.N) != 0 {
		t.Error("Modulus N doesn't match")
	}
	if originalKey.E != rsaKey.E {
		t.Error("Exponent E doesn't match")
	}
	if originalKey.D.Cmp(rsaKey.D) != 0 {
		t.Error("Private exponent D doesn't match")
	}
}

func TestFromECDSAPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	if jwk.Kty != string(KeyTypeEC) {
		t.Errorf("Expected kty=EC, got %s", jwk.Kty)
	}
	if jwk.Crv != string(CurveP256) {
		t.Errorf("Expected crv=P-256, got %s", jwk.Crv)
	}
	if jwk.X == "" {
		t.Error("X coordinate should not be empty")
	}
	if jwk.Y == "" {
		t.Error("Y coordinate should not be empty")
	}
	if jwk.D != "" {
		t.Error("D should be empty for public key")
	}
}

func TestECDSARoundTrip(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			originalKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			jwk, err := FromPrivateKey(originalKey)
			if err != nil {
				t.Fatalf("FromPrivateKey failed: %v", err)
			}

			recoveredKey, err := jwk.ToPrivateKey()
			if err != nil {
				t.Fatalf("ToPrivateKey failed: %v", err)
			}

			ecdsaKey, ok := recoveredKey.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatal("Recovered key is not *ecdsa.PrivateKey")
			}

			if !originalKey.Equal(ecdsaKey) {
				t.Error("Recovered ECDSA private key doesn't match original")
			}
		})
	}
}

func TestFromEd25519PublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	jwk, err := FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	if jwk.Kty != string(KeyTypeOKP) {
		t.Errorf("Expected kty=OKP, got %s", jwk.Kty)
	}
	if jwk.Crv != string(CurveEd25519) {
		t.Errorf("Expected crv=Ed25519, got %s", jwk.Crv)
	}
	if jwk.X == "" {
		t.Error("X coordinate should not be empty")
	}
}

func TestEd25519RoundTrip(t *testing.T) {
	_, originalKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	jwk, err := FromPrivateKey(originalKey)
	if err != nil {
		t.Fatalf("FromPrivateKey failed: %v", err)
	}

	recoveredKey, err := jwk.ToPrivateKey()
	if err != nil {
		t.Fatalf("ToPrivateKey failed: %v", err)
	}

	ed25519Key, ok := recoveredKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("Recovered key is not ed25519.PrivateKey")
	}

	if !originalKey.Equal(ed25519Key) {
		t.Error("Recovered Ed25519 private key doesn't match original")
	}
}

func TestFromSymmetricKey(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	jwk, err := FromSymmetricKey(key, "A256GCM")
	if err != nil {
		t.Fatalf("FromSymmetricKey failed: %v", err)
	}

	if jwk.Kty != string(KeyTypeOct) {
		t.Errorf("Expected kty=oct, got %s", jwk.Kty)
	}
	if jwk.K == "" {
		t.Error("K should not be empty")
	}
}

func TestSymmetricKeyRoundTrip(t *testing.T) {
	originalKey := make([]byte, 32)
	_, err := rand.Read(originalKey)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	jwk, err := FromSymmetricKey(originalKey, "A256GCM")
	if err != nil {
		t.Fatalf("FromSymmetricKey failed: %v", err)
	}

	recoveredKey, err := jwk.ToSymmetricKey()
	if err != nil {
		t.Fatalf("ToSymmetricKey failed: %v", err)
	}

	if string(originalKey) != string(recoveredKey) {
		t.Error("Recovered symmetric key doesn't match original")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create JWK
	original, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	// Marshal
	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal
	recovered, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Compare
	if original.Kty != recovered.Kty {
		t.Errorf("Kty mismatch: %s vs %s", original.Kty, recovered.Kty)
	}
	if original.N != recovered.N {
		t.Errorf("N mismatch")
	}
	if original.E != recovered.E {
		t.Errorf("E mismatch")
	}
}

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		name     string
		jwk      *JWK
		expected bool
	}{
		{
			name:     "RSA private key",
			jwk:      &JWK{Kty: string(KeyTypeRSA), D: "some-value"},
			expected: true,
		},
		{
			name:     "RSA public key",
			jwk:      &JWK{Kty: string(KeyTypeRSA), D: ""},
			expected: false,
		},
		{
			name:     "EC private key",
			jwk:      &JWK{Kty: string(KeyTypeEC), D: "some-value"},
			expected: true,
		},
		{
			name:     "EC public key",
			jwk:      &JWK{Kty: string(KeyTypeEC), D: ""},
			expected: false,
		},
		{
			name:     "OKP private key",
			jwk:      &JWK{Kty: string(KeyTypeOKP), D: "some-value"},
			expected: true,
		},
		{
			name:     "OKP public key",
			jwk:      &JWK{Kty: string(KeyTypeOKP), D: ""},
			expected: false,
		},
		{
			name:     "Symmetric key",
			jwk:      &JWK{Kty: string(KeyTypeOct), K: "some-value"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.jwk.IsPrivate()
			if result != tt.expected {
				t.Errorf("IsPrivate() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestUnsupportedKeyType(t *testing.T) {
	// This test uses a custom type that won't be recognized
	type customKey struct {
		crypto.PublicKey
	}

	_, err := FromPublicKey(customKey{})
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

func TestInvalidJWKConversion(t *testing.T) {
	// Test with empty JWK
	emptyJWK := &JWK{}
	_, err := emptyJWK.ToPublicKey()
	if err == nil {
		t.Error("Expected error for empty JWK")
	}
}

func TestToPrivateKeyOnPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create public key JWK
	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	// Try to extract private key from public JWK
	_, err = jwk.ToPrivateKey()
	if err == nil {
		t.Error("Expected error when extracting private key from public JWK")
	}
}

func TestSymmetricKeyErrors(t *testing.T) {
	// Test empty symmetric key
	_, err := FromSymmetricKey(nil, "")
	if err == nil {
		t.Error("Expected error for nil symmetric key")
	}

	// Test ToSymmetricKey on non-symmetric JWK
	rsaJWK := &JWK{Kty: string(KeyTypeRSA)}
	_, err = rsaJWK.ToSymmetricKey()
	if err == nil {
		t.Error("Expected error for ToSymmetricKey on RSA JWK")
	}

	// Test ToSymmetricKey with empty key data
	emptyJWK := &JWK{Kty: string(KeyTypeOct), K: ""}
	_, err = emptyJWK.ToSymmetricKey()
	if err == nil {
		t.Error("Expected error for empty symmetric key data")
	}

	// Test ToSymmetricKey with invalid base64
	invalidJWK := &JWK{Kty: string(KeyTypeOct), K: "!!!invalid!!!"}
	_, err = invalidJWK.ToSymmetricKey()
	if err == nil {
		t.Error("Expected error for invalid base64 symmetric key")
	}
}

func TestMarshalIndent(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	data, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	// Verify it's properly indented
	if !contains(string(data), "  \"kty\"") {
		t.Error("MarshalIndent should produce indented output")
	}
}

func TestToPublicKeyAllTypes(t *testing.T) {
	// RSA
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaJWK, err := FromPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create RSA JWK: %v", err)
	}
	pubKey, err := rsaJWK.ToPublicKey()
	if err != nil {
		t.Fatalf("RSA ToPublicKey failed: %v", err)
	}
	if _, ok := pubKey.(*rsa.PublicKey); !ok {
		t.Error("Expected *rsa.PublicKey")
	}

	// ECDSA
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	ecJWK, err := FromPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create ECDSA JWK: %v", err)
	}
	pubKey, err = ecJWK.ToPublicKey()
	if err != nil {
		t.Fatalf("ECDSA ToPublicKey failed: %v", err)
	}
	if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
		t.Error("Expected *ecdsa.PublicKey")
	}

	// Ed25519
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
	edJWK, err := FromPublicKey(edPub)
	if err != nil {
		t.Fatalf("Failed to create Ed25519 JWK: %v", err)
	}
	pubKey, err = edJWK.ToPublicKey()
	if err != nil {
		t.Fatalf("Ed25519 ToPublicKey failed: %v", err)
	}
	if _, ok := pubKey.(ed25519.PublicKey); !ok {
		t.Error("Expected ed25519.PublicKey")
	}
}

func TestToPublicKeyErrors(t *testing.T) {
	tests := []struct {
		name string
		jwk  *JWK
	}{
		{
			name: "unsupported_key_type",
			jwk: &JWK{
				Kty: "UNSUPPORTED",
			},
		},
		{
			name: "invalid_RSA_base64",
			jwk: &JWK{
				Kty: string(KeyTypeRSA),
				N:   "!!!invalid-base64!!!",
				E:   "AQAB",
			},
		},
		{
			name: "invalid_EC_base64_X",
			jwk: &JWK{
				Kty: string(KeyTypeEC),
				Crv: string(CurveP256),
				X:   "!!!invalid-base64!!!",
				Y:   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
			},
		},
		{
			name: "invalid_EC_base64_Y",
			jwk: &JWK{
				Kty: string(KeyTypeEC),
				Crv: string(CurveP256),
				X:   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
				Y:   "!!!invalid-base64!!!",
			},
		},
		{
			name: "invalid_EC_curve",
			jwk: &JWK{
				Kty: string(KeyTypeEC),
				Crv: "INVALID-CURVE",
				X:   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
				Y:   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
			},
		},
		{
			name: "invalid_Ed25519_base64",
			jwk: &JWK{
				Kty: string(KeyTypeOKP),
				Crv: string(CurveEd25519),
				X:   "!!!invalid-base64!!!",
			},
		},
		{
			name: "Ed25519_wrong_length",
			jwk: &JWK{
				Kty: string(KeyTypeOKP),
				Crv: string(CurveEd25519),
				X:   "AQAB", // Too short
			},
		},
		{
			name: "unsupported_OKP_curve",
			jwk: &JWK{
				Kty: string(KeyTypeOKP),
				Crv: "Ed448", // Unsupported curve
				X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.jwk.ToPublicKey()
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

func TestToPrivateKeyErrors(t *testing.T) {
	tests := []struct {
		name string
		jwk  *JWK
	}{
		{
			name: "unsupported_key_type",
			jwk: &JWK{
				Kty: "UNSUPPORTED",
				D:   "test",
			},
		},
		{
			name: "RSA_invalid_base64_D",
			jwk: &JWK{
				Kty: string(KeyTypeRSA),
				N:   "AQAB",
				E:   "AQAB",
				D:   "!!!invalid-base64!!!",
			},
		},
		{
			name: "EC_missing_D",
			jwk: &JWK{
				Kty: string(KeyTypeEC),
				Crv: string(CurveP256),
				X:   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
				Y:   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
				D:   "",
			},
		},
		{
			name: "Ed25519_wrong_D_length",
			jwk: &JWK{
				Kty: string(KeyTypeOKP),
				Crv: string(CurveEd25519),
				X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				D:   "AQAB", // Too short
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.jwk.ToPrivateKey()
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

func TestUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "invalid_json",
			json: "{invalid json}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(tt.json))
			if err == nil {
				t.Error("Expected error for invalid JSON")
			}
		})
	}
}

func TestFromPrivateKeyUnsupportedType(t *testing.T) {
	type unsupportedPrivateKey struct{}
	key := unsupportedPrivateKey{}

	_, err := FromPrivateKey(key)
	if err == nil {
		t.Error("Expected error for unsupported private key type")
	}
}

func TestECDSACurveMapping(t *testing.T) {
	tests := []struct {
		name          string
		curve         elliptic.Curve
		expectedCurve Curve
	}{
		{"P-224", elliptic.P224(), ""},
		{"P-256", elliptic.P256(), CurveP256},
		{"P-384", elliptic.P384(), CurveP384},
		{"P-521", elliptic.P521(), CurveP521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			jwk, err := FromPublicKey(&key.PublicKey)
			if tt.expectedCurve == "" {
				// P-224 is not supported
				if err == nil {
					t.Error("Expected error for unsupported curve")
				}
			} else {
				if err != nil {
					t.Fatalf("FromPublicKey failed: %v", err)
				}
				if jwk.Crv != string(tt.expectedCurve) {
					t.Errorf("Expected curve %s, got %s", tt.expectedCurve, jwk.Crv)
				}
			}
		})
	}
}

// Helper function for TestMarshalIndent
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// X25519 Tests
// =============================================================================

func TestX25519PublicKey(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	jwk, err := FromPublicKey(key.PublicKey())
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}

	if jwk.Kty != string(KeyTypeOKP) {
		t.Errorf("Expected kty=OKP, got %s", jwk.Kty)
	}
	if jwk.Crv != string(CurveX25519) {
		t.Errorf("Expected crv=X25519, got %s", jwk.Crv)
	}
	if jwk.X == "" {
		t.Error("X coordinate should not be empty")
	}
}

func TestX25519PrivateKey(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	jwk, err := FromPrivateKey(key)
	if err != nil {
		t.Fatalf("FromPrivateKey failed: %v", err)
	}

	if jwk.Kty != string(KeyTypeOKP) {
		t.Errorf("Expected kty=OKP, got %s", jwk.Kty)
	}
	if jwk.Crv != string(CurveX25519) {
		t.Errorf("Expected crv=X25519, got %s", jwk.Crv)
	}
	if jwk.D == "" {
		t.Error("D should not be empty for private key")
	}
}

func TestX25519RoundTrip(t *testing.T) {
	// Generate key
	originalKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	// Convert to JWK
	jwk1, err := FromPrivateKey(originalKey)
	if err != nil {
		t.Fatalf("FromPrivateKey failed: %v", err)
	}

	// Marshal/unmarshal
	data, err := jwk1.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	jwk2, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Convert back to private key
	recoveredKey, err := jwk2.toX25519PrivateKey()
	if err != nil {
		t.Fatalf("toX25519PrivateKey failed: %v", err)
	}

	// Verify the keys match
	if string(recoveredKey.Bytes()) != string(originalKey.Bytes()) {
		t.Error("Round-trip key doesn't match original")
	}

	// Verify public keys match
	originalPub := originalKey.PublicKey()
	recoveredPub := recoveredKey.PublicKey()
	if string(originalPub.Bytes()) != string(recoveredPub.Bytes()) {
		t.Error("Round-trip public key doesn't match original")
	}
}

// TestX25519InvalidKey tests error handling for invalid X25519 keys
func TestX25519InvalidKey(t *testing.T) {
	// Test invalid X coordinate (wrong size)
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveX25519),
		X:   "invalid", // Too short
	}

	_, err := jwk.toX25519PublicKey()
	if err == nil {
		t.Error("Expected error for invalid X25519 public key size")
	}

	// Test invalid D coordinate (wrong size)
	jwk2 := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveX25519),
		X:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // Valid size
		D:   "invalid",                                     // Too short
	}

	_, err = jwk2.toX25519PrivateKey()
	if err == nil {
		t.Error("Expected error for invalid X25519 private key size")
	}
}

// TestFromPublicKeyUnsupportedType tests FromPublicKey with unsupported key type
func TestFromPublicKeyUnsupportedType(t *testing.T) {
	// Use a type that's not supported
	unsupportedKey := struct{ Dummy int }{Dummy: 42}

	_, err := FromPublicKey(unsupportedKey)
	if err == nil {
		t.Error("Expected error for unsupported public key type")
	}
}

// TestToPublicKeyUnsupportedType tests ToPublicKey with unsupported key type
func TestToPublicKeyUnsupportedType(t *testing.T) {
	// Create JWK with unsupported key type
	jwk := &JWK{
		Kty: "unsupported",
		N:   "test",
	}

	_, err := jwk.ToPublicKey()
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

// TestToPrivateKeyUnsupportedType tests ToPrivateKey with unsupported key type
func TestToPrivateKeyUnsupportedType(t *testing.T) {
	// Create JWK with unsupported key type
	jwk := &JWK{
		Kty: "unsupported",
		N:   "test",
		D:   "test",
	}

	_, err := jwk.ToPrivateKey()
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

// =============================================================================
// ECDH Curve Error Path Tests
// =============================================================================

func TestFromPublicKey_UnsupportedECDHCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve ecdh.Curve
	}{
		{"P-256", ecdh.P256()},
		{"P-384", ecdh.P384()},
		{"P-521", ecdh.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate %s ECDH key: %v", tc.name, err)
			}
			_, err = FromPublicKey(key.PublicKey())
			if err == nil {
				t.Errorf("Expected error for unsupported ECDH curve %s", tc.name)
			}
		})
	}
}

func TestFromPrivateKey_UnsupportedECDHCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve ecdh.Curve
	}{
		{"P-256", ecdh.P256()},
		{"P-384", ecdh.P384()},
		{"P-521", ecdh.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate %s ECDH key: %v", tc.name, err)
			}
			_, err = FromPrivateKey(key)
			if err == nil {
				t.Errorf("Expected error for unsupported ECDH curve %s", tc.name)
			}
		})
	}
}

// =============================================================================
// RSA/ECDSA Field Validation Tests
// =============================================================================

func TestToRSAPublicKey_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		jwk  *JWK
	}{
		{
			name: "missing_N",
			jwk: &JWK{
				Kty: string(KeyTypeRSA),
				E:   "AQAB",
			},
		},
		{
			name: "missing_E",
			jwk: &JWK{
				Kty: string(KeyTypeRSA),
				N:   "AQAB",
			},
		},
		{
			name: "exponent_too_large",
			jwk: &JWK{
				Kty: string(KeyTypeRSA),
				N:   "AQAB",
				E:   "f____________________w",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.jwk.toRSAPublicKey()
			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

func TestToECDSAPublicKey_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		jwk  *JWK
	}{
		{
			name: "missing_crv",
			jwk: &JWK{
				Kty: string(KeyTypeEC),
				X:   "AQAB",
				Y:   "AQAB",
			},
		},
		{
			name: "missing_x",
			jwk: &JWK{
				Kty: string(KeyTypeEC),
				Crv: "P-256",
				Y:   "AQAB",
			},
		},
		{
			name: "missing_y",
			jwk: &JWK{
				Kty: string(KeyTypeEC),
				Crv: "P-256",
				X:   "AQAB",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.jwk.toECDSAPublicKey()
			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

// TestMarshalIndent verifies indented JSON output of a JWK
func TestJWK_MarshalIndentMethod(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey() error = %v", err)
	}

	data, err := jwk.MarshalIndent("", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("MarshalIndent() returned empty data")
	}

	// Verify it's valid JSON and contains indentation
	var parsed JWK
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("MarshalIndent() produced invalid JSON: %v", err)
	}
	if parsed.Kty != string(KeyTypeEC) {
		t.Errorf("MarshalIndent() Kty = %q, want %q", parsed.Kty, string(KeyTypeEC))
	}
}

// TestMarshalIndent_WithPrefix verifies MarshalIndent with a custom prefix
func TestMarshalIndent_WithPrefix(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeOct),
		K:   "dGVzdC1rZXk",
	}
	data, err := jwk.MarshalIndent(">> ", "\t")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("MarshalIndent() returned empty data")
	}
}

// TestIsPublic verifies IsPublic returns the correct result
func TestIsPublic(t *testing.T) {
	tests := []struct {
		name string
		jwk  JWK
		want bool
	}{
		{
			name: "RSA public key",
			jwk:  JWK{Kty: string(KeyTypeRSA), N: "modulus", E: "AQAB"},
			want: true,
		},
		{
			name: "EC public key",
			jwk:  JWK{Kty: string(KeyTypeEC), Crv: "P-256", X: "x-coord", Y: "y-coord"},
			want: true,
		},
		{
			name: "OKP public key",
			jwk:  JWK{Kty: string(KeyTypeOKP), Crv: "Ed25519", X: "pub-bytes"},
			want: true,
		},
		{
			name: "private key (has D)",
			jwk:  JWK{Kty: string(KeyTypeEC), Crv: "P-256", X: "x", Y: "y", D: "priv"},
			want: false,
		},
		{
			name: "symmetric key (has K)",
			jwk:  JWK{Kty: string(KeyTypeOct), K: "secret"},
			want: false,
		},
		{
			name: "empty JWK",
			jwk:  JWK{Kty: string(KeyTypeRSA)},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.jwk.IsPublic()
			if got != tt.want {
				t.Errorf("IsPublic() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsSymmetric verifies IsSymmetric returns the correct result
func TestIsSymmetric(t *testing.T) {
	tests := []struct {
		name string
		jwk  JWK
		want bool
	}{
		{
			name: "symmetric key",
			jwk:  JWK{Kty: string(KeyTypeOct), K: "secret"},
			want: true,
		},
		{
			name: "RSA key",
			jwk:  JWK{Kty: string(KeyTypeRSA), N: "modulus"},
			want: false,
		},
		{
			name: "EC key",
			jwk:  JWK{Kty: string(KeyTypeEC), Crv: "P-256"},
			want: false,
		},
		{
			name: "OKP key",
			jwk:  JWK{Kty: string(KeyTypeOKP), Crv: "Ed25519"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.jwk.IsSymmetric()
			if got != tt.want {
				t.Errorf("IsSymmetric() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestToECDSAPrivateKey_InvalidD tests the error path when D field has invalid base64
func TestToECDSAPrivateKey_InvalidD(t *testing.T) {
	// Generate a valid EC public key for the JWK
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey() error = %v", err)
	}
	// Set an invalid base64 D value
	jwk.D = "!!!invalid-base64!!!"

	_, err = jwk.ToPrivateKey()
	if err == nil {
		t.Fatal("ToPrivateKey() with invalid D base64 should return error")
	}
}

// TestToRSAPrivateKey_InvalidP tests the error path when P field has invalid base64
func TestToRSAPrivateKey_InvalidP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	jwk, err := FromPrivateKey(key)
	if err != nil {
		t.Fatalf("FromPrivateKey() error = %v", err)
	}
	// Set invalid base64 for P
	jwk.P = "!!!invalid-base64!!!"

	_, err = jwk.ToPrivateKey()
	if err == nil {
		t.Fatal("ToPrivateKey() with invalid P base64 should return error")
	}
}

// TestToRSAPrivateKey_InvalidQ tests the error path when Q field has invalid base64
func TestToRSAPrivateKey_InvalidQ(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	jwk, err := FromPrivateKey(key)
	if err != nil {
		t.Fatalf("FromPrivateKey() error = %v", err)
	}
	// Set invalid base64 for Q only (P is valid)
	jwk.Q = "!!!invalid-base64!!!"

	_, err = jwk.ToPrivateKey()
	if err == nil {
		t.Fatal("ToPrivateKey() with invalid Q base64 should return error")
	}
}

// TestToX25519PublicKey_InvalidBase64 tests the error path for invalid X field base64
func TestToX25519PublicKey_InvalidBase64(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveX25519),
		X:   "!!!invalid-base64!!!",
	}
	_, err := jwk.ToPublicKey()
	if err == nil {
		t.Fatal("ToPublicKey() with invalid X25519 base64 should return error")
	}
}

// TestToX25519PublicKey_InvalidSize tests the error path for wrong key size
func TestToX25519PublicKey_InvalidSize(t *testing.T) {
	// Encode a 16-byte value (wrong size, should be 32)
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveX25519),
		X:   "AAAAAAAAAAAAAAAAAAAAAA", // 16 bytes in base64url
	}
	_, err := jwk.ToPublicKey()
	if err == nil {
		t.Fatal("ToPublicKey() with wrong X25519 key size should return error")
	}
}

// TestToX25519PrivateKey_InvalidBase64 tests the error path for invalid D field base64
func TestToX25519PrivateKey_InvalidBase64(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveX25519),
		D:   "!!!invalid-base64!!!",
	}
	_, err := jwk.ToPrivateKey()
	if err == nil {
		t.Fatal("ToPrivateKey() with invalid X25519 D base64 should return error")
	}
}

// TestToX25519PrivateKey_InvalidSize tests the error path for wrong private key size
func TestToX25519PrivateKey_InvalidSize(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveX25519),
		D:   "AAAAAAAAAAAAAAAAAAAAAA", // 16 bytes, should be 32
	}
	_, err := jwk.ToPrivateKey()
	if err == nil {
		t.Fatal("ToPrivateKey() with wrong X25519 private key size should return error")
	}
}

// TestToEd25519PrivateKey_InvalidBase64 tests the error path for invalid D field base64
func TestToEd25519PrivateKey_InvalidBase64(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveEd25519),
		D:   "!!!invalid-base64!!!",
	}
	_, err := jwk.ToPrivateKey()
	if err == nil {
		t.Fatal("ToPrivateKey() with invalid Ed25519 D base64 should return error")
	}
}

// TestToEd25519PrivateKey_InvalidSeedSize tests the error path for wrong seed size
func TestToEd25519PrivateKey_InvalidSeedSize(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: string(CurveEd25519),
		D:   "AAAAAAAAAAAAAAAAAAAAAA", // 16 bytes, should be 32 (ed25519.SeedSize)
	}
	_, err := jwk.ToPrivateKey()
	if err == nil {
		t.Fatal("ToPrivateKey() with wrong Ed25519 seed size should return error")
	}
}

// TestToPrivateKey_UnsupportedOKPCurve tests the error path for unsupported OKP curve
func TestToPrivateKey_UnsupportedOKPCurve(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: "X448",
		D:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	_, err := jwk.ToPrivateKey()
	if err == nil {
		t.Fatal("ToPrivateKey() with unsupported OKP curve should return error")
	}
}

// TestToPublicKey_UnsupportedOKPCurve tests the error path for unsupported OKP curve in public key
func TestToPublicKey_UnsupportedOKPCurve(t *testing.T) {
	jwk := &JWK{
		Kty: string(KeyTypeOKP),
		Crv: "X448",
		X:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	_, err := jwk.ToPublicKey()
	if err == nil {
		t.Fatal("ToPublicKey() with unsupported OKP curve should return error")
	}
}
