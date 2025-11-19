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

			if originalKey.X.Cmp(ecdsaKey.X) != 0 {
				t.Error("X coordinate doesn't match")
			}
			if originalKey.Y.Cmp(ecdsaKey.Y) != 0 {
				t.Error("Y coordinate doesn't match")
			}
			if originalKey.D.Cmp(ecdsaKey.D) != 0 {
				t.Error("Private key D doesn't match")
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
		t.Error("X should not be empty")
	}
	if jwk.D != "" {
		t.Error("D should be empty for public key")
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

	if len(originalKey) != len(ed25519Key) {
		t.Error("Key lengths don't match")
	}
	for i := range originalKey {
		if originalKey[i] != ed25519Key[i] {
			t.Error("Keys don't match")
			break
		}
	}
}

func TestFromSymmetricKey(t *testing.T) {
	keyBytes := make([]byte, 32) // 256-bit key
	_, err := rand.Read(keyBytes)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	jwk, err := FromSymmetricKey(keyBytes, "A256GCM")
	if err != nil {
		t.Fatalf("FromSymmetricKey failed: %v", err)
	}

	if jwk.Kty != string(KeyTypeOct) {
		t.Errorf("Expected kty=oct, got %s", jwk.Kty)
	}
	if jwk.K == "" {
		t.Error("K should not be empty")
	}
	if jwk.Alg != "A256GCM" {
		t.Errorf("Expected alg=A256GCM, got %s", jwk.Alg)
	}
}

func TestSymmetricKeyRoundTrip(t *testing.T) {
	originalKey := make([]byte, 32)
	_, err := rand.Read(originalKey)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	jwk, err := FromSymmetricKey(originalKey, "A256GCM")
	if err != nil {
		t.Fatalf("FromSymmetricKey failed: %v", err)
	}

	recoveredKey, err := jwk.ToSymmetricKey()
	if err != nil {
		t.Fatalf("ToSymmetricKey failed: %v", err)
	}

	if len(originalKey) != len(recoveredKey) {
		t.Error("Key lengths don't match")
	}
	for i := range originalKey {
		if originalKey[i] != recoveredKey[i] {
			t.Error("Keys don't match")
			break
		}
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	originalJWK, err := FromPrivateKey(key)
	if err != nil {
		t.Fatalf("FromPrivateKey failed: %v", err)
	}

	// Marshal to JSON
	jsonBytes, err := originalJWK.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify it's valid JSON
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
		t.Fatalf("JSON is invalid: %v", err)
	}

	// Unmarshal back
	recoveredJWK, err := Unmarshal(jsonBytes)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Compare fields
	if originalJWK.Kty != recoveredJWK.Kty {
		t.Error("Kty doesn't match")
	}
	if originalJWK.N != recoveredJWK.N {
		t.Error("N doesn't match")
	}
	if originalJWK.E != recoveredJWK.E {
		t.Error("E doesn't match")
	}
	if originalJWK.D != recoveredJWK.D {
		t.Error("D doesn't match")
	}
}

func TestIsPrivate(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Public key JWK
	pubJWK, _ := FromPublicKey(&rsaKey.PublicKey)
	if pubJWK.IsPrivate() {
		t.Error("Public key JWK should not be marked as private")
	}
	if !pubJWK.IsPublic() {
		t.Error("Public key JWK should be marked as public")
	}

	// Private key JWK
	privJWK, _ := FromPrivateKey(rsaKey)
	if !privJWK.IsPrivate() {
		t.Error("Private key JWK should be marked as private")
	}
	if privJWK.IsPublic() {
		t.Error("Private key JWK should not be marked as public")
	}

	// Symmetric key JWK
	symKey := make([]byte, 32)
	_, _ = rand.Read(symKey)
	symJWK, _ := FromSymmetricKey(symKey, "A256GCM")
	if !symJWK.IsPrivate() {
		t.Error("Symmetric key JWK should be marked as private")
	}
	if !symJWK.IsSymmetric() {
		t.Error("Symmetric key JWK should be marked as symmetric")
	}
}

func TestUnsupportedKeyType(t *testing.T) {
	type unsupportedKey struct{}
	key := unsupportedKey{}

	_, err := FromPublicKey(key)
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

func TestInvalidJWKConversion(t *testing.T) {
	// JWK without required fields
	jwk := &JWK{
		Kty: string(KeyTypeRSA),
		// Missing N and E
	}

	_, err := jwk.ToPublicKey()
	if err == nil {
		t.Error("Expected error when converting invalid JWK")
	}
}

func TestToPrivateKeyOnPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		keyFunc func() (crypto.PublicKey, error)
	}{
		{
			name: "RSA_public_key",
			keyFunc: func() (crypto.PublicKey, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA_public_key",
			keyFunc: func() (crypto.PublicKey, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "Ed25519_public_key",
			keyFunc: func() (crypto.PublicKey, error) {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				return pub, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := tt.keyFunc()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			jwk, err := FromPublicKey(pubKey)
			if err != nil {
				t.Fatalf("FromPublicKey failed: %v", err)
			}

			_, err = jwk.ToPrivateKey()
			if err == nil {
				t.Error("Expected error when calling ToPrivateKey on public key JWK")
			}
		})
	}
}

func TestSymmetricKeyErrors(t *testing.T) {
	// Empty key
	_, err := FromSymmetricKey([]byte{}, "A256GCM")
	if err == nil {
		t.Error("Expected error for empty symmetric key")
	}

	// Try to get symmetric key from RSA JWK
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaJWK, _ := FromPublicKey(&rsaKey.PublicKey)
	_, err = rsaJWK.ToSymmetricKey()
	if err == nil {
		t.Error("Expected error when calling ToSymmetricKey on RSA JWK")
	}

	// Invalid base64 in symmetric key
	invalidJWK := &JWK{
		Kty: string(KeyTypeOct),
		K:   "!!!invalid-base64!!!",
	}
	_, err = invalidJWK.ToSymmetricKey()
	if err == nil {
		t.Error("Expected error for invalid base64 in symmetric key")
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

	jsonBytes, err := jwk.MarshalIndent("", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	if len(jsonBytes) == 0 {
		t.Error("MarshalIndent returned empty bytes")
	}

	// Verify it's valid JSON and properly indented
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
		t.Fatalf("MarshalIndent produced invalid JSON: %v", err)
	}

	// Check that it contains indentation
	if !contains(string(jsonBytes), "  ") {
		t.Error("MarshalIndent output doesn't contain indentation")
	}
}

func TestToPublicKeyAllTypes(t *testing.T) {
	tests := []struct {
		name    string
		keyFunc func() (crypto.PublicKey, error)
	}{
		{
			name: "RSA",
			keyFunc: func() (crypto.PublicKey, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA_P256",
			keyFunc: func() (crypto.PublicKey, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA_P384",
			keyFunc: func() (crypto.PublicKey, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA_P521",
			keyFunc: func() (crypto.PublicKey, error) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "Ed25519",
			keyFunc: func() (crypto.PublicKey, error) {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				return pub, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := tt.keyFunc()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			jwk, err := FromPublicKey(pubKey)
			if err != nil {
				t.Fatalf("FromPublicKey failed: %v", err)
			}

			recoveredKey, err := jwk.ToPublicKey()
			if err != nil {
				t.Fatalf("ToPublicKey failed: %v", err)
			}

			if recoveredKey == nil {
				t.Error("ToPublicKey returned nil key")
			}
		})
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
				D:   "some-private-key-data",
			},
		},
		{
			name: "RSA_invalid_D_base64",
			jwk: &JWK{
				Kty: string(KeyTypeRSA),
				N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				E:   "AQAB",
				D:   "!!!invalid-base64!!!",
			},
		},
		{
			name: "EC_invalid_D_base64",
			jwk: &JWK{
				Kty: string(KeyTypeEC),
				Crv: string(CurveP256),
				X:   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
				Y:   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
				D:   "!!!invalid-base64!!!",
			},
		},
		{
			name: "Ed25519_invalid_D_base64",
			jwk: &JWK{
				Kty: string(KeyTypeOKP),
				Crv: string(CurveEd25519),
				X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				D:   "!!!invalid-base64!!!",
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

// TestX25519PublicKey tests X25519 public key conversion
func TestX25519PublicKey(t *testing.T) {
	// Generate X25519 key pair
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	publicKey := privateKey.PublicKey()

	// Convert to JWK
	jwk, err := fromX25519PublicKey(publicKey)
	if err != nil {
		t.Fatalf("fromX25519PublicKey failed: %v", err)
	}

	// Verify JWK properties
	if jwk.Kty != string(KeyTypeOKP) {
		t.Errorf("Expected kty=OKP, got %s", jwk.Kty)
	}
	if jwk.Crv != string(CurveX25519) {
		t.Errorf("Expected crv=X25519, got %s", jwk.Crv)
	}
	if jwk.X == "" {
		t.Error("X coordinate should not be empty")
	}
	if jwk.D != "" {
		t.Error("D should be empty for public key")
	}

	// Convert back to public key
	recoveredKey, err := jwk.toX25519PublicKey()
	if err != nil {
		t.Fatalf("toX25519PublicKey failed: %v", err)
	}

	// Verify the keys match
	if string(recoveredKey.Bytes()) != string(publicKey.Bytes()) {
		t.Error("Recovered public key doesn't match original")
	}
}

// TestX25519PrivateKey tests X25519 private key conversion
func TestX25519PrivateKey(t *testing.T) {
	// Generate X25519 key pair
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	// Convert to JWK
	jwk, err := fromX25519PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("fromX25519PrivateKey failed: %v", err)
	}

	// Verify JWK properties
	if jwk.Kty != string(KeyTypeOKP) {
		t.Errorf("Expected kty=OKP, got %s", jwk.Kty)
	}
	if jwk.Crv != string(CurveX25519) {
		t.Errorf("Expected crv=X25519, got %s", jwk.Crv)
	}
	if jwk.X == "" {
		t.Error("X coordinate should not be empty")
	}
	if jwk.D == "" {
		t.Error("D should not be empty for private key")
	}

	// Convert back to private key
	recoveredKey, err := jwk.toX25519PrivateKey()
	if err != nil {
		t.Fatalf("toX25519PrivateKey failed: %v", err)
	}

	// Verify the keys match
	if string(recoveredKey.Bytes()) != string(privateKey.Bytes()) {
		t.Error("Recovered private key doesn't match original")
	}
}

// TestX25519RoundTrip tests full round-trip conversion
func TestX25519RoundTrip(t *testing.T) {
	// Generate X25519 key pair
	originalKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate X25519 key: %v", err)
	}

	// Convert to JWK
	jwk, err := fromX25519PrivateKey(originalKey)
	if err != nil {
		t.Fatalf("fromX25519PrivateKey failed: %v", err)
	}

	// Marshal to JSON and back
	jsonData, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("Failed to marshal JWK: %v", err)
	}

	var jwk2 JWK
	if err := json.Unmarshal(jsonData, &jwk2); err != nil {
		t.Fatalf("Failed to unmarshal JWK: %v", err)
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
