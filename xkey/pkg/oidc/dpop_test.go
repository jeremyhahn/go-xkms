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

package oidc

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateDPoPKey(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	if key == nil {
		t.Fatal("GenerateDPoPKey() returned nil key")
	}

	if key.PrivateKey == nil {
		t.Fatal("GenerateDPoPKey() returned key with nil PrivateKey")
	}

	// Verify it's P-256
	if key.PrivateKey.Curve != elliptic.P256() {
		t.Errorf("Expected P-256 curve, got %v", key.PrivateKey.Curve.Params().Name)
	}
}

func TestGenerateDPoPKey_Uniqueness(t *testing.T) {
	key1, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	key2, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	// Keys should be different
	if key1.PrivateKey.D.Cmp(key2.PrivateKey.D) == 0 {
		t.Error("Generated keys should be unique")
	}
}

func TestDPoPKey_GenerateProof(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	opts := &DPoPProofOptions{
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/token",
	}

	proof, err := key.GenerateProof(opts)
	if err != nil {
		t.Fatalf("GenerateProof() error = %v", err)
	}

	if proof == "" {
		t.Fatal("GenerateProof() returned empty proof")
	}

	// Verify it's a valid JWT structure (3 parts)
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("Expected 3 JWT parts, got %d", len(parts))
	}

	// Decode and verify header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to decode header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("Failed to unmarshal header: %v", err)
	}

	// Verify header fields
	if header["typ"] != "dpop+jwt" {
		t.Errorf("Expected typ=dpop+jwt, got %v", header["typ"])
	}
	if header["alg"] != "ES256" {
		t.Errorf("Expected alg=ES256, got %v", header["alg"])
	}

	// Verify JWK is present
	jwk, ok := header["jwk"].(map[string]interface{})
	if !ok {
		t.Fatal("Header missing jwk")
	}
	if jwk["kty"] != "EC" {
		t.Errorf("Expected kty=EC, got %v", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("Expected crv=P-256, got %v", jwk["crv"])
	}

	// Decode and verify payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	// Verify payload fields
	if payload["htm"] != "POST" {
		t.Errorf("Expected htm=POST, got %v", payload["htm"])
	}
	if payload["htu"] != "https://example.com/token" {
		t.Errorf("Expected htu=https://example.com/token, got %v", payload["htu"])
	}
	if _, ok := payload["jti"]; !ok {
		t.Error("Payload missing jti")
	}
	if _, ok := payload["iat"]; !ok {
		t.Error("Payload missing iat")
	}
}

func TestDPoPKey_GenerateProof_WithAccessToken(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	opts := &DPoPProofOptions{
		HTTPMethod:  "GET",
		HTTPUri:     "https://api.example.com/resource",
		AccessToken: "test-access-token",
	}

	proof, err := key.GenerateProof(opts)
	if err != nil {
		t.Fatalf("GenerateProof() error = %v", err)
	}

	// Decode payload
	parts := strings.Split(proof, ".")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	// Verify ath claim is present
	if _, ok := payload["ath"]; !ok {
		t.Error("Payload missing ath claim when AccessToken provided")
	}
}

func TestDPoPKey_GenerateProof_WithNonce(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	opts := &DPoPProofOptions{
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/token",
		Nonce:      "server-provided-nonce",
	}

	proof, err := key.GenerateProof(opts)
	if err != nil {
		t.Fatalf("GenerateProof() error = %v", err)
	}

	// Decode payload
	parts := strings.Split(proof, ".")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	// Verify nonce claim
	if payload["nonce"] != "server-provided-nonce" {
		t.Errorf("Expected nonce=server-provided-nonce, got %v", payload["nonce"])
	}
}

func TestDPoPKey_GenerateProof_InvalidOptions(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	tests := []struct {
		name string
		opts *DPoPProofOptions
	}{
		{
			name: "missing HTTP method",
			opts: &DPoPProofOptions{
				HTTPUri: "https://example.com/token",
			},
		},
		{
			name: "missing HTTP URI",
			opts: &DPoPProofOptions{
				HTTPMethod: "POST",
			},
		},
		{
			name: "both missing",
			opts: &DPoPProofOptions{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := key.GenerateProof(tt.opts)
			if err == nil {
				t.Error("Expected error for invalid options")
			}
		})
	}
}

func TestDPoPKey_GenerateProof_NilKey(t *testing.T) {
	key := &DPoPKey{PrivateKey: nil}

	opts := &DPoPProofOptions{
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/token",
	}

	_, err := key.GenerateProof(opts)
	if err == nil {
		t.Error("Expected error for nil private key")
	}
}

func TestDPoPKey_GenerateProof_SignatureValid(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	opts := &DPoPProofOptions{
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/token",
	}

	proof, err := key.GenerateProof(opts)
	if err != nil {
		t.Fatalf("GenerateProof() error = %v", err)
	}

	// Parse and verify the token with the public key
	token, err := jwt.Parse(proof, func(token *jwt.Token) (interface{}, error) {
		return &key.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Token verification failed: %v", err)
	}

	if !token.Valid {
		t.Error("Token should be valid")
	}
}

func TestDPoPKey_PublicJWK(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	jwk := key.PublicJWK()
	if jwk == nil {
		t.Fatal("PublicJWK() returned nil")
	}

	if jwk.KeyType != "EC" {
		t.Errorf("Expected kty=EC, got %s", jwk.KeyType)
	}
	if jwk.Curve != "P-256" {
		t.Errorf("Expected crv=P-256, got %s", jwk.Curve)
	}
	if jwk.X == "" {
		t.Error("JWK missing X coordinate")
	}
	if jwk.Y == "" {
		t.Error("JWK missing Y coordinate")
	}
}

func TestDPoPKey_PublicJWK_NilKey(t *testing.T) {
	key := &DPoPKey{PrivateKey: nil}
	jwk := key.PublicJWK()
	if jwk != nil {
		t.Error("Expected nil JWK for nil private key")
	}
}

func TestDPoPKey_SerializeDeserialize(t *testing.T) {
	// Generate key
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	// Serialize
	pemData, err := key.SerializePrivateKey()
	if err != nil {
		t.Fatalf("SerializePrivateKey() error = %v", err)
	}

	if pemData == "" {
		t.Fatal("SerializePrivateKey() returned empty string")
	}

	// Verify PEM format
	if !strings.Contains(pemData, "-----BEGIN EC PRIVATE KEY-----") {
		t.Error("PEM missing BEGIN marker")
	}
	if !strings.Contains(pemData, "-----END EC PRIVATE KEY-----") {
		t.Error("PEM missing END marker")
	}

	// Deserialize
	restored, err := DeserializeDPoPKey(pemData)
	if err != nil {
		t.Fatalf("DeserializeDPoPKey() error = %v", err)
	}

	// Verify key is equivalent
	if key.PrivateKey.D.Cmp(restored.PrivateKey.D) != 0 {
		t.Error("Restored key has different D value")
	}
	if key.PrivateKey.PublicKey.X.Cmp(restored.PrivateKey.PublicKey.X) != 0 {
		t.Error("Restored key has different X value")
	}
	if key.PrivateKey.PublicKey.Y.Cmp(restored.PrivateKey.PublicKey.Y) != 0 {
		t.Error("Restored key has different Y value")
	}
}

func TestDPoPKey_SerializePrivateKey_NilKey(t *testing.T) {
	key := &DPoPKey{PrivateKey: nil}
	_, err := key.SerializePrivateKey()
	if err == nil {
		t.Error("Expected error for nil private key")
	}
}

func TestDeserializeDPoPKey_InvalidPEM(t *testing.T) {
	tests := []struct {
		name    string
		pemData string
	}{
		{
			name:    "empty string",
			pemData: "",
		},
		{
			name:    "invalid base64",
			pemData: "not a pem",
		},
		{
			name:    "wrong key type",
			pemData: "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeDPoPKey(tt.pemData)
			if err == nil {
				t.Error("Expected error for invalid PEM")
			}
		})
	}
}

func TestDPoPKey_RoundTrip_ProofStillValid(t *testing.T) {
	// Generate key
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	// Serialize
	pemData, err := key.SerializePrivateKey()
	if err != nil {
		t.Fatalf("SerializePrivateKey() error = %v", err)
	}

	// Deserialize
	restored, err := DeserializeDPoPKey(pemData)
	if err != nil {
		t.Fatalf("DeserializeDPoPKey() error = %v", err)
	}

	// Generate proof with restored key
	opts := &DPoPProofOptions{
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/token",
	}

	proof, err := restored.GenerateProof(opts)
	if err != nil {
		t.Fatalf("GenerateProof() error = %v", err)
	}

	// Verify proof with original public key
	token, err := jwt.Parse(proof, func(token *jwt.Token) (interface{}, error) {
		return &key.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Token verification failed: %v", err)
	}

	if !token.Valid {
		t.Error("Token should be valid")
	}
}

func TestDPoPKeyFromCoordinates(t *testing.T) {
	// Generate a key first
	original, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	// Extract coordinates
	x := original.PrivateKey.PublicKey.X.Bytes()
	y := original.PrivateKey.PublicKey.Y.Bytes()
	d := original.PrivateKey.D.Bytes()

	// Reconstruct key
	reconstructed, err := DPoPKeyFromCoordinates(x, y, d)
	if err != nil {
		t.Fatalf("DPoPKeyFromCoordinates() error = %v", err)
	}

	// Verify keys match
	if original.PrivateKey.D.Cmp(reconstructed.PrivateKey.D) != 0 {
		t.Error("D values don't match")
	}
}

func TestComputeAccessTokenHash(t *testing.T) {
	// Test vector: known token should produce consistent hash
	token := "test-access-token"
	hash1 := computeAccessTokenHash(token)
	hash2 := computeAccessTokenHash(token)

	if hash1 != hash2 {
		t.Error("Hash should be deterministic")
	}

	// Different tokens should produce different hashes
	hash3 := computeAccessTokenHash("different-token")
	if hash1 == hash3 {
		t.Error("Different tokens should produce different hashes")
	}

	// Hash should be base64url encoded
	_, err := base64.RawURLEncoding.DecodeString(hash1)
	if err != nil {
		t.Errorf("Hash should be valid base64url: %v", err)
	}
}

func TestDPoPKey_GenerateProof_UniqueJTI(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	opts := &DPoPProofOptions{
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/token",
	}

	// Generate multiple proofs
	jtis := make(map[string]bool)
	for i := 0; i < 10; i++ {
		proof, err := key.GenerateProof(opts)
		if err != nil {
			t.Fatalf("GenerateProof() error = %v", err)
		}

		// Extract JTI
		parts := strings.Split(proof, ".")
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var payload map[string]interface{}
		json.Unmarshal(payloadJSON, &payload)

		jti := payload["jti"].(string)
		if jtis[jti] {
			t.Errorf("Duplicate JTI found: %s", jti)
		}
		jtis[jti] = true
	}
}

func BenchmarkGenerateDPoPKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateDPoPKey()
	}
}

func BenchmarkGenerateProof(b *testing.B) {
	key, _ := GenerateDPoPKey()
	opts := &DPoPProofOptions{
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/token",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = key.GenerateProof(opts)
	}
}

func BenchmarkSerializeDeserialize(b *testing.B) {
	key, _ := GenerateDPoPKey()
	pemData, _ := key.SerializePrivateKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeDPoPKey(pemData)
	}
}

// Verify the generated proof is valid ES256 that can be verified by external libraries
func TestDPoPKey_ES256Compatibility(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	opts := &DPoPProofOptions{
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/token",
	}

	proof, err := key.GenerateProof(opts)
	if err != nil {
		t.Fatalf("GenerateProof() error = %v", err)
	}

	// Verify using standard jwt-go ES256 method
	token, err := jwt.Parse(proof, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &key.PrivateKey.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("Standard ES256 verification failed: %v", err)
	}

	if !token.Valid {
		t.Error("Token should be valid with standard ES256 verification")
	}
}

// Test that P-256 coordinate padding is correct (32 bytes each)
func TestDPoPKey_CoordinatePadding(t *testing.T) {
	// Generate many keys to find one with leading zeros in coordinates
	for i := 0; i < 100; i++ {
		key, err := GenerateDPoPKey()
		if err != nil {
			continue
		}

		jwk := key.PublicJWK()

		// Decode X and Y
		xBytes, _ := base64.RawURLEncoding.DecodeString(jwk.X)
		yBytes, _ := base64.RawURLEncoding.DecodeString(jwk.Y)

		// P-256 coordinates should always be 32 bytes
		if len(xBytes) != 32 {
			t.Errorf("X coordinate should be 32 bytes, got %d", len(xBytes))
		}
		if len(yBytes) != 32 {
			t.Errorf("Y coordinate should be 32 bytes, got %d", len(yBytes))
		}
	}
}

// Test interoperability with ecdsa.PublicKey
func TestDPoPKey_PublicKeyInterop(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey() error = %v", err)
	}

	// Get public key
	pub := &key.PrivateKey.PublicKey

	// Verify it's a valid EC public key
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		t.Error("Public key point not on curve")
	}

	// Verify it's P-256
	if pub.Curve != elliptic.P256() {
		t.Error("Expected P-256 curve")
	}
}
