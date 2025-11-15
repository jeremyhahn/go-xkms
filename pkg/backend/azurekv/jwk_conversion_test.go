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

//go:build azurekv

package azurekv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"
)

func TestConvertToAzureJWK_RSA(t *testing.T) {
	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to standard JWK
	standardJWK, err := jwk.FromPrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to convert to standard JWK: %v", err)
	}

	// Define key operations
	keyOps := []*azkeys.KeyOperation{
		ptrKeyOp(azkeys.KeyOperationSign),
		ptrKeyOp(azkeys.KeyOperationVerify),
	}

	// Convert to Azure JWK
	azureJWK, err := convertToAzureJWK(standardJWK, keyOps)
	if err != nil {
		t.Fatalf("convertToAzureJWK failed: %v", err)
	}

	// Verify key type
	if azureJWK.Kty == nil || *azureJWK.Kty != azkeys.KeyTypeRSA {
		t.Errorf("Expected key type RSA, got %v", azureJWK.Kty)
	}

	// Verify required fields are present
	if azureJWK.N == nil || len(azureJWK.N) == 0 {
		t.Error("N should not be empty")
	}
	if azureJWK.E == nil || len(azureJWK.E) == 0 {
		t.Error("E should not be empty")
	}
	if azureJWK.D == nil || len(azureJWK.D) == 0 {
		t.Error("D should not be empty for private key")
	}
	if azureJWK.P == nil || len(azureJWK.P) == 0 {
		t.Error("P should not be empty for private key")
	}
	if azureJWK.Q == nil || len(azureJWK.Q) == 0 {
		t.Error("Q should not be empty for private key")
	}

	// Verify key operations
	if len(azureJWK.KeyOps) != 2 {
		t.Errorf("Expected 2 key operations, got %d", len(azureJWK.KeyOps))
	}
}

func TestConvertToAzureJWK_ECDSA(t *testing.T) {
	curves := []struct {
		curve       elliptic.Curve
		expectedCrv azkeys.CurveName
	}{
		{elliptic.P256(), azkeys.CurveNameP256},
		{elliptic.P384(), azkeys.CurveNameP384},
		{elliptic.P521(), azkeys.CurveNameP521},
	}

	for _, tc := range curves {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			// Generate an ECDSA key
			ecKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			// Convert to standard JWK
			standardJWK, err := jwk.FromPrivateKey(ecKey)
			if err != nil {
				t.Fatalf("Failed to convert to standard JWK: %v", err)
			}

			// Define key operations
			keyOps := []*azkeys.KeyOperation{
				ptrKeyOp(azkeys.KeyOperationSign),
				ptrKeyOp(azkeys.KeyOperationVerify),
			}

			// Convert to Azure JWK
			azureJWK, err := convertToAzureJWK(standardJWK, keyOps)
			if err != nil {
				t.Fatalf("convertToAzureJWK failed: %v", err)
			}

			// Verify key type
			if azureJWK.Kty == nil || *azureJWK.Kty != azkeys.KeyTypeEC {
				t.Errorf("Expected key type EC, got %v", azureJWK.Kty)
			}

			// Verify curve
			if azureJWK.Crv == nil || *azureJWK.Crv != tc.expectedCrv {
				t.Errorf("Expected curve %v, got %v", tc.expectedCrv, azureJWK.Crv)
			}

			// Verify required fields are present
			if azureJWK.X == nil || len(azureJWK.X) == 0 {
				t.Error("X should not be empty")
			}
			if azureJWK.Y == nil || len(azureJWK.Y) == 0 {
				t.Error("Y should not be empty")
			}
			if azureJWK.D == nil || len(azureJWK.D) == 0 {
				t.Error("D should not be empty for private key")
			}
		})
	}
}

func TestConvertFromAzureJWK_RSA(t *testing.T) {
	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to standard JWK
	originalJWK, err := jwk.FromPrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to convert to standard JWK: %v", err)
	}

	// Convert to Azure JWK
	keyOps := []*azkeys.KeyOperation{ptrKeyOp(azkeys.KeyOperationSign)}
	azureJWK, err := convertToAzureJWK(originalJWK, keyOps)
	if err != nil {
		t.Fatalf("convertToAzureJWK failed: %v", err)
	}

	// Convert back to standard JWK
	recoveredJWK, err := convertFromAzureJWK(azureJWK)
	if err != nil {
		t.Fatalf("convertFromAzureJWK failed: %v", err)
	}

	// Verify key type
	if recoveredJWK.Kty != string(jwk.KeyTypeRSA) {
		t.Errorf("Expected key type RSA, got %s", recoveredJWK.Kty)
	}

	// Verify fields match
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

func TestConvertFromAzureJWK_ECDSA(t *testing.T) {
	// Generate an ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Convert to standard JWK
	originalJWK, err := jwk.FromPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("Failed to convert to standard JWK: %v", err)
	}

	// Convert to Azure JWK
	keyOps := []*azkeys.KeyOperation{ptrKeyOp(azkeys.KeyOperationSign)}
	azureJWK, err := convertToAzureJWK(originalJWK, keyOps)
	if err != nil {
		t.Fatalf("convertToAzureJWK failed: %v", err)
	}

	// Convert back to standard JWK
	recoveredJWK, err := convertFromAzureJWK(azureJWK)
	if err != nil {
		t.Fatalf("convertFromAzureJWK failed: %v", err)
	}

	// Verify key type
	if recoveredJWK.Kty != string(jwk.KeyTypeEC) {
		t.Errorf("Expected key type EC, got %s", recoveredJWK.Kty)
	}

	// Verify fields match
	if originalJWK.Crv != recoveredJWK.Crv {
		t.Error("Crv doesn't match")
	}
	if originalJWK.X != recoveredJWK.X {
		t.Error("X doesn't match")
	}
	if originalJWK.Y != recoveredJWK.Y {
		t.Error("Y doesn't match")
	}
	if originalJWK.D != recoveredJWK.D {
		t.Error("D doesn't match")
	}
}

func TestConvertRoundTrip_RSA(t *testing.T) {
	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to standard JWK
	originalJWK, err := jwk.FromPrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to convert to standard JWK: %v", err)
	}

	// Convert to Azure JWK and back
	keyOps := []*azkeys.KeyOperation{ptrKeyOp(azkeys.KeyOperationSign)}
	azureJWK, err := convertToAzureJWK(originalJWK, keyOps)
	if err != nil {
		t.Fatalf("convertToAzureJWK failed: %v", err)
	}

	recoveredJWK, err := convertFromAzureJWK(azureJWK)
	if err != nil {
		t.Fatalf("convertFromAzureJWK failed: %v", err)
	}

	// Convert both JWKs to crypto.PrivateKey and verify they match
	originalKey, err := originalJWK.ToPrivateKey()
	if err != nil {
		t.Fatalf("Failed to convert original JWK to private key: %v", err)
	}

	recoveredKey, err := recoveredJWK.ToPrivateKey()
	if err != nil {
		t.Fatalf("Failed to convert recovered JWK to private key: %v", err)
	}

	originalRSA, ok := originalKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Original key is not *rsa.PrivateKey")
	}

	recoveredRSA, ok := recoveredKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Recovered key is not *rsa.PrivateKey")
	}

	// Compare key parameters
	if originalRSA.N.Cmp(recoveredRSA.N) != 0 {
		t.Error("Modulus N doesn't match")
	}
	if originalRSA.E != recoveredRSA.E {
		t.Error("Exponent E doesn't match")
	}
	if originalRSA.D.Cmp(recoveredRSA.D) != 0 {
		t.Error("Private exponent D doesn't match")
	}
}

func TestConvertRoundTrip_ECDSA(t *testing.T) {
	// Generate an ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Convert to standard JWK
	originalJWK, err := jwk.FromPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("Failed to convert to standard JWK: %v", err)
	}

	// Convert to Azure JWK and back
	keyOps := []*azkeys.KeyOperation{ptrKeyOp(azkeys.KeyOperationSign)}
	azureJWK, err := convertToAzureJWK(originalJWK, keyOps)
	if err != nil {
		t.Fatalf("convertToAzureJWK failed: %v", err)
	}

	recoveredJWK, err := convertFromAzureJWK(azureJWK)
	if err != nil {
		t.Fatalf("convertFromAzureJWK failed: %v", err)
	}

	// Convert both JWKs to crypto.PrivateKey and verify they match
	originalKey, err := originalJWK.ToPrivateKey()
	if err != nil {
		t.Fatalf("Failed to convert original JWK to private key: %v", err)
	}

	recoveredKey, err := recoveredJWK.ToPrivateKey()
	if err != nil {
		t.Fatalf("Failed to convert recovered JWK to private key: %v", err)
	}

	originalEC, ok := originalKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("Original key is not *ecdsa.PrivateKey")
	}

	recoveredEC, ok := recoveredKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("Recovered key is not *ecdsa.PrivateKey")
	}

	// Compare key parameters
	if originalEC.X.Cmp(recoveredEC.X) != 0 {
		t.Error("X coordinate doesn't match")
	}
	if originalEC.Y.Cmp(recoveredEC.Y) != 0 {
		t.Error("Y coordinate doesn't match")
	}
	if originalEC.D.Cmp(recoveredEC.D) != 0 {
		t.Error("Private key D doesn't match")
	}
}

func TestConvertFromAzureJWK_Errors(t *testing.T) {
	tests := []struct {
		name    string
		jwk     *azkeys.JSONWebKey
		wantErr bool
	}{
		{
			name:    "nil key type",
			jwk:     &azkeys.JSONWebKey{},
			wantErr: true,
		},
		{
			name: "unsupported key type",
			jwk: &azkeys.JSONWebKey{
				Kty: func() *azkeys.KeyType {
					kt := azkeys.KeyType("UNSUPPORTED")
					return &kt
				}(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := convertFromAzureJWK(tt.jwk)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertFromAzureJWK() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
