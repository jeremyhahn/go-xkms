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

package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	xkmsjwt "github.com/jeremyhahn/go-xkms/pkg/encoding/jwt"
)

// Example_basicSigning demonstrates basic JWT signing and verification
func Example_basicSigning() {
	// Generate an RSA key for demonstration
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Create a signer
	signer := xkmsjwt.NewSigner()

	// Create claims
	claims := jwt.MapClaims{
		"sub":   "user123",
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}

	// Sign the token
	tokenString, err := signer.Sign(privateKey, claims)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Token signed successfully")

	// Verify the token
	verifier := xkmsjwt.NewVerifier()
	token, err := verifier.Verify(tokenString, &privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	if token.Valid {
		fmt.Println("Token is valid")
	}

	// Output:
	// Token signed successfully
	// Token is valid
}

// Example_withKID demonstrates signing with a Key ID
func Example_withKID() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	signer := xkmsjwt.NewSigner()

	claims := jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	// Sign with Key ID
	tokenString, err := signer.SignWithKID(privateKey, claims, "pkcs11:signing-key")
	if err != nil {
		log.Fatal(err)
	}

	// Extract Key ID from token
	kid, err := xkmsjwt.ExtractKID(tokenString)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Token signed with Key ID: %s\n", kid)

	// Output:
	// Token signed with Key ID: pkcs11:signing-key
}

// Example_customClaims demonstrates using custom claims
func Example_customClaims() {
	type CustomClaims struct {
		UserID       string   `json:"uid"`
		Email        string   `json:"email"`
		Roles        []string `json:"roles"`
		Organization string   `json:"org"`
		jwt.RegisteredClaims
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	signer := xkmsjwt.NewSigner()

	now := time.Now()
	claims := CustomClaims{
		UserID:       "12345",
		Email:        "admin@example.com",
		Roles:        []string{"admin", "user"},
		Organization: "acme-corp",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "go-xkms",
			Subject:   "admin@example.com",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	_, err = signer.Sign(privateKey, claims)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Custom claims token created")

	// Output:
	// Custom claims token created
}

// Example_verifyWithOptions demonstrates verification with issuer and audience validation
func Example_verifyWithOptions() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	signer := xkmsjwt.NewSigner()

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "go-xkms",
		Subject:   "user123",
		Audience:  jwt.ClaimStrings{"my-app"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	tokenString, err := signer.Sign(privateKey, claims)
	if err != nil {
		log.Fatal(err)
	}

	// Verify with options
	verifier := xkmsjwt.NewVerifier()
	opts := &xkmsjwt.VerifyOptions{
		ValidateIssuer:   true,
		ExpectedIssuer:   "go-xkms",
		ValidateAudience: true,
		ExpectedAudience: "my-app",
	}

	token, err := verifier.VerifyWithOptions(tokenString, &privateKey.PublicKey, opts)
	if err != nil {
		log.Fatal(err)
	}

	if token.Valid {
		fmt.Println("Token verified with issuer and audience validation")
	}

	// Output:
	// Token verified with issuer and audience validation
}
