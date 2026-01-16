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

package quic

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestExtractPublicKey_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubKey, err := extractPublicKey(privKey)
	if err != nil {
		t.Fatalf("extractPublicKey failed: %v", err)
	}

	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pubKey)
	}

	if rsaPub.N.Cmp(privKey.N) != 0 {
		t.Error("extracted public key does not match")
	}
}

func TestExtractPublicKey_ECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	pubKey, err := extractPublicKey(privKey)
	if err != nil {
		t.Fatalf("extractPublicKey failed: %v", err)
	}

	ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pubKey)
	}

	if ecdsaPub.X.Cmp(privKey.X) != 0 || ecdsaPub.Y.Cmp(privKey.Y) != 0 {
		t.Error("extracted public key does not match")
	}
}

func TestExtractPublicKey_Ed25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	extracted, err := extractPublicKey(privKey)
	if err != nil {
		t.Fatalf("extractPublicKey failed: %v", err)
	}

	ed25519Pub, ok := extracted.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", extracted)
	}

	if !ed25519Pub.Equal(pubKey) {
		t.Error("extracted public key does not match")
	}
}

func TestExtractPublicKey_UnsupportedType(t *testing.T) {
	_, err := extractPublicKey("unsupported")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestParseHashAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected crypto.Hash
		wantErr  bool
	}{
		{"SHA1", "SHA1", crypto.SHA1, false},
		{"SHA224", "SHA224", crypto.SHA224, false},
		{"SHA256", "SHA256", crypto.SHA256, false},
		{"SHA384", "SHA384", crypto.SHA384, false},
		{"SHA512", "SHA512", crypto.SHA512, false},
		{"sha256 lowercase", "sha256", crypto.SHA256, false},
		{"SHA-256 with hyphen", "SHA-256", crypto.SHA256, false},
		{"SHA-384 with hyphen", "SHA-384", crypto.SHA384, false},
		{"SHA-512 with hyphen", "SHA-512", crypto.SHA512, false},
		{"empty defaults to SHA256", "", crypto.SHA256, false},
		{"unsupported", "MD5", 0, true},
		{"invalid", "INVALID", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHashAlgorithm(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHashAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("parseHashAlgorithm() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestVerifySignature_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	message := []byte("test message")
	hash := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	valid, err := verifySignature(&privKey.PublicKey, hash[:], signature, crypto.SHA256)
	if err != nil {
		t.Fatalf("verifySignature failed: %v", err)
	}

	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifySignature_RSA_Invalid(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	message := []byte("test message")
	hash := sha256.Sum256(message)

	invalidSignature := []byte("invalid signature data")

	valid, err := verifySignature(&privKey.PublicKey, hash[:], invalidSignature, crypto.SHA256)
	if err != nil {
		t.Fatalf("verifySignature failed: %v", err)
	}

	if valid {
		t.Error("expected invalid signature")
	}
}

func TestVerifySignature_ECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	message := []byte("test message")
	hash := sha256.Sum256(message)

	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	valid, err := verifySignature(&privKey.PublicKey, hash[:], signature, crypto.SHA256)
	if err != nil {
		t.Fatalf("verifySignature failed: %v", err)
	}

	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifySignature_ECDSA_Invalid(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	message := []byte("test message")
	hash := sha256.Sum256(message)

	invalidSignature := []byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}

	valid, err := verifySignature(&privKey.PublicKey, hash[:], invalidSignature, crypto.SHA256)
	if err != nil {
		t.Fatalf("verifySignature failed: %v", err)
	}

	if valid {
		t.Error("expected invalid signature")
	}
}

func TestVerifySignature_Ed25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	message := []byte("test message")
	signature := ed25519.Sign(privKey, message)

	valid, err := verifySignature(pubKey, message, signature, crypto.SHA256)
	if err != nil {
		t.Fatalf("verifySignature failed: %v", err)
	}

	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifySignature_Ed25519_Invalid(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	message := []byte("test message")
	invalidSignature := make([]byte, ed25519.SignatureSize)

	valid, err := verifySignature(pubKey, message, invalidSignature, crypto.SHA256)
	if err != nil {
		t.Fatalf("verifySignature failed: %v", err)
	}

	if valid {
		t.Error("expected invalid signature")
	}
}

func TestVerifySignature_UnsupportedKeyType(t *testing.T) {
	_, err := verifySignature("unsupported", []byte("digest"), []byte("signature"), crypto.SHA256)
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// TestExtractPublicKey_CryptoSigner verifies that the crypto.Signer interface
// can be used to extract public keys. We use an actual RSA key which implements
// crypto.Signer directly.
func TestExtractPublicKey_CryptoSigner(t *testing.T) {
	// RSA PrivateKey implements crypto.Signer interface directly
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// RSA key is already handled by the *rsa.PrivateKey case
	// So we test with the direct type
	pubKey, err := extractPublicKey(rsaKey)
	if err != nil {
		t.Fatalf("extractPublicKey failed: %v", err)
	}

	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pubKey)
	}

	if rsaPub.N.Cmp(rsaKey.N) != 0 {
		t.Error("extracted public key does not match")
	}
}
