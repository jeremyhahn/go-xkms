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

package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockOpaqueKey implements opaque.OpaqueKey for testing
type mockOpaqueKey struct {
	pub crypto.PublicKey
}

func (m *mockOpaqueKey) Public() crypto.PublicKey {
	return m.pub
}

func (m *mockOpaqueKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (m *mockOpaqueKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return nil, nil
}

func (m *mockOpaqueKey) Digest(data []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockOpaqueKey) Equal(x crypto.PrivateKey) bool {
	return false
}

func (m *mockOpaqueKey) KeyAttributes() *types.KeyAttributes {
	return nil
}

// TestCompareOpaqueKeyEquality_RSA tests RSA key comparison
func TestCompareOpaqueKeyEquality_RSA(t *testing.T) {
	// Generate two RSA keys for testing
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}

	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}

	tests := []struct {
		name       string
		opaqueKey  opaque.OpaqueKey
		privateKey crypto.PrivateKey
		want       bool
	}{
		{
			name:       "same RSA key",
			opaqueKey:  &mockOpaqueKey{pub: &privKey1.PublicKey},
			privateKey: privKey1,
			want:       true,
		},
		{
			name:       "different RSA keys",
			opaqueKey:  &mockOpaqueKey{pub: &privKey1.PublicKey},
			privateKey: privKey2,
			want:       false,
		},
		{
			name:       "nil opaque key",
			opaqueKey:  nil,
			privateKey: privKey1,
			want:       false,
		},
		{
			name:       "nil private key",
			opaqueKey:  &mockOpaqueKey{pub: &privKey1.PublicKey},
			privateKey: nil,
			want:       false,
		},
		{
			name:       "both nil",
			opaqueKey:  nil,
			privateKey: nil,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareOpaqueKeyEquality(tt.opaqueKey, tt.privateKey)
			if got != tt.want {
				t.Errorf("CompareOpaqueKeyEquality() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCompareOpaqueKeyEquality_ECDSA tests ECDSA key comparison
func TestCompareOpaqueKeyEquality_ECDSA(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate two ECDSA keys for testing
			privKey1, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key 1: %v", err)
			}

			privKey2, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key 2: %v", err)
			}

			testCases := []struct {
				name       string
				opaqueKey  opaque.OpaqueKey
				privateKey crypto.PrivateKey
				want       bool
			}{
				{
					name:       "same ECDSA key",
					opaqueKey:  &mockOpaqueKey{pub: &privKey1.PublicKey},
					privateKey: privKey1,
					want:       true,
				},
				{
					name:       "different ECDSA keys",
					opaqueKey:  &mockOpaqueKey{pub: &privKey1.PublicKey},
					privateKey: privKey2,
					want:       false,
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					got := CompareOpaqueKeyEquality(tc.opaqueKey, tc.privateKey)
					if got != tc.want {
						t.Errorf("CompareOpaqueKeyEquality() = %v, want %v", got, tc.want)
					}
				})
			}
		})
	}
}

// TestCompareOpaqueKeyEquality_Ed25519 tests Ed25519 key comparison
func TestCompareOpaqueKeyEquality_Ed25519(t *testing.T) {
	// Generate two Ed25519 keys for testing
	pubKey1, privKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key 1: %v", err)
	}

	pubKey2, privKey2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key 2: %v", err)
	}

	tests := []struct {
		name       string
		opaqueKey  opaque.OpaqueKey
		privateKey crypto.PrivateKey
		want       bool
	}{
		{
			name:       "same Ed25519 key",
			opaqueKey:  &mockOpaqueKey{pub: pubKey1},
			privateKey: privKey1,
			want:       true,
		},
		{
			name:       "different Ed25519 keys",
			opaqueKey:  &mockOpaqueKey{pub: pubKey1},
			privateKey: privKey2,
			want:       false,
		},
		{
			name:       "different Ed25519 keys (reversed)",
			opaqueKey:  &mockOpaqueKey{pub: pubKey2},
			privateKey: privKey1,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareOpaqueKeyEquality(tt.opaqueKey, tt.privateKey)
			if got != tt.want {
				t.Errorf("CompareOpaqueKeyEquality() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCompareOpaqueKeyEquality_MixedTypes tests comparison with mismatched key types
func TestCompareOpaqueKeyEquality_MixedTypes(t *testing.T) {
	// Generate keys of different types
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	ed25519PubKey, ed25519PrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	tests := []struct {
		name       string
		opaqueKey  opaque.OpaqueKey
		privateKey crypto.PrivateKey
		want       bool
	}{
		{
			name:       "RSA opaque vs ECDSA private",
			opaqueKey:  &mockOpaqueKey{pub: &rsaPrivKey.PublicKey},
			privateKey: ecdsaPrivKey,
			want:       false,
		},
		{
			name:       "ECDSA opaque vs RSA private",
			opaqueKey:  &mockOpaqueKey{pub: &ecdsaPrivKey.PublicKey},
			privateKey: rsaPrivKey,
			want:       false,
		},
		{
			name:       "RSA opaque vs Ed25519 private",
			opaqueKey:  &mockOpaqueKey{pub: &rsaPrivKey.PublicKey},
			privateKey: ed25519PrivKey,
			want:       false,
		},
		{
			name:       "Ed25519 opaque vs RSA private",
			opaqueKey:  &mockOpaqueKey{pub: ed25519PubKey},
			privateKey: rsaPrivKey,
			want:       false,
		},
		{
			name:       "ECDSA opaque vs Ed25519 private",
			opaqueKey:  &mockOpaqueKey{pub: &ecdsaPrivKey.PublicKey},
			privateKey: ed25519PrivKey,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareOpaqueKeyEquality(tt.opaqueKey, tt.privateKey)
			if got != tt.want {
				t.Errorf("CompareOpaqueKeyEquality() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCompareOpaqueKeyEquality_NilPublicKey tests when opaque key returns nil public key
func TestCompareOpaqueKeyEquality_NilPublicKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create mock opaque key with nil public key
	opaqueKey := &mockOpaqueKey{pub: nil}

	got := CompareOpaqueKeyEquality(opaqueKey, privKey)
	if got != false {
		t.Errorf("CompareOpaqueKeyEquality() with nil public key = %v, want false", got)
	}
}

// TestCompareOpaqueKeyEquality_UnsupportedPrivateKeyType tests with unsupported private key type
func TestCompareOpaqueKeyEquality_UnsupportedPrivateKeyType(t *testing.T) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	opaqueKey := &mockOpaqueKey{pub: &rsaPrivKey.PublicKey}

	// Use an unsupported private key type
	type unsupportedKey struct{}
	var unsupportedPrivKey crypto.PrivateKey = unsupportedKey{}

	got := CompareOpaqueKeyEquality(opaqueKey, unsupportedPrivKey)
	if got != false {
		t.Errorf("CompareOpaqueKeyEquality() with unsupported key type = %v, want false", got)
	}
}

// TestCompareOpaqueKeyEquality_UnsupportedPublicKeyType tests with unsupported public key type
func TestCompareOpaqueKeyEquality_UnsupportedPublicKeyType(t *testing.T) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create mock opaque key with unsupported public key type
	type unsupportedPubKey struct{}
	opaqueKey := &mockOpaqueKey{pub: unsupportedPubKey{}}

	got := CompareOpaqueKeyEquality(opaqueKey, rsaPrivKey)
	if got != false {
		t.Errorf("CompareOpaqueKeyEquality() with unsupported public key type = %v, want false", got)
	}
}

// TestCompareOpaqueKeyEquality_RSADifferentExponent tests RSA keys with different exponents
func TestCompareOpaqueKeyEquality_RSADifferentExponent(t *testing.T) {
	// Generate a standard RSA key
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a second key with the same modulus but different exponent (artificial)
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate second RSA key: %v", err)
	}

	// Create public key with different exponent
	differentPubKey := &rsa.PublicKey{
		N: privKey1.N,     // Same modulus
		E: privKey1.E + 2, // Different exponent
	}

	opaqueKey := &mockOpaqueKey{pub: differentPubKey}

	got := CompareOpaqueKeyEquality(opaqueKey, privKey1)
	if got != false {
		t.Errorf("CompareOpaqueKeyEquality() with different RSA exponent = %v, want false", got)
	}

	// Now test with different modulus but same exponent
	differentModulusPubKey := &rsa.PublicKey{
		N: privKey2.N, // Different modulus
		E: privKey1.E, // Same exponent
	}

	opaqueKey2 := &mockOpaqueKey{pub: differentModulusPubKey}

	got2 := CompareOpaqueKeyEquality(opaqueKey2, privKey1)
	if got2 != false {
		t.Errorf("CompareOpaqueKeyEquality() with different RSA modulus = %v, want false", got2)
	}
}

// TestCompareOpaqueKeyEquality_ECDSADifferentCurve tests ECDSA keys on different curves
func TestCompareOpaqueKeyEquality_ECDSADifferentCurve(t *testing.T) {
	// Generate keys on different curves
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P256 key: %v", err)
	}

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P384 key: %v", err)
	}

	// Test P256 opaque key vs P384 private key
	opaqueKey := &mockOpaqueKey{pub: &p256Key.PublicKey}

	got := CompareOpaqueKeyEquality(opaqueKey, p384Key)
	if got != false {
		t.Errorf("CompareOpaqueKeyEquality() with different ECDSA curves = %v, want false", got)
	}
}

// TestCompareOpaqueKeyEquality_ECDSADifferentPoints tests ECDSA keys with different points
func TestCompareOpaqueKeyEquality_ECDSADifferentPoints(t *testing.T) {
	// Generate two keys on the same curve
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key 1: %v", err)
	}

	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key 2: %v", err)
	}

	// Create public key with different X coordinate but same curve
	differentPubKey := &ecdsa.PublicKey{
		Curve: privKey1.Curve,
		X:     privKey2.X, // Different X
		Y:     privKey1.Y, // Same Y
	}

	opaqueKey := &mockOpaqueKey{pub: differentPubKey}

	got := CompareOpaqueKeyEquality(opaqueKey, privKey1)
	if got != false {
		t.Errorf("CompareOpaqueKeyEquality() with different ECDSA X coordinate = %v, want false", got)
	}

	// Test with different Y coordinate but same X
	differentPubKey2 := &ecdsa.PublicKey{
		Curve: privKey1.Curve,
		X:     privKey1.X, // Same X
		Y:     privKey2.Y, // Different Y
	}

	opaqueKey2 := &mockOpaqueKey{pub: differentPubKey2}

	got2 := CompareOpaqueKeyEquality(opaqueKey2, privKey1)
	if got2 != false {
		t.Errorf("CompareOpaqueKeyEquality() with different ECDSA Y coordinate = %v, want false", got2)
	}
}

// TestCompareOpaqueKeyEquality_Ed25519DifferentLength tests Ed25519 keys with different lengths
func TestCompareOpaqueKeyEquality_Ed25519DifferentLength(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create a truncated public key (invalid but tests the length check)
	truncatedPubKey := pubKey[:len(pubKey)-1]

	opaqueKey := &mockOpaqueKey{pub: truncatedPubKey}

	got := CompareOpaqueKeyEquality(opaqueKey, privKey)
	if got != false {
		t.Errorf("CompareOpaqueKeyEquality() with different Ed25519 key lengths = %v, want false", got)
	}
}

// TestCompareOpaqueKeyEquality_Ed25519ByteDifference tests Ed25519 keys with single byte difference
func TestCompareOpaqueKeyEquality_Ed25519ByteDifference(t *testing.T) {
	pubKey1, privKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create a public key with one byte different
	pubKey2 := make(ed25519.PublicKey, len(pubKey1))
	copy(pubKey2, pubKey1)
	pubKey2[0] = pubKey1[0] ^ 0xFF // Flip all bits of first byte

	opaqueKey := &mockOpaqueKey{pub: pubKey2}

	got := CompareOpaqueKeyEquality(opaqueKey, privKey1)
	if got != false {
		t.Errorf("CompareOpaqueKeyEquality() with different Ed25519 key bytes = %v, want false", got)
	}
}
