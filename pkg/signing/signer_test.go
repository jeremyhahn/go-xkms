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

package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
)

// TestNewSigner tests the creation of a new signer
func TestNewSigner(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name    string
		signer  crypto.Signer
		wantErr error
	}{
		{
			name:    "valid signer",
			signer:  privKey,
			wantErr: nil,
		},
		{
			name:    "nil signer",
			signer:  nil,
			wantErr: ErrSignerRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.signer)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if signer == nil {
				t.Fatal("expected non-nil signer")
			}
		})
	}
}

// TestSignerPublic tests the Public method
func TestSignerPublic(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	pub := signer.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}

	if pub != &privKey.PublicKey {
		t.Error("Public() returned different public key")
	}
}

// TestSignerSignRSAPKCS1v15 tests RSA PKCS#1 v1.5 signing
func TestSignerSignRSAPKCS1v15(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data to sign")
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)

	opts := NewSignerOpts(crypto.SHA256)
	signature, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}

	// Verify signature
	err = rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, digest, signature)
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// TestSignerSignRSAPSS tests RSA-PSS signing
func TestSignerSignRSAPSS(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data to sign")
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}
	opts := NewSignerOpts(crypto.SHA256).WithPSSOptions(pssOpts)

	signature, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}

	// Verify signature
	err = rsa.VerifyPSS(&privKey.PublicKey, crypto.SHA256, digest, signature, pssOpts)
	if err != nil {
		t.Errorf("PSS signature verification failed: %v", err)
	}
}

// TestSignerSignECDSA tests ECDSA signing
func TestSignerSignECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data to sign")
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)

	opts := NewSignerOpts(crypto.SHA256)
	signature, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}

	// Verify signature
	if !ecdsa.VerifyASN1(&privKey.PublicKey, digest, signature) {
		t.Error("ECDSA signature verification failed")
	}
}

// TestSignerSignEd25519 tests Ed25519 signing
func TestSignerSignEd25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data to sign")

	opts := NewSignerOpts(crypto.Hash(0)).WithBlobData(testData)
	signature, err := signer.Sign(rand.Reader, nil, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}

	// Verify signature
	if !ed25519.Verify(pubKey, testData, signature) {
		t.Error("Ed25519 signature verification failed")
	}
}

// TestSignerSignWithBlobData tests signing with blob data
func TestSignerSignWithBlobData(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data to sign")
	opts := NewSignerOpts(crypto.SHA256).WithBlobData(testData)

	// Pass nil digest since BlobData will be used
	signature, err := signer.Sign(rand.Reader, nil, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}

	// Verify signature
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)
	err = rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, digest, signature)
	if err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// TestSignerGetKeyAlgorithm tests the GetKeyAlgorithm method
func TestSignerGetKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		keyGen   func() (crypto.Signer, error)
		expected x509.PublicKeyAlgorithm
	}{
		{
			name: "RSA",
			keyGen: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
			expected: x509.RSA,
		},
		{
			name: "ECDSA",
			keyGen: func() (crypto.Signer, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
			expected: x509.ECDSA,
		},
		{
			name: "Ed25519",
			keyGen: func() (crypto.Signer, error) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, err
			},
			expected: x509.Ed25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.keyGen()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			signer, err := NewSigner(key)
			if err != nil {
				t.Fatalf("failed to create signer: %v", err)
			}

			alg := signer.GetKeyAlgorithm()
			if alg != tt.expected {
				t.Errorf("GetKeyAlgorithm() = %v, want %v", alg, tt.expected)
			}
		})
	}
}

// TestSignerSupportsHashAlgorithm tests the SupportsHashAlgorithm method
func TestSignerSupportsHashAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		keyGen   func() (crypto.Signer, error)
		hash     crypto.Hash
		expected bool
	}{
		{
			name: "RSA with SHA256",
			keyGen: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
			hash:     crypto.SHA256,
			expected: true,
		},
		{
			name: "ECDSA with SHA256",
			keyGen: func() (crypto.Signer, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
			hash:     crypto.SHA256,
			expected: true,
		},
		{
			name: "Ed25519 with zero hash",
			keyGen: func() (crypto.Signer, error) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, err
			},
			hash:     crypto.Hash(0),
			expected: true,
		},
		{
			name: "Ed25519 with SHA256",
			keyGen: func() (crypto.Signer, error) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, err
			},
			hash:     crypto.SHA256,
			expected: false,
		},
		{
			name: "RSA with invalid hash",
			keyGen: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
			hash:     crypto.Hash(999),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.keyGen()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			signer, err := NewSigner(key)
			if err != nil {
				t.Fatalf("failed to create signer: %v", err)
			}

			supported := signer.SupportsHashAlgorithm(tt.hash)
			if supported != tt.expected {
				t.Errorf("SupportsHashAlgorithm(%v) = %v, want %v", tt.hash, supported, tt.expected)
			}
		})
	}
}

// TestSignerSignStandardOpts tests signing with standard crypto.SignerOpts
func TestSignerSignStandardOpts(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data")
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)

	// Test with standard hash opts
	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}
}

// TestSignerSignWithBlobCN tests signing with blob CN
func TestSignerSignWithBlobCN(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data")
	opts := NewSignerOpts(crypto.SHA256).
		WithBlobCN("test-blob").
		WithBlobData(testData)

	signature, err := signer.Sign(rand.Reader, nil, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}
}

// TestSignerMultipleHashes tests signing with different hash functions
func TestSignerMultipleHashes(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data")

	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := tt.hash.New()
			hasher.Write(testData)
			digest := hasher.Sum(nil)

			opts := NewSignerOpts(tt.hash)
			signature, err := signer.Sign(rand.Reader, digest, opts)
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}
			if len(signature) == 0 {
				t.Error("expected non-empty signature")
			}

			// Verify signature
			err = rsa.VerifyPKCS1v15(&privKey.PublicKey, tt.hash, digest, signature)
			if err != nil {
				t.Errorf("signature verification failed: %v", err)
			}
		})
	}
}

// TestSignerECDSACurves tests ECDSA signing with different curves
func TestSignerECDSACurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key: %v", err)
			}

			signer, err := NewSigner(privKey)
			if err != nil {
				t.Fatalf("failed to create signer: %v", err)
			}

			testData := []byte("test data")
			hasher := crypto.SHA256.New()
			hasher.Write(testData)
			digest := hasher.Sum(nil)

			opts := NewSignerOpts(crypto.SHA256)
			signature, err := signer.Sign(rand.Reader, digest, opts)
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}
			if len(signature) == 0 {
				t.Error("expected non-empty signature")
			}

			// Verify signature
			if !ecdsa.VerifyASN1(&privKey.PublicKey, digest, signature) {
				t.Error("ECDSA signature verification failed")
			}
		})
	}
}

// TestSignerEd25519WithDigest tests Ed25519 signing with pre-computed digest
func TestSignerEd25519WithDigest(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data")
	opts := NewSignerOpts(crypto.Hash(0))

	// Ed25519 signs the message directly, not a hash
	signature, err := signer.Sign(rand.Reader, testData, opts)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}

	// Verify signature
	if !ed25519.Verify(pubKey, testData, signature) {
		t.Error("Ed25519 signature verification failed")
	}
}

// TestSignerSignWithInvalidHashInOpts tests signing with invalid hash in options
func TestSignerSignWithInvalidHashInOpts(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	testData := []byte("test data")
	opts := NewSignerOpts(crypto.Hash(999)).WithBlobData(testData)

	// Should fail due to invalid hash
	_, err = signer.Sign(rand.Reader, nil, opts)
	if err == nil {
		t.Error("expected error with invalid hash")
	}
}

// TestSignerInterface verifies the signer implements crypto.Signer
func TestSignerInterface(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Verify it implements crypto.Signer
	var _ crypto.Signer = signer
}

// Copyright (c) 2025 Jeremy Hahn
