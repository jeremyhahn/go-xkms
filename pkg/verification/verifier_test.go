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

package verification

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
)

// mockChecksumProvider is a mock implementation of ChecksumProvider for testing
type mockChecksumProvider struct {
	checksums map[string][]byte
	err       error
}

func newMockChecksumProvider() *mockChecksumProvider {
	return &mockChecksumProvider{
		checksums: make(map[string][]byte),
	}
}

func (m *mockChecksumProvider) Checksum(opts *VerifyOpts) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	/* Convert to string */
	checksum, exists := m.checksums[string(opts.BlobCN)]
	if !exists {
		return nil, ErrChecksumNotFound
	}
	return checksum, nil
}

func (m *mockChecksumProvider) setChecksum(blobName string, checksum []byte) {
	m.checksums[blobName] = checksum
}

func (m *mockChecksumProvider) setError(err error) {
	m.err = err
}

// Test RSA PKCS1v15 signature verification
func TestVerify_RSA_PKCS1v15(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data for RSA PKCS1v15 signing")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	verifier := NewVerifier(nil)

	// Test verification with opts
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		PSSOptions: nil, // Use PKCS1v15
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err != nil {
		t.Errorf("RSA PKCS1v15 verification failed: %v", err)
	}

	// Test verification without opts (default path)
	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, nil)
	if err != nil {
		t.Errorf("RSA PKCS1v15 default verification failed: %v", err)
	}
}

// Test RSA PSS signature verification
func TestVerify_RSA_PSS(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data for RSA PSS signing")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data using PSS
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       hash,
	}
	signature, err := rsa.SignPSS(rand.Reader, privateKey, hash, hashed, pssOpts)
	if err != nil {
		t.Fatalf("Failed to sign data with PSS: %v", err)
	}

	verifier := NewVerifier(nil)

	// Test verification with PSS options
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		PSSOptions: pssOpts,
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err != nil {
		t.Errorf("RSA PSS verification failed: %v", err)
	}
}

// Test ECDSA signature verification
func TestVerify_ECDSA(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data for ECDSA signing")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	verifier := NewVerifier(nil)

	// Test verification with opts
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
		},
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err != nil {
		t.Errorf("ECDSA verification failed: %v", err)
	}

	// Test verification without opts (default path)
	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, nil)
	if err != nil {
		t.Errorf("ECDSA default verification failed: %v", err)
	}
}

// Test Ed25519 signature verification
func TestVerify_Ed25519(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create test data
	data := []byte("test data for Ed25519 signing")

	// Sign the data (Ed25519 doesn't use separate hashing)
	signature := ed25519.Sign(privateKey, data)

	verifier := NewVerifier(nil)

	// Test verification with opts
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.Ed25519,
		},
	}

	err = verifier.Verify(publicKey, crypto.SHA256, data, signature, opts)
	if err != nil {
		t.Errorf("Ed25519 verification failed: %v", err)
	}

	// Test verification without opts (default path)
	err = verifier.Verify(publicKey, crypto.SHA256, data, signature, nil)
	if err != nil {
		t.Errorf("Ed25519 default verification failed: %v", err)
	}
}

// Test integrity checking
func TestVerify_IntegrityCheck_Success(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data with integrity check")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Setup mock checksum provider with correct checksum
	mockProvider := newMockChecksumProvider()
	blobName := "test-blob"
	expectedChecksum := hex.EncodeToString(hashed)
	mockProvider.setChecksum(blobName, []byte(expectedChecksum))

	verifier := NewVerifier(mockProvider)

	// Test verification with integrity check
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		BlobCN:         []byte(blobName),
		IntegrityCheck: true,
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err != nil {
		t.Errorf("Verification with integrity check failed: %v", err)
	}
}

// Test integrity check failure with mismatched checksum
func TestVerify_IntegrityCheck_Mismatch(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data with integrity check")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Setup mock checksum provider with wrong checksum
	mockProvider := newMockChecksumProvider()
	blobName := "test-blob"
	wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"
	mockProvider.setChecksum(blobName, []byte(wrongChecksum))

	verifier := NewVerifier(mockProvider)

	// Test verification with integrity check - should fail
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		BlobCN:         []byte(blobName),
		IntegrityCheck: true,
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err == nil {
		t.Error("Expected integrity check to fail with mismatched checksum")
	}
	if !errors.Is(err, ErrFileIntegrityCheckFailed) {
		t.Errorf("Expected ErrFileIntegrityCheckFailed, got: %v", err)
	}
}

// Test integrity check with missing blob name
func TestVerify_IntegrityCheck_MissingBlobName(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	mockProvider := newMockChecksumProvider()
	verifier := NewVerifier(mockProvider)

	// Test verification with integrity check but no blob name
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		BlobCN:         nil, // Missing blob name
		IntegrityCheck: true,
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err == nil {
		t.Error("Expected error for missing blob name")
	}
	if !errors.Is(err, ErrInvalidBlobName) {
		t.Errorf("Expected ErrInvalidBlobName, got: %v", err)
	}
}

// Test integrity check with no checksum provider
func TestVerify_IntegrityCheck_NoProvider(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Create verifier without checksum provider
	verifier := NewVerifier(nil)

	// Test verification with integrity check
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		BlobCN:         []byte("test-blob"),
		IntegrityCheck: true,
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err == nil {
		t.Error("Expected error when no checksum provider is set")
	}
	if !errors.Is(err, ErrChecksumNotFound) {
		t.Errorf("Expected ErrChecksumNotFound, got: %v", err)
	}
}

// Test invalid RSA public key type
func TestVerify_InvalidRSAPublicKey(t *testing.T) {
	// Generate ECDSA key (wrong type)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	verifier := NewVerifier(nil)

	// Try to verify RSA signature with ECDSA public key
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA, // Claim it's RSA
		},
	}

	err = verifier.Verify(&ecdsaKey.PublicKey, hash, hashed, []byte("fake-sig"), opts)
	if err == nil {
		t.Error("Expected error for invalid RSA public key type")
	}
	if !errors.Is(err, ErrInvalidPublicKeyRSA) {
		t.Errorf("Expected ErrInvalidPublicKeyRSA, got: %v", err)
	}
}

// Test invalid ECDSA public key type
func TestVerify_InvalidECDSAPublicKey(t *testing.T) {
	// Generate RSA key (wrong type)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	verifier := NewVerifier(nil)

	// Try to verify ECDSA signature with RSA public key
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.ECDSA, // Claim it's ECDSA
		},
	}

	err = verifier.Verify(&rsaKey.PublicKey, hash, hashed, []byte("fake-sig"), opts)
	if err == nil {
		t.Error("Expected error for invalid ECDSA public key type")
	}
	if !errors.Is(err, ErrInvalidPublicKeyECDSA) {
		t.Errorf("Expected ErrInvalidPublicKeyECDSA, got: %v", err)
	}
}

// Test invalid Ed25519 public key type
func TestVerify_InvalidEd25519PublicKey(t *testing.T) {
	// Generate RSA key (wrong type)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data")

	verifier := NewVerifier(nil)

	// Try to verify Ed25519 signature with RSA public key
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.Ed25519, // Claim it's Ed25519
		},
	}

	err = verifier.Verify(&rsaKey.PublicKey, crypto.SHA256, data, []byte("fake-sig"), opts)
	if err == nil {
		t.Error("Expected error for invalid Ed25519 public key type")
	}
	if !errors.Is(err, ErrInvalidPublicKeyEd25519) {
		t.Errorf("Expected ErrInvalidPublicKeyEd25519, got: %v", err)
	}
}

// Test invalid signature algorithm
func TestVerify_InvalidAlgorithm(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	verifier := NewVerifier(nil)

	// Use invalid algorithm
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.PublicKeyAlgorithm(99), // Invalid
		},
	}

	err = verifier.Verify(&rsaKey.PublicKey, hash, hashed, []byte("fake-sig"), opts)
	if err == nil {
		t.Error("Expected error for invalid signature algorithm")
	}
	if !errors.Is(err, ErrInvalidSignatureAlgorithm) {
		t.Errorf("Expected ErrInvalidSignatureAlgorithm, got: %v", err)
	}
}

// Test signature verification failure with invalid signature
func TestVerify_InvalidSignature_RSA(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	verifier := NewVerifier(nil)

	// Use invalid signature
	invalidSig := []byte("this is not a valid signature")

	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, invalidSig, opts)
	if err == nil {
		t.Error("Expected verification to fail with invalid signature")
	}
}

// Test signature verification failure with invalid signature for ECDSA
func TestVerify_InvalidSignature_ECDSA(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	verifier := NewVerifier(nil)

	// Use invalid signature
	invalidSig := []byte("invalid")

	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
		},
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, invalidSig, opts)
	if err == nil {
		t.Error("Expected verification to fail with invalid signature")
	}
	if !errors.Is(err, ErrSignatureVerification) {
		t.Errorf("Expected ErrSignatureVerification, got: %v", err)
	}
}

// Test signature verification failure with invalid signature for Ed25519
func TestVerify_InvalidSignature_Ed25519(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create test data
	data := []byte("test data")

	verifier := NewVerifier(nil)

	// Use invalid signature (wrong length)
	invalidSig := []byte("invalid signature that is too short")

	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.Ed25519,
		},
	}

	err = verifier.Verify(publicKey, crypto.SHA256, data, invalidSig, opts)
	if err == nil {
		t.Error("Expected verification to fail with invalid signature")
	}
	if !errors.Is(err, ErrSignatureVerification) {
		t.Errorf("Expected ErrSignatureVerification, got: %v", err)
	}
}

// Test checksum provider error handling
func TestVerify_ChecksumProviderError(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create test data and hash
	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Setup mock checksum provider with error
	mockProvider := newMockChecksumProvider()
	testErr := errors.New("checksum retrieval failed")
	mockProvider.setError(testErr)

	verifier := NewVerifier(mockProvider)

	// Test verification with integrity check
	opts := &VerifyOpts{
		KeyAttributes: &KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		BlobCN:         []byte("test-blob"),
		IntegrityCheck: true,
	}

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, opts)
	if err == nil {
		t.Error("Expected error from checksum provider")
	}
	if !errors.Is(err, testErr) {
		t.Errorf("Expected test error, got: %v", err)
	}
}

// Test that default verification path works with unsupported key type
func TestVerify_Default_UnsupportedKeyType(t *testing.T) {
	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	verifier := NewVerifier(nil)

	// Use an unsupported key type (string)
	unsupportedKey := "not a real key"

	err := verifier.Verify(unsupportedKey, hash, hashed, []byte("fake-sig"), nil)
	if err == nil {
		t.Error("Expected error for unsupported key type in default path")
	}
	if !errors.Is(err, ErrInvalidSignatureAlgorithm) {
		t.Errorf("Expected ErrInvalidSignatureAlgorithm, got: %v", err)
	}
}

// Test known good signature verification (test vector)
func TestVerify_KnownGoodSignature_RSA(t *testing.T) {
	// Use a deterministic RSA key for reproducible test
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Known data
	data := []byte("Hello, World!")
	hash := crypto.SHA256

	// Hash the data
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	verifier := NewVerifier(nil)

	// Verify the signature
	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, nil)
	if err != nil {
		t.Errorf("Failed to verify known good RSA signature: %v", err)
	}
}

// Test known good ECDSA signature
func TestVerify_KnownGoodSignature_ECDSA(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Known data
	data := []byte("ECDSA test vector")
	hash := crypto.SHA384

	// Hash the data
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Sign the data
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashed)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	verifier := NewVerifier(nil)

	// Verify the signature
	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, signature, nil)
	if err != nil {
		t.Errorf("Failed to verify known good ECDSA signature: %v", err)
	}
}

// Test verification with invalid signature in default path (RSA)
func TestVerify_Default_InvalidSignature_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	verifier := NewVerifier(nil)

	// Use invalid signature
	invalidSig := []byte("not a valid signature")

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, invalidSig, nil)
	if err == nil {
		t.Error("Expected verification to fail with invalid signature in default path")
	}
}

// Test verification with invalid signature in default path (ECDSA)
func TestVerify_Default_InvalidSignature_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	data := []byte("test data")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)

	verifier := NewVerifier(nil)

	// Use invalid signature
	invalidSig := []byte("not valid")

	err = verifier.Verify(&privateKey.PublicKey, hash, hashed, invalidSig, nil)
	if err == nil {
		t.Error("Expected verification to fail with invalid signature in default path")
	}
	if !errors.Is(err, ErrSignatureVerification) {
		t.Errorf("Expected ErrSignatureVerification, got: %v", err)
	}
}

// Test verification with invalid signature in default path (Ed25519)
func TestVerify_Default_InvalidSignature_Ed25519(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	data := []byte("test data")

	verifier := NewVerifier(nil)

	// Use invalid signature
	invalidSig := []byte("not valid at all")

	err = verifier.Verify(publicKey, crypto.SHA256, data, invalidSig, nil)
	if err == nil {
		t.Error("Expected verification to fail with invalid signature in default path")
	}
	if !errors.Is(err, ErrSignatureVerification) {
		t.Errorf("Expected ErrSignatureVerification, got: %v", err)
	}
}
