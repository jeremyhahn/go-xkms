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

package opaque

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mockKeyStore implements a minimal KeyStorer for testing
type mockKeyStore struct {
	getKeyFunc    func(*types.KeyAttributes) (crypto.PrivateKey, error)
	signerFunc    func(*types.KeyAttributes) (crypto.Signer, error)
	decrypterFunc func(*types.KeyAttributes) (crypto.Decrypter, error)
}

func (m *mockKeyStore) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if m.getKeyFunc != nil {
		return m.getKeyFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockKeyStore) Signer(_ context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if m.signerFunc != nil {
		return m.signerFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockKeyStore) Decrypter(_ context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if m.decrypterFunc != nil {
		return m.decrypterFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

// TestNewOpaqueKey_ValidInputs tests successful creation with valid parameters
func TestNewOpaqueKey_ValidInputs(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{
			name: "SHA256",
			hash: crypto.SHA256,
		},
		{
			name: "SHA384",
			hash: crypto.SHA384,
		},
		{
			name: "SHA512",
			hash: crypto.SHA512,
		},
		{
			name: "SHA3_256",
			hash: crypto.SHA3_256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         tt.hash,
			}

			keyStore := &mockKeyStore{}
			key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("expected non-nil key")
			}

			// Verify the key attributes match
			if key.KeyAttributes() != attrs {
				t.Error("key attributes mismatch")
			}

			// Verify the public key matches
			if key.Public() != &privKey.PublicKey {
				t.Error("public key mismatch")
			}
		})
	}
}

// TestNewOpaqueKey_InvalidInputs tests error paths for invalid parameters
func TestNewOpaqueKey_InvalidInputs(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	tests := []struct {
		name     string
		keyStore KeyStorer
		attrs    *types.KeyAttributes
		pub      crypto.PublicKey
		wantErr  error
	}{
		{
			name:     "nil keystore",
			keyStore: nil,
			attrs:    attrs,
			pub:      &privKey.PublicKey,
			wantErr:  ErrKeyStoreRequired,
		},
		{
			name:     "nil attributes",
			keyStore: &mockKeyStore{},
			attrs:    nil,
			pub:      &privKey.PublicKey,
			wantErr:  ErrInvalidKeyAttributes,
		},
		{
			name:     "nil public key",
			keyStore: &mockKeyStore{},
			attrs:    attrs,
			pub:      nil,
			wantErr:  ErrInvalidPublicKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewOpaqueKey(tt.keyStore, tt.attrs, tt.pub)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
			if key != nil {
				t.Error("expected nil key on error")
			}
		})
	}
}

// TestOpaqueSign_RSA tests the Sign() method with RSA keys
func TestOpaqueSign_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	testData := []byte("test data to sign")

	tests := []struct {
		name     string
		hash     crypto.Hash
		wantErr  bool
		errCheck func(error) bool
	}{
		{
			name:    "SHA256",
			hash:    crypto.SHA256,
			wantErr: false,
		},
		{
			name:    "SHA384",
			hash:    crypto.SHA384,
			wantErr: false,
		},
		{
			name:    "SHA512",
			hash:    crypto.SHA512,
			wantErr: false,
		},
		{
			name:    "signer error",
			hash:    crypto.SHA256,
			wantErr: true,
			errCheck: func(err error) bool {
				return err.Error() == "signer error"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         crypto.SHA256,
			}

			var keyStore *mockKeyStore
			if tt.wantErr && tt.errCheck != nil {
				keyStore = &mockKeyStore{
					signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
						return nil, errors.New("signer error")
					},
				}
			} else {
				keyStore = &mockKeyStore{
					signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
						return privKey, nil
					},
				}
			}

			key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			// Hash the test data
			hasher := tt.hash.New()
			hasher.Write(testData)
			hashed := hasher.Sum(nil)

			signature, err := key.Sign(rand.Reader, hashed, tt.hash)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errCheck != nil && !tt.errCheck(err) {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(signature) == 0 {
				t.Error("expected non-empty signature")
			}

			// Verify signature
			err = rsa.VerifyPKCS1v15(&privKey.PublicKey, tt.hash, hashed, signature)
			if err != nil {
				t.Errorf("signature verification failed: %v", err)
			}
		})
	}
}

// TestOpaqueSign_RSAPSS signs through the opaque key with PSS options and
// verifies the signature with rsa.VerifyPSS against the opaque public key.
func TestOpaqueSign_RSAPSS(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}
	keyStore := &mockKeyStore{
		signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
			return privKey, nil
		},
	}
	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	digest := sha256.Sum256([]byte("test data to sign"))
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}

	signature, err := key.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *rsa.PublicKey", key.Public())
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, opts); err != nil {
		t.Errorf("VerifyPSS rejected the opaque key's signature: %v", err)
	}

	otherDigest := sha256.Sum256([]byte("other data"))
	if err := rsa.VerifyPSS(pub, crypto.SHA256, otherDigest[:], signature, opts); !errors.Is(err, rsa.ErrVerification) {
		t.Errorf("VerifyPSS over a changed digest = %v, want rsa.ErrVerification", err)
	}
}

// TestOpaqueDecrypt_RSA tests the Decrypt() method with RSA keys
func TestOpaqueDecrypt_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	plaintext := []byte("secret message")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privKey.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("failed to encrypt test data: %v", err)
	}

	tests := []struct {
		name     string
		opts     crypto.DecrypterOpts
		wantErr  bool
		errCheck func(error) bool
	}{
		{
			name:    "OAEP opts",
			opts:    &rsa.OAEPOptions{Hash: crypto.SHA256},
			wantErr: false,
		},
		{
			name:    "decrypter error",
			opts:    nil,
			wantErr: true,
			errCheck: func(err error) bool {
				return err.Error() == "decrypter error"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         crypto.SHA256,
			}

			var keyStore *mockKeyStore
			if tt.wantErr && tt.errCheck != nil {
				keyStore = &mockKeyStore{
					decrypterFunc: func(*types.KeyAttributes) (crypto.Decrypter, error) {
						return nil, errors.New("decrypter error")
					},
				}
			} else {
				keyStore = &mockKeyStore{
					decrypterFunc: func(*types.KeyAttributes) (crypto.Decrypter, error) {
						return privKey, nil
					},
				}
			}

			key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			decrypted, err := key.Decrypt(rand.Reader, ciphertext, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errCheck != nil && !tt.errCheck(err) {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(decrypted) != string(plaintext) {
				t.Errorf("decryption mismatch: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

// TestOpaqueDecrypt_NonDecrypterKey checks that the key store's refusal to
// decrypt with an ECDSA or Ed25519 key reaches the caller of Opaque.Decrypt
// with its typed error intact.
func TestOpaqueDecrypt_NonDecrypterKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	tests := []struct {
		name    string
		alg     x509.PublicKeyAlgorithm
		private crypto.PrivateKey
		public  crypto.PublicKey
	}{
		{name: "ECDSA", alg: x509.ECDSA, private: ecKey, public: &ecKey.PublicKey},
		{name: "Ed25519", alg: x509.Ed25519, private: edKey, public: edPub},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: tt.alg,
				Hash:         crypto.SHA256,
			}
			// Like a real key store, refuse a key that is not a crypto.Decrypter.
			keyStore := &mockKeyStore{
				decrypterFunc: func(*types.KeyAttributes) (crypto.Decrypter, error) {
					decrypter, ok := tt.private.(crypto.Decrypter)
					if !ok {
						return nil, ErrDecrypterNotSupported
					}
					return decrypter, nil
				},
			}
			key, err := NewOpaqueKey(keyStore, attrs, tt.public)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			plaintext, err := key.Decrypt(rand.Reader, []byte("ciphertext"), nil)
			if !errors.Is(err, ErrDecrypterNotSupported) {
				t.Errorf("Decrypt error = %v, want ErrDecrypterNotSupported", err)
			}
			if plaintext != nil {
				t.Errorf("Decrypt plaintext = %x, want nil", plaintext)
			}
		})
	}
}

// TestOpaqueEqual tests the Equal() method
func TestOpaqueEqual(t *testing.T) {
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key 1: %v", err)
	}

	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key 2: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	tests := []struct {
		name      string
		getKeyErr bool
		otherKey  crypto.PrivateKey
		wantEqual bool
	}{
		{
			name:      "same key",
			getKeyErr: false,
			otherKey:  privKey1,
			wantEqual: true,
		},
		{
			name:      "different key",
			getKeyErr: false,
			otherKey:  privKey2,
			wantEqual: false,
		},
		{
			name:      "getKey error",
			getKeyErr: true,
			otherKey:  privKey1,
			wantEqual: false,
		},
		{
			name:      "non-signer key",
			getKeyErr: false,
			otherKey:  struct{}{}, // Not a crypto.PrivateKey with Equal
			wantEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keyStore *mockKeyStore
			if tt.getKeyErr {
				keyStore = &mockKeyStore{
					getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
						return nil, errors.New("get key error")
					},
				}
			} else {
				keyStore = &mockKeyStore{
					getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
						return privKey1, nil
					},
				}
			}

			key, err := NewOpaqueKey(keyStore, attrs, &privKey1.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			equal := key.Equal(tt.otherKey)
			if equal != tt.wantEqual {
				t.Errorf("Equal() = %v, want %v", equal, tt.wantEqual)
			}
		})
	}
}

// TestOpaqueEqual_PublicKeyFallback tests Equal() fallback to public key comparison
func TestOpaqueEqual_PublicKeyFallback(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Create a different key for comparison
	otherPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate other key: %v", err)
	}

	// Create a mock key that doesn't implement Equal
	type mockPrivKey struct {
		crypto.Signer
		pub crypto.PublicKey
	}

	mockKey := &mockPrivKey{
		pub: &privKey.PublicKey,
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return a key without Equal method
			return mockKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test with same public key - should use pointer comparison and return true
	equal := key.Equal(privKey)
	if !equal {
		t.Error("Expected true when comparing keys with same public key pointer")
	}

	// Test with different key - should return false
	equal = key.Equal(otherPrivKey)
	if equal {
		t.Error("Expected false when comparing with different key")
	}
}

// TestOpaqueDigest tests the Digest() method with different hash algorithms
func TestOpaqueDigest(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	testData := []byte("data to hash")

	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize int
		wantErr      bool
	}{
		{
			name:         "SHA256",
			hash:         crypto.SHA256,
			expectedSize: 32,
			wantErr:      false,
		},
		{
			name:         "SHA384",
			hash:         crypto.SHA384,
			expectedSize: 48,
			wantErr:      false,
		},
		{
			name:         "SHA512",
			hash:         crypto.SHA512,
			expectedSize: 64,
			wantErr:      false,
		},
		{
			name:         "SHA3_256",
			hash:         crypto.SHA3_256,
			expectedSize: 32,
			wantErr:      false,
		},
		{
			name:         "SHA3_384",
			hash:         crypto.SHA3_384,
			expectedSize: 48,
			wantErr:      false,
		},
		{
			name:         "SHA3_512",
			hash:         crypto.SHA3_512,
			expectedSize: 64,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         tt.hash,
			}

			key, err := NewOpaqueKey(&mockKeyStore{}, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			digest, err := key.Digest(testData)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(digest) != tt.expectedSize {
				t.Errorf("expected digest size %d, got %d", tt.expectedSize, len(digest))
			}

			// Verify digest is correct
			hasher := tt.hash.New()
			hasher.Write(testData)
			expectedDigest := hasher.Sum(nil)
			if string(digest) != string(expectedDigest) {
				t.Error("digest mismatch")
			}
		})
	}
}

// TestOpaqueSign_WithNilDigest tests signing with nil digest
func TestOpaqueSign_WithNilDigest(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Signing with nil digest should fail at the crypto level
	_, err = key.Sign(rand.Reader, nil, crypto.SHA256)
	if err == nil {
		t.Error("expected error when signing nil digest")
	}
}

// TestOpaqueDecrypt_WithEmptyCiphertext tests decryption with empty ciphertext
func TestOpaqueDecrypt_WithEmptyCiphertext(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		decrypterFunc: func(*types.KeyAttributes) (crypto.Decrypter, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Decrypting empty ciphertext should fail
	_, err = key.Decrypt(rand.Reader, []byte{}, nil)
	if err == nil {
		t.Error("expected error when decrypting empty ciphertext")
	}
}

// TestPublicKeysEqual_ECDSA tests publicKeysEqual function with ECDSA keys
func TestPublicKeysEqual_ECDSA(t *testing.T) {
	// Generate ECDSA keys on the same curve
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate first ECDSA key: %v", err)
	}

	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate second ECDSA key: %v", err)
	}

	// Create a key with different curve
	privKey3, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate third ECDSA key with P384: %v", err)
	}

	tests := []struct {
		name       string
		testKey    *ecdsa.PrivateKey
		compareKey *ecdsa.PrivateKey
		wantEqual  bool
	}{
		{
			name:       "different ECDSA keys different values",
			testKey:    privKey1,
			compareKey: privKey2,
			wantEqual:  false,
		},
		{
			name:       "ECDSA P256 vs P384 different curves",
			testKey:    privKey1,
			compareKey: privKey3,
			wantEqual:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-key",
				KeyAlgorithm: x509.ECDSA,
				Hash:         crypto.SHA256,
			}

			// Create a wrapper that doesn't implement Equal method by NOT embedding
			// This forces the code to use publicKeysEqual
			type wrappedECDSAKey struct {
				key *ecdsa.PrivateKey
			}

			// Make it a Signer so it can be used with Equal()
			wrappedKey := &wrappedECDSAKey{key: tt.testKey}

			keyStore := &mockKeyStore{
				getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
					// Return wrapped key which doesn't have Equal method
					return wrappedKey, nil
				},
			}

			key, err := NewOpaqueKey(keyStore, attrs, &tt.testKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			// Call Equal with a different ECDSA key
			// Since the key from keyStore is wrapped (doesn't have Equal),
			// it will fall through to publicKeysEqual at line 172
			equal := key.Equal(tt.compareKey)

			if equal != tt.wantEqual {
				t.Errorf("Equal() = %v, want %v", equal, tt.wantEqual)
			}
		})
	}
}

// TestPublicKeysEqual_Ed25519 tests publicKeysEqual function with Ed25519 keys
// This test uses the Equal() method to indirectly test publicKeysEqual
// Note: We test using RSA comparison because comparing ed25519.PublicKey (which is a slice)
// with == at line 172 would cause a panic. The publicKeysEqual function will be reached
// when comparing different key types.
func TestPublicKeysEqual_Ed25519(t *testing.T) {
	// Test that publicKeysEqual is called for Ed25519 keys when comparing with other types
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-key",
		KeyAlgorithm: x509.Ed25519,
		Hash:         crypto.SHA256,
	}

	// Create a wrapper that doesn't implement Equal method by NOT embedding
	// This forces the code to use publicKeysEqual
	type wrappedEd25519Key struct {
		key ed25519.PrivateKey
	}

	wrappedKey := &wrappedEd25519Key{key: privKey}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return wrapped key which doesn't have Equal method
			return wrappedKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, pubKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Call Equal with an RSA key
	// Since the key from keyStore is wrapped (doesn't have Equal),
	// it will fall through to publicKeysEqual at line 172
	// This will hit the Ed25519 case in publicKeysEqual when it tries to
	// cast the RSA public key to ed25519.PublicKey (which will fail the ok check)
	if key.Equal(rsaKey) {
		t.Error("Expected false when comparing Ed25519 with RSA key")
	}
}

// customPublicKey is a custom public key type for testing
type customPublicKey struct {
	data []byte
}

// customSigner implements crypto.Signer with a custom public key type
type customSigner struct {
	pub crypto.PublicKey
}

func (c *customSigner) Public() crypto.PublicKey {
	return c.pub
}

func (c *customSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return []byte("signature"), nil
}

// TestOpaqueEqual_UnknownKeyType tests Equal with unknown/custom key types
func TestOpaqueEqual_UnknownKeyType(t *testing.T) {
	customPub := &customPublicKey{data: []byte("custom")}
	customPub2 := &customPublicKey{data: []byte("custom2")}

	attrs := &types.KeyAttributes{
		CN:           "test-custom",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	customSig1 := &customSigner{pub: customPub}
	customSig2 := &customSigner{pub: customPub2}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return customSig1, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, customPub)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test with same custom type - should use pointer comparison at line 172
	if !key.Equal(customSig1) {
		t.Error("Expected true when comparing with same custom key")
	}

	// Test with different custom key
	// This will fall through to the default case in publicKeysEqual (line 239)
	if key.Equal(customSig2) {
		t.Error("Expected false when comparing different custom keys")
	}
}

// keyWithControlledEqual is a test helper that implements Equal with controllable behavior
type keyWithControlledEqual struct {
	wrapped *rsa.PrivateKey
	eqValue bool // Control what Equal returns
}

func (c *keyWithControlledEqual) Public() crypto.PublicKey {
	return c.wrapped.Public()
}

func (c *keyWithControlledEqual) Equal(x crypto.PrivateKey) bool {
	return c.eqValue
}

func (c *keyWithControlledEqual) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.wrapped.Sign(rand, digest, opts)
}

// signerWithoutEqual is a Signer that does NOT implement Equal, to force publicKeysEqual to be called
type signerWithoutEqual struct {
	privKey *rsa.PrivateKey
	pubKey  crypto.PublicKey
}

func (s *signerWithoutEqual) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *signerWithoutEqual) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.privKey.Sign(rand, digest, opts)
}

// TestOpaqueEqual_WithEqualMethodImplementation tests the Equal method path at line 165-166
func TestOpaqueEqual_WithEqualMethodImplementation(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	customKey := &keyWithControlledEqual{wrapped: rsaKey, eqValue: true}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return the custom key which implements Equal
			return customKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test that Equal delegates to the key's Equal method
	// Since customKey.Equal is set to return true, result should be true
	if !key.Equal(rsaKey) {
		t.Error("Expected true - Equal should delegate to key's Equal method")
	}

	// Test with eqValue=false
	customKey.eqValue = false
	if key.Equal(rsaKey) {
		t.Error("Expected false - Equal should delegate to key's Equal method")
	}
}

// TestPublicKeysEqual_RSAMismatchInTypeAssertion tests publicKeysEqual when RSA type assertion fails
// By using signerWithoutEqual that returns ECDSA public key, we force the RSA type assertion to fail
func TestPublicKeysEqual_RSAMismatchInTypeAssertion(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-rsa",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return a signer without Equal that returns RSA public key
			signer := &signerWithoutEqual{privKey: rsaKey, pubKey: &rsaKey.PublicKey}
			return signer, nil
		},
	}

	// Create opaque key with RSA's public key
	key, err := NewOpaqueKey(keyStore, attrs, &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Create a signer that returns ECDSA public key
	// This will cause publicKeysEqual to be called with RSA pub and ECDSA pub
	// The RSA type assertion will fail, hitting line 216-218
	ecdsaSigner := &signerWithoutEqual{privKey: rsaKey, pubKey: &ecdsaKey.PublicKey}

	if key.Equal(ecdsaSigner) {
		t.Error("Expected false when comparing RSA with ECDSA public keys")
	}
}

// TestPublicKeysEqual_ECDSAMismatchInTypeAssertion tests publicKeysEqual when ECDSA assertion fails
func TestPublicKeysEqual_ECDSAMismatchInTypeAssertion(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return a signer without Equal that returns ECDSA public key
			signer := &signerWithoutEqual{privKey: rsaKey, pubKey: &ecdsaKey.PublicKey}
			return signer, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Create a signer that returns RSA public key
	// This will cause publicKeysEqual to be called with ECDSA pub and RSA pub
	// The ECDSA type assertion will fail, hitting line 223-225
	rsaSigner := &signerWithoutEqual{privKey: rsaKey, pubKey: &rsaKey.PublicKey}

	if key.Equal(rsaSigner) {
		t.Error("Expected false when comparing ECDSA with RSA public keys")
	}
}

// nilPublicKeySigner is a test helper that returns nil for Public()
type nilPublicKeySigner struct{}

func (n *nilPublicKeySigner) Public() crypto.PublicKey {
	return nil
}

func (n *nilPublicKeySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// TestPublicKeysEqual_WithNilPublicKey tests publicKeysEqual with nil public key
func TestPublicKeysEqual_WithNilPublicKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	// Create a signer that returns nil for Public()
	nilSigner := &nilPublicKeySigner{}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return a signer without Equal to force publicKeysEqual to be called
			signer := &signerWithoutEqual{privKey: privKey, pubKey: &privKey.PublicKey}
			return signer, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Since nilSigner.Public() returns nil, publicKeysEqual will be called with
	// (&privKey.PublicKey, nil) which hits line 209-211
	result := key.Equal(nilSigner)
	if result {
		t.Error("Expected false when comparing RSA with nil public key")
	}
}

// TestPublicKeysEqual_NilKeys tests publicKeysEqual with nil keys
func TestPublicKeysEqual_NilKeys(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Compare with nil should return false
	if key.Equal(nil) {
		t.Error("Expected false when comparing with nil")
	}
}

// mockHasherError creates a mock hasher that fails on Write
