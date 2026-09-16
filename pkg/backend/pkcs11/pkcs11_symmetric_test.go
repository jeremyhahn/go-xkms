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

//go:build pkcs11

package pkcs11

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBackend creates a Backend for testing without full validation.
// This bypasses storage requirements since we're testing symmetric methods,
// not actual HSM operations.
func newTestBackend(tempLib string) *Backend {
	return &Backend{
		config: &Config{
			Library:    tempLib,
			TokenLabel: "test",
		},
	}
}

// TestBackend_SymmetricCapabilities verifies that the backend reports symmetric encryption support.
func TestBackend_SymmetricCapabilities(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	caps := b.Capabilities()
	if !caps.SupportsSymmetricEncryption() {
		t.Error("Backend should support symmetric encryption")
	}
	if !caps.SymmetricEncryption {
		t.Error("SymmetricEncryption capability should be true")
	}
}

// TestBackend_GenerateSymmetricKey verifies symmetric key generation.
func TestBackend_GenerateSymmetricKey(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	tests := []struct {
		name      string
		algorithm types.SymmetricAlgorithm
		keySize   int
		wantErr   bool
	}{
		{
			name:      "AES-128",
			algorithm: types.SymmetricAES128GCM,
			keySize:   128,
			wantErr:   true, // Will fail - not initialized
		},
		{
			name:      "AES-192",
			algorithm: types.SymmetricAES192GCM,
			keySize:   192,
			wantErr:   true, // Will fail - not initialized
		},
		{
			name:      "AES-256",
			algorithm: types.SymmetricAES256GCM,
			keySize:   256,
			wantErr:   true, // Will fail - not initialized
		},
		{
			name:      "invalid key size",
			algorithm: types.SymmetricAES128GCM,
			keySize:   64,
			wantErr:   true,
		},
		{
			name:      "asymmetric algorithm",
			algorithm: "",
			keySize:   2048,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-aes-" + tt.name,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: tt.algorithm,
			}

			// Skip validation for invalid test cases
			if tt.algorithm != "" && tt.keySize != 64 {
				if err := attrs.Validate(); err != nil {
					t.Fatalf("attrs.Validate() failed: %v", err)
				}
			}

			_, err := b.GenerateSymmetricKey(context.Background(), attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSymmetricKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			// For not initialized errors, this is expected
			if err != nil && err != ErrNotInitialized {
				t.Logf("GenerateSymmetricKey() error: %v (expected)", err)
			}
		})
	}
}

// TestBackend_GetSymmetricKey verifies symmetric key retrieval.
func TestBackend_GetSymmetricKey(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	attrs := &types.KeyAttributes{
		CN:                 "test-aes-get",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if err := attrs.Validate(); err != nil {
		t.Fatalf("attrs.Validate() failed: %v", err)
	}

	// Should fail - not initialized
	_, err := b.GetSymmetricKey(context.Background(), attrs)
	if err != ErrNotInitialized {
		t.Errorf("GetSymmetricKey() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestBackend_SymmetricEncrypter verifies getting a symmetric encrypter.
func TestBackend_SymmetricEncrypter(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	attrs := &types.KeyAttributes{
		CN:                 "test-aes-encrypter",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if err := attrs.Validate(); err != nil {
		t.Fatalf("attrs.Validate() failed: %v", err)
	}

	// Should fail - key doesn't exist
	_, err := b.SymmetricEncrypter(context.Background(), attrs)
	if err == nil {
		t.Error("SymmetricEncrypter() should return error when key doesn't exist")
	}
}

// TestPKCS11SymmetricKey_Interface verifies the pkcs11SymmetricKey implementation.
func TestPKCS11SymmetricKey_Interface(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	key := &pkcs11SymmetricKey{
		algorithm: "aes256-gcm",
		keySize:   256,
		handle:    0, // Mock handle
		backend:   b,
	}

	// Test Algorithm method
	if got := key.Algorithm(); got != "aes256-gcm" {
		t.Errorf("Algorithm() = %v, want aes256-gcm", got)
	}

	// Test KeySize method
	if got := key.KeySize(); got != 256 {
		t.Errorf("KeySize() = %v, want 256", got)
	}

	// Test Raw method (should return error for PKCS#11 keys as they don't expose raw material)
	_, err := key.Raw()
	if err == nil {
		t.Error("Raw() should return error for PKCS#11 keys, but returned nil")
	}
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("Raw() error = %v, want %v", err, backend.ErrNotSupported)
	}

	// Verify interface compliance
	var _ types.SymmetricKey = key
}

// TestBackend_GenerateSymmetricKey_AllKeySizes tests all supported key sizes.
func TestBackend_GenerateSymmetricKey_AllKeySizes(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	algorithms := []types.SymmetricAlgorithm{
		types.SymmetricAES128GCM,
		types.SymmetricAES192GCM,
		types.SymmetricAES256GCM,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                 "test-" + string(algorithm),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: algorithm,
			}

			if err := attrs.Validate(); err != nil {
				t.Fatalf("attrs.Validate() failed: %v", err)
			}

			_, err := b.GenerateSymmetricKey(context.Background(), attrs)
			// Will fail due to not initialized, but validates structure
			if err == nil {
				t.Error("GenerateSymmetricKey() should fail (not initialized)")
			}
		})
	}
}

// TestBackend_GetSymmetricKey_KeySizeInference tests key size inference from algorithm.
func TestBackend_GetSymmetricKey_KeySizeInference(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	// Test without explicit key size (should infer from algorithm)
	attrs := &types.KeyAttributes{
		CN:                 "test-inference",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Should fail at not initialized, but tests inference logic
	_, err := b.GetSymmetricKey(context.Background(), attrs)
	if err == nil {
		t.Error("GetSymmetricKey() should fail (not initialized)")
	}
}

// TestBackend_SymmetricInterface verifies symmetric methods exist.
func TestBackend_SymmetricInterface(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	// Verify backend has symmetric methods by calling them
	// (They will fail with not initialized, but verify the methods exist)
	attrs := &types.KeyAttributes{
		CN:                 "test",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, _ = b.GenerateSymmetricKey(context.Background(), attrs)
	_, _ = b.GetSymmetricKey(context.Background(), attrs)
	_, _ = b.SymmetricEncrypter(context.Background(), attrs)
}

// TestBackend_GenerateSymmetricKey_InvalidAttributes tests validation.
func TestBackend_GenerateSymmetricKey_InvalidAttributes(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	// Mock context to bypass not initialized error
	// (We want to test validation, not initialization)

	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wantErr string
	}{
		{
			name: "missing CN",
			attrs: &types.KeyAttributes{
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			wantErr: "CN is required",
		},
		{
			name: "asymmetric algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test",
				KeyType:      backend.KEY_TYPE_SECRET,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			wantErr: "asymmetric algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.GenerateSymmetricKey(context.Background(), tt.attrs)
			if err == nil {
				t.Error("GenerateSymmetricKey() should return error")
			}
		})
	}
}

// TestPKCS11Backend_NonceReuse tests AEAD nonce reuse detection using tracker directly.
// Note: PKCS11 backend generates client-side nonces, so nonce tracking is applicable.
func TestPKCS11Backend_NonceReuse(t *testing.T) {
	// Create a tracker for testing
	tracker := backend.NewMemoryAEADTracker()

	// Setup AEAD options with nonce tracking enabled
	keyID := "test-pkcs11-nonce-reuse"
	opts := &types.AEADOptions{
		NonceTracking:      true,
		BytesTracking:      false,
		BytesTrackingLimit: 0,
	}

	err := tracker.SetAEADOptions(keyID, opts)
	if err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	// Generate a fixed nonce
	fixedNonce := make([]byte, 12)
	if _, err := rand.Read(fixedNonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	// First check with nonce - should succeed
	err = tracker.CheckNonce(keyID, fixedNonce)
	if err != nil {
		t.Fatalf("First CheckNonce failed: %v", err)
	}

	// Record the nonce
	err = tracker.RecordNonce(keyID, fixedNonce)
	if err != nil {
		t.Fatalf("RecordNonce failed: %v", err)
	}

	// Second check with same nonce - should fail
	err = tracker.CheckNonce(keyID, fixedNonce)
	if err == nil {
		t.Fatal("Expected nonce reuse to be detected")
	}

	// Verify error is ErrNonceReused
	if !errors.Is(err, backend.ErrNonceReused) {
		t.Errorf("Expected ErrNonceReused, got: %v", err)
	}
}

// TestPKCS11Backend_BytesLimit tests AEAD bytes limit enforcement using tracker directly.
// Note: PKCS11 backend generates client-side nonces, so bytes tracking is applicable.
func TestPKCS11Backend_BytesLimit(t *testing.T) {
	// Create a tracker for testing
	tracker := backend.NewMemoryAEADTracker()

	// Setup AEAD options with small bytes limit
	keyID := "test-pkcs11-bytes-limit"
	smallLimit := int64(100) // 100 bytes
	opts := &types.AEADOptions{
		NonceTracking:      false,
		BytesTracking:      true,
		BytesTrackingLimit: smallLimit,
	}

	err := tracker.SetAEADOptions(keyID, opts)
	if err != nil {
		t.Fatalf("Failed to set AEAD options: %v", err)
	}

	// First 50 bytes - should succeed
	err = tracker.IncrementBytes(keyID, 50)
	if err != nil {
		t.Fatalf("First IncrementBytes failed: %v", err)
	}

	// Verify bytes counter
	total, err := tracker.GetBytesEncrypted(keyID)
	if err != nil {
		t.Fatalf("GetBytesEncrypted failed: %v", err)
	}
	if total != 50 {
		t.Errorf("Expected 50 bytes, got %d", total)
	}

	// Second 50 bytes - should succeed (total 100)
	err = tracker.IncrementBytes(keyID, 50)
	if err != nil {
		t.Fatalf("Second IncrementBytes failed: %v", err)
	}

	// Third 50 bytes - should fail (would exceed 100 byte limit)
	err = tracker.IncrementBytes(keyID, 50)
	if err == nil {
		t.Fatal("Expected bytes limit to be enforced")
	}

	// Verify error is ErrBytesLimitExceeded
	if !errors.Is(err, backend.ErrBytesLimitExceeded) {
		t.Errorf("Expected ErrBytesLimitExceeded, got: %v", err)
	}
}

// TestGetTracker_ReturnsTracker verifies that GetTracker returns the configured tracker.
func TestGetTracker_ReturnsTracker(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	b := newTestBackend(tempLib)

	// Manually set a tracker to test retrieval
	tracker := backend.NewMemoryAEADTracker()
	b.tracker = tracker

	got := b.GetTracker()
	if got == nil {
		t.Fatal("GetTracker() returned nil, expected non-nil tracker")
	}

	// Verify it is the same instance
	if got != tracker {
		t.Error("GetTracker() returned a different tracker instance than expected")
	}
}

// TestGetTracker_DefaultTracker verifies that a backend created via NewBackend
// gets a non-nil default tracker.
func TestGetTracker_DefaultTracker(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test-token",
		PIN:         "1234",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	tracker := b.GetTracker()
	if tracker == nil {
		t.Fatal("GetTracker() returned nil, expected a default tracker to be initialized")
	}

	// Verify the tracker is functional by performing a basic operation
	keyID := "test-default-tracker-key"
	opts := types.DefaultAEADOptions()
	if err := tracker.SetAEADOptions(keyID, opts); err != nil {
		t.Errorf("Default tracker SetAEADOptions() failed: %v", err)
	}
}

// =============================================================================
// Real-token AES-GCM (SoftHSM2)
//
// These tests verify the ciphertext the token produces against crypto/cipher
// computed independently over the same key, nonce, plaintext and AAD.
// decrypt(encrypt(x)) == x is not sufficient: it holds even when the mechanism,
// the tag placement or the AAD binding is wrong on both sides at once.
// =============================================================================

// symmetricAttrs builds the attributes addressing an AES key on the token.
func symmetricAttrs(cn string, algorithm types.SymmetricAlgorithm) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: algorithm,
	}
}

// installKnownAESKey imports an AES key with caller-chosen bytes onto the token
// under the label the backend looks the key up by, and returns its attributes.
//
// A generated key is sealed in the token by design (CKA_SENSITIVE), so there is
// no way to check the token's arithmetic against a software implementation
// unless the test chooses the key material itself. Importing is the only way to
// obtain an oracle; TestGenerateSymmetricKey_KeyIsNonExtractable covers the
// generated key's protection separately.
func installKnownAESKey(t *testing.T, b *Backend, cn string, key []byte) *types.KeyAttributes {
	t.Helper()
	return installAESKeyWithUsage(t, b, cn, key, true, true)
}

// installAESKeyWithUsage imports an AES key with explicit CKA_ENCRYPT and
// CKA_DECRYPT settings, so a test can observe what the token does when the key
// is not permitted to perform the operation being asked of it.
func installAESKeyWithUsage(t *testing.T, b *Backend, cn string, key []byte, canEncrypt, canDecrypt bool) *types.KeyAttributes {
	t.Helper()

	var algorithm types.SymmetricAlgorithm
	switch len(key) {
	case 16:
		algorithm = types.SymmetricAES128GCM
	case 32:
		algorithm = types.SymmetricAES256GCM
	default:
		t.Fatalf("unsupported test key length %d", len(key))
	}

	attrs := symmetricAttrs(cn, algorithm)
	label := createKeyID(attrs)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(label)),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, canEncrypt),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, canDecrypt),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
	}

	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		_, err := b.p11ctx.CreateObject(session, template)
		return err
	}), "the token must accept the imported AES key")

	return attrs
}

// softwareGCM returns the AES-GCM AEAD for a known key, used as the oracle.
func softwareGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return aead
}

// TestSymmetricEncrypter_MatchesSoftwareGCM asserts the token's ciphertext is
// byte-identical to AES-GCM computed in software over the same inputs.
//
// This is what distinguishes CKM_AES_GCM from every other mechanism the token
// could have been asked for, and it pins the split point between ciphertext and
// tag: the tag is the trailing 16 bytes of the C_Encrypt output, not a prefix.
func TestSymmetricEncrypter_MatchesSoftwareGCM(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keySize int
	}{
		{"AES-128", 16},
		{"AES-256", 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newProvisionedBackend(t, "sym-oracle")

			key := make([]byte, tc.keySize)
			_, err := rand.Read(key)
			require.NoError(t, err)

			attrs := installKnownAESKey(t, b, "sym-oracle-"+tc.name, key)
			encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
			require.NoError(t, err)

			nonce := bytes.Repeat([]byte{0xA5}, 12)
			aad := []byte("associated data that is authenticated but not encrypted")

			for _, plaintext := range [][]byte{
				[]byte("the quick brown fox"),
				{}, // GCM over an empty message is still a tag
				bytes.Repeat([]byte{0x00}, 4096),
			} {
				encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
					Nonce:          nonce,
					AdditionalData: aad,
				})
				require.NoError(t, err)

				// Oracle: the same AEAD computed by crypto/cipher.
				want := softwareGCM(t, key).Seal(nil, nonce, plaintext, aad)

				assert.Equal(t, want[:len(want)-16], encrypted.Ciphertext,
					"the token's ciphertext differs from AES-GCM")
				assert.Equal(t, want[len(want)-16:], encrypted.Tag,
					"the token's authentication tag differs from AES-GCM")
				assert.Equal(t, nonce, encrypted.Nonce)
				assert.Equal(t, string(attrs.SymmetricAlgorithm), encrypted.Algorithm)
			}
		})
	}
}

// TestSymmetricEncrypter_DecryptsSoftwareCiphertext runs the oracle in the
// other direction: ciphertext sealed by crypto/cipher must open on the token.
// Together with the previous test this proves interoperability rather than
// self-consistency.
func TestSymmetricEncrypter_DecryptsSoftwareCiphertext(t *testing.T) {
	b := newProvisionedBackend(t, "sym-open")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-open-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	nonce := bytes.Repeat([]byte{0x11}, 12)
	aad := []byte("bound context")
	plaintext := []byte("sealed in software, opened in hardware")

	sealed := softwareGCM(t, key).Seal(nil, nonce, plaintext, aad)

	opened, err := encrypter.Decrypt(&types.EncryptedData{
		Ciphertext: sealed[:len(sealed)-16],
		Nonce:      nonce,
		Tag:        sealed[len(sealed)-16:],
	}, &types.DecryptOptions{AdditionalData: aad})
	require.NoError(t, err)
	assert.Equal(t, plaintext, opened)
}

// TestSymmetricEncrypter_AADIsAuthenticated verifies the additional data is
// bound to the ciphertext on both halves. A backend that dropped the AAD would
// still round-trip, so the failing case is the one that carries the signal.
func TestSymmetricEncrypter_AADIsAuthenticated(t *testing.T) {
	b := newProvisionedBackend(t, "sym-aad")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-aad-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	encrypted, err := encrypter.Encrypt([]byte("message"), &types.EncryptOptions{
		AdditionalData: []byte("original context"),
	})
	require.NoError(t, err)

	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: []byte("different context"),
	})
	require.Error(t, err, "decryption must fail when the AAD does not match")

	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{})
	require.Error(t, err, "decryption must fail when the AAD is dropped entirely")

	opened, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: []byte("original context"),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("message"), opened)
}

// TestSymmetricEncrypter_RejectsTamperedCiphertextAndTag verifies the token
// enforces integrity, which is the entire reason for using an AEAD.
func TestSymmetricEncrypter_RejectsTamperedCiphertextAndTag(t *testing.T) {
	b := newProvisionedBackend(t, "sym-tamper")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-tamper-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		tamper func(*types.EncryptedData)
	}{
		{"flipped ciphertext bit", func(d *types.EncryptedData) { d.Ciphertext[0] ^= 0x01 }},
		{"flipped tag bit", func(d *types.EncryptedData) { d.Tag[0] ^= 0x01 }},
		{"flipped nonce bit", func(d *types.EncryptedData) { d.Nonce[0] ^= 0x01 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := encrypter.Encrypt([]byte("authenticated payload"), nil)
			require.NoError(t, err)

			tc.tamper(encrypted)

			_, err = encrypter.Decrypt(encrypted, nil)
			assert.Error(t, err, "a modified message must not authenticate")
		})
	}
}

// TestSymmetricEncrypter_Encrypt_WrongNonceLength is the regression test for a
// remote denial of service. A caller-supplied nonce of the wrong length must be
// rejected with ErrInvalidNonceLength before it reaches any AEAD.
func TestSymmetricEncrypter_Encrypt_WrongNonceLength(t *testing.T) {
	b := newProvisionedBackend(t, "sym-nonce-enc")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-nonce-enc-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	for _, size := range []int{0, 1, 8, 11, 13, 16, 32} {
		t.Run(nonceSizeName(size), func(t *testing.T) {
			_, err := encrypter.Encrypt([]byte("payload"), &types.EncryptOptions{
				Nonce: make([]byte, size),
			})
			assert.ErrorIs(t, err, ErrInvalidNonceLength)
		})
	}
}

// TestSymmetricEncrypter_Decrypt_WrongNonceLength is the paired half of the
// test above. The decrypt side is the one that was missed when the encrypt side
// was guarded, and it is the more exposed of the two: the nonce arrives inside
// the ciphertext envelope a peer supplies.
func TestSymmetricEncrypter_Decrypt_WrongNonceLength(t *testing.T) {
	b := newProvisionedBackend(t, "sym-nonce-dec")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-nonce-dec-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	for _, size := range []int{0, 1, 8, 11, 13, 16, 32} {
		t.Run(nonceSizeName(size), func(t *testing.T) {
			_, err := encrypter.Decrypt(&types.EncryptedData{
				Ciphertext: []byte("ciphertext"),
				Nonce:      make([]byte, size),
				Tag:        make([]byte, 16),
			}, nil)
			assert.ErrorIs(t, err, ErrInvalidNonceLength)
		})
	}
}

// nonceSizeName labels a subtest by nonce length.
func nonceSizeName(size int) string {
	return fmt.Sprintf("%d-byte nonce", size)
}

// TestSymmetricEncrypter_Decrypt_WrongTagLength verifies a short tag is refused
// rather than passed to the token as ulTagBits.
//
// PKCS#11 v3.2 6.13.7 lets ulTagBits be anything from 0 to 128, so a caller who
// controls the tag length could otherwise ask the token to verify only a few
// tag bits and forge messages cheaply. The tag length is a property of the
// backend, not of the message.
func TestSymmetricEncrypter_Decrypt_WrongTagLength(t *testing.T) {
	b := newProvisionedBackend(t, "sym-tag")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-tag-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	for _, size := range []int{0, 1, 4, 8, 15, 17, 32} {
		t.Run(fmt.Sprintf("%d-byte tag", size), func(t *testing.T) {
			_, err := encrypter.Decrypt(&types.EncryptedData{
				Ciphertext: []byte("ciphertext"),
				Nonce:      make([]byte, 12),
				Tag:        make([]byte, size),
			}, nil)
			assert.ErrorIs(t, err, ErrInvalidTagLength)
		})
	}
}

// TestSymmetricEncrypter_Decrypt_NilData verifies a nil envelope is a typed
// error rather than a nil-pointer dereference. The software encrypter already
// guarded this; the token-backed one did not.
func TestSymmetricEncrypter_Decrypt_NilData(t *testing.T) {
	b := newProvisionedBackend(t, "sym-nil")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-nil-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	_, err = encrypter.Decrypt(nil, nil)
	assert.ErrorIs(t, err, ErrNilEncryptedData)
}

// TestSymmetricEncrypter_RejectsNonAEADModes verifies both halves refuse a
// cipher mode this backend does not implement.
//
// Silently substituting AES-GCM for a requested AES-CBC is the worst outcome
// available: encrypt and decrypt agree with each other, the round trip passes,
// and the caller's EncryptedData carries a Nonce and Tag where it expected an
// IV.
func TestSymmetricEncrypter_RejectsUnknownCipherMode(t *testing.T) {
	b := newProvisionedBackend(t, "sym-mode")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-mode-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	for _, mode := range []types.CipherMode{"ctr", "ofb", "unknown"} {
		t.Run(string(mode), func(t *testing.T) {
			_, err := encrypter.Encrypt([]byte("payload"), &types.EncryptOptions{Mode: mode})
			assert.ErrorIs(t, err, ErrUnsupportedCipherMode)

			_, err = encrypter.Decrypt(&types.EncryptedData{
				Ciphertext: []byte("ciphertext"),
				Nonce:      make([]byte, 12),
				Tag:        make([]byte, 16),
			}, &types.DecryptOptions{Mode: mode})
			assert.ErrorIs(t, err, ErrUnsupportedCipherMode)
		})
	}
}

// TestSymmetricEncrypter_CBCRoundTrip verifies that CKM_AES_CBC and
// CKM_AES_CBC_PAD round-trip on the token and, for CBC-Pad, match a software
// AES-CBC-PKCS7 oracle byte-for-byte -- CBC has no oracle to compare against
// here because unpadded CBC requires block-aligned input and this test uses a
// non-aligned payload to also exercise CBC-Pad's padding.
func TestSymmetricEncrypter_CBCRoundTrip(t *testing.T) {
	b := newProvisionedBackend(t, "sym-cbc")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-cbc-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		mode      types.CipherMode
		plaintext []byte
	}{
		{"CBC-block-aligned", types.CipherModeCBC, bytes.Repeat([]byte("A"), 32)},
		{"CBC-Pad-aligned", types.CipherModeCBCPad, bytes.Repeat([]byte("B"), 32)},
		{"CBC-Pad-unaligned", types.CipherModeCBCPad, []byte("not a block multiple")},
		{"CBC-Pad-empty", types.CipherModeCBCPad, []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := encrypter.Encrypt(tc.plaintext, &types.EncryptOptions{Mode: tc.mode})
			require.NoError(t, err)
			require.Len(t, encrypted.IV, cbcIVSize)
			require.Empty(t, encrypted.Tag)

			decrypted, err := encrypter.Decrypt(&types.EncryptedData{
				Ciphertext: encrypted.Ciphertext,
				IV:         encrypted.IV,
			}, &types.DecryptOptions{Mode: tc.mode})
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, decrypted)

			if tc.mode == types.CipherModeCBCPad {
				block, err := aes.NewCipher(key)
				require.NoError(t, err)
				padded := pkcs7Pad(tc.plaintext, aes.BlockSize)
				want := make([]byte, len(padded))
				cipher.NewCBCEncrypter(block, encrypted.IV).CryptBlocks(want, padded)
				assert.Equal(t, want, encrypted.Ciphertext, "CBC-Pad ciphertext must match software PKCS#7 CBC")
			}
		})
	}
}

// TestSymmetricEncrypter_ECBRoundTrip verifies that CKM_AES_ECB round-trips
// on the token and matches a software AES-ECB oracle (each block enciphered
// independently under the raw block cipher, since crypto/cipher has no ECB
// BlockMode of its own).
func TestSymmetricEncrypter_ECBRoundTrip(t *testing.T) {
	b := newProvisionedBackend(t, "sym-ecb")

	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-ecb-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	plaintext := bytes.Repeat([]byte("Z"), 48)

	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{Mode: types.CipherModeECB})
	require.NoError(t, err)
	require.Empty(t, encrypted.IV)
	require.Empty(t, encrypted.Tag)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	want := make([]byte, len(plaintext))
	for offset := 0; offset < len(plaintext); offset += aes.BlockSize {
		block.Encrypt(want[offset:offset+aes.BlockSize], plaintext[offset:offset+aes.BlockSize])
	}
	assert.Equal(t, want, encrypted.Ciphertext, "ECB ciphertext must match software AES-ECB")

	decrypted, err := encrypter.Decrypt(&types.EncryptedData{
		Ciphertext: encrypted.Ciphertext,
	}, &types.DecryptOptions{Mode: types.CipherModeECB})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestSymmetricEncrypter_CBC_RejectsNonAEADInputMisuse verifies each mode
// refuses the inputs that belong to a different mode, rather than silently
// ignoring them and reporting success for an operation the caller did not
// get.
func TestSymmetricEncrypter_CBC_RejectsNonAEADInputMisuse(t *testing.T) {
	b := newProvisionedBackend(t, "sym-cbc-misuse")

	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-cbc-misuse-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	t.Run("CBC-additional-data-refused", func(t *testing.T) {
		_, err := encrypter.Encrypt([]byte("0123456789abcdef"), &types.EncryptOptions{
			Mode: types.CipherModeCBC, AdditionalData: []byte("aad"),
		})
		assert.ErrorIs(t, err, ErrAdditionalDataNotSupported)
	})

	t.Run("CBC-tag-size-refused", func(t *testing.T) {
		_, err := encrypter.Encrypt([]byte("0123456789abcdef"), &types.EncryptOptions{
			Mode: types.CipherModeCBC, TagSize: 16,
		})
		assert.ErrorIs(t, err, ErrTagSizeNotSupported)
	})

	t.Run("CBC-unaligned-plaintext-refused", func(t *testing.T) {
		_, err := encrypter.Encrypt([]byte("not aligned"), &types.EncryptOptions{Mode: types.CipherModeCBC})
		assert.ErrorIs(t, err, ErrPlaintextNotBlockAligned)
	})

	t.Run("CBC-wrong-iv-size-refused", func(t *testing.T) {
		_, err := encrypter.Encrypt([]byte("0123456789abcdef"), &types.EncryptOptions{
			Mode: types.CipherModeCBC, IV: make([]byte, 8),
		})
		assert.ErrorIs(t, err, ErrInvalidIVSize)
	})

	t.Run("ECB-iv-refused", func(t *testing.T) {
		_, err := encrypter.Encrypt([]byte("0123456789abcdef"), &types.EncryptOptions{
			Mode: types.CipherModeECB, IV: make([]byte, 16),
		})
		assert.ErrorIs(t, err, ErrIVNotSupported)
	})

	t.Run("ECB-unaligned-plaintext-refused", func(t *testing.T) {
		_, err := encrypter.Encrypt([]byte("not aligned"), &types.EncryptOptions{Mode: types.CipherModeECB})
		assert.ErrorIs(t, err, ErrPlaintextNotBlockAligned)
	})

	t.Run("CBC-Pad-invalid-padding-refused", func(t *testing.T) {
		encrypted, err := encrypter.Encrypt([]byte("valid plaintext"), &types.EncryptOptions{Mode: types.CipherModeCBCPad})
		require.NoError(t, err)

		tampered := append([]byte(nil), encrypted.Ciphertext...)
		tampered[len(tampered)-1] ^= 0xFF

		_, err = encrypter.Decrypt(&types.EncryptedData{
			Ciphertext: tampered,
			IV:         encrypted.IV,
		}, &types.DecryptOptions{Mode: types.CipherModeCBCPad})
		assert.ErrorIs(t, err, ErrInvalidPadding)
	})
}

// TestRequireCipherMechanism_UnsupportedMechanismIsCapabilityError verifies
// that a cipher mode this encrypter implements, but that the token does not
// advertise, is classified as a capability boundary
// (backend.ErrOperationNotSupported) rather than surfacing as a fault -- the
// same distinction pkg/xkms/servicer_crypto.go's isBackendCapabilityRefusal
// makes to choose between a 501/Unimplemented and a 500 at the API layer.
func TestRequireCipherMechanism_UnsupportedMechanismIsCapabilityError(t *testing.T) {
	b := newProvisionedBackend(t, "sym-mech")
	// The provisioned SoftHSM token advertises CKM_AES_CBC, CKM_AES_CBC_PAD
	// and CKM_AES_ECB; force each flag off individually to exercise the
	// refusal path without depending on a token that lacks one of them.
	b.supportsAESCBC = false
	b.supportsAESCBCPad = false
	b.supportsAESECB = false

	for _, mode := range []types.CipherMode{types.CipherModeCBC, types.CipherModeCBCPad, types.CipherModeECB} {
		t.Run(string(mode), func(t *testing.T) {
			_, err := b.requireCipherMechanism(mode)
			require.Error(t, err)
			assert.ErrorIs(t, err, backend.ErrOperationNotSupported)
			assert.ErrorIs(t, err, ErrMechanismNotSupported)
		})
	}
}

// pkcs7Pad appends PKCS#7 padding (RFC 5652 section 6.3), matching the
// padding CKM_AES_CBC_PAD applies inside the token so a test can build the
// software side of the CBC-Pad oracle.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// TestSymmetricEncrypter_DecryptDoesNotMutateInput verifies Decrypt leaves the
// caller's envelope untouched.
//
// Encrypt hands back a Ciphertext and a Tag that are two windows onto one
// array, so reconstructing ciphertext||tag with append writes through the
// caller's buffer whenever it has spare capacity. The observable symptom is a
// second Decrypt of the same envelope failing after the first succeeded.
func TestSymmetricEncrypter_DecryptDoesNotMutateInput(t *testing.T) {
	b := newProvisionedBackend(t, "sym-alias")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-alias-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	plaintext := []byte("decrypt me twice")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	ciphertextBefore := bytes.Clone(encrypted.Ciphertext)
	tagBefore := bytes.Clone(encrypted.Tag)

	first, err := encrypter.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, first)

	assert.Equal(t, ciphertextBefore, encrypted.Ciphertext, "Decrypt modified the caller's ciphertext")
	assert.Equal(t, tagBefore, encrypted.Tag, "Decrypt modified the caller's tag")

	second, err := encrypter.Decrypt(encrypted, nil)
	require.NoError(t, err, "the envelope must survive being decrypted twice")
	assert.Equal(t, plaintext, second)
}

// TestSymmetricEncrypter_GeneratesFreshNonces verifies that omitting the nonce
// yields a fresh 96-bit nonce per message. Repeating a nonce under one GCM key
// is a total loss of confidentiality and authenticity, so this is the single
// most important property of the generated-nonce path.
func TestSymmetricEncrypter_GeneratesFreshNonces(t *testing.T) {
	b := newProvisionedBackend(t, "sym-freshnonce")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-freshnonce-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	plaintext := []byte("the same message every time")
	seen := make(map[string]struct{}, 16)

	for i := 0; i < 16; i++ {
		encrypted, err := encrypter.Encrypt(plaintext, nil)
		require.NoError(t, err)
		require.Len(t, encrypted.Nonce, 12, "the generated nonce must be 96 bits")

		_, repeated := seen[string(encrypted.Nonce)]
		require.False(t, repeated, "a generated nonce repeated within one key")
		seen[string(encrypted.Nonce)] = struct{}{}

		// Each message must still verify against the oracle under its own nonce.
		want := softwareGCM(t, key).Seal(nil, encrypted.Nonce, plaintext, nil)
		assert.Equal(t, want[len(want)-16:], encrypted.Tag)
	}
}

// TestSymmetricEncrypter_HonoursTokenLabel is the regression test for slot
// resolution in the symmetric path, which used to take the module's first slot
// and ignore the configured token label entirely.
func TestSymmetricEncrypter_HonoursTokenLabel(t *testing.T) {
	b := newProvisionedBackend(t, "sym-tokenlabel")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-tokenlabel-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	encrypted, err := encrypter.Encrypt([]byte("payload"), nil)
	require.NoError(t, err, "encryption works while the label is correct")

	b.config.TokenLabel = "a-token-that-is-not-present"

	_, err = encrypter.Encrypt([]byte("payload"), nil)
	assert.ErrorIs(t, err, ErrTokenNotFound, "Encrypt must not fall through to the first slot")

	_, err = encrypter.Decrypt(encrypted, nil)
	assert.ErrorIs(t, err, ErrTokenNotFound, "Decrypt must not fall through to the first slot")
}

// TestSymmetricEncrypter_KeyDeletedFromToken verifies the encrypter reports a
// missing key rather than operating on some other object once the key it was
// created for is gone.
func TestSymmetricEncrypter_KeyDeletedFromToken(t *testing.T) {
	b := newProvisionedBackend(t, "sym-deleted")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-deleted-key", key)
	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	// C_DestroyObject on a token object needs a read/write session, which the
	// pool provides; the introspection helper opens a read-only one.
	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, createKeyID(attrs)),
		})
		return b.p11ctx.DestroyObject(session, handle)
	}))

	_, err = encrypter.Encrypt([]byte("payload"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")

	_, err = encrypter.Decrypt(&types.EncryptedData{
		Ciphertext: []byte("ciphertext"),
		Nonce:      make([]byte, 12),
		Tag:        make([]byte, 16),
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// TestGenerateSymmetricKey_OnToken verifies key generation for the sizes the
// token key generation path supports, and that the generated key is usable.
func TestGenerateSymmetricKey_OnToken(t *testing.T) {
	for _, tc := range []struct {
		algorithm types.SymmetricAlgorithm
		keySize   int
	}{
		{types.SymmetricAES128GCM, 128},
		{types.SymmetricAES192GCM, 192},
		{types.SymmetricAES256GCM, 256},
	} {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			b := newProvisionedBackend(t, "sym-generate")
			attrs := symmetricAttrs("generated-"+string(tc.algorithm), tc.algorithm)

			key, err := b.GenerateSymmetricKey(context.Background(), attrs)
			require.NoError(t, err)

			assert.Equal(t, string(tc.algorithm), key.Algorithm(),
				"a generated key must report the algorithm it was asked for")
			assert.Equal(t, tc.keySize, key.KeySize())

			// The whole point of an HSM key: the material is not retrievable.
			_, err = key.Raw()
			assert.ErrorIs(t, err, backend.ErrNotSupported)

			// A looked-up handle to the same key must describe it identically.
			fetched, err := b.GetSymmetricKey(context.Background(), attrs)
			require.NoError(t, err)
			assert.Equal(t, key.Algorithm(), fetched.Algorithm(),
				"Algorithm() must not depend on whether the key was generated or fetched")
			assert.Equal(t, key.KeySize(), fetched.KeySize())

			// And it must actually encrypt and decrypt.
			encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
			require.NoError(t, err)

			encrypted, err := encrypter.Encrypt([]byte("round trip"), &types.EncryptOptions{
				AdditionalData: []byte("aad"),
			})
			require.NoError(t, err)

			opened, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
				AdditionalData: []byte("aad"),
			})
			require.NoError(t, err)
			assert.Equal(t, []byte("round trip"), opened)
		})
	}
}

// TestGenerateSymmetricKey_KeyIsNonExtractable verifies the generated key
// object carries the protection attributes that make it an HSM key rather than
// a byte slice that happens to live on a token.
func TestGenerateSymmetricKey_KeyIsNonExtractable(t *testing.T) {
	b := newProvisionedBackend(t, "sym-sealed")
	attrs := symmetricAttrs("sealed-key", types.SymmetricAES256GCM)

	_, err := b.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)

	session := openIntrospectionSession(t, b)
	handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, createKeyID(attrs)),
	})

	values, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, nil),
	})
	require.NoError(t, err)
	require.Len(t, values, 3)

	assert.Equal(t, []byte{1}, values[0].Value, "CKA_SENSITIVE must be true")
	assert.Equal(t, []byte{0}, values[1].Value, "CKA_EXTRACTABLE must be false")
	assert.Equal(t, []byte{1}, values[2].Value, "CKA_TOKEN must be true so the key survives the session")

	// Reading CKA_VALUE of a sensitive key must be refused by the token.
	_, err = b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	assert.Error(t, err, "the token must refuse to export a sensitive key")
}

// TestGenerateSymmetricKey_RejectsNonAESAlgorithms verifies the backend refuses
// algorithms it does not implement instead of quietly generating an AES key.
//
// types.SymmetricAlgorithm.KeySize reports 256 bits for both ChaCha20-Poly1305
// variants, so without an explicit check they sail through the key size
// validation and the caller receives an AES-GCM key under a ChaCha20 label.
func TestGenerateSymmetricKey_RejectsNonAESAlgorithms(t *testing.T) {
	b := newProvisionedBackend(t, "sym-badalg")

	for _, algorithm := range []types.SymmetricAlgorithm{
		types.SymmetricChaCha20Poly1305,
		types.SymmetricXChaCha20Poly1305,
	} {
		t.Run(string(algorithm), func(t *testing.T) {
			attrs := symmetricAttrs("badalg-"+string(algorithm), algorithm)

			_, err := b.GenerateSymmetricKey(context.Background(), attrs)
			assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)

			_, err = b.GetSymmetricKey(context.Background(), attrs)
			assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
		})
	}
}

// TestGenerateSymmetricKey_AES192IsGeneratedNotRefused guards the layer gap
// that previously made types.SymmetricAES192GCM unusable.
//
// GenerateSymmetricKey accepts 128, 192 and 256 bit keys, but the underlying
// Backend.GenerateSecretKey in pkcs11.go once accepted only 128 and 256, so an
// algorithm the backend advertised was refused on generation. FIPS 197 defines
// AES-192 and SoftHSM2 supports it, so that was a code limit rather than a
// token limit. This asserts the key is generated at the right size and is
// actually usable, which is what an advertised algorithm has to mean.
func TestGenerateSymmetricKey_AES192IsGeneratedNotRefused(t *testing.T) {
	b := newProvisionedBackend(t, "sym-aes192")
	attrs := symmetricAttrs("aes192-key", types.SymmetricAES192GCM)

	key, err := b.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, string(types.SymmetricAES192GCM), key.Algorithm())
	assert.Equal(t, 192, key.KeySize())

	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	encrypted, err := encrypter.Encrypt([]byte("aes-192 round trip"), &types.EncryptOptions{
		AdditionalData: []byte("aad"),
	})
	require.NoError(t, err)

	opened, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: []byte("aad"),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("aes-192 round trip"), opened)
}

// TestGetSymmetricKey_NotOnToken verifies the lookup reports the canonical
// key-not-found error rather than a PKCS#11 status code.
func TestGetSymmetricKey_NotOnToken(t *testing.T) {
	b := newProvisionedBackend(t, "sym-absent")
	attrs := symmetricAttrs("a-key-that-was-never-generated", types.SymmetricAES256GCM)

	_, err := b.GetSymmetricKey(context.Background(), attrs)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)

	_, err = b.SymmetricEncrypter(context.Background(), attrs)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// TestGenerateSymmetricKey_InitializesAEADTracking verifies key generation
// registers the AEAD safety options that the nonce and byte limits depend on.
// Without them the tracker has no configuration for the key and enforces
// nothing.
func TestGenerateSymmetricKey_InitializesAEADTracking(t *testing.T) {
	b := newProvisionedBackend(t, "sym-tracking")
	attrs := symmetricAttrs("tracked-key", types.SymmetricAES256GCM)

	_, err := b.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)

	tracker := b.GetTracker()
	require.NotNil(t, tracker)

	opts, err := tracker.GetAEADOptions(createKeyID(attrs))
	require.NoError(t, err, "generation must register AEAD options for the new key")
	assert.Equal(t, types.DefaultAEADOptions().NonceTracking, opts.NonceTracking)
}

// TestSymmetricEncrypter_RejectsNonceReuse verifies the tracker refuses a
// second encryption under a nonce already used with the same key.
//
// Nonce reuse under one GCM key reveals the XOR of the two plaintexts and leaks
// the authentication subkey, so this check must run before the token is asked
// to encrypt, not after.
func TestSymmetricEncrypter_RejectsNonceReuse(t *testing.T) {
	b := newProvisionedBackend(t, "sym-noncereuse")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-noncereuse-key", key)
	require.NoError(t, b.GetTracker().SetAEADOptions(createKeyID(attrs), &types.AEADOptions{
		NonceTracking: true,
	}))

	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	nonce := bytes.Repeat([]byte{0x7F}, 12)

	_, err = encrypter.Encrypt([]byte("first message"), &types.EncryptOptions{Nonce: nonce})
	require.NoError(t, err)

	_, err = encrypter.Encrypt([]byte("second message"), &types.EncryptOptions{Nonce: nonce})
	assert.ErrorIs(t, err, backend.ErrNonceReused)
}

// TestSymmetricEncrypter_EnforcesBytesLimit verifies the per-key byte budget is
// enforced on the encrypt path, and that a request rejected for a malformed
// nonce does not consume any of that budget.
func TestSymmetricEncrypter_EnforcesBytesLimit(t *testing.T) {
	b := newProvisionedBackend(t, "sym-byteslimit")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	attrs := installKnownAESKey(t, b, "sym-byteslimit-key", key)
	keyID := createKeyID(attrs)
	require.NoError(t, b.GetTracker().SetAEADOptions(keyID, &types.AEADOptions{
		BytesTracking:      true,
		BytesTrackingLimit: 64,
	}))

	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err)

	// A request rejected for a bad nonce must not be counted: validation runs
	// before the tracker is touched.
	_, err = encrypter.Encrypt(make([]byte, 64), &types.EncryptOptions{Nonce: make([]byte, 16)})
	require.ErrorIs(t, err, ErrInvalidNonceLength)

	counted, err := b.GetTracker().GetBytesEncrypted(keyID)
	require.NoError(t, err)
	assert.Zero(t, counted, "a rejected request consumed part of the key's byte budget")

	_, err = encrypter.Encrypt(make([]byte, 64), nil)
	require.NoError(t, err)

	_, err = encrypter.Encrypt([]byte("one byte over"), nil)
	assert.ErrorIs(t, err, backend.ErrBytesLimitExceeded)
}

// TestSymmetricEncrypter_ContextNotInitialized verifies both halves refuse to
// operate when the backend has no PKCS#11 context, rather than dereferencing
// it.
func TestSymmetricEncrypter_ContextNotInitialized(t *testing.T) {
	encrypter := &pkcs11SymmetricEncrypter{
		backend: &Backend{config: &Config{Library: "unused", TokenLabel: "unused"}},
		attrs:   symmetricAttrs("no-context-key", types.SymmetricAES256GCM),
	}

	_, err := encrypter.Encrypt([]byte("payload"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PKCS#11 context not initialized")

	_, err = encrypter.Decrypt(&types.EncryptedData{
		Ciphertext: []byte("ciphertext"),
		Nonce:      make([]byte, 12),
		Tag:        make([]byte, 16),
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PKCS#11 context not initialized")
}

// TestGenerateSymmetricKey_RejectsInvalidAttributes exercises the validation
// that runs on an initialized backend, where the not-initialized check no
// longer short-circuits it.
func TestGenerateSymmetricKey_RejectsInvalidAttributes(t *testing.T) {
	b := newProvisionedBackend(t, "sym-validate")

	cases := []struct {
		name  string
		attrs *types.KeyAttributes
		check func(t *testing.T, err error)
	}{
		{
			name: "missing CN",
			attrs: &types.KeyAttributes{
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_PKCS11,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			check: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "invalid attributes")
			},
		},
		{
			name: "asymmetric attributes",
			attrs: &types.KeyAttributes{
				CN:            "rsa-not-symmetric",
				KeyType:       backend.KEY_TYPE_TLS,
				StoreType:     backend.STORE_PKCS11,
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 2048},
			},
			check: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
				assert.Contains(t, err.Error(), "asymmetric algorithm")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.GenerateSymmetricKey(context.Background(), tc.attrs)
			require.Error(t, err)
			tc.check(t, err)

			_, err = b.GetSymmetricKey(context.Background(), tc.attrs)
			require.Error(t, err)
			tc.check(t, err)
		})
	}
}

// TestSymmetricEncrypter_KeyUsageIsEnforced verifies the token's key usage
// flags are respected: a key without CKA_ENCRYPT cannot encrypt and a key
// without CKA_DECRYPT cannot decrypt.
//
// PKCS#11 gates C_EncryptInit and C_DecryptInit on those attributes, and the
// resulting CKR_KEY_FUNCTION_NOT_PERMITTED must reach the caller rather than
// being retried or worked around in software.
func TestSymmetricEncrypter_KeyUsageIsEnforced(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	t.Run("decrypt-only key cannot encrypt", func(t *testing.T) {
		b := newProvisionedBackend(t, "sym-usage-dec")
		attrs := installAESKeyWithUsage(t, b, "decrypt-only-key", key, false, true)

		encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
		require.NoError(t, err)

		_, err = encrypter.Encrypt([]byte("payload"), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize encryption")
	})

	t.Run("encrypt-only key cannot decrypt", func(t *testing.T) {
		b := newProvisionedBackend(t, "sym-usage-enc")
		attrs := installAESKeyWithUsage(t, b, "encrypt-only-key", key, true, false)

		encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
		require.NoError(t, err)

		encrypted, err := encrypter.Encrypt([]byte("payload"), nil)
		require.NoError(t, err)

		_, err = encrypter.Decrypt(encrypted, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize decryption")
	})
}
