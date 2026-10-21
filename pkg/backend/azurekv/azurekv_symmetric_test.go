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

//go:build azurekv

package azurekv

import (
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// testBackend creates a test backend with mock client and memory storage
func testBackend(t *testing.T) (*Backend, *MockKeyVaultClient) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	return b, mockClient
}

// testBackendWithSecrets creates a test backend with both a mock key-vault
// client and a mock secrets client, wired together through
// NewBackendWithClients (go-xkms#1090). Unlike testBackend, this lets
// GenerateSymmetricKey/GetSymmetricKey exercise their real Secrets API call
// path -- SetSecret/GetSecret through SecretsClient -- instead of requiring
// key material to be injected directly as newLocalSymmetricKey does.
func testBackendWithSecrets(t *testing.T) (*Backend, *MockSecretsClient) {
	t.Helper()

	secretsClient := NewMockSecretsClient()
	config := &Config{
		VaultURL:    "https://mock-vault.vault.azure.net",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClients(config, NewMockKeyVaultClient(), secretsClient)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	return b, secretsClient
}

// newLocalSymmetricKey builds the concrete symmetric key the backend returns,
// with locally generated key material and the backend's real AEAD tracker
// attached.
//
// GenerateSymmetricKey and GetSymmetricKey's own Secrets API round trip is
// covered directly by TestGenerateSymmetricKey_StoresSecretAndRoundTrips and
// friends below (go-xkms#1090) via testBackendWithSecrets, and end to end
// against the real Key Vault emulator by test/integration/azurekv. The
// AES-GCM tests below don't need either: they assert Encrypt/Decrypt, AAD
// binding, nonce-reuse detection and the bytes limit, all of which run
// locally in azureSymmetricKey once key material exists, so injecting it
// directly keeps those tests focused on the crypto, not the Secrets API.
func newLocalSymmetricKey(t *testing.T, b *Backend, attrs *types.KeyAttributes) *azureSymmetricKey {
	t.Helper()

	keySize := attrs.SymmetricAlgorithm.KeySize()
	if keySize == 0 {
		t.Fatalf("algorithm %s reports no key size", attrs.SymmetricAlgorithm)
	}

	keyBytes := make([]byte, keySize/8)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	// Mirror GenerateSymmetricKey: register the caller's AEAD policy, or the
	// default when none was requested.
	aeadOptions := types.DefaultAEADOptions()
	if attrs.AEADOptions != nil {
		aeadOptions = attrs.AEADOptions
	}
	if b.tracker != nil {
		if err := b.tracker.SetAEADOptions(attrs.ID(), aeadOptions); err != nil {
			t.Fatalf("set AEAD options: %v", err)
		}
	}

	return &azureSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
		backend:   b,
		attrs:     attrs,
		keyData:   keyBytes,
	}
}

// TestSymmetricBackendImplementation verifies that Backend implements SymmetricBackend interface
func TestSymmetricBackendImplementation(t *testing.T) {
	var _ types.SymmetricKeyProvider = (*Backend)(nil)
}

// TestGenerateSymmetricKey_RejectsUnsupportedKeySize verifies GenerateSymmetricKey
// validates the requested AES key size before it ever contacts Azure.
//
// The success path — generate, store as a Key Vault secret, read back — is
// covered against the SecretsClient seam by
// TestGenerateSymmetricKey_StoresSecretAndRoundTrips below, and end to end
// against the real Key Vault emulator by test/integration/azurekv.
func TestGenerateSymmetricKey_RejectsUnsupportedKeySize(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-symmetric-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAlgorithm("aes-512-gcm"),
	}

	key, err := b.GenerateSymmetricKey(context.Background(), attrs)
	if err == nil {
		t.Fatal("GenerateSymmetricKey must reject an unsupported AES key size")
	}
	if key != nil {
		t.Error("GenerateSymmetricKey must not return a key alongside an error")
	}
}

// TestSupportedSymmetricAlgorithmsReportTheirKeySize pins the AES sizes the
// backend accepts, which is the property GenerateSymmetricKey validates
// against before storing anything.
func TestSupportedSymmetricAlgorithmsReportTheirKeySize(t *testing.T) {
	for _, tc := range []struct {
		algorithm types.SymmetricAlgorithm
		keySize   int
	}{
		{types.SymmetricAES128GCM, 128},
		{types.SymmetricAES192GCM, 192},
		{types.SymmetricAES256GCM, 256},
	} {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			if got := tc.algorithm.KeySize(); got != tc.keySize {
				t.Errorf("KeySize() = %d, want %d", got, tc.keySize)
			}

			// The local key the backend hands back must carry that size.
			b, _ := testBackend(t)
			defer func() { _ = b.Close() }()

			attrs := &types.KeyAttributes{
				CN:                 "test-" + string(tc.algorithm),
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
				SymmetricAlgorithm: tc.algorithm,
			}
			key := newLocalSymmetricKey(t, b, attrs)
			if key.KeySize() != tc.keySize {
				t.Errorf("key.KeySize() = %d, want %d", key.KeySize(), tc.keySize)
			}
			if key.Algorithm() != string(tc.algorithm) {
				t.Errorf("key.Algorithm() = %s, want %s", key.Algorithm(), tc.algorithm)
			}
		})
	}
}

// TestGetSymmetricKeyNotFound tests error when key doesn't exist
func TestGetSymmetricKeyNotFound(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "non-existent-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	// Try to get a key that doesn't exist
	_, err := b.GetSymmetricKey(context.Background(), attrs)
	if err == nil {
		t.Error("Expected error for non-existent key, got nil")
	}
}

// TestGenerateSymmetricKey_StoresSecretAndRoundTrips is the happy path for
// GenerateSymmetricKey/GetSymmetricKey against the SecretsClient seam
// (go-xkms#1090): the key GenerateSymmetricKey returns and the key a
// subsequent GetSymmetricKey resolves must carry identical raw material,
// proving the round trip through SetSecret/GetSecret -- base64 encode on
// the way in, decode on the way out -- is lossless.
func TestGenerateSymmetricKey_StoresSecretAndRoundTrips(t *testing.T) {
	b, secretsClient := testBackendWithSecrets(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-roundtrip-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	generated, err := b.GenerateSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}
	if generated.KeySize() != 256 {
		t.Errorf("KeySize() = %d, want 256", generated.KeySize())
	}
	if secretsClient.SetSecretCallCount() != 1 {
		t.Errorf("SetSecret call count = %d, want 1", secretsClient.SetSecretCallCount())
	}
	generatedRaw, err := generated.Raw()
	if err != nil {
		t.Fatalf("generated.Raw() failed: %v", err)
	}

	fetched, err := b.GetSymmetricKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey failed: %v", err)
	}
	fetchedRaw, err := fetched.Raw()
	if err != nil {
		t.Fatalf("fetched.Raw() failed: %v", err)
	}

	if !bytes.Equal(generatedRaw, fetchedRaw) {
		t.Error("GetSymmetricKey did not return the same key material GenerateSymmetricKey stored")
	}
}

// TestGenerateSymmetricKey_SecretsClientSetSecretError verifies that a
// SecretsClient.SetSecret failure -- a throttled or unreachable Key Vault --
// surfaces as an error from GenerateSymmetricKey with no key returned,
// rather than a key that silently was never persisted.
func TestGenerateSymmetricKey_SecretsClientSetSecretError(t *testing.T) {
	b, secretsClient := testBackendWithSecrets(t)
	defer func() { _ = b.Close() }()

	secretsClient.SetSetError(errors.New("azure: throttled"))

	attrs := &types.KeyAttributes{
		CN:                 "test-generate-set-error-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	key, err := b.GenerateSymmetricKey(context.Background(), attrs)
	if err == nil {
		t.Fatal("GenerateSymmetricKey must fail when the secrets client's SetSecret fails")
	}
	if key != nil {
		t.Error("GenerateSymmetricKey must not return a key alongside an error")
	}
}

// TestGetSymmetricKey_SecretsClientGetSecretError verifies that a
// SecretsClient.GetSecret failure -- an RBAC denial, a transport fault --
// surfaces as an error from GetSymmetricKey even though local metadata for
// the key exists.
func TestGetSymmetricKey_SecretsClientGetSecretError(t *testing.T) {
	b, secretsClient := testBackendWithSecrets(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-get-error-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	secretsClient.SetGetError(errors.New("azure: forbidden"))

	if _, err := b.GetSymmetricKey(context.Background(), attrs); err == nil {
		t.Fatal("GetSymmetricKey must fail when the secrets client's GetSecret fails")
	}
}

// TestGetSymmetricKey_SecretNotFoundInVault verifies that GetSymmetricKey
// fails when the backing secret has been removed directly in Key Vault --
// out of band from this backend's in-memory metadata, which still records
// the key from the earlier GenerateSymmetricKey call. This is a different
// failure than TestGetSymmetricKeyNotFound, which never gets past the
// in-memory metadata check before touching the secrets client at all.
func TestGetSymmetricKey_SecretNotFoundInVault(t *testing.T) {
	b, secretsClient := testBackendWithSecrets(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-secret-deleted-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	secretsClient.DeleteSecretValue(attrs.CN)

	if _, err := b.GetSymmetricKey(context.Background(), attrs); err == nil {
		t.Fatal("GetSymmetricKey must fail when the backing secret no longer exists in Key Vault")
	}
}

// TestGetSymmetricKey_MalformedSecretData verifies that GetSymmetricKey
// returns an error, rather than panicking or returning a corrupt key, when
// the Key Vault secret's Value does not carry what storeSymmetricKeySecret
// itself would ever write: a nil Value, or content that is not valid
// base64.
func TestGetSymmetricKey_MalformedSecretData(t *testing.T) {
	notBase64 := "not-valid-base64!!!"

	tests := []struct {
		name  string
		value *string
	}{
		{name: "nil secret value", value: nil},
		{name: "non-base64 secret value", value: &notBase64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, secretsClient := testBackendWithSecrets(t)
			defer func() { _ = b.Close() }()

			attrs := &types.KeyAttributes{
				CN:                 "test-malformed-" + tt.name,
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_AZUREKV,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}
			if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
				t.Fatalf("GenerateSymmetricKey failed: %v", err)
			}

			secretsClient.SetSecretValue(attrs.CN, tt.value)

			if _, err := b.GetSymmetricKey(context.Background(), attrs); err == nil {
				t.Fatal("GetSymmetricKey must fail on malformed secret data")
			}
		})
	}
}

// TestSymmetricEncryptDecrypt tests encryption and decryption operations
func TestSymmetricEncryptDecrypt(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-encrypt-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := newLocalSymmetricKey(t, b, attrs)

	// Test data
	plaintext := []byte("Sensitive data to encrypt using Azure Key Vault")

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if encrypted == nil {
		t.Fatal("Encrypted data is nil")
	}

	if len(encrypted.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}

	if len(encrypted.Nonce) == 0 {
		t.Error("Nonce is empty")
	}

	if len(encrypted.Tag) == 0 {
		t.Error("Tag is empty")
	}

	if encrypted.Algorithm != string(types.SymmetricAES256GCM) {
		t.Errorf("Algorithm mismatch: got %s, want %s", encrypted.Algorithm, types.SymmetricAES256GCM)
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data mismatch:\ngot:  %s\nwant: %s", string(decrypted), string(plaintext))
	}
}

// TestSymmetricEncryptDecryptWithAAD tests encryption/decryption with Additional Authenticated Data
func TestSymmetricEncryptDecryptWithAAD(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-aad-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := newLocalSymmetricKey(t, b, attrs)

	plaintext := []byte("Secret message")
	aad := []byte("context-information")

	// Encrypt with AAD
	encrypted, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Encryption with AAD failed: %v", err)
	}

	// Decrypt with correct AAD
	decrypted, err := encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: aad,
	})
	if err != nil {
		t.Fatalf("Decryption with AAD failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}

	// Decrypt with wrong AAD should fail
	wrongAAD := []byte("wrong-context")
	_, err = encrypter.Decrypt(encrypted, &types.DecryptOptions{
		AdditionalData: wrongAAD,
	})
	if err == nil {
		t.Error("Expected decryption to fail with wrong AAD, but it succeeded")
	}
}

// TestSymmetricDecrypt_WrongNonceLength verifies that Decrypt returns an
// error instead of panicking when the encrypted data carries a nonce that
// is not exactly the GCM nonce size. crypto/cipher.AEAD.Open panics on a
// mismatched nonce length, so a caller-controlled nonce must be validated
// before it reaches Open.
func TestSymmetricDecrypt_WrongNonceLength(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-length-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := newLocalSymmetricKey(t, b, attrs)

	encrypted, err := encrypter.Encrypt([]byte("Sensitive data"), nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	tests := []struct {
		name      string
		nonceSize int
	}{
		{name: "16-byte AES-CBC-style IV", nonceSize: 16},
		{name: "empty nonce", nonceSize: 0},
		{name: "single byte nonce", nonceSize: 1},
		{name: "oversized nonce", nonceSize: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := *encrypted
			tampered.Nonce = make([]byte, tt.nonceSize)
			if _, err := encrypter.Decrypt(&tampered, nil); err == nil {
				t.Fatalf("Decrypt() with %d-byte nonce should return an error, not panic", tt.nonceSize)
			}
		})
	}
}

// TestSymmetricEncryptEmptyData tests encryption of empty data
func TestSymmetricEncryptEmptyData(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-empty-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := newLocalSymmetricKey(t, b, attrs)

	// Encrypt empty data
	plaintext := []byte{}
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption of empty data failed: %v", err)
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption of empty data failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("Expected empty decrypted data, got %d bytes", len(decrypted))
	}
}

// TestSymmetricEncryptLargeData tests encryption of larger data
func TestSymmetricEncryptLargeData(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-large-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	encrypter := newLocalSymmetricKey(t, b, attrs)

	// Create 1MB of test data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	// Encrypt
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption of large data failed: %v", err)
	}

	// Decrypt
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption of large data failed: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Decrypted data length mismatch: got %d, want %d", len(decrypted), len(plaintext))
	}

	// Verify data integrity
	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Data mismatch at byte %d: got %d, want %d", i, decrypted[i], plaintext[i])
			break
		}
	}
}

// TestSymmetricInvalidAttributes tests error handling for invalid attributes
func TestSymmetricInvalidAttributes(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{
			name:  "Nil attributes",
			attrs: nil,
		},
		{
			name: "Asymmetric algorithm",
			attrs: &types.KeyAttributes{
				CN:           "test-invalid",
				KeyType:      backend.KEY_TYPE_SECRET,
				StoreType:    backend.STORE_AZUREKV,
				KeyAlgorithm: x509.RSA, // Asymmetric algorithm
			},
		},
		{
			name: "Missing symmetric algorithm",
			attrs: &types.KeyAttributes{
				CN:        "test-missing-attrs",
				KeyType:   backend.KEY_TYPE_SECRET,
				StoreType: backend.STORE_AZUREKV,
				// No SymmetricAlgorithm set
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.GenerateSymmetricKey(context.Background(), tt.attrs)
			if err == nil {
				t.Error("Expected error for invalid attributes, got nil")
			}
		})
	}
}

// TestCapabilitiesSymmetricEncryption verifies symmetric encryption capability is reported
func TestCapabilitiesSymmetricEncryption(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	caps := b.Capabilities()
	if !caps.SymmetricEncryption {
		t.Error("SymmetricEncryption capability should be true")
	}

	if !caps.SupportsSymmetricEncryption() {
		t.Error("SupportsSymmetricEncryption() should return true")
	}
}

// TestAzureKVBackend_NonceReuse tests AEAD nonce reuse detection.
func TestAzureKVBackend_NonceReuse(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	// Generate a key with nonce tracking enabled
	attrs := &types.KeyAttributes{
		CN:                 "test-nonce-reuse",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      true,
			BytesTracking:      false,
			BytesTrackingLimit: 0,
		},
	}

	encrypter := newLocalSymmetricKey(t, b, attrs)

	// Generate a fixed nonce for testing
	fixedNonce := make([]byte, 12)
	copy(fixedNonce, []byte("testnonce123"))

	plaintext := []byte("Test message")
	opts := &types.EncryptOptions{
		Nonce: fixedNonce,
	}

	// First encryption with fixed nonce - should succeed
	_, err := encrypter.Encrypt(plaintext, opts)
	if fips140.Enforced() {
		// A caller-supplied nonce is arbitrary-IV GCM, which
		// GODEBUG=fips140=only refuses before any nonce is tracked.
		if !errors.Is(err, aead.ErrArbitraryIVGCMUnavailable) {
			t.Fatalf("Encrypt with a caller nonce under fips140=only: got %v, want ErrArbitraryIVGCMUnavailable", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("First encryption with fixed nonce failed: %v", err)
	}

	// Second encryption with same nonce - should fail
	_, err = encrypter.Encrypt(plaintext, opts)
	if err == nil {
		t.Fatal("Expected nonce reuse to be detected")
	}

	// Verify error contains AEAD safety check message
	if !contains(err.Error(), "nonce reused") && !contains(err.Error(), "AEAD safety check failed") {
		t.Errorf("Expected nonce reuse error, got: %v", err)
	}
}

// TestAzureKVBackend_BytesLimit tests AEAD bytes limit enforcement.
func TestAzureKVBackend_BytesLimit(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	// Generate a key with small bytes limit for testing
	smallLimit := int64(100) // 100 bytes
	attrs := &types.KeyAttributes{
		CN:                 "test-bytes-limit",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		AEADOptions: &types.AEADOptions{
			NonceTracking:      false,
			BytesTracking:      true,
			BytesTrackingLimit: smallLimit,
		},
	}

	encrypter := newLocalSymmetricKey(t, b, attrs)

	// Encrypt up to the limit
	plaintext := make([]byte, 50)

	// First 50 bytes - should succeed
	_, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second 50 bytes - should succeed (total 100)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Third 50 bytes - should fail (would exceed 100 byte limit)
	_, err = encrypter.Encrypt(plaintext, nil)
	if err == nil {
		t.Fatal("Expected bytes limit to be enforced")
	}

	// Verify error contains bytes limit message
	if !contains(err.Error(), "bytes") && !contains(err.Error(), "limit") && !contains(err.Error(), "AEAD safety check failed") {
		t.Errorf("Expected bytes limit error, got: %v", err)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && containsHelper(s, substr)
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestGetTracker_ReturnsTracker verifies that GetTracker returns the configured tracker.
func TestGetTracker_ReturnsTracker(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	tracker := b.GetTracker()
	if tracker == nil {
		t.Fatal("GetTracker() returned nil, expected non-nil default tracker")
	}

	// Verify it is the same instance as the backend's tracker field
	if tracker != b.tracker {
		t.Error("GetTracker() returned a different tracker instance than the backend's tracker field")
	}
}

// TestGetTracker_DefaultTracker verifies that a backend created without an explicit
// tracker gets a non-nil default tracker from NewBackendWithClient.
func TestGetTracker_DefaultTracker(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

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
