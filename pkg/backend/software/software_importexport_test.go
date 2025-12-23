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

package software

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestGetImportParameters tests generating import parameters
func TestGetImportParameters(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test-import.com", 2048)

	tests := []struct {
		name      string
		algorithm backend.WrappingAlgorithm
		wantErr   bool
	}{
		{
			name:      "RSAES_OAEP_SHA_1",
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
			wantErr:   false,
		},
		{
			name:      "RSAES_OAEP_SHA_256",
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			wantErr:   false,
		},
		{
			name:      "RSA_AES_KEY_WRAP_SHA_1",
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
			wantErr:   false,
		},
		{
			name:      "RSA_AES_KEY_WRAP_SHA_256",
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			wantErr:   false,
		},
		{
			name:      "Invalid algorithm",
			algorithm: backend.WrappingAlgorithm("INVALID"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := be.(backend.ImportExportBackend).GetImportParameters(attrs, tt.algorithm)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			// Validate the returned parameters
			if params.WrappingPublicKey == nil {
				t.Error("wrapping public key is nil")
			}

			if len(params.ImportToken) == 0 {
				t.Error("import token is nil or empty")
			}

			if params.Algorithm != tt.algorithm {
				t.Errorf("algorithm mismatch: got %s, want %s", params.Algorithm, tt.algorithm)
			}

			if params.ExpiresAt == nil {
				t.Error("expiration time is nil")
			} else {
				// Should expire in approximately 24 hours
				expectedExpiry := time.Now().Add(24 * time.Hour)
				if params.ExpiresAt.Before(expectedExpiry.Add(-1*time.Minute)) ||
					params.ExpiresAt.After(expectedExpiry.Add(1*time.Minute)) {
					t.Errorf("expiration time not within expected range: got %v", params.ExpiresAt)
				}
			}

			if params.KeySpec == "" {
				t.Error("key spec is empty")
			}
		})
	}
}

// TestWrapKey tests key wrapping with different algorithms
func TestWrapKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test-wrap.com", 2048)

	// Generate some test key material
	testKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(testKey); err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name      string
		algorithm backend.WrappingAlgorithm
		keySize   int
		wantErr   bool
	}{
		{
			name:      "RSAES_OAEP_SHA_256 small key",
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			keySize:   32,
			wantErr:   false,
		},
		{
			name:      "RSA_AES_KEY_WRAP_SHA_256 large key",
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			keySize:   256, // Large key that requires hybrid wrapping
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get import parameters
			params, err := be.(backend.ImportExportBackend).GetImportParameters(attrs, tt.algorithm)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			// Generate test key material of specified size
			keyMaterial := make([]byte, tt.keySize)
			if _, err := rand.Read(keyMaterial); err != nil {
				t.Fatalf("failed to generate key material: %v", err)
			}

			// Wrap the key
			wrapped, err := be.(backend.ImportExportBackend).WrapKey(keyMaterial, params)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("WrapKey failed: %v", err)
			}

			// Validate wrapped key material
			if len(wrapped.WrappedKey) == 0 {
				t.Error("wrapped key is nil or empty")
			}

			if wrapped.Algorithm != tt.algorithm {
				t.Errorf("algorithm mismatch: got %s, want %s", wrapped.Algorithm, tt.algorithm)
			}

			if string(wrapped.ImportToken) != string(params.ImportToken) {
				t.Error("import token mismatch")
			}
		})
	}
}

// TestWrapKey_InvalidInputs tests error handling for invalid inputs
func TestWrapKey_InvalidInputs(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test.com", 2048)
	params, _ := be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	tests := []struct {
		name        string
		keyMaterial []byte
		params      *backend.ImportParameters
		wantErr     bool
	}{
		{
			name:        "nil key material",
			keyMaterial: nil,
			params:      params,
			wantErr:     true,
		},
		{
			name:        "empty key material",
			keyMaterial: []byte{},
			params:      params,
			wantErr:     true,
		},
		{
			name:        "nil params",
			keyMaterial: []byte{1, 2, 3},
			params:      nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := be.(backend.ImportExportBackend).WrapKey(tt.keyMaterial, tt.params)
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
		})
	}
}

// TestUnwrapKey tests key unwrapping
func TestUnwrapKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test-unwrap.com", 2048)

	tests := []struct {
		name      string
		algorithm backend.WrappingAlgorithm
		keySize   int
	}{
		{
			name:      "RSAES_OAEP_SHA_1",
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
			keySize:   32,
		},
		{
			name:      "RSAES_OAEP_SHA_256",
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			keySize:   32,
		},
		{
			name:      "RSA_AES_KEY_WRAP_SHA_256",
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			keySize:   128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get import parameters
			params, err := be.(backend.ImportExportBackend).GetImportParameters(attrs, tt.algorithm)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			// Generate and wrap key material
			keyMaterial := make([]byte, tt.keySize)
			if _, err := rand.Read(keyMaterial); err != nil {
				t.Fatalf("failed to generate key material: %v", err)
			}

			wrapped, err := be.(backend.ImportExportBackend).WrapKey(keyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey failed: %v", err)
			}

			// Unwrap the key
			unwrapped, err := be.(backend.ImportExportBackend).UnwrapKey(wrapped, params)
			if err != nil {
				t.Fatalf("UnwrapKey failed: %v", err)
			}

			// Verify unwrapped key matches original
			if len(unwrapped) != len(keyMaterial) {
				t.Errorf("unwrapped key size mismatch: got %d, want %d", len(unwrapped), len(keyMaterial))
			}

			for i := range keyMaterial {
				if unwrapped[i] != keyMaterial[i] {
					t.Errorf("unwrapped key data mismatch at byte %d", i)
					break
				}
			}
		})
	}
}

// TestUnwrapKey_InvalidToken tests unwrapping with invalid token
func TestUnwrapKey_InvalidToken(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test.com", 2048)
	params, _ := be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	// Create wrapped material with invalid token
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte{1, 2, 3},
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte("invalid-token-uuid"),
	}

	_, err := be.(backend.ImportExportBackend).UnwrapKey(wrapped, params)
	if err == nil {
		t.Error("expected error for invalid token but got nil")
	}
}

// TestImportKey tests importing various key types
func TestImportKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		algorithm backend.WrappingAlgorithm
		genKey    func() []byte
	}{
		{
			name:      "Import RSA key",
			attrs:     createRSAAttrs("imported-rsa.com", 2048),
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			genKey: func() []byte {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
				return pkcs8
			},
		},
		{
			name:      "Import AES key",
			attrs:     createAESAttrs("imported-aes", 256, types.SymmetricAES256GCM),
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			genKey: func() []byte {
				key := make([]byte, 32)
				_, _ = rand.Read(key)
				return key
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get import parameters
			params, err := be.(backend.ImportExportBackend).GetImportParameters(tt.attrs, tt.algorithm)
			if err != nil {
				t.Fatalf("GetImportParameters failed: %v", err)
			}

			// Generate key material
			keyMaterial := tt.genKey()

			// Wrap the key
			wrapped, err := be.(backend.ImportExportBackend).WrapKey(keyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey failed: %v", err)
			}

			// Import the key
			err = be.(backend.ImportExportBackend).ImportKey(tt.attrs, wrapped)
			if err != nil {
				t.Fatalf("ImportKey failed: %v", err)
			}

			// Verify the key was imported
			if tt.attrs.IsSymmetric() {
				_, err = be.GetSymmetricKey(tt.attrs)
			} else {
				_, err = be.GetKey(tt.attrs)
			}

			if err != nil {
				t.Errorf("failed to retrieve imported key: %v", err)
			}
		})
	}
}

// TestImportKey_InvalidInputs tests error handling for import
func TestImportKey_InvalidInputs(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test", 256, types.SymmetricAES256GCM)
	params, _ := be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	// Create valid wrapped material
	keyMaterial := make([]byte, 32)
	_, _ = rand.Read(keyMaterial)
	wrapped, _ := be.(backend.ImportExportBackend).WrapKey(keyMaterial, params)

	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wrapped *backend.WrappedKeyMaterial
		wantErr bool
	}{
		{
			name:    "nil attributes",
			attrs:   nil,
			wrapped: wrapped,
			wantErr: true,
		},
		{
			name:    "nil wrapped",
			attrs:   attrs,
			wrapped: nil,
			wantErr: true,
		},
		{
			name:  "invalid token",
			attrs: attrs,
			wrapped: &backend.WrappedKeyMaterial{
				WrappedKey:  wrapped.WrappedKey,
				Algorithm:   wrapped.Algorithm,
				ImportToken: []byte("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := be.(backend.ImportExportBackend).ImportKey(tt.attrs, tt.wrapped)
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
		})
	}
}

// TestExportKey tests exporting keys
func TestExportKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		algorithm backend.WrappingAlgorithm
		setup     func(*types.KeyAttributes) error
	}{
		{
			name: "Export RSA key",
			attrs: func() *types.KeyAttributes {
				attrs := createRSAAttrs("export-rsa.com", 2048)
				attrs.Exportable = true
				return attrs
			}(),
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			setup: func(attrs *types.KeyAttributes) error {
				_, err := be.GenerateKey(attrs)
				return err
			},
		},
		{
			name: "Export AES key",
			attrs: func() *types.KeyAttributes {
				attrs := createAESAttrs("export-aes", 256, types.SymmetricAES256GCM)
				attrs.Exportable = true
				return attrs
			}(),
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			setup: func(attrs *types.KeyAttributes) error {
				_, err := be.GenerateSymmetricKey(attrs)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup: create the key
			if err := tt.setup(tt.attrs); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			// Export the key
			wrapped, err := be.(backend.ImportExportBackend).ExportKey(tt.attrs, tt.algorithm)
			if err != nil {
				t.Fatalf("ExportKey failed: %v", err)
			}

			// Validate exported key
			if len(wrapped.WrappedKey) == 0 {
				t.Error("wrapped key is nil or empty")
			}

			if wrapped.Algorithm != tt.algorithm {
				t.Errorf("algorithm mismatch: got %s, want %s", wrapped.Algorithm, tt.algorithm)
			}

			if len(wrapped.ImportToken) == 0 {
				t.Error("import token is nil or empty")
			}
		})
	}
}

// TestImportExportRoundTrip tests full import/export workflow
func TestImportExportRoundTrip(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		algorithm backend.WrappingAlgorithm
		genKey    func() error
	}{
		{
			name: "RSA round trip",
			attrs: func() *types.KeyAttributes {
				attrs := createRSAAttrs("roundtrip-rsa.com", 2048)
				attrs.Exportable = true
				return attrs
			}(),
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			genKey: func() error {
				attrs := createRSAAttrs("roundtrip-rsa.com", 2048)
				attrs.Exportable = true
				_, err := be.GenerateKey(attrs)
				return err
			},
		},
		{
			name: "AES round trip",
			attrs: func() *types.KeyAttributes {
				attrs := createAESAttrs("roundtrip-aes", 256, types.SymmetricAES256GCM)
				attrs.Exportable = true
				return attrs
			}(),
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			genKey: func() error {
				attrs := createAESAttrs("roundtrip-aes", 256, types.SymmetricAES256GCM)
				attrs.Exportable = true
				_, err := be.GenerateSymmetricKey(attrs)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Generate a key
			if err := tt.genKey(); err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			// Step 2: Export the key
			wrapped, err := be.(backend.ImportExportBackend).ExportKey(tt.attrs, tt.algorithm)
			if err != nil {
				t.Fatalf("ExportKey failed: %v", err)
			}

			// Step 3: Delete the original key
			if err := be.DeleteKey(tt.attrs); err != nil {
				t.Fatalf("failed to delete original key: %v", err)
			}

			// Step 4: Import the key back
			if err := be.(backend.ImportExportBackend).ImportKey(tt.attrs, wrapped); err != nil {
				t.Fatalf("ImportKey failed: %v", err)
			}

			// Step 5: Verify the key is accessible
			if tt.attrs.IsSymmetric() {
				key, err := be.GetSymmetricKey(tt.attrs)
				if err != nil {
					t.Fatalf("failed to retrieve imported symmetric key: %v", err)
				}
				if key == nil {
					t.Error("imported symmetric key is nil")
				}
			} else {
				key, err := be.GetKey(tt.attrs)
				if err != nil {
					t.Fatalf("failed to retrieve imported asymmetric key: %v", err)
				}
				if key == nil {
					t.Error("imported asymmetric key is nil")
				}
			}
		})
	}
}

// TestImportExportConcurrency tests concurrent import/export operations
func TestImportExportConcurrency(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	const numGoroutines = 10

	errCh := make(chan error, numGoroutines)
	doneCh := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { doneCh <- true }()

			attrs := createAESAttrs(fmt.Sprintf("concurrent-key-%d", id), 256, types.SymmetricAES256GCM)

			// Get import parameters
			params, err := be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
			if err != nil {
				errCh <- err
				return
			}

			// Generate and wrap key
			keyMaterial := make([]byte, 32)
			_, _ = rand.Read(keyMaterial)

			wrapped, err := be.(backend.ImportExportBackend).WrapKey(keyMaterial, params)
			if err != nil {
				errCh <- err
				return
			}

			// Import the key
			if err := be.(backend.ImportExportBackend).ImportKey(attrs, wrapped); err != nil {
				errCh <- err
				return
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-doneCh
	}

	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Errorf("concurrent operation failed: %v", err)
		}
	}
}

// TestImportTokenExpiration tests that expired tokens are rejected
func TestImportTokenExpiration(t *testing.T) {
	// This test is challenging without being able to manipulate time
	// We'll just verify the expiration is set correctly
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test-expiry.com", 2048)
	params, err := be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	if params.ExpiresAt == nil {
		t.Fatal("expiration time is nil")
	}

	// Verify expiration is in the future
	if params.ExpiresAt.Before(time.Now()) {
		t.Error("expiration time is in the past")
	}

	// Verify expiration is approximately 24 hours from now
	expectedExpiry := time.Now().Add(24 * time.Hour)
	diff := params.ExpiresAt.Sub(expectedExpiry)
	if diff < -1*time.Minute || diff > 1*time.Minute {
		t.Errorf("expiration time not within expected range: got %v, want ~%v", params.ExpiresAt, expectedExpiry)
	}
}

// TestCapabilities_ImportExport verifies ImportExport capability is set
func TestCapabilities_ImportExport(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	caps := be.Capabilities()
	if !caps.Import {
		t.Error("Import capability should be true")
	}
	if !caps.Export {
		t.Error("Export capability should be true")
	}

	if !caps.SupportsImportExport() {
		t.Error("SupportsImportExport() should return true")
	}
}

// TestDetermineKeySpec tests key spec generation
func TestDetermineKeySpec(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		expected string
	}{
		{
			name:     "RSA 2048",
			attrs:    createRSAAttrs("test.com", 2048),
			expected: "RSA_2048",
		},
		{
			name:     "RSA 4096",
			attrs:    createRSAAttrs("test.com", 4096),
			expected: "RSA_4096",
		},
		{
			name:     "AES 256",
			attrs:    createAESAttrs("test", 256, types.SymmetricAES256GCM),
			expected: "AES_256",
		},
		{
			name:     "ECDSA P-256",
			attrs:    createECDSAAttrs("test.com", "P-256"),
			expected: "ECC_NIST_P256",
		},
		{
			name:     "Ed25519",
			attrs:    createEd25519Attrs("test.com"),
			expected: "ED25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := determineKeySpec(tt.attrs)
			if spec != tt.expected {
				t.Errorf("determineKeySpec() = %s, want %s", spec, tt.expected)
			}
		})
	}
}

// TestValidateKeyType tests key type validation
func TestValidateKeyType(t *testing.T) {
	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name    string
		key     interface{}
		attrs   *types.KeyAttributes
		wantErr bool
	}{
		{
			name:    "Valid RSA key",
			key:     rsaKey,
			attrs:   createRSAAttrs("test.com", 2048),
			wantErr: false,
		},
		{
			name:    "RSA key with wrong attributes",
			key:     rsaKey,
			attrs:   createECDSAAttrs("test.com", "P-256"),
			wantErr: true,
		},
		{
			name:    "RSA key with wrong size",
			key:     rsaKey,
			attrs:   createRSAAttrs("test.com", 4096),
			wantErr: true,
		},
		{
			name:    "Public key instead of private",
			key:     &rsaKey.PublicKey,
			attrs:   createRSAAttrs("test.com", 2048),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyType(tt.key, tt.attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKeyType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestImportKey_WrongKeySize tests importing key with wrong size
func TestImportKey_WrongKeySize(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Create attributes for 256-bit key
	attrs := createAESAttrs("test", 256, types.SymmetricAES256GCM)

	params, err := be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	// Try to import a 128-bit key instead
	keyMaterial := make([]byte, 16) // 128-bit
	_, _ = rand.Read(keyMaterial)

	wrapped, err := be.(backend.ImportExportBackend).WrapKey(keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// This should fail because key size doesn't match attributes
	err = be.(backend.ImportExportBackend).ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("expected error for wrong key size but got nil")
	}
}

// TestBackendClosed tests operations on closed backend
func TestBackendClosed(t *testing.T) {
	keyStorage := storage.New()
	config := &Config{KeyStorage: keyStorage}
	be, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}

	// Close the backend
	_ = be.Close()

	attrs := createRSAAttrs("test.com", 2048)

	// All operations should fail on closed backend
	_, err = be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("expected error on closed backend for GetImportParameters")
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte{1, 2, 3},
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte("token"),
	}

	_, err = be.(backend.ImportExportBackend).UnwrapKey(wrapped, nil)
	if err == nil {
		t.Error("expected error on closed backend for UnwrapKey")
	}

	err = be.(backend.ImportExportBackend).ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("expected error on closed backend for ImportKey")
	}

	_, err = be.(backend.ImportExportBackend).ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("expected error on closed backend for ExportKey")
	}
}

// TestExportKey_NonExistentKey tests exporting a key that doesn't exist
func TestExportKey_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("nonexistent.com", 2048)

	_, err := be.(backend.ImportExportBackend).ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Error("expected error when exporting non-existent key")
	}
}

// TestExportKey_InvalidAlgorithm tests exporting with invalid algorithm
func TestExportKey_InvalidAlgorithm(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Generate a key
	attrs := createAESAttrs("test", 256, types.SymmetricAES256GCM)
	_, err := be.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	// Try to export with invalid algorithm
	_, err = be.(backend.ImportExportBackend).ExportKey(attrs, backend.WrappingAlgorithm("INVALID"))
	if err == nil {
		t.Error("expected error for invalid wrapping algorithm")
	}
}

// TestUnwrapKey_ExpiredToken tests unwrapping with expired token
func TestUnwrapKey_ExpiredToken(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Cast to access internal structure
	swBe := be.(*SoftwareBackend)

	// Manually create an expired token
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenUUID := "expired-token-uuid"
	swBe.importMu.Lock()
	swBe.importTokens[tokenUUID] = &importTokenData{
		privateKey: rsaKey,
		algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		expiresAt:  time.Now().Add(-1 * time.Hour), // Already expired
		keySpec:    "RSA_2048",
	}
	swBe.importMu.Unlock()

	// Try to unwrap with expired token
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte{1, 2, 3},
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte(tokenUUID),
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		ImportToken:       []byte(tokenUUID),
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	_, err := be.(backend.ImportExportBackend).UnwrapKey(wrapped, params)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

// TestUnwrapKey_AlgorithmMismatch tests unwrapping with mismatched algorithm
func TestUnwrapKey_AlgorithmMismatch(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test", 256, types.SymmetricAES256GCM)

	// Get params with SHA256 algorithm
	params, err := be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	// Try to unwrap with different algorithm
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte{1, 2, 3},
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_1, // Different algorithm
		ImportToken: params.ImportToken,
	}

	_, err = be.(backend.ImportExportBackend).UnwrapKey(wrapped, params)
	if err == nil {
		t.Error("expected error for algorithm mismatch")
	}
}

// TestUnwrapKey_EmptyToken tests unwrapping with empty token
func TestUnwrapKey_EmptyToken(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte{1, 2, 3},
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte{}, // Empty token
	}

	params := &backend.ImportParameters{
		Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	_, err := be.(backend.ImportExportBackend).UnwrapKey(wrapped, params)
	if err == nil {
		t.Error("expected error for empty import token")
	}
}

// TestImportKey_ExpiredToken tests importing with expired token
func TestImportKey_ExpiredToken(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	// Cast to access internal structure
	swBe := be.(*SoftwareBackend)

	// Manually create an expired token
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenUUID := "expired-import-token"
	swBe.importMu.Lock()
	swBe.importTokens[tokenUUID] = &importTokenData{
		privateKey: rsaKey,
		algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		expiresAt:  time.Now().Add(-1 * time.Hour), // Already expired
		keySpec:    "AES_256",
	}
	swBe.importMu.Unlock()

	attrs := createAESAttrs("test", 256, types.SymmetricAES256GCM)
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte{1, 2, 3},
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte(tokenUUID),
	}

	err := be.(backend.ImportExportBackend).ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("expected error for expired import token")
	}
}

// TestImportKey_EmptyToken tests importing with empty token
func TestImportKey_EmptyToken(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("test", 256, types.SymmetricAES256GCM)
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte{1, 2, 3},
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte{}, // Empty token
	}

	err := be.(backend.ImportExportBackend).ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("expected error for empty import token")
	}
}

// TestImportAsymmetricKey_InvalidPKCS8 tests importing invalid PKCS8 data
func TestImportAsymmetricKey_InvalidPKCS8(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("test.com", 2048)
	params, err := be.(backend.ImportExportBackend).GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	// Wrap invalid PKCS8 data
	invalidPKCS8 := []byte("not valid pkcs8 data")
	wrapped, err := be.(backend.ImportExportBackend).WrapKey(invalidPKCS8, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	// Try to import - should fail on PKCS8 parsing
	err = be.(backend.ImportExportBackend).ImportKey(attrs, wrapped)
	if err == nil {
		t.Error("expected error for invalid PKCS8 data")
	}
}

// TestDetermineKeySpec_NilAttributes tests determineKeySpec with nil
func TestDetermineKeySpec_NilAttributes(t *testing.T) {
	spec := determineKeySpec(nil)
	if spec != "UNKNOWN" {
		t.Errorf("expected UNKNOWN for nil attributes, got %s", spec)
	}
}

// TestDetermineKeySpec_AllCurves tests all ECC curves
func TestDetermineKeySpec_AllCurves(t *testing.T) {
	tests := []struct {
		curve    string
		expected string
	}{
		{"P-256", "ECC_NIST_P256"},
		{"P-384", "ECC_NIST_P384"},
		{"P-521", "ECC_NIST_P521"},
		{"unknown", "ECC_NIST_P256"}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.curve, func(t *testing.T) {
			attrs := createECDSAAttrs("test.com", tt.curve)
			spec := determineKeySpec(attrs)
			if spec != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, spec)
			}
		})
	}
}

// TestDetermineKeySpec_NoAttributes tests defaults when attributes are missing
func TestDetermineKeySpec_NoAttributes(t *testing.T) {
	// RSA without RSAAttributes
	attrs := &types.KeyAttributes{
		KeyAlgorithm: x509.RSA,
	}
	spec := determineKeySpec(attrs)
	if spec != "RSA_2048" {
		t.Errorf("expected RSA_2048 default, got %s", spec)
	}

	// ECDSA without ECCAttributes
	attrs = &types.KeyAttributes{
		KeyAlgorithm: x509.ECDSA,
	}
	spec = determineKeySpec(attrs)
	if spec != "ECC_NIST_P256" {
		t.Errorf("expected ECC_NIST_P256 default, got %s", spec)
	}

	// Symmetric key
	attrs = &types.KeyAttributes{
		KeyType:            backend.KEY_TYPE_SECRET,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	spec = determineKeySpec(attrs)
	if spec != "AES_256" {
		t.Errorf("expected AES_256 default, got %s", spec)
	}

	// Unknown algorithm
	attrs = &types.KeyAttributes{
		KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}
	spec = determineKeySpec(attrs)
	if spec != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %s", spec)
	}
}
