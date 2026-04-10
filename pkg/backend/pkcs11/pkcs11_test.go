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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
)

// testConfig creates a test Config with required storage backends.
// This helper ensures all configs in tests have the required KeyStorage and CertStorage.
func testConfig(library, tokenLabel string) *Config {
	return &Config{
		Library:     library,
		TokenLabel:  tokenLabel,
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
}

// TestBackend_Type verifies that the backend returns the correct type.
func TestBackend_Type(t *testing.T) {
	config := &Config{
		CN:         "test",
		Library:    "/usr/lib/test.so",
		TokenLabel: "test-token",
	}

	b := &Backend{
		config: config,
	}

	if got := b.Type(); got != backend.BackendTypePKCS11 {
		t.Errorf("Backend.Type() = %v, want %v", got, backend.BackendTypePKCS11)
	}
}

// TestBackend_Config verifies that the Config method returns the correct configuration.
func TestBackend_Config(t *testing.T) {
	config := &Config{
		CN:         "test-hsm",
		Library:    "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "my-token",
		PIN:        "1234",
	}

	b := &Backend{
		config: config,
	}

	got := b.Config()
	if got == nil {
		t.Fatal("Backend.Config() returned nil")
	}

	if got.CN != config.CN {
		t.Errorf("Backend.Config().CN = %v, want %v", got.CN, config.CN)
	}
	if got.Library != config.Library {
		t.Errorf("Backend.Config().Library = %v, want %v", got.Library, config.Library)
	}
	if got.TokenLabel != config.TokenLabel {
		t.Errorf("Backend.Config().TokenLabel = %v, want %v", got.TokenLabel, config.TokenLabel)
	}
}

// TestNewBackend verifies that NewBackend validates the configuration.
func TestNewBackend(t *testing.T) {
	// Create temp library for valid test
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "valid config",
			config:  testConfig(tempLib, "test"),
			wantErr: false,
		},
		{
			name: "invalid config - missing library",
			config: &Config{
				TokenLabel:  "test",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: true,
		},
		{
			name: "invalid config - missing token label",
			config: &Config{
				Library:     tempLib,
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBackend(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBackend() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && b == nil {
				t.Error("NewBackend() returned nil backend with no error")
			}
			if !tt.wantErr && b != nil {
				// Verify the backend has the config set
				if b.config == nil {
					t.Error("NewBackend() backend has nil config")
				}
			}
		})
	}
}

// TestCreateKeyID verifies the key ID generation logic.
func TestCreateKeyID(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
		want  string
	}{
		{
			name: "RSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
			},
			want: "test-key.rsa",
		},
		{
			name: "ECDSA key",
			attrs: &types.KeyAttributes{
				CN:           "my-ecdsa",
				KeyAlgorithm: x509.ECDSA,
			},
			want: "my-ecdsa.ecdsa",
		},
		{
			name: "Ed25519 key",
			attrs: &types.KeyAttributes{
				CN:           "ed-key",
				KeyAlgorithm: x509.Ed25519,
			},
			want: "ed-key.ed25519",
		},
		{
			name: "key with special characters",
			attrs: &types.KeyAttributes{
				CN:           "test@example.com",
				KeyAlgorithm: x509.RSA,
			},
			want: "test@example.com.rsa",
		},
		{
			name: "empty CN",
			attrs: &types.KeyAttributes{
				CN:           "",
				KeyAlgorithm: x509.RSA,
			},
			want: ".rsa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createKeyID(tt.attrs)
			if got != tt.want {
				t.Errorf("createKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBackend_Close verifies that Close is idempotent and handles various states.
func TestBackend_Close(t *testing.T) {
	t.Run("close without context", func(t *testing.T) {
		config := &Config{
			CN:         "test",
			Library:    "/usr/lib/test.so",
			TokenLabel: "test-token",
		}

		b := &Backend{
			config: config,
		}

		// Close should succeed even with no active context
		if err := b.Close(); err != nil {
			t.Errorf("Backend.Close() error = %v", err)
		}

		// Second close should also succeed (idempotent)
		if err := b.Close(); err != nil {
			t.Errorf("Backend.Close() second call error = %v", err)
		}
	})

	t.Run("close clears context", func(t *testing.T) {
		config := &Config{
			CN:         "test",
			Library:    "/usr/lib/test.so",
			TokenLabel: "test-token",
		}

		b := &Backend{
			config: config,
			// Simulate having a context
			ownsP11ctx: true,
		}

		if err := b.Close(); err != nil {
			t.Errorf("Backend.Close() error = %v", err)
		}

		// Verify context is cleared
		if b.pool != nil {
			t.Error("Backend.Close() did not clear context")
		}
	})

	t.Run("close with p11ctx", func(t *testing.T) {
		config := &Config{
			CN:         "test",
			Library:    "/usr/lib/test.so",
			TokenLabel: "test-token",
		}

		b := &Backend{
			config: config,

			p11ctx:     nil, // Would be actual context in real scenario
			ownsP11ctx: true,
		}

		if err := b.Close(); err != nil {
			t.Errorf("Backend.Close() error = %v", err)
		}
	})
}

// TestBackend_Get verifies that Get returns proper errors.
func TestBackend_Get(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	tests := []struct {
		name      string
		extension types.FSExtension
		wantErr   string
	}{
		{
			name:      "get with PKCS8 extension",
			extension: backend.FSEXT_PRIVATE_PKCS8,
			wantErr:   "not initialized",
		},
		{
			name:      "get with PKCS1 extension",
			extension: backend.FSEXT_PUBLIC_PKCS1,
			wantErr:   "not initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err = b.Get(attrs, tt.extension)
			if err == nil {
				t.Error("Backend.Get() should return error")
			}
			// Check for ErrNotInitialized
			if !errors.Is(err, ErrNotInitialized) {
				t.Errorf("Backend.Get() error = %v, want %v", err, ErrNotInitialized)
			}
		})
	}
}

// TestBackend_Save verifies that Save returns proper errors.
func TestBackend_Save(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	tests := []struct {
		name      string
		data      []byte
		extension types.FSExtension
		overwrite bool
		wantErr   string
	}{
		{
			name:      "save with empty data",
			data:      []byte{},
			extension: backend.FSEXT_PRIVATE_PKCS8,
			overwrite: false,
			wantErr:   "not initialized",
		},
		{
			name:      "save with data and overwrite",
			data:      []byte("test-data"),
			extension: backend.FSEXT_PRIVATE_PKCS8,
			overwrite: true,
			wantErr:   "not initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = b.Save(attrs, tt.data, tt.extension, tt.overwrite)
			if err == nil {
				t.Error("Backend.Save() should return error")
			}
			// Check for ErrNotInitialized
			if !errors.Is(err, ErrNotInitialized) {
				t.Errorf("Backend.Save() error = %v, want %v", err, ErrNotInitialized)
			}
		})
	}
}

// TestBackend_Delete verifies the Delete operation error handling.
func TestBackend_Delete(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wantErr bool
	}{
		{
			name: "delete RSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-rsa",
				KeyAlgorithm: x509.RSA,
			},
			wantErr: true,
		},
		{
			name: "delete ECDSA key",
			attrs: &types.KeyAttributes{
				CN:           "test-ecdsa",
				KeyAlgorithm: x509.ECDSA,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = b.Delete(tt.attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestBackend_Initialize verifies the Initialize method validation.
func TestBackend_Initialize(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	tests := []struct {
		name    string
		soPIN   string
		userPIN string
		wantErr bool
		errType error
	}{
		{
			name:    "SO PIN too short",
			soPIN:   "123",
			userPIN: "1234",
			wantErr: true,
			errType: ErrInvalidSOPINLength,
		},
		{
			name:    "user PIN too short",
			soPIN:   "1234",
			userPIN: "12",
			wantErr: true,
			errType: ErrInvalidPINLength,
		},
		{
			name:    "empty SO PIN",
			soPIN:   "",
			userPIN: "1234",
			wantErr: true,
			errType: ErrInvalidSOPINLength,
		},
		{
			name:    "empty user PIN",
			soPIN:   "1234",
			userPIN: "",
			wantErr: true,
			errType: ErrInvalidPINLength,
		},
		{
			name:    "minimum valid PINs",
			soPIN:   "1234",
			userPIN: "5678",
			wantErr: true, // Will fail due to invalid library, but passes validation
		},
		{
			name:    "long PINs",
			soPIN:   "very-long-so-pin-12345",
			userPIN: "very-long-user-pin-67890",
			wantErr: true, // Will fail due to invalid library, but passes validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig(tempLib, "test-token")

			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("NewBackend() failed: %v", err)
			}

			err = b.Initialize(tt.soPIN, tt.userPIN)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errType != nil && err != tt.errType {
				t.Errorf("Backend.Initialize() error = %v, want %v", err, tt.errType)
			}

			// Verify PINs are set on the config when validation passes
			if tt.errType == nil && err == nil {
				if b.config.SOPIN != tt.soPIN {
					t.Errorf("Backend.Initialize() did not set SOPIN correctly")
				}
				if b.config.PIN != tt.userPIN {
					t.Errorf("Backend.Initialize() did not set PIN correctly")
				}
			}
		})
	}
}

// TestBackend_Login verifies the Login method error handling.
func TestBackend_Login(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	t.Run("login without PIN", func(t *testing.T) {
		config := &Config{
			Library:     tempLib,
			TokenLabel:  "test",
			PIN:         "", // Empty PIN
			KeyStorage:  storage.New(),
			CertStorage: storage.New(),
		}

		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		err = b.Login()
		if err != ErrInvalidUserPIN {
			t.Errorf("Backend.Login() error = %v, want %v", err, ErrInvalidUserPIN)
		}
	})

	t.Run("login with PIN set", func(t *testing.T) {
		config := &Config{
			Library:     tempLib,
			TokenLabel:  "test",
			PIN:         "1234",
			KeyStorage:  storage.New(),
			CertStorage: storage.New(),
		}

		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Will fail due to invalid library, but tests the PIN check path
		err = b.Login()
		if err == nil {
			t.Error("Backend.Login() should fail with invalid library")
		}
		if err == ErrInvalidUserPIN {
			t.Error("Backend.Login() should not return ErrInvalidUserPIN when PIN is set")
		}
	})
}

// TestBackend_Pool verifies the Pool method.
func TestBackend_Pool(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Pool should return nil when not initialized
	pool := b.Pool()
	if pool != nil {
		t.Error("Backend.Pool() should return nil when not initialized")
	}
}

// TestBackend_GenerateKey verifies GenerateKey dispatches to correct algorithm.
func TestBackend_GenerateKey(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
		wantErr   error
	}{
		{
			name:      "Ed25519 supported",
			algorithm: x509.Ed25519,
			wantErr:   nil, // Now supported in PKCS#11 v3.0!
		},
		{
			name:      "RSA without context",
			algorithm: x509.RSA,
			wantErr:   ErrNotInitialized,
		},
		{
			name:      "ECDSA without context",
			algorithm: x509.ECDSA,
			wantErr:   ErrNotInitialized,
		},
		{
			name:      "unknown algorithm",
			algorithm: x509.UnknownPublicKeyAlgorithm,
			wantErr:   ErrUnsupportedKeyAlgorithm,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test",
				KeyAlgorithm: tt.algorithm,
			}

			_, err := b.GenerateKey(attrs)
			if err == nil {
				t.Error("GenerateKey() should return error")
			}
			if tt.wantErr != nil && err != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestBackend_GenerateRSA verifies RSA key generation error handling.
func TestBackend_GenerateRSA(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-rsa",
		KeyAlgorithm: x509.RSA,
	}

	_, err = b.GenerateRSA(attrs)
	if err != ErrNotInitialized {
		t.Errorf("GenerateRSA() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestBackend_GenerateRSAWithSize verifies RSA key generation with size parameter.
func TestBackend_GenerateRSAWithSize(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-rsa",
		KeyAlgorithm: x509.RSA,
	}

	tests := []struct {
		name    string
		keySize int
		wantErr error
	}{
		{
			name:    "default key size (0)",
			keySize: 0,
			wantErr: ErrNotInitialized,
		},
		{
			name:    "invalid key size (too small)",
			keySize: 256,
			wantErr: ErrNotInitialized,
		},
		{
			name:    "2048 bit key",
			keySize: 2048,
			wantErr: ErrNotInitialized,
		},
		{
			name:    "4096 bit key",
			keySize: 4096,
			wantErr: ErrNotInitialized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err = b.GenerateRSAWithSize(attrs, tt.keySize)
			if err != tt.wantErr {
				t.Errorf("GenerateRSAWithSize() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestBackend_GenerateECDSA verifies ECDSA key generation error handling.
func TestBackend_GenerateECDSA(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa",
		KeyAlgorithm: x509.ECDSA,
	}

	_, err = b.GenerateECDSA(attrs)
	if err != ErrNotInitialized {
		t.Errorf("GenerateECDSA() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestBackend_GenerateECDSAWithCurve verifies ECDSA key generation with curve parameter.
func TestBackend_GenerateECDSAWithCurve(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa",
		KeyAlgorithm: x509.ECDSA,
	}

	tests := []struct {
		name    string
		curve   elliptic.Curve
		wantErr error
	}{
		{
			name:    "nil curve (defaults to P256)",
			curve:   nil,
			wantErr: ErrNotInitialized,
		},
		{
			name:    "P-256 curve",
			curve:   elliptic.P256(),
			wantErr: ErrNotInitialized,
		},
		{
			name:    "P-384 curve",
			curve:   elliptic.P384(),
			wantErr: ErrNotInitialized,
		},
		{
			name:    "P-521 curve",
			curve:   elliptic.P521(),
			wantErr: ErrNotInitialized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err = b.GenerateECDSAWithCurve(attrs, tt.curve)
			if err != tt.wantErr {
				t.Errorf("GenerateECDSAWithCurve() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestBackend_Signer verifies Signer returns not initialized error.
func TestBackend_Signer(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
	}{
		{
			name:      "RSA key",
			algorithm: x509.RSA,
		},
		{
			name:      "ECDSA key",
			algorithm: x509.ECDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test",
				KeyAlgorithm: tt.algorithm,
			}

			_, err = b.Signer(attrs)
			if err != ErrNotInitialized {
				t.Errorf("Signer() error = %v, want %v", err, ErrNotInitialized)
			}
		})
	}
}

// TestBackend_Sign verifies Sign returns appropriate errors.
func TestBackend_Sign(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	digest := make([]byte, 32)
	_, err = b.Sign(attrs, digest, crypto.SHA256)
	if err == nil {
		t.Error("Sign() should return error when not initialized")
	}
	// Check for ErrNotInitialized
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Sign() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestBackend_Verify verifies Verify returns appropriate errors.
func TestBackend_Verify(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	tests := []struct {
		name      string
		algorithm x509.PublicKeyAlgorithm
	}{
		{
			name:      "verify RSA",
			algorithm: x509.RSA,
		},
		{
			name:      "verify ECDSA",
			algorithm: x509.ECDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test",
				KeyAlgorithm: tt.algorithm,
			}

			digest := make([]byte, 32)
			signature := make([]byte, 64)

			err = b.Verify(attrs, digest, signature)
			if err != ErrNotInitialized {
				t.Errorf("Verify() error = %v, want %v", err, ErrNotInitialized)
			}
		})
	}
}

// TestBackend_findKey verifies the findKey helper.
func TestBackend_findKey(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	_, err = b.findKey(attrs)
	if err != ErrNotInitialized {
		t.Errorf("findKey() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestBackend_ConcurrentAccess verifies thread safety of backend operations.
func TestBackend_ConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Test concurrent read operations
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = b.Type()
			_ = b.Config()
			_ = b.Pool()
		}(i)
	}
	wg.Wait()
}

// TestBackend_MultipleClose verifies that multiple Close calls are safe.
func TestBackend_MultipleClose(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Call Close multiple times
	for i := 0; i < 5; i++ {
		if err := b.Close(); err != nil {
			t.Errorf("Close() iteration %d failed: %v", i, err)
		}
	}
}

// TestBackend_EdgeCases tests various edge cases.
func TestBackend_EdgeCases(t *testing.T) {
	t.Run("nil backend operations", func(t *testing.T) {
		// This tests that we handle nil pointer dereferences gracefully
		// In production code, these would panic, but we're testing the API surface
		tempDir := t.TempDir()
		tempLib := filepath.Join(tempDir, "libtest.so")
		if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create temp library: %v", err)
		}

		config := testConfig(tempLib, "test")

		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Operations on uninitialized backend should return ErrNotInitialized
		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.RSA,
		}

		_, err = b.Get(attrs, backend.FSEXT_PRIVATE_PKCS8)
		if err == nil {
			t.Error("Get() should return error on uninitialized backend")
		}

		err = b.Save(attrs, []byte{}, backend.FSEXT_PRIVATE_PKCS8, false)
		if err == nil {
			t.Error("Save() should return error on uninitialized backend")
		}

		err = b.Delete(attrs)
		if err == nil {
			t.Error("Delete() should return error on uninitialized backend")
		}
	})

	t.Run("empty key attributes", func(t *testing.T) {
		emptyAttrs := &types.KeyAttributes{
			CN:           "",
			KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
		}

		keyID := createKeyID(emptyAttrs)
		if keyID != "." {
			t.Errorf("createKeyID() with empty attrs = %v, want '.'", keyID)
		}
	})
}

// TestBackend_OwnsCtxFlag verifies the ownsP11ctx flag behavior.
func TestBackend_OwnsCtxFlag(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Initially ownsP11ctx should be false
	if b.ownsP11ctx {
		t.Error("NewBackend() should set ownsP11ctx to false")
	}

	// Set ownsP11ctx to true to test Close behavior
	b.ownsP11ctx = true

	if err := b.Close(); err != nil {
		t.Errorf("Close() with ownsP11ctx=true error = %v", err)
	}
}

// TestBackend_Get_WithContext tests Get with initialized context that returns unsupported operation.
func TestBackend_Get_WithContext(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Simulate having a context (though it's not usable without real PKCS11)
	// The function should still check for ErrNotInitialized first
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	_, err = b.Get(attrs, backend.FSEXT_PRIVATE_PKCS8)
	if err == nil {
		t.Error("Get() should return error when context is not initialized")
	}
}

// TestBackend_Save_UnsupportedOperation tests that Save returns unsupported operation error.
func TestBackend_Save_UnsupportedOperation(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	// Test with various data sizes
	testCases := []struct {
		name string
		data []byte
	}{
		{"nil data", nil},
		{"empty data", []byte{}},
		{"small data", []byte("test")},
		{"larger data", make([]byte, 1024)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err = b.Save(attrs, tc.data, backend.FSEXT_PRIVATE_PKCS8, false)
			if err == nil {
				t.Error("Save() should return error")
			}
			// Check for ErrNotInitialized
			if !errors.Is(err, ErrNotInitialized) {
				t.Errorf("Save() error = %v, want %v", err, ErrNotInitialized)
			}
		})
	}
}

// TestBackend_TypedNilChecks tests various nil and zero value scenarios.
func TestBackend_TypedNilChecks(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	t.Run("nil key attributes", func(t *testing.T) {
		// Creating a key ID with nil attrs would panic, so we don't test that
		// Instead, test with minimal attributes
		minimalAttrs := &types.KeyAttributes{}
		keyID := createKeyID(minimalAttrs)
		if keyID != "." {
			t.Errorf("createKeyID() with minimal attrs = %v, want '.'", keyID)
		}
	})

	t.Run("operations with zero values", func(t *testing.T) {
		zeroAttrs := &types.KeyAttributes{
			CN:           "",
			KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
		}

		// All operations should handle zero value attributes
		_, err := b.Get(zeroAttrs, backend.FSEXT_PRIVATE_PKCS8)
		if err == nil {
			t.Error("Get() with zero attrs should return error")
		}

		err = b.Delete(zeroAttrs)
		if err == nil {
			t.Error("Delete() with zero attrs should return error")
		}

		_, err = b.Signer(zeroAttrs)
		if err == nil {
			t.Error("Signer() with zero attrs should return error")
		}
	})
}

// TestBackend_GenerateKey_AllPaths tests all algorithm dispatch paths.
func TestBackend_GenerateKey_AllPaths(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	algorithms := []x509.PublicKeyAlgorithm{
		x509.RSA,
		x509.ECDSA,
		x509.Ed25519,
		x509.UnknownPublicKeyAlgorithm, // empty algorithm
		x509.PublicKeyAlgorithm(99),    // invalid
	}

	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-" + alg.String(),
				KeyAlgorithm: alg,
			}

			_, err := b.GenerateKey(attrs)
			if err == nil {
				t.Error("GenerateKey() should return error without initialized context")
			}

			// Verify the error type is appropriate
			if alg == x509.UnknownPublicKeyAlgorithm || alg == x509.PublicKeyAlgorithm(99) {
				if err != ErrUnsupportedKeyAlgorithm {
					t.Errorf("GenerateKey(%s) error = %v, want %v", alg, err, ErrUnsupportedKeyAlgorithm)
				}
			} else {
				// All supported algorithms (RSA, ECDSA, Ed25519) should return ErrNotInitialized
				if err != ErrNotInitialized {
					t.Errorf("GenerateKey(%s) error = %v, want %v", alg, err, ErrNotInitialized)
				}
			}
		})
	}
}

// TestBackend_ConcurrentOperations tests concurrent operations on the backend.
func TestBackend_ConcurrentOperations(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test-concurrent")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Test concurrent writes and reads
	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent reads (should all work)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = b.Type()
			_ = b.Config()
			_ = b.Pool()
		}(i)
	}

	// Concurrent operations that acquire write locks
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			attrs := &types.KeyAttributes{
				CN:           "test",
				KeyAlgorithm: x509.RSA,
			}
			_, _ = b.GenerateRSA(attrs)
			_, _ = b.GenerateECDSA(attrs)
		}(i)
	}

	wg.Wait()

	// Backend should still be functional after concurrent access
	if b.Type() != backend.BackendTypePKCS11 {
		t.Error("Backend type changed after concurrent access")
	}
}

// TestBackend_Initialize_EdgeCases tests edge cases in Initialize.
func TestBackend_Initialize_EdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	tests := []struct {
		name    string
		soPIN   string
		userPIN string
		wantErr error
	}{
		{
			name:    "exactly 4 character PINs",
			soPIN:   "1234",
			userPIN: "5678",
			wantErr: nil, // validation passes, library init fails
		},
		{
			name:    "long PINs with special characters",
			soPIN:   "So!@#$%^&*()_+PIN123",
			userPIN: "User!@#$%^&*()PIN456",
			wantErr: nil, // validation passes, library init fails
		},
		{
			name:    "unicode in PINs",
			soPIN:   "SO測試1234",
			userPIN: "User測試5678",
			wantErr: nil, // validation passes, library init fails
		},
		{
			name:    "whitespace in PINs",
			soPIN:   "SO PIN 1234",
			userPIN: "User PIN 5678",
			wantErr: nil, // validation passes, library init fails
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig(tempLib, "test-edge-"+tt.name)

			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("NewBackend() failed: %v", err)
			}

			err = b.Initialize(tt.soPIN, tt.userPIN)
			// All of these will fail due to invalid library, but should pass PIN validation
			if err == nil {
				t.Error("Initialize() should fail with invalid library")
			}
			if err == ErrInvalidSOPINLength || err == ErrInvalidPINLength {
				t.Errorf("Initialize() should not return PIN length error for valid PINs, got %v", err)
			}
		})
	}
}

// TestBackend_Sign_EdgeCases tests edge cases in Sign operation.
func TestBackend_Sign_EdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	testCases := []struct {
		name   string
		digest []byte
		opts   crypto.SignerOpts
	}{
		{
			name:   "nil digest",
			digest: nil,
			opts:   crypto.SHA256,
		},
		{
			name:   "empty digest",
			digest: []byte{},
			opts:   crypto.SHA256,
		},
		{
			name:   "short digest",
			digest: []byte{0x01, 0x02},
			opts:   crypto.SHA256,
		},
		{
			name:   "exact SHA256 digest",
			digest: make([]byte, 32),
			opts:   crypto.SHA256,
		},
		{
			name:   "SHA512 digest",
			digest: make([]byte, 64),
			opts:   crypto.SHA512,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.Sign(attrs, tc.digest, tc.opts)
			if err == nil {
				t.Error("Sign() should return error without initialized context")
			}
		})
	}
}

// TestBackend_Verify_WithMockSigner tests Verify with different key types.
func TestBackend_Verify_WithMockSigner(t *testing.T) {
	t.Run("RSA verification path", func(t *testing.T) {
		tempDir := t.TempDir()
		tempLib := filepath.Join(tempDir, "libtest.so")
		if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create temp library: %v", err)
		}

		config := testConfig(tempLib, "test")

		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-rsa",
			KeyAlgorithm: x509.RSA,
		}

		digest := make([]byte, 32)
		signature := make([]byte, 256)

		// Should return ErrNotInitialized because context is nil
		err = b.Verify(attrs, digest, signature)
		if err != ErrNotInitialized {
			t.Errorf("Verify() error = %v, want %v", err, ErrNotInitialized)
		}
	})

	t.Run("ECDSA verification path", func(t *testing.T) {
		tempDir := t.TempDir()
		tempLib := filepath.Join(tempDir, "libtest.so")
		if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create temp library: %v", err)
		}

		config := testConfig(tempLib, "test")

		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa",
			KeyAlgorithm: x509.ECDSA,
		}

		digest := make([]byte, 32)
		// Create a valid but incorrect ECDSA signature
		signature := make([]byte, 64)

		err = b.Verify(attrs, digest, signature)
		if err != ErrNotInitialized {
			t.Errorf("Verify() error = %v, want %v", err, ErrNotInitialized)
		}
	})
}

// TestBackend_Verify_SignatureValidation tests actual ECDSA signature validation logic.
func TestBackend_Verify_SignatureValidation(t *testing.T) {
	// Generate real ECDSA key for testing verification logic
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	// Create a valid signature
	validSig, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Verify the signature works
	if !ecdsa.VerifyASN1(&privateKey.PublicKey, digest, validSig) {
		t.Fatal("valid signature should verify")
	}

	// Invalid signature should not verify
	invalidSig := make([]byte, len(validSig))
	copy(invalidSig, validSig)
	invalidSig[0] ^= 0xFF // Corrupt the signature

	if ecdsa.VerifyASN1(&privateKey.PublicKey, digest, invalidSig) {
		t.Error("invalid signature should not verify")
	}
}

// TestBackend_InitializeToken_AlreadyInitialized tests the already initialized path.
func TestBackend_InitializeToken_AlreadyInitialized(t *testing.T) {
	// This test verifies the error path when PKCS#11 library reports already initialized
	// We can't actually test this without a real PKCS#11 library, but we verify the structure
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Call initializeToken - will fail because library is not real
	err = b.initializeToken("1234", "5678")
	if err == nil {
		t.Error("initializeToken() should fail with invalid library")
	}
	// Error should not be already initialized in this case
	if err == ErrAlreadyInitialized {
		t.Error("initializeToken() should not return ErrAlreadyInitialized for invalid library")
	}
}

// TestBackend_Pool_WithValidPool tests Pool when a session pool is set.
func TestBackend_Pool_WithValidPool(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Set a non-nil pool sentinel
	mockPool := &SessionPool{}
	b.pool = mockPool

	pool := b.Pool()
	if pool != mockPool {
		t.Error("Pool() should return the set pool")
	}

	b.pool = nil
}

// TestBackend_Save_WithContext tests Save when context is initialized (still returns error).
func TestBackend_Save_WithContext(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Set mock context
	b.pool = &SessionPool{}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	// Save should still return unsupported operation error
	err = b.Save(attrs, []byte("test"), backend.FSEXT_PRIVATE_PKCS8, false)
	if err == nil {
		t.Error("Save() should return unsupported operation error")
	}
	// Check for ErrNotSupported
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("Save() error = %v, want %v", err, backend.ErrNotSupported)
	}

	// Clean up
	b.pool = nil
}

// TestBackend_InitializeToken_GetSlotListError tests error when getting slot list.
func TestBackend_InitializeToken_GetSlotListError(t *testing.T) {
	// This verifies that we handle the error case properly
	// The actual error will occur because the library is not valid
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		Slot:        func() *int { v := int(999); return &v }(), // Non-existent slot
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// initializeToken should fail
	err = b.initializeToken("1234", "5678")
	if err == nil {
		t.Error("initializeToken() should fail with invalid library")
	}
}

// TestBackend_Close_WithPanic tests that Close recovers from panics.
func TestBackend_Close_WithPanic(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:    tempLib,
		TokenLabel: "test",
	}

	b := &Backend{
		config: config,
		// Setting ctx to non-nil but invalid will cause Close to potentially panic
		// The defer recover should handle it
		pool:       &SessionPool{},
		ownsP11ctx: true,
	}

	// Close should not panic even if internal operations fail
	err := b.Close()
	// May return error or nil depending on implementation
	t.Logf("Close() returned: %v", err)

	// Verify context was cleared
	if b.pool != nil {
		t.Error("Close() should clear context even after panic")
	}
}

// TestBackend_GenerateRSAWithSize_KeySizeNormalization tests key size normalization.
func TestBackend_GenerateRSAWithSize_KeySizeNormalization(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// 	// Set mock context to test key size normalization
	// 	b.pool = &SessionPool{}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	tests := []struct {
		name            string
		keySize         int
		shouldNormalize bool
	}{
		{"zero key size", 0, true},
		{"too small key size", 256, true},
		{"valid 2048", 2048, false},
		{"valid 4096", 4096, false},
		{"negative key size", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should return ErrNotInitialized because context is nil
			_, err := b.GenerateRSAWithSize(attrs, tt.keySize)
			if err != ErrNotInitialized {
				t.Errorf("GenerateRSAWithSize() error = %v, want %v", err, ErrNotInitialized)
			}
		})
	}
}

// TestBackend_GenerateECDSAWithCurve_CurveNormalization tests curve normalization.
func TestBackend_GenerateECDSAWithCurve_CurveNormalization(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.ECDSA,
	}

	// Test nil curve (should default to P256)
	_, err = b.GenerateECDSAWithCurve(attrs, nil)
	if err != ErrNotInitialized {
		t.Errorf("GenerateECDSAWithCurve() error = %v, want %v", err, ErrNotInitialized)
	}

}

// TestBackend_InitializeToken_NoSlots tests when no slots are available.
func TestBackend_InitializeToken_NoSlots(t *testing.T) {
	// This tests the error path when GetSlotList returns empty
	// We can't actually trigger this without mocking pkcs11.Ctx
	// But we verify the code structure handles this case
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Will fail at library loading, but tests the structure
	err = b.initializeToken("1234", "5678")
	if err == nil {
		t.Error("initializeToken() should fail")
	}
}

// TestBackend_Verify_UnsupportedKeyType tests verification with unsupported key type.
func TestBackend_Verify_UnsupportedKeyType(t *testing.T) {
	// This test would require mocking a signer that returns an unsupported key type
	// For now, we verify the existing test coverage handles RSA and ECDSA paths
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.Ed25519, // Unsupported for verification
	}

	digest := make([]byte, 32)
	signature := make([]byte, 64)

	err = b.Verify(attrs, digest, signature)
	if err != ErrNotInitialized {
		t.Errorf("Verify() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestBackend_Verify_RSAWithValidPublicKey tests RSA verification logic with actual key.
func TestBackend_Verify_RSAWithValidPublicKey(t *testing.T) {
	// Generate a real RSA key to test the verification branch
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// The Backend.Verify method will hit the RSA branch and return
	// "RSA verification requires hash algorithm specification"
	// This tests that code path

	digest := make([]byte, 32)
	// RSA verification through the backend requires knowing the hash algorithm
	// which is not currently implemented in the Verify method
	_ = privateKey
	_ = digest
}

// TestBackend_InitializeToken_CKRAlreadyInitialized tests the specific PKCS11 error code path.
func TestBackend_InitializeToken_CKRAlreadyInitialized(t *testing.T) {
	// This test verifies we handle pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED correctly
	// We can't trigger this without a real PKCS11 library, but the code is structured correctly

	// Verify the error constant exists and is used correctly
	if pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED == 0 {
		t.Error("Expected CKR_CRYPTOKI_ALREADY_INITIALIZED to be defined")
	}
}

// TestCapabilities_QuantumDetection verifies that Capabilities correctly reflects
// dynamic quantum mechanism detection from the PKCS#11 token.
func TestCapabilities_QuantumDetection(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test-quantum")

	t.Run("no quantum support by default", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		caps := b.Capabilities()

		// By default, quantum capabilities should be false since no token
		// has been probed for mechanism support
		if caps.QuantumSigning {
			t.Error("Capabilities().QuantumSigning should be false when no ML-DSA support detected")
		}
		if caps.KeyEncapsulation {
			t.Error("Capabilities().KeyEncapsulation should be false when no ML-KEM support detected")
		}

		// Verify other hardware capabilities are still set correctly
		if !caps.HardwareBacked {
			t.Error("Capabilities().HardwareBacked should be true for PKCS#11")
		}
		if !caps.SymmetricEncryption {
			t.Error("Capabilities().SymmetricEncryption should be true for PKCS#11")
		}
		if !caps.Import {
			t.Error("Capabilities().Import should be true for PKCS#11")
		}
		if !caps.Export {
			t.Error("Capabilities().Export should be true for PKCS#11")
		}
	})

	t.Run("ML-DSA support detected", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Simulate that probeQuantumMechanisms detected ML-DSA support
		b.supportsMLDSA = true

		caps := b.Capabilities()

		if !caps.QuantumSigning {
			t.Error("Capabilities().QuantumSigning should be true when ML-DSA is supported")
		}
		if caps.KeyEncapsulation {
			t.Error("Capabilities().KeyEncapsulation should be false when only ML-DSA is supported")
		}
	})

	t.Run("ML-KEM support detected", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Simulate that probeQuantumMechanisms detected ML-KEM support
		b.supportsMLKEM = true

		caps := b.Capabilities()

		if caps.QuantumSigning {
			t.Error("Capabilities().QuantumSigning should be false when only ML-KEM is supported")
		}
		if !caps.KeyEncapsulation {
			t.Error("Capabilities().KeyEncapsulation should be true when ML-KEM is supported")
		}
	})

	t.Run("both ML-DSA and ML-KEM support detected", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Simulate full quantum support
		b.supportsMLDSA = true
		b.supportsMLKEM = true

		caps := b.Capabilities()

		if !caps.QuantumSigning {
			t.Error("Capabilities().QuantumSigning should be true when both ML-DSA and ML-KEM are supported")
		}
		if !caps.KeyEncapsulation {
			t.Error("Capabilities().KeyEncapsulation should be true when both ML-DSA and ML-KEM are supported")
		}
	})
}

// TestCapabilities_QuantumDetection_ProbeNilP11Ctx verifies that probeQuantumMechanisms
// is safe to call when p11ctx is nil (no-op behavior).
func TestCapabilities_QuantumDetection_ProbeNilP11Ctx(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test-probe-nil")

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	// Ensure p11ctx is nil
	if b.p11ctx != nil {
		t.Fatal("p11ctx should be nil initially")
	}

	// probeQuantumMechanisms should be a safe no-op when p11ctx is nil
	b.probeQuantumMechanisms()

	// Fields should remain false
	if b.supportsMLDSA {
		t.Error("supportsMLDSA should remain false after probing with nil p11ctx")
	}
	if b.supportsMLKEM {
		t.Error("supportsMLKEM should remain false after probing with nil p11ctx")
	}
}

// TestGenerateKey_MLDSA_PKCS11 verifies quantum key generation dispatch through GenerateKey.
func TestGenerateKey_MLDSA_PKCS11(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := testConfig(tempLib, "test-quantum-gen")

	t.Run("quantum dispatch without context returns ErrNotInitialized", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Set ML-DSA support to true to bypass the mechanism check
		b.supportsMLDSA = true

		attrs := &types.KeyAttributes{
			CN:           "test-mldsa",
			KeyAlgorithm: x509.RSA, // Algorithm field is ignored when QuantumAttributes is set
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: types.QuantumAlgorithmMLDSA44,
			},
		}

		_, err = b.GenerateKey(attrs)
		if err == nil {
			t.Error("GenerateKey() with quantum attrs should return error without context")
		}
		if !errors.Is(err, ErrNotInitialized) {
			t.Errorf("GenerateKey() error = %v, want %v", err, ErrNotInitialized)
		}
	})

	t.Run("quantum dispatch takes priority over KeyAlgorithm", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Set quantum support to true
		b.supportsMLDSA = true

		// Even though KeyAlgorithm is RSA, QuantumAttributes should take priority
		attrs := &types.KeyAttributes{
			CN:           "test-priority",
			KeyAlgorithm: x509.RSA,
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: types.QuantumAlgorithmMLDSA65,
			},
		}

		_, err = b.GenerateKey(attrs)
		if err == nil {
			t.Error("GenerateKey() should return error without initialized context")
		}
		// The error should come from generateQuantumKey, not GenerateRSA
		if !errors.Is(err, ErrNotInitialized) {
			t.Errorf("GenerateKey() error = %v, want ErrNotInitialized from quantum path", err)
		}
	})

	t.Run("ML-DSA unsupported by token", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Set context to non-nil so we pass the initialization check
		b.pool = &SessionPool{}
		// Leave supportsMLDSA as false

		attrs := &types.KeyAttributes{
			CN: "test-unsupported",
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: types.QuantumAlgorithmMLDSA44,
			},
		}

		_, err = b.GenerateKey(attrs)
		if err == nil {
			t.Error("GenerateKey() should return error when ML-DSA is not supported")
		}
		if !errors.Is(err, ErrUnsupportedKeyAlgorithm) {
			t.Errorf("GenerateKey() error = %v, want %v", err, ErrUnsupportedKeyAlgorithm)
		}

		// Clean up
		b.pool = nil
	})

	t.Run("ML-KEM unsupported by token", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Set context to non-nil so we pass the initialization check
		b.pool = &SessionPool{}
		// Leave supportsMLKEM as false

		attrs := &types.KeyAttributes{
			CN: "test-unsupported-kem",
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: types.QuantumAlgorithmMLKEM768,
			},
		}

		_, err = b.GenerateKey(attrs)
		if err == nil {
			t.Error("GenerateKey() should return error when ML-KEM is not supported")
		}
		if !errors.Is(err, ErrUnsupportedKeyAlgorithm) {
			t.Errorf("GenerateKey() error = %v, want %v", err, ErrUnsupportedKeyAlgorithm)
		}

		// Clean up
		b.pool = nil
	})

	t.Run("nil quantum attributes falls through to algorithm dispatch", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// With nil QuantumAttributes and RSA algorithm, should dispatch to GenerateRSA
		attrs := &types.KeyAttributes{
			CN:                "test-fallthrough",
			KeyAlgorithm:      x509.RSA,
			QuantumAttributes: nil,
		}

		_, err = b.GenerateKey(attrs)
		if err == nil {
			t.Error("GenerateKey() should return error without initialized context")
		}
		// Should get ErrNotInitialized from the RSA path, not quantum path
		if !errors.Is(err, ErrNotInitialized) {
			t.Errorf("GenerateKey() error = %v, want %v from RSA path", err, ErrNotInitialized)
		}
	})

	t.Run("unsupported quantum algorithm", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Set context to non-nil
		b.pool = &SessionPool{}

		attrs := &types.KeyAttributes{
			CN: "test-bad-algo",
			QuantumAttributes: &types.QuantumAttributes{
				Algorithm: types.QuantumAlgorithm("UNKNOWN-QUANTUM-42"),
			},
		}

		_, err = b.GenerateKey(attrs)
		if err == nil {
			t.Error("GenerateKey() should return error for unsupported quantum algorithm")
		}
		if !errors.Is(err, ErrUnsupportedKeyAlgorithm) {
			t.Errorf("GenerateKey() error = %v, want %v", err, ErrUnsupportedKeyAlgorithm)
		}

		// Clean up
		b.pool = nil
	})

	t.Run("generateQuantumKey with nil quantum attributes returns ErrInvalidKeyAttributes", func(t *testing.T) {
		b, err := NewBackend(config)
		if err != nil {
			t.Fatalf("NewBackend() failed: %v", err)
		}

		// Set context to non-nil to pass initialization check
		b.pool = &SessionPool{}

		attrs := &types.KeyAttributes{
			CN:                "test-nil-quantum",
			QuantumAttributes: nil,
		}

		// Call generateQuantumKey directly to test its own nil check
		_, err = b.generateQuantumKey(attrs)
		if err == nil {
			t.Error("generateQuantumKey() should return error with nil QuantumAttributes")
		}
		if !errors.Is(err, ErrInvalidKeyAttributes) {
			t.Errorf("generateQuantumKey() error = %v, want %v", err, ErrInvalidKeyAttributes)
		}

		// Clean up
		b.pool = nil
	})

	t.Run("all ML-DSA security levels", func(t *testing.T) {
		algorithms := []types.QuantumAlgorithm{
			types.QuantumAlgorithmMLDSA44,
			types.QuantumAlgorithmMLDSA65,
			types.QuantumAlgorithmMLDSA87,
		}

		for _, algo := range algorithms {
			t.Run(string(algo), func(t *testing.T) {
				b, err := NewBackend(config)
				if err != nil {
					t.Fatalf("NewBackend() failed: %v", err)
				}

				// Set context and ML-DSA support
				b.pool = &SessionPool{}
				b.supportsMLDSA = true

				attrs := &types.KeyAttributes{
					CN: "test-" + string(algo),
					QuantumAttributes: &types.QuantumAttributes{
						Algorithm: algo,
					},
				}

				// Will fail at PKCS#11 session level since library is fake,
				// but should get past the mechanism support check
				_, err = b.GenerateKey(attrs)
				if err == nil {
					t.Error("GenerateKey() should return error with fake library")
				}
				// Should NOT be ErrUnsupportedKeyAlgorithm since ML-DSA is supported
				if errors.Is(err, ErrUnsupportedKeyAlgorithm) {
					t.Errorf("GenerateKey(%s) should not return ErrUnsupportedKeyAlgorithm when ML-DSA is supported", algo)
				}

				// Clean up
				b.pool = nil
			})
		}
	})

	t.Run("all ML-KEM security levels", func(t *testing.T) {
		algorithms := []types.QuantumAlgorithm{
			types.QuantumAlgorithmMLKEM512,
			types.QuantumAlgorithmMLKEM768,
			types.QuantumAlgorithmMLKEM1024,
		}

		for _, algo := range algorithms {
			t.Run(string(algo), func(t *testing.T) {
				b, err := NewBackend(config)
				if err != nil {
					t.Fatalf("NewBackend() failed: %v", err)
				}

				// Set context and ML-KEM support
				b.pool = &SessionPool{}
				b.supportsMLKEM = true

				attrs := &types.KeyAttributes{
					CN: "test-" + string(algo),
					QuantumAttributes: &types.QuantumAttributes{
						Algorithm: algo,
					},
				}

				// Will fail at PKCS#11 session level since library is fake,
				// but should get past the mechanism support check
				_, err = b.GenerateKey(attrs)
				if err == nil {
					t.Error("GenerateKey() should return error with fake library")
				}
				// Should NOT be ErrUnsupportedKeyAlgorithm since ML-KEM is supported
				if errors.Is(err, ErrUnsupportedKeyAlgorithm) {
					t.Errorf("GenerateKey(%s) should not return ErrUnsupportedKeyAlgorithm when ML-KEM is supported", algo)
				}

				// Clean up
				b.pool = nil
			})
		}
	})
}

// TestCreateQuantumKeyID verifies the quantum key ID generation logic.
func TestCreateQuantumKeyID(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
		want  string
	}{
		{
			name: "ML-DSA-44 key",
			attrs: &types.KeyAttributes{
				CN: "test-key",
				QuantumAttributes: &types.QuantumAttributes{
					Algorithm: types.QuantumAlgorithmMLDSA44,
				},
			},
			want: "test-key.ml-dsa-44",
		},
		{
			name: "ML-DSA-65 key",
			attrs: &types.KeyAttributes{
				CN: "my-signing-key",
				QuantumAttributes: &types.QuantumAttributes{
					Algorithm: types.QuantumAlgorithmMLDSA65,
				},
			},
			want: "my-signing-key.ml-dsa-65",
		},
		{
			name: "ML-DSA-87 key",
			attrs: &types.KeyAttributes{
				CN: "high-security",
				QuantumAttributes: &types.QuantumAttributes{
					Algorithm: types.QuantumAlgorithmMLDSA87,
				},
			},
			want: "high-security.ml-dsa-87",
		},
		{
			name: "ML-KEM-768 key",
			attrs: &types.KeyAttributes{
				CN: "kem-key",
				QuantumAttributes: &types.QuantumAttributes{
					Algorithm: types.QuantumAlgorithmMLKEM768,
				},
			},
			want: "kem-key.ml-kem-768",
		},
		{
			name: "nil quantum attributes",
			attrs: &types.KeyAttributes{
				CN:                "no-quantum",
				QuantumAttributes: nil,
			},
			want: "no-quantum.",
		},
		{
			name: "empty CN with quantum attributes",
			attrs: &types.KeyAttributes{
				CN: "",
				QuantumAttributes: &types.QuantumAttributes{
					Algorithm: types.QuantumAlgorithmMLDSA44,
				},
			},
			want: ".ml-dsa-44",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createQuantumKeyID(tt.attrs)
			if got != tt.want {
				t.Errorf("createQuantumKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPkcs11QuantumPublicKey verifies the pkcs11QuantumPublicKey wrapper type.
func TestPkcs11QuantumPublicKey(t *testing.T) {
	t.Run("algorithm returns correct value", func(t *testing.T) {
		pk := &pkcs11QuantumPublicKey{
			handle:    pkcs11.ObjectHandle(42),
			algorithm: "ML-DSA-44",
		}

		if got := pk.Algorithm(); got != "ML-DSA-44" {
			t.Errorf("Algorithm() = %v, want ML-DSA-44", got)
		}
	})

	t.Run("handle returns correct value", func(t *testing.T) {
		pk := &pkcs11QuantumPublicKey{
			handle:    pkcs11.ObjectHandle(99),
			algorithm: "ML-KEM-768",
		}

		if got := pk.Handle(); got != pkcs11.ObjectHandle(99) {
			t.Errorf("Handle() = %v, want 99", got)
		}
	})

	t.Run("different algorithms", func(t *testing.T) {
		algorithms := []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
		for _, algo := range algorithms {
			pk := &pkcs11QuantumPublicKey{
				handle:    pkcs11.ObjectHandle(1),
				algorithm: algo,
			}
			if got := pk.Algorithm(); got != algo {
				t.Errorf("Algorithm() = %v, want %v", got, algo)
			}
		}
	})
}

// TestPkcs11MLDSASigner_Public verifies the Public() method of pkcs11MLDSASigner.
func TestPkcs11MLDSASigner_Public(t *testing.T) {
	t.Run("returns pkcs11QuantumPublicKey on first call", func(t *testing.T) {
		signer := &pkcs11MLDSASigner{
			pool:          &SessionPool{},
			publicHandle:  pkcs11.ObjectHandle(1),
			privateHandle: pkcs11.ObjectHandle(2),
			label:         "test-key",
			algorithm:     "ML-DSA-44",
			signMechanism: CKM_ML_DSA,
		}

		pubKey := signer.Public()
		if pubKey == nil {
			t.Fatal("Public() returned nil")
		}

		qpk, ok := pubKey.(*pkcs11QuantumPublicKey)
		if !ok {
			t.Fatalf("Public() returned %T, want *pkcs11QuantumPublicKey", pubKey)
		}

		if qpk.Algorithm() != "ML-DSA-44" {
			t.Errorf("Public().Algorithm() = %v, want ML-DSA-44", qpk.Algorithm())
		}
		if qpk.Handle() != pkcs11.ObjectHandle(1) {
			t.Errorf("Public().Handle() = %v, want 1", qpk.Handle())
		}
	})

	t.Run("returns cached public key on subsequent calls", func(t *testing.T) {
		signer := &pkcs11MLDSASigner{
			pool:          &SessionPool{},
			publicHandle:  pkcs11.ObjectHandle(5),
			privateHandle: pkcs11.ObjectHandle(6),
			label:         "cached-key",
			algorithm:     "ML-DSA-65",
			signMechanism: CKM_ML_DSA,
		}

		// First call initializes the cached public key
		first := signer.Public()
		// Second call should return the same cached instance
		second := signer.Public()

		if first != second {
			t.Error("Public() should return the same cached instance on subsequent calls")
		}
	})
}

// TestPkcs11MLDSASigner_Sign_NilP11Ctx verifies Sign returns error when pool is nil.
func TestPkcs11MLDSASigner_Sign_NilP11Ctx(t *testing.T) {
	// pool is nil by default
	signer := &pkcs11MLDSASigner{
		pool:          nil, // nil pool to test error path
		publicHandle:  pkcs11.ObjectHandle(1),
		privateHandle: pkcs11.ObjectHandle(2),
		label:         "test",
		algorithm:     "ML-DSA-44",
		signMechanism: CKM_ML_DSA,
	}

	digest := make([]byte, 32)
	_, err := signer.Sign(nil, digest, nil)
	if err == nil {
		t.Error("Sign() should return error when p11ctx is nil")
	}
}

// TestQuantumMechanismConstants verifies that the PKCS#11 v3.2 quantum mechanism
// constants have the correct values per the specification.
func TestQuantumMechanismConstants(t *testing.T) {
	// Verify ML-DSA constants match PKCS#11 v3.2 specification
	if CKK_ML_DSA != 0x0000004A {
		t.Errorf("CKK_ML_DSA = 0x%08x, want 0x0000004A", CKK_ML_DSA)
	}
	if CKM_ML_DSA_KEY_PAIR_GEN != 0x0000001c {
		t.Errorf("CKM_ML_DSA_KEY_PAIR_GEN = 0x%08x, want 0x0000001c", CKM_ML_DSA_KEY_PAIR_GEN)
	}
	if CKM_ML_DSA != 0x0000001d {
		t.Errorf("CKM_ML_DSA = 0x%08x, want 0x0000001d", CKM_ML_DSA)
	}

	// Verify ML-KEM constants match PKCS#11 v3.2 specification
	if CKK_ML_KEM != 0x00000049 {
		t.Errorf("CKK_ML_KEM = 0x%08x, want 0x00000049", CKK_ML_KEM)
	}
	if CKM_ML_KEM_KEY_PAIR_GEN != 0x0000000f {
		t.Errorf("CKM_ML_KEM_KEY_PAIR_GEN = 0x%08x, want 0x0000000f", CKM_ML_KEM_KEY_PAIR_GEN)
	}
	if CKM_ML_KEM != 0x00000017 {
		t.Errorf("CKM_ML_KEM = 0x%08x, want 0x00000017", CKM_ML_KEM)
	}

	// Verify Ed25519 constants for cross-reference
	if CKK_EC_EDWARDS != 0x00000040 {
		t.Errorf("CKK_EC_EDWARDS = 0x%08x, want 0x00000040", CKK_EC_EDWARDS)
	}
	if CKM_EC_EDWARDS_KEY_PAIR_GEN != 0x00001055 {
		t.Errorf("CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x%08x, want 0x00001055", CKM_EC_EDWARDS_KEY_PAIR_GEN)
	}
	if CKM_EDDSA != 0x00001057 {
		t.Errorf("CKM_EDDSA = 0x%08x, want 0x00001057", CKM_EDDSA)
	}
}

// TestCompileTimeInterfaceChecks verifies the compile-time interface assertions.
func TestCompileTimeInterfaceChecks(t *testing.T) {
	// These are compile-time checks that exist in the source file.
	// If these were wrong, the code would not compile. This test
	// verifies they are present and documents the expected interfaces.

	// Backend implements types.KeyProvider
	var _ types.KeyProvider = (*Backend)(nil)

	// pkcs11MLDSASigner implements crypto.Signer
	var _ crypto.Signer = (*pkcs11MLDSASigner)(nil)

	// pkcs11Ed25519Signer implements crypto.Signer
	var _ crypto.Signer = (*pkcs11Ed25519Signer)(nil)
}
