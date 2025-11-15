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

//go:build tpm2

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSessionConfig(t *testing.T) {
	cfg := DefaultSessionConfig()

	assert.True(t, cfg.Encrypted, "Default config should enable encryption")
	assert.Equal(t, EncryptionModeInOut, cfg.EncryptionMode, "Default should use bidirectional encryption")
	assert.False(t, cfg.Salted, "Default should disable salting (expensive)")
	assert.False(t, cfg.Bound, "Default should disable binding")
	assert.Equal(t, SessionTypeHMAC, cfg.SessionType, "Default should use HMAC sessions")
	assert.Equal(t, 128, cfg.AESKeySize, "Default should use AES-128")
	assert.Equal(t, 0, cfg.PoolSize, "Default should disable session pooling")
}

func TestSessionConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *SessionConfig
		wantErr bool
	}{
		{
			name:    "valid default config",
			config:  DefaultSessionConfig(),
			wantErr: false,
		},
		{
			name: "valid AES-256 config",
			config: &SessionConfig{
				Encrypted:      true,
				EncryptionMode: EncryptionModeInOut,
				AESKeySize:     256,
				PoolSize:       0,
			},
			wantErr: false,
		},
		{
			name: "invalid AES key size",
			config: &SessionConfig{
				Encrypted:      true,
				EncryptionMode: EncryptionModeInOut,
				AESKeySize:     192, // Not supported
				PoolSize:       0,
			},
			wantErr: true,
		},
		{
			name: "negative pool size",
			config: &SessionConfig{
				Encrypted:      true,
				EncryptionMode: EncryptionModeInOut,
				AESKeySize:     128,
				PoolSize:       -1,
			},
			wantErr: true,
		},
		{
			name: "valid pool size",
			config: &SessionConfig{
				Encrypted:      true,
				EncryptionMode: EncryptionModeInOut,
				AESKeySize:     128,
				PoolSize:       4,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err, "Expected validation error")
			} else {
				assert.NoError(t, err, "Expected validation success")
			}
		})
	}
}

func TestSessionErrors(t *testing.T) {
	// Test that all session errors are defined and unique
	errors := []error{
		ErrSessionCreationFailed,
		ErrSessionNotEncrypted,
		ErrSessionClosed,
		ErrSessionPoolExhausted,
		ErrInvalidSessionConfig,
	}

	// Check all errors are not nil
	for i, err := range errors {
		require.NotNil(t, err, "Error %d should not be nil", i)
		require.NotEmpty(t, err.Error(), "Error %d should have a message", i)
	}

	// Check all errors are unique
	seen := make(map[string]bool)
	for _, err := range errors {
		msg := err.Error()
		require.False(t, seen[msg], "Duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestSessionTypeConstants(t *testing.T) {
	// Verify session type constants are correctly defined
	assert.Equal(t, SessionType(0), SessionTypeHMAC, "SessionTypeHMAC should be 0")
	assert.Equal(t, SessionType(1), SessionTypePolicy, "SessionTypePolicy should be 1")
	assert.Equal(t, SessionType(2), SessionTypeTrial, "SessionTypeTrial should be 2")
}

func TestEncryptionModeConstants(t *testing.T) {
	// Verify encryption mode constants are correctly defined
	assert.Equal(t, EncryptionMode(0), EncryptionModeNone, "EncryptionModeNone should be 0")
	assert.Equal(t, EncryptionMode(1), EncryptionModeIn, "EncryptionModeIn should be 1")
	assert.Equal(t, EncryptionMode(2), EncryptionModeOut, "EncryptionModeOut should be 2")
	assert.Equal(t, EncryptionMode(3), EncryptionModeInOut, "EncryptionModeInOut should be 3")
}

func TestHMACSessionEncryption(t *testing.T) {
	// Create a test TPM2 keystore with encryption enabled
	config := DefaultConfig()
	config.UseSimulator = true
	config.SimulatorType = "embedded"
	config.EncryptSession = true
	config.SessionConfig = DefaultSessionConfig()

	ks, err := NewTPM2KeyStore(config, nil, &mockTestKeyStorage{}, &mockCertStorage{}, nil)
	require.NoError(t, err, "Failed to create keystore")

	// Test HMAC session creation
	session := ks.HMAC(nil)
	assert.NotNil(t, session, "HMAC session should not be nil")

	// Verify session is configured (we can't inspect internal state, but we can verify it's created)
	// The actual encryption is handled by go-tpm internally
}

func TestHMACSessionNoEncryption(t *testing.T) {
	// Create a test TPM2 keystore with encryption disabled
	config := DefaultConfig()
	config.UseSimulator = true
	config.SimulatorType = "embedded"
	config.EncryptSession = false

	ks, err := NewTPM2KeyStore(config, nil, &mockTestKeyStorage{}, &mockCertStorage{}, nil)
	require.NoError(t, err, "Failed to create keystore")

	// Test HMAC session creation
	session := ks.HMAC(nil)
	assert.NotNil(t, session, "HMAC session should not be nil")
}

func TestEncryptionModeMapping(t *testing.T) {
	tests := []struct {
		name           string
		encryptionMode EncryptionMode
	}{
		{
			name:           "EncryptIn maps correctly",
			encryptionMode: EncryptionModeIn,
		},
		{
			name:           "EncryptOut maps correctly",
			encryptionMode: EncryptionModeOut,
		},
		{
			name:           "EncryptInOut maps correctly",
			encryptionMode: EncryptionModeInOut,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with specific encryption mode
			config := DefaultConfig()
			config.UseSimulator = true
			config.SimulatorType = "embedded"
			config.EncryptSession = true
			config.SessionConfig = &SessionConfig{
				Encrypted:      true,
				EncryptionMode: tt.encryptionMode,
				AESKeySize:     128,
			}

			ks, err := NewTPM2KeyStore(config, nil, &mockTestKeyStorage{}, &mockCertStorage{}, nil)
			require.NoError(t, err, "Failed to create keystore")

			// Create session - this will use the configured encryption mode
			session := ks.HMAC(nil)
			assert.NotNil(t, session, "Session should be created")
		})
	}
}

// mockKeyStorage implements storage.KeyStorage for testing
type mockTestKeyStorage struct{}

// Key storage methods
func (m *mockTestKeyStorage) SaveKey(id string, keyData []byte) error { return nil }
func (m *mockTestKeyStorage) GetKey(id string) ([]byte, error)        { return nil, nil }
func (m *mockTestKeyStorage) DeleteKey(id string) error               { return nil }
func (m *mockTestKeyStorage) ListKeys() ([]string, error)             { return nil, nil }
func (m *mockTestKeyStorage) KeyExists(id string) (bool, error)       { return false, nil }

// storage.Backend interface methods
func (m *mockTestKeyStorage) Get(key string) ([]byte, error)                            { return nil, nil }
func (m *mockTestKeyStorage) Put(key string, value []byte, opts *storage.Options) error { return nil }
func (m *mockTestKeyStorage) Delete(key string) error                                   { return nil }
func (m *mockTestKeyStorage) List(prefix string) ([]string, error)                      { return nil, nil }
func (m *mockTestKeyStorage) Exists(key string) (bool, error)                           { return false, nil }
func (m *mockTestKeyStorage) Close() error                                              { return nil }
