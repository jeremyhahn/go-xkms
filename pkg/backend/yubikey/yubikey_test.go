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

//go:build yubikey && pkcs11

package yubikey

import (
	"crypto/elliptic"
	"crypto/x509"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getTestConfig returns a YubiKey configuration for testing
func getTestConfig(t *testing.T) (*Config, bool) {
	// Check for YubiKey PKCS#11 library
	yubikeyLib := os.Getenv("YUBIKEY_PKCS11_LIBRARY")
	if yubikeyLib == "" {
		yubikeyLib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
		if _, err := os.Stat(yubikeyLib); os.IsNotExist(err) {
			candidates := []string{
				"/usr/lib/libykcs11.so",
				"/usr/local/lib/libykcs11.so",
				"/usr/local/lib/libykcs11.dylib",
			}

			found := false
			for _, path := range candidates {
				if _, err := os.Stat(path); err == nil {
					yubikeyLib = path
					found = true
					break
				}
			}

			if !found {
				t.Log("YubiKey PKCS#11 library not found")
				return nil, false
			}
		}
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		pin = DefaultPIN
	}

	keyStorage := memory.New()
	certStorage := memory.New()

	config := &Config{
		PIN:           pin,
		ManagementKey: DefaultMgmtKey,
		Library:       yubikeyLib,
		KeyStorage:    keyStorage,
		CertStorage:   certStorage,
	}

	return config, true
}

// TestNewBackend tests YubiKey backend creation
func TestNewBackend(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	require.NotNil(t, backend)

	assert.Equal(t, config, backend.config)
}

// TestNewBackend_NilConfig tests backend creation with nil config
func TestNewBackend_NilConfig(t *testing.T) {
	_, err := NewBackend(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

// TestBackend_Type tests backend type identification
func TestBackend_Type(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	backendType := backend.Type()
	assert.Equal(t, types.BackendType("yubikey"), backendType)
}

// TestBackend_Capabilities tests backend capabilities reporting
func TestBackend_Capabilities(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	caps := backend.Capabilities()
	assert.True(t, caps.Keys, "Should support keys")
	assert.True(t, caps.HardwareBacked, "Should be hardware-backed")
	assert.True(t, caps.Signing, "Should support signing")
	assert.True(t, caps.Decryption, "Should support decryption")
	assert.False(t, caps.SymmetricEncryption, "Should not support symmetric encryption")
	assert.False(t, caps.Import, "Should not support import")
	assert.False(t, caps.Export, "Should not support export")
}

// TestBackend_CNToSlot tests CN to PIV slot mapping
func TestBackend_CNToSlot(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	tests := []struct {
		name     string
		cn       string
		expected PIVSlot
	}{
		{"Authentication prefix", "auth-mykey", SlotAuthentication},
		{"Authentication full", "authentication-mykey", SlotAuthentication},
		{"Signature prefix", "sig-mykey", SlotSignature},
		{"Signature full", "signature-mykey", SlotSignature},
		{"Key management prefix", "keymgmt-mykey", SlotKeyManagement},
		{"Key management full", "keymanagement-mykey", SlotKeyManagement},
		{"Card auth prefix", "card-mykey", SlotCardAuth},
		{"Card auth full", "cardauth-mykey", SlotCardAuth},
		{"Retired 1", "retired1-mykey", SlotRetired1},
		{"Retired 10", "retired10-mykey", SlotRetired10},
		{"Retired 20", "retired20-mykey", SlotRetired20},
		{"Default (no prefix)", "mykey", SlotAuthentication},
		{"Case insensitive", "AUTH-MYKEY", SlotAuthentication},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot := backend.cnToSlot(tt.cn)
			assert.Equal(t, tt.expected, slot, "CN %s should map to slot %s", tt.cn, tt.expected)
		})
	}
}

// TestBackend_PIVSlot tests PIVSlot method
func TestBackend_PIVSlot(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN: "sig-test-key",
	}

	slot := backend.PIVSlot(attrs)
	assert.Equal(t, SlotSignature, slot)
}

// TestBackend_Initialize tests backend initialization
func TestBackend_Initialize(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	err = backend.Initialize()
	require.NoError(t, err)

	// Check that backend is initialized
	backend.mu.RLock()
	initialized := backend.initialized
	backend.mu.RUnlock()
	assert.True(t, initialized)

	// Second initialization should be no-op
	err = backend.Initialize()
	require.NoError(t, err)
}

// TestBackend_Close tests backend cleanup
func TestBackend_Close(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)

	err = backend.Initialize()
	require.NoError(t, err)

	err = backend.Close()
	require.NoError(t, err)

	// Check that backend is not initialized
	backend.mu.RLock()
	initialized := backend.initialized
	backend.mu.RUnlock()
	assert.False(t, initialized)

	// Second close should be safe
	err = backend.Close()
	require.NoError(t, err)
}

// TestBackend_GenerateRSA tests RSA key generation
func TestBackend_GenerateRSA(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	err = backend.Initialize()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "auth-test-rsa",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	key, err := backend.GenerateRSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}

	require.NotNil(t, key)
	defer backend.DeleteKey(attrs)

	// Verify slot mapping
	slot := backend.PIVSlot(attrs)
	assert.Equal(t, SlotAuthentication, slot)
}

// TestBackend_GenerateECDSA tests ECDSA key generation
func TestBackend_GenerateECDSA(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	err = backend.Initialize()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "sig-test-ecdsa",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	key, err := backend.GenerateECDSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Skip("YubiKey PIV slot may be in use or require manual configuration")
		return
	}

	require.NotNil(t, key)
	defer backend.DeleteKey(attrs)

	// Verify slot mapping
	slot := backend.PIVSlot(attrs)
	assert.Equal(t, SlotSignature, slot)
}

// TestBackend_AvailableSlots tests slot enumeration
func TestBackend_AvailableSlots(t *testing.T) {
	config, ok := getTestConfig(t)
	if !ok {
		t.Skip("YubiKey not available")
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	err = backend.Initialize()
	require.NoError(t, err)

	slots, err := backend.AvailableSlots()
	require.NoError(t, err)
	require.NotEmpty(t, slots)

	// Should return all 24 PIV slots
	assert.Equal(t, 24, len(slots), "Should have 24 PIV slots (4 primary + 20 retired)")

	// Verify primary slots are present
	assert.Contains(t, slots, SlotAuthentication)
	assert.Contains(t, slots, SlotSignature)
	assert.Contains(t, slots, SlotKeyManagement)
	assert.Contains(t, slots, SlotCardAuth)
}

// TestConfig_Validate tests configuration validation
func TestConfig_Validate(t *testing.T) {
	keyStorage := memory.New()
	certStorage := memory.New()

	tests := []struct {
		name      string
		config    *Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "Valid config",
			config: &Config{
				PIN:           "123456",
				ManagementKey: make([]byte, 24),
				KeyStorage:    keyStorage,
				CertStorage:   certStorage,
			},
			expectErr: false,
		},
		{
			name: "Missing PIN",
			config: &Config{
				ManagementKey: make([]byte, 24),
				KeyStorage:    keyStorage,
				CertStorage:   certStorage,
			},
			expectErr: true,
			errMsg:    "PIN is required",
		},
		{
			name: "PIN too short",
			config: &Config{
				PIN:           "12345",
				ManagementKey: make([]byte, 24),
				KeyStorage:    keyStorage,
				CertStorage:   certStorage,
			},
			expectErr: true,
			errMsg:    "PIN must be 6-8 characters",
		},
		{
			name: "PIN too long",
			config: &Config{
				PIN:           "123456789",
				ManagementKey: make([]byte, 24),
				KeyStorage:    keyStorage,
				CertStorage:   certStorage,
			},
			expectErr: true,
			errMsg:    "PIN must be 6-8 characters",
		},
		{
			name: "Missing management key",
			config: &Config{
				PIN:         "123456",
				KeyStorage:  keyStorage,
				CertStorage: certStorage,
			},
			expectErr: true,
			errMsg:    "management key is required",
		},
		{
			name: "Invalid management key length",
			config: &Config{
				PIN:           "123456",
				ManagementKey: make([]byte, 16),
				KeyStorage:    keyStorage,
				CertStorage:   certStorage,
			},
			expectErr: true,
			errMsg:    "management key must be 24 bytes",
		},
		{
			name: "Missing key storage",
			config: &Config{
				PIN:           "123456",
				ManagementKey: make([]byte, 24),
				CertStorage:   certStorage,
			},
			expectErr: true,
			errMsg:    "key storage is required",
		},
		{
			name: "Missing cert storage",
			config: &Config{
				PIN:           "123456",
				ManagementKey: make([]byte, 24),
				KeyStorage:    keyStorage,
			},
			expectErr: true,
			errMsg:    "certificate storage is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfig_SetDefaults tests configuration default values
func TestConfig_SetDefaults(t *testing.T) {
	config := &Config{}
	config.SetDefaults()

	assert.Equal(t, DefaultPIN, config.PIN)
	assert.Equal(t, DefaultMgmtKey, config.ManagementKey)
	assert.NotEmpty(t, config.Library)
}
