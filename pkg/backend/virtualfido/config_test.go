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

package virtualfido

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigValidate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			PIN:           "123456",
			PUK:           "12345678",
			ManagementKey: make([]byte, 24),
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("nil config", func(t *testing.T) {
		var cfg *Config
		err := cfg.Validate()
		assert.Error(t, err)
	})

	t.Run("PIN too short", func(t *testing.T) {
		cfg := &Config{PIN: "123"}
		err := cfg.Validate()
		assert.Error(t, err)
	})

	t.Run("PIN too long", func(t *testing.T) {
		cfg := &Config{PIN: "123456789"}
		err := cfg.Validate()
		assert.Error(t, err)
	})

	t.Run("PUK wrong length", func(t *testing.T) {
		cfg := &Config{PUK: "1234567"} // 7 chars, should be 8
		err := cfg.Validate()
		assert.Error(t, err)
	})

	t.Run("management key wrong size", func(t *testing.T) {
		cfg := &Config{ManagementKey: make([]byte, 16)}
		err := cfg.Validate()
		assert.Error(t, err)
	})

	t.Run("empty PIN is valid (defaults will be set)", func(t *testing.T) {
		cfg := &Config{}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestConfigSetDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.SetDefaults()

	assert.NotEmpty(t, cfg.SerialNumber)
	assert.Equal(t, DefaultManufacturer, cfg.Manufacturer)
	assert.Equal(t, DefaultProduct, cfg.Product)
	assert.Equal(t, DefaultPIN, cfg.PIN)
	assert.Equal(t, DefaultPUK, cfg.PUK)
	assert.NotNil(t, cfg.ManagementKey)
	assert.Len(t, cfg.ManagementKey, ManagementKeySize)
	assert.Equal(t, DefaultPINRetries, cfg.PINRetries)
	assert.Equal(t, DefaultPUKRetries, cfg.PUKRetries)
	assert.True(t, cfg.AutoApprove)
}

func TestConfigSetDefaultsPreservesExisting(t *testing.T) {
	cfg := &Config{
		SerialNumber: "CUSTOM001",
		Manufacturer: "CustomMfg",
		Product:      "CustomProduct",
		PIN:          "654321",
		PUK:          "87654321",
		PINRetries:   5,
		PUKRetries:   5,
	}
	cfg.SetDefaults()

	assert.Equal(t, "CUSTOM001", cfg.SerialNumber)
	assert.Equal(t, "CustomMfg", cfg.Manufacturer)
	assert.Equal(t, "CustomProduct", cfg.Product)
	assert.Equal(t, "654321", cfg.PIN)
	assert.Equal(t, "87654321", cfg.PUK)
	assert.Equal(t, 5, cfg.PINRetries)
	assert.Equal(t, 5, cfg.PUKRetries)
}

func TestGenerateSerialNumber(t *testing.T) {
	sn1 := generateSerialNumber()
	sn2 := generateSerialNumber()

	assert.NotEmpty(t, sn1)
	assert.NotEmpty(t, sn2)
	assert.NotEqual(t, sn1, sn2, "serial numbers should be unique")
	assert.True(t, len(sn1) >= 6)
}

func TestDefaultManagementKey(t *testing.T) {
	key := defaultManagementKey()
	assert.Len(t, key, ManagementKeySize)
}
