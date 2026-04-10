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

package authenticator

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeConfigHash(t *testing.T) {
	t.Run("returns 32-byte hash for valid config", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		hash, err := ComputeConfigHash(cfg)
		require.NoError(t, err)
		require.NotNil(t, hash)
		require.Len(t, hash, 32, "SHA-256 hash must be 32 bytes")
	})

	t.Run("same config produces same hash (deterministic)", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		hash1, err := ComputeConfigHash(cfg)
		require.NoError(t, err)

		hash2, err := ComputeConfigHash(cfg)
		require.NoError(t, err)

		require.True(t, bytes.Equal(hash1, hash2), "hashes should be identical for same config")
	})

	t.Run("different MinPINLength produces different hash", func(t *testing.T) {
		cfg1 := DefaultConfig()
		cfg1.Storage = NewMemoryStorage()
		cfg1.PINMinLength = 4

		cfg2 := DefaultConfig()
		cfg2.Storage = NewMemoryStorage()
		cfg2.PINMinLength = 8

		hash1, err := ComputeConfigHash(cfg1)
		require.NoError(t, err)

		hash2, err := ComputeConfigHash(cfg2)
		require.NoError(t, err)

		require.False(t, bytes.Equal(hash1, hash2), "different MinPINLength should produce different hashes")
	})

	t.Run("different AlwaysUV produces different hash", func(t *testing.T) {
		cfg1 := DefaultConfig()
		cfg1.Storage = NewMemoryStorage()
		cfg1.AlwaysUV = false

		cfg2 := DefaultConfig()
		cfg2.Storage = NewMemoryStorage()
		cfg2.AlwaysUV = true

		hash1, err := ComputeConfigHash(cfg1)
		require.NoError(t, err)

		hash2, err := ComputeConfigHash(cfg2)
		require.NoError(t, err)

		require.False(t, bytes.Equal(hash1, hash2), "different AlwaysUV should produce different hashes")
	})

	t.Run("nil config returns ErrDeviceConfigNilConfig", func(t *testing.T) {
		hash, err := ComputeConfigHash(nil)
		require.ErrorIs(t, err, ErrDeviceConfigNilConfig)
		require.Nil(t, hash)
	})
}

func TestBuildDeviceConfigExtension(t *testing.T) {
	t.Run("builds extension with correct MinPINLength", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()
		cfg.PINMinLength = 6

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)
		require.NotNil(t, ext)
		require.Equal(t, 6, ext.MinPINLength)
	})

	t.Run("builds extension with correct AlwaysUV", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()
		cfg.AlwaysUV = true

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)
		require.NotNil(t, ext)
		require.True(t, ext.AlwaysUV)
	})

	t.Run("builds extension with PINProtocol", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)
		require.NotNil(t, ext)
		require.Equal(t, PINProtocolVersion1, ext.PINProtocol)
	})

	t.Run("builds extension with nil attestedHash (tampered=false)", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)
		require.NotNil(t, ext)
		require.Nil(t, ext.AttestedHash)
		require.NotNil(t, ext.CurrentHash)
		require.False(t, ext.Tampered, "should not be tampered when no attested hash is provided")
	})

	t.Run("builds extension with matching attestedHash (tampered=false)", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		// Compute the attested hash from the same config
		attestedHash, err := ComputeConfigHash(cfg)
		require.NoError(t, err)

		ext, err := BuildDeviceConfigExtension(cfg, attestedHash)
		require.NoError(t, err)
		require.NotNil(t, ext)
		require.True(t, bytes.Equal(attestedHash, ext.AttestedHash))
		require.True(t, bytes.Equal(ext.AttestedHash, ext.CurrentHash))
		require.False(t, ext.Tampered, "should not be tampered when hashes match")
	})

	t.Run("builds extension with mismatched attestedHash (tampered=true)", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()
		cfg.PINMinLength = 4

		// Compute attested hash from original config
		attestedHash, err := ComputeConfigHash(cfg)
		require.NoError(t, err)

		// Modify config to simulate tampering
		cfg.PINMinLength = 8

		ext, err := BuildDeviceConfigExtension(cfg, attestedHash)
		require.NoError(t, err)
		require.NotNil(t, ext)
		require.True(t, bytes.Equal(attestedHash, ext.AttestedHash))
		require.False(t, bytes.Equal(ext.AttestedHash, ext.CurrentHash))
		require.True(t, ext.Tampered, "should be tampered when hashes do not match")
	})

	t.Run("nil config returns ErrDeviceConfigNilConfig", func(t *testing.T) {
		ext, err := BuildDeviceConfigExtension(nil, nil)
		require.ErrorIs(t, err, ErrDeviceConfigNilConfig)
		require.Nil(t, ext)
	})
}

func TestDeviceConfigExtension_Encode(t *testing.T) {
	t.Run("encodes to valid CBOR", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		encoded, err := ext.Encode()
		require.NoError(t, err)
		require.NotNil(t, encoded)
		require.Greater(t, len(encoded), 0, "encoded data should not be empty")
	})

	t.Run("encoded data can be decoded back", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()
		cfg.PINMinLength = 6
		cfg.AlwaysUV = true

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		encoded, err := ext.Encode()
		require.NoError(t, err)

		decoded, err := DecodeDeviceConfigExtension(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)

		require.Equal(t, ext.MinPINLength, decoded.MinPINLength)
		require.Equal(t, ext.AlwaysUV, decoded.AlwaysUV)
		require.Equal(t, ext.PINProtocol, decoded.PINProtocol)
		require.True(t, bytes.Equal(ext.CurrentHash, decoded.CurrentHash))
		require.Equal(t, ext.Tampered, decoded.Tampered)
	})

	t.Run("nil extension returns error", func(t *testing.T) {
		var ext *DeviceConfigExtension
		encoded, err := ext.Encode()
		require.ErrorIs(t, err, ErrDeviceConfigEncodingFailed)
		require.Nil(t, encoded)
	})
}

func TestDeviceConfigExtension_IsValid(t *testing.T) {
	t.Run("returns true when not tampered", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		attestedHash, err := ComputeConfigHash(cfg)
		require.NoError(t, err)

		ext, err := BuildDeviceConfigExtension(cfg, attestedHash)
		require.NoError(t, err)

		require.True(t, ext.IsValid(), "should be valid when not tampered")
	})

	t.Run("returns false when tampered", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()
		cfg.PINMinLength = 4

		// Compute attested hash
		attestedHash, err := ComputeConfigHash(cfg)
		require.NoError(t, err)

		// Modify config to cause tampering
		cfg.PINMinLength = 8

		ext, err := BuildDeviceConfigExtension(cfg, attestedHash)
		require.NoError(t, err)

		require.False(t, ext.IsValid(), "should be invalid when tampered")
	})

	t.Run("returns false for nil extension", func(t *testing.T) {
		var ext *DeviceConfigExtension
		require.False(t, ext.IsValid(), "nil extension should not be valid")
	})
}

func TestDecodeDeviceConfigExtension(t *testing.T) {
	t.Run("decodes valid CBOR to extension", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()
		cfg.PINMinLength = 5
		cfg.AlwaysUV = true

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		encoded, err := ext.Encode()
		require.NoError(t, err)

		decoded, err := DecodeDeviceConfigExtension(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		require.Equal(t, 5, decoded.MinPINLength)
		require.True(t, decoded.AlwaysUV)
		require.Equal(t, PINProtocolVersion1, decoded.PINProtocol)
	})

	t.Run("empty data returns error", func(t *testing.T) {
		decoded, err := DecodeDeviceConfigExtension([]byte{})
		require.ErrorIs(t, err, ErrDeviceConfigEncodingFailed)
		require.Nil(t, decoded)
	})

	t.Run("invalid CBOR returns error", func(t *testing.T) {
		invalidCBOR := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		decoded, err := DecodeDeviceConfigExtension(invalidCBOR)
		require.ErrorIs(t, err, ErrDeviceConfigEncodingFailed)
		require.Nil(t, decoded)
	})
}

func TestDeviceConfigExtension_VendorExtensions(t *testing.T) {
	t.Run("WithVendorExtension adds vendor data", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		result := ext.WithVendorExtension("com.example.feature", "enabled")
		require.NotNil(t, result)
		require.Same(t, ext, result, "should return same extension for chaining")
		require.NotNil(t, ext.Vendor)
		require.Equal(t, "enabled", ext.Vendor["com.example.feature"])
	})

	t.Run("HasVendorExtension returns true for existing key", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		ext.WithVendorExtension("com.test.key", "value")
		require.True(t, ext.HasVendorExtension("com.test.key"))
	})

	t.Run("HasVendorExtension returns false for missing key", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		require.False(t, ext.HasVendorExtension("nonexistent.key"))
	})

	t.Run("GetVendorExtension returns correct value", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		ext.WithVendorExtension("com.example.config", map[string]int{"count": 42})
		value := ext.GetVendorExtension("com.example.config")
		require.NotNil(t, value)

		configMap, ok := value.(map[string]int)
		require.True(t, ok)
		require.Equal(t, 42, configMap["count"])
	})

	t.Run("GetVendorExtension returns nil for missing key", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		value := ext.GetVendorExtension("missing.key")
		require.Nil(t, value)
	})

	t.Run("multiple vendor extensions can coexist", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Storage = NewMemoryStorage()

		ext, err := BuildDeviceConfigExtension(cfg, nil)
		require.NoError(t, err)

		ext.WithVendorExtension("com.vendor1.feature", "value1").
			WithVendorExtension("com.vendor2.feature", "value2").
			WithVendorExtension("com.vendor3.feature", 123)

		require.True(t, ext.HasVendorExtension("com.vendor1.feature"))
		require.True(t, ext.HasVendorExtension("com.vendor2.feature"))
		require.True(t, ext.HasVendorExtension("com.vendor3.feature"))

		require.Equal(t, "value1", ext.GetVendorExtension("com.vendor1.feature"))
		require.Equal(t, "value2", ext.GetVendorExtension("com.vendor2.feature"))
		require.Equal(t, 123, ext.GetVendorExtension("com.vendor3.feature"))
	})

	t.Run("nil extension handles vendor operations safely", func(t *testing.T) {
		var ext *DeviceConfigExtension

		result := ext.WithVendorExtension("key", "value")
		require.Nil(t, result)

		require.False(t, ext.HasVendorExtension("key"))

		value := ext.GetVendorExtension("key")
		require.Nil(t, value)
	})
}

func TestExtensionDeviceConfig_Constant(t *testing.T) {
	t.Run("ExtensionDeviceConfig equals deviceConfig", func(t *testing.T) {
		require.Equal(t, "deviceConfig", ExtensionDeviceConfig)
	})
}
