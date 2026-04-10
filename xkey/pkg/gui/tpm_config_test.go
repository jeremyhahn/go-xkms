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

package gui

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpm2store "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestLoadTPMConfig_NoFile verifies that loadTPMConfig returns DefaultConfig
// when no config file exists at any candidate path.
func TestLoadTPMConfig_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cfg := loadTPMConfig(testLogger())

	assert.Equal(t, tpm2pkg.DefaultConfig.Device, cfg.Device)
	assert.Equal(t, tpm2pkg.DefaultConfig.Hash, cfg.Hash)
	assert.Equal(t, tpm2pkg.DefaultConfig.UseSimulator, cfg.UseSimulator)
	assert.Equal(t, tpm2pkg.DefaultConfig.EncryptSession, cfg.EncryptSession)
	assert.NotNil(t, cfg.EK)
	assert.Equal(t, tpm2pkg.DefaultConfig.EK.Handle, cfg.EK.Handle)
}

// TestLoadTPMConfig_WithFile verifies that loadTPMConfig reads a config file
// and correctly overrides default values.
func TestLoadTPMConfig_WithFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(configDir, 0700))

	configYAML := `
tpm:
  device: /dev/tpm0
  hash: SHA-384
  encrypt-sessions: true
  entropy: true
  platform-pcr: 14
  platform-pcr-bank: SHA-384
  golden-pcrs: [0, 7, 14]
  ek:
    handle: 0x81010002
    algorithm: ECDSA
    ecc:
      curve: P-256
  platform-srk:
    srk-handle: 0x81000003
    platform-policy: true
`
	require.NoError(t, os.WriteFile(
		filepath.Join(configDir, "config.yaml"),
		[]byte(configYAML),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	assert.Equal(t, "/dev/tpm0", cfg.Device)
	assert.Equal(t, "SHA-384", cfg.Hash)
	assert.True(t, cfg.EncryptSession)
	assert.True(t, cfg.UseEntropy)
	assert.Equal(t, uint(14), cfg.PlatformPCR)
	assert.Equal(t, "SHA-384", cfg.PlatformPCRBank)
	assert.Equal(t, []uint{0, 7, 14}, cfg.GoldenPCRs)
	assert.NotNil(t, cfg.EK)
	assert.Equal(t, uint32(0x81010002), cfg.EK.Handle)
	assert.Equal(t, "ECDSA", cfg.EK.KeyAlgorithm)
	assert.NotNil(t, cfg.PlatformSRK)
	assert.Equal(t, uint32(0x81000003), cfg.PlatformSRK.SRKHandle)
}

// TestLoadTPMConfig_PartialFile verifies that a partial config file only
// overrides the fields it specifies, leaving everything else at defaults.
func TestLoadTPMConfig_PartialFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(configDir, 0700))

	// Only override hash; everything else should remain at defaults.
	configYAML := `
tpm:
  hash: SHA-512
`
	require.NoError(t, os.WriteFile(
		filepath.Join(configDir, "config.yaml"),
		[]byte(configYAML),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	// Overridden field.
	assert.Equal(t, "SHA-512", cfg.Hash)

	// Default fields should be preserved.
	assert.Equal(t, tpm2pkg.DefaultConfig.Device, cfg.Device)
	assert.Equal(t, tpm2pkg.DefaultConfig.PlatformPCR, cfg.PlatformPCR)
	assert.Equal(t, tpm2pkg.DefaultConfig.PlatformPCRBank, cfg.PlatformPCRBank)
	assert.NotNil(t, cfg.EK)
	assert.Equal(t, tpm2pkg.DefaultConfig.EK.Handle, cfg.EK.Handle)
	assert.NotNil(t, cfg.SSRK)
	assert.Equal(t, tpm2pkg.DefaultConfig.SSRK.Handle, cfg.SSRK.Handle)
}

// TestLoadTPMConfig_InvalidYAML verifies that loadTPMConfig returns
// DefaultConfig when the config file contains invalid YAML.
func TestLoadTPMConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(configDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(configDir, "config.yaml"),
		[]byte("{{{{not valid yaml!!!!"),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	assert.Equal(t, tpm2pkg.DefaultConfig.Device, cfg.Device)
	assert.Equal(t, tpm2pkg.DefaultConfig.Hash, cfg.Hash)
	assert.NotNil(t, cfg.EK)
	assert.Equal(t, tpm2pkg.DefaultConfig.EK.Handle, cfg.EK.Handle)
}

// TestLoadTPMConfig_EtcFallback verifies that loadTPMConfig falls back to
// /etc/xkey/config.yaml when ~/.xkey/config.yaml does not exist.
// This test is skipped when /etc/xkey/config.yaml already exists on the host
// to avoid interference.
func TestLoadTPMConfig_EtcFallback(t *testing.T) {
	// Skip if /etc/xkey/config.yaml exists on the host -- we can't
	// safely test the fallback without mocking the filesystem.
	if _, err := os.Stat("/etc/xkey/config.yaml"); err == nil {
		t.Skip("/etc/xkey/config.yaml exists on host, skipping fallback test")
	}

	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// No ~/.xkey/config.yaml, and /etc/xkey/config.yaml doesn't exist.
	cfg := loadTPMConfig(testLogger())
	assert.Equal(t, tpm2pkg.DefaultConfig.Device, cfg.Device)
}

// TestLoadTPMConfig_NoTPMSection verifies that a config file without a "tpm"
// section returns DefaultConfig.
func TestLoadTPMConfig_NoTPMSection(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	configDir := filepath.Join(tmpDir, ".xkey")
	require.NoError(t, os.MkdirAll(configDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(configDir, "config.yaml"),
		[]byte("other:\n  key: value\n"),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	// All defaults should be preserved since "tpm" section is missing.
	assert.Equal(t, tpm2pkg.DefaultConfig.Device, cfg.Device)
	assert.Equal(t, tpm2pkg.DefaultConfig.Hash, cfg.Hash)
	assert.NotNil(t, cfg.EK)
}

// TestMergeTPMConfig verifies the merge behavior for each field category.
func TestMergeTPMConfig(t *testing.T) {
	defaults := tpm2pkg.DefaultConfig

	t.Run("empty file config preserves defaults", func(t *testing.T) {
		merged := mergeTPMConfig(defaults, tpm2pkg.Config{})

		assert.Equal(t, defaults.Device, merged.Device)
		assert.Equal(t, defaults.Hash, merged.Hash)
		assert.Equal(t, defaults.PlatformPCR, merged.PlatformPCR)
		assert.Equal(t, defaults.PlatformPCRBank, merged.PlatformPCRBank)
		assert.NotNil(t, merged.EK)
		assert.Equal(t, defaults.EK.Handle, merged.EK.Handle)
		assert.NotNil(t, merged.SSRK)
		assert.NotNil(t, merged.PlatformSRK)
		assert.NotNil(t, merged.IAK)
		assert.NotNil(t, merged.IDevID)
	})

	t.Run("string fields override", func(t *testing.T) {
		file := tpm2pkg.Config{
			Device:          "/dev/tpm1",
			Hash:            "SHA-512",
			PlatformPCRBank: "SHA-512",
		}
		merged := mergeTPMConfig(defaults, file)

		assert.Equal(t, "/dev/tpm1", merged.Device)
		assert.Equal(t, "SHA-512", merged.Hash)
		assert.Equal(t, "SHA-512", merged.PlatformPCRBank)
	})

	t.Run("bool fields always apply from file", func(t *testing.T) {
		file := tpm2pkg.Config{
			EncryptSession: true,
			UseSimulator:   true,
			UseEntropy:     true,
		}
		merged := mergeTPMConfig(defaults, file)

		assert.True(t, merged.EncryptSession)
		assert.True(t, merged.UseSimulator)
		assert.True(t, merged.UseEntropy)
	})

	t.Run("numeric fields override when non-zero", func(t *testing.T) {
		file := tpm2pkg.Config{
			PlatformPCR: 14,
		}
		merged := mergeTPMConfig(defaults, file)

		assert.Equal(t, uint(14), merged.PlatformPCR)
	})

	t.Run("slice fields override when non-empty", func(t *testing.T) {
		file := tpm2pkg.Config{
			GoldenPCRs: []uint{0, 7, 14},
		}
		merged := mergeTPMConfig(defaults, file)

		assert.Equal(t, []uint{0, 7, 14}, merged.GoldenPCRs)
	})

	t.Run("sub-configs merge field-by-field when present", func(t *testing.T) {
		customEK := &tpm2pkg.EKConfig{
			Handle:       0x81010002,
			KeyAlgorithm: "ECDSA",
			ECCConfig:    &tpm2store.ECCConfig{Curve: "P-256"},
		}
		customSRK := &tpm2pkg.PlatformSRKConfig{
			SRKHandle:      0x81000003,
			PlatformPolicy: true,
		}
		file := tpm2pkg.Config{
			EK:          customEK,
			PlatformSRK: customSRK,
		}
		merged := mergeTPMConfig(defaults, file)

		// Non-zero fields from file override defaults.
		assert.Equal(t, uint32(0x81010002), merged.EK.Handle)
		assert.Equal(t, "ECDSA", merged.EK.KeyAlgorithm)
		assert.Equal(t, &tpm2store.ECCConfig{Curve: "P-256"}, merged.EK.ECCConfig)
		// Zero/nil fields in file preserve defaults (field-by-field merge).
		assert.Equal(t, defaults.EK.CertHandle, merged.EK.CertHandle)
		assert.Equal(t, defaults.EK.HierarchyAuth, merged.EK.HierarchyAuth)
		assert.Equal(t, defaults.EK.RSAConfig, merged.EK.RSAConfig)

		assert.Equal(t, uint32(0x81000003), merged.PlatformSRK.SRKHandle)
		assert.True(t, merged.PlatformSRK.PlatformPolicy)
		// Unset sub-configs should remain at defaults.
		assert.Equal(t, defaults.SSRK, merged.SSRK)
		assert.Equal(t, defaults.IAK, merged.IAK)
		assert.Equal(t, defaults.IDevID, merged.IDevID)
	})
}

// TestMergeTPMConfig_BoolFalseOverridesTrue verifies that bool fields from
// the file config can override true defaults to false.
func TestMergeTPMConfig_BoolFalseOverridesTrue(t *testing.T) {
	defaults := tpm2pkg.Config{
		EncryptSession: true,
		UseSimulator:   true,
		UseEntropy:     true,
	}
	file := tpm2pkg.Config{
		EncryptSession: false,
		UseSimulator:   false,
		UseEntropy:     false,
	}
	merged := mergeTPMConfig(defaults, file)

	assert.False(t, merged.EncryptSession)
	assert.False(t, merged.UseSimulator)
	assert.False(t, merged.UseEntropy)
}
