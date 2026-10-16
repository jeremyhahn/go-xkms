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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestLoadTPMConfig_NoFile verifies that loadTPMConfig returns DefaultTPMConfig
// when no config file exists at any candidate path.
func TestLoadTPMConfig_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	cfg := loadTPMConfig(testLogger())

	assert.Equal(t, xkms.DefaultTPMConfig.Device, cfg.Device)
	assert.Equal(t, xkms.DefaultTPMConfig.Hash, cfg.Hash)
	assert.Equal(t, xkms.DefaultTPMConfig.UseSimulator, cfg.UseSimulator)
	assert.NotNil(t, cfg.EK)
	assert.Equal(t, xkms.DefaultTPMConfig.EK.Handle, cfg.EK.Handle)
}

// TestLoadTPMConfig_WithFile verifies that loadTPMConfig reads a config file
// and correctly overrides default values.
func TestLoadTPMConfig_WithFile(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	require.NoError(t, os.MkdirAll(tmpDir, 0700))

	configYAML := `
tpm:
  device: /dev/tpm0
  hash: SHA-384
  entropy: true
  platform-pcrs: [7, 14]
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
		filepath.Join(tmpDir, "xkey.yaml"),
		[]byte(configYAML),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	assert.Equal(t, "/dev/tpm0", cfg.Device)
	assert.Equal(t, "SHA-384", cfg.Hash)
	assert.True(t, cfg.UseEntropy)
	assert.Equal(t, xkms.TPMPCRSet{7, 14}, cfg.PlatformPCRs)
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
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	require.NoError(t, os.MkdirAll(tmpDir, 0700))

	// Only override hash; everything else should remain at defaults.
	configYAML := `
tpm:
  hash: SHA-512
`
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "xkey.yaml"),
		[]byte(configYAML),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	// Overridden field.
	assert.Equal(t, "SHA-512", cfg.Hash)

	// Default fields should be preserved.
	assert.Equal(t, xkms.DefaultTPMConfig.Device, cfg.Device)
	assert.Equal(t, xkms.DefaultTPMConfig.PlatformPCRs, cfg.PlatformPCRs)
	assert.Equal(t, xkms.DefaultTPMConfig.PlatformPCRBank, cfg.PlatformPCRBank)
	assert.NotNil(t, cfg.EK)
	assert.Equal(t, xkms.DefaultTPMConfig.EK.Handle, cfg.EK.Handle)
	assert.NotNil(t, cfg.SSRK)
	assert.Equal(t, xkms.DefaultTPMConfig.SSRK.Handle, cfg.SSRK.Handle)
}

// TestLoadTPMConfig_InvalidYAML verifies that loadTPMConfig returns
// DefaultTPMConfig when the config file contains invalid YAML.
func TestLoadTPMConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "xkey.yaml"),
		[]byte("{{{{not valid yaml!!!!"),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	assert.Equal(t, xkms.DefaultTPMConfig.Device, cfg.Device)
	assert.Equal(t, xkms.DefaultTPMConfig.Hash, cfg.Hash)
	assert.NotNil(t, cfg.EK)
	assert.Equal(t, xkms.DefaultTPMConfig.EK.Handle, cfg.EK.Handle)
}

// TestLoadTPMConfig_RefusedPlatformPCRs verifies a sealing PCR set holding
// resettable PCR 16 is refused at parse time and never reaches the TPM
// config: the loader keeps the default set.
func TestLoadTPMConfig_RefusedPlatformPCRs(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "xkey.yaml"),
		[]byte("tpm:\n  platform-pcrs: [7, 16]\n"),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	assert.Equal(t, xkms.DefaultPlatformPCRs(), cfg.PlatformPCRs)
}

// TestLoadTPMConfig_MissingUserConfig verifies that loadTPMConfig returns
// DefaultTPMConfig when the resolved config path does not exist. loadTPMConfig
// consults config.ConfigPath() only; it has no /etc fallback, so the config
// directory is redirected into a temp dir and left empty.
func TestLoadTPMConfig_MissingUserConfig(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	cfg := loadTPMConfig(testLogger())
	assert.Equal(t, xkms.DefaultTPMConfig.Device, cfg.Device)
	assert.Equal(t, xkms.DefaultTPMConfig.Hash, cfg.Hash)
	assert.NotNil(t, cfg.EK)
}

// TestLoadTPMConfig_NoTPMSection verifies that a config file without a "tpm"
// section returns DefaultTPMConfig.
func TestLoadTPMConfig_NoTPMSection(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "xkey.yaml"),
		[]byte("other:\n  key: value\n"),
		0600,
	))

	cfg := loadTPMConfig(testLogger())

	// All defaults should be preserved since "tpm" section is missing.
	assert.Equal(t, xkms.DefaultTPMConfig.Device, cfg.Device)
	assert.Equal(t, xkms.DefaultTPMConfig.Hash, cfg.Hash)
	assert.NotNil(t, cfg.EK)
}

// TestMergeTPMConfig verifies the merge behavior for each field category.
func TestMergeTPMConfig(t *testing.T) {
	defaults := xkms.DefaultTPMConfig

	t.Run("empty file config preserves defaults", func(t *testing.T) {
		merged := mergeTPMConfig(defaults, xkms.TPMConfig{})

		assert.Equal(t, defaults.Device, merged.Device)
		assert.Equal(t, defaults.Hash, merged.Hash)
		assert.Equal(t, defaults.PlatformPCRs, merged.PlatformPCRs)
		assert.Equal(t, defaults.PlatformPCRBank, merged.PlatformPCRBank)
		assert.NotNil(t, merged.EK)
		assert.Equal(t, defaults.EK.Handle, merged.EK.Handle)
		assert.NotNil(t, merged.SSRK)
		assert.NotNil(t, merged.PlatformSRK)
		assert.NotNil(t, merged.IAK)
		assert.NotNil(t, merged.IDevID)
	})

	t.Run("string fields override", func(t *testing.T) {
		file := xkms.TPMConfig{
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
		file := xkms.TPMConfig{
			UseSimulator: true,
			UseEntropy:   true,
		}
		merged := mergeTPMConfig(defaults, file)

		assert.True(t, merged.UseSimulator)
		assert.True(t, merged.UseEntropy)
	})

	t.Run("sealing PCR set overrides when set", func(t *testing.T) {
		file := xkms.TPMConfig{
			PlatformPCRs: xkms.TPMPCRSet{7, 14},
		}
		merged := mergeTPMConfig(defaults, file)

		assert.Equal(t, xkms.TPMPCRSet{7, 14}, merged.PlatformPCRs)
	})

	t.Run("slice fields override when non-empty", func(t *testing.T) {
		file := xkms.TPMConfig{
			GoldenPCRs: []uint{0, 7, 14},
		}
		merged := mergeTPMConfig(defaults, file)

		assert.Equal(t, []uint{0, 7, 14}, merged.GoldenPCRs)
	})

	t.Run("sub-configs merge field-by-field when present", func(t *testing.T) {
		customEK := &xkms.EKConfig{
			Handle:       0x81010002,
			KeyAlgorithm: "ECDSA",
			ECCConfig:    &xkms.ECCConfig{Curve: "P-256"},
		}
		customSRK := &xkms.PlatformSRKConfig{
			SRKHandle:      0x81000003,
			PlatformPolicy: true,
		}
		file := xkms.TPMConfig{
			EK:          customEK,
			PlatformSRK: customSRK,
		}
		merged := mergeTPMConfig(defaults, file)

		// Non-zero fields from file override defaults.
		assert.Equal(t, uint32(0x81010002), merged.EK.Handle)
		assert.Equal(t, "ECDSA", merged.EK.KeyAlgorithm)
		assert.Equal(t, &xkms.ECCConfig{Curve: "P-256"}, merged.EK.ECCConfig)
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
	defaults := xkms.TPMConfig{
		UseSimulator: true,
		UseEntropy:   true,
	}
	file := xkms.TPMConfig{
		UseSimulator: false,
		UseEntropy:   false,
	}
	merged := mergeTPMConfig(defaults, file)

	assert.False(t, merged.UseSimulator)
	assert.False(t, merged.UseEntropy)
}

// TestMergeTPMConfig_DoesNotMutateDefaults verifies merging a file EK never
// writes through the defaults' EK pointer: callers pass the package-level
// xkms.DefaultTPMConfig, and a write-through would leak one config file's EK
// handle into every later default.
func TestMergeTPMConfig_DoesNotMutateDefaults(t *testing.T) {
	defaults := xkms.DefaultTPMConfig
	before := *defaults.EK

	merged := mergeTPMConfig(defaults, xkms.TPMConfig{
		EK: &xkms.EKConfig{Handle: 0x81010002, CertHandle: 0x01C0000A, KeyAlgorithm: "ECDSA"},
	})

	assert.Equal(t, uint32(0x81010002), merged.EK.Handle)
	assert.Equal(t, before, *defaults.EK, "the defaults' EK must be unchanged by the merge")
	assert.Equal(t, before, *xkms.DefaultTPMConfig.EK, "the package-level default EK must be unchanged")
}

// TestMergeTPMConfig_EKFieldsAndSubConfigs covers the EK fields the main
// table leaves out and the sub-configs a file replaces wholesale.
func TestMergeTPMConfig_EKFieldsAndSubConfigs(t *testing.T) {
	t.Run("file EK is used when defaults have none", func(t *testing.T) {
		fileEK := &xkms.EKConfig{Handle: 0x81010001}

		merged := mergeTPMConfig(xkms.TPMConfig{}, xkms.TPMConfig{EK: fileEK})

		assert.Same(t, fileEK, merged.EK)
	})

	t.Run("EK cert handle, hierarchy auth, RSA config and debug override", func(t *testing.T) {
		auth := &xkms.SecretValue{Raw: "owner-auth"}
		rsa := &xkms.RSAConfig{}

		merged := mergeTPMConfig(xkms.DefaultTPMConfig, xkms.TPMConfig{
			EK: &xkms.EKConfig{CertHandle: 0x01C00002, HierarchyAuth: auth, RSAConfig: rsa, Debug: true},
		})

		assert.Equal(t, uint32(0x01C00002), merged.EK.CertHandle)
		assert.Same(t, auth, merged.EK.HierarchyAuth)
		assert.Same(t, rsa, merged.EK.RSAConfig)
		assert.True(t, merged.EK.Debug)
		assert.Equal(t, xkms.DefaultTPMConfig.EK.Handle, merged.EK.Handle, "an unset handle keeps the default")
	})

	t.Run("empty hierarchy auth keeps the default", func(t *testing.T) {
		merged := mergeTPMConfig(xkms.DefaultTPMConfig, xkms.TPMConfig{
			EK: &xkms.EKConfig{HierarchyAuth: &xkms.SecretValue{}},
		})

		assert.Equal(t, xkms.DefaultTPMConfig.EK.HierarchyAuth, merged.EK.HierarchyAuth)
	})

	t.Run("SSRK, IAK and IDevID are replaced wholesale", func(t *testing.T) {
		ssrk := &xkms.SRKConfig{}
		iak := &xkms.IAKConfig{}
		idevid := &xkms.IDevIDConfig{}

		merged := mergeTPMConfig(xkms.DefaultTPMConfig, xkms.TPMConfig{SSRK: ssrk, IAK: iak, IDevID: idevid})

		assert.Same(t, ssrk, merged.SSRK)
		assert.Same(t, iak, merged.IAK)
		assert.Same(t, idevid, merged.IDevID)
	})
}
