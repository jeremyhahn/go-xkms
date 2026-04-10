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

package luks

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultKDF_Standard(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "")
	assert.Equal(t, KDFArgon2id, DefaultKDF(),
		"DefaultKDF must return argon2id when FIPS mode is not active")
}

func TestDefaultKDF_FIPS(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "v1.0.0")
	assert.Equal(t, KDFPBKDF2, DefaultKDF(),
		"DefaultKDF must return pbkdf2 when FIPS mode is active")
}

func TestVolumeConfig_Validate_Valid(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
		KDF:        KDFArgon2id,
	}
	require.NoError(t, cfg.Validate())
}

func TestVolumeConfig_Validate_ValidNoKDF(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
	}
	require.NoError(t, cfg.Validate(),
		"Validate must accept empty KDF because SetDefaults fills it later")
}

func TestVolumeConfig_Validate_EmptyLUKSPath(t *testing.T) {
	cfg := &VolumeConfig{
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestVolumeConfig_Validate_EmptyMountPoint(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MapperName: "xkms-test",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestVolumeConfig_Validate_EmptyMapperName(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestVolumeConfig_Validate_InvalidKDF(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
		KDF:        "scrypt",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKDF)
}

func TestVolumeConfig_Validate_ValidPBKDF2(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
		KDF:        KDFPBKDF2,
	}
	require.NoError(t, cfg.Validate())
}

func TestVolumeConfig_SetDefaults_FillsKDF(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "")
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
	}
	cfg.SetDefaults()
	assert.Equal(t, KDFArgon2id, cfg.KDF,
		"SetDefaults must fill KDF with argon2id in standard mode")
}

func TestVolumeConfig_SetDefaults_FillsKDF_FIPS(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "v1.0.0")
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
	}
	cfg.SetDefaults()
	assert.Equal(t, KDFPBKDF2, cfg.KDF,
		"SetDefaults must fill KDF with pbkdf2 in FIPS mode")
}

func TestVolumeConfig_SetDefaults_FillsIterTime(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
	}
	cfg.SetDefaults()
	assert.Equal(t, 2000, cfg.PBKDFIterTime,
		"SetDefaults must set PBKDFIterTime to 2000 when zero")
}

func TestVolumeConfig_SetDefaults_PreservesExistingKDF(t *testing.T) {
	t.Setenv(fips.EnvGOFIPS140, "")
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
		KDF:        KDFPBKDF2,
	}
	cfg.SetDefaults()
	assert.Equal(t, KDFPBKDF2, cfg.KDF,
		"SetDefaults must not overwrite an explicitly set KDF")
}

func TestVolumeConfig_SetDefaults_PreservesExistingIterTime(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:      "/tmp/test.luks",
		MountPoint:    "/mnt/test",
		MapperName:    "xkms-test",
		PBKDFIterTime: 5000,
	}
	cfg.SetDefaults()
	assert.Equal(t, 5000, cfg.PBKDFIterTime,
		"SetDefaults must not overwrite an explicitly set PBKDFIterTime")
}
