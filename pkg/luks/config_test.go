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
	"crypto/fips140"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultKDF_Standard(t *testing.T) {
	assert.Equal(t, KDFArgon2id, DefaultKDF(),
		"DefaultKDF must return argon2id when FIPS mode is not active")
}

// TestDefaultKDF_FIPS is the compliance assertion for go-xkms #21: DefaultKDF
// selects pbkdf2 because crypto/fips140.Enabled is true, not because of a
// GOFIPS140 environment variable this package used to read itself.
// crypto/fips140.Enabled is fixed when the process starts, so this re-execs
// under GODEBUG=fips140=on, mirroring
// pkg/quantum/mlkem512.TestNewAndCreate_RefuseUnderFIPS.
func TestDefaultKDF_FIPS(t *testing.T) {
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		if !fips140.Enabled() {
			t.Fatal("child process is not FIPS-active; GODEBUG=fips140=on was not honored")
		}
		if got := DefaultKDF(); got != KDFPBKDF2 {
			t.Fatalf("DefaultKDF() = %q, want %q under GODEBUG=fips140=on", got, KDFPBKDF2)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestDefaultKDF_FIPS", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=on subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=on subprocess did not pass:\n%s", out)
	}
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
	cfg := &VolumeConfig{
		LUKSPath:   "/tmp/test.luks",
		MountPoint: "/mnt/test",
		MapperName: "xkms-test",
	}
	cfg.SetDefaults()
	assert.Equal(t, KDFArgon2id, cfg.KDF,
		"SetDefaults must fill KDF with argon2id in standard mode")
}

// TestVolumeConfig_SetDefaults_FillsKDF_FIPS re-execs under GODEBUG=
// fips140=on for the same reason TestDefaultKDF_FIPS does (go-xkms #21).
func TestVolumeConfig_SetDefaults_FillsKDF_FIPS(t *testing.T) {
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		if !fips140.Enabled() {
			t.Fatal("child process is not FIPS-active; GODEBUG=fips140=on was not honored")
		}
		cfg := &VolumeConfig{
			LUKSPath:   "/tmp/test.luks",
			MountPoint: "/mnt/test",
			MapperName: "xkms-test",
		}
		cfg.SetDefaults()
		if cfg.KDF != KDFPBKDF2 {
			t.Fatalf("SetDefaults() filled KDF=%q under GODEBUG=fips140=on, want %q", cfg.KDF, KDFPBKDF2)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestVolumeConfig_SetDefaults_FillsKDF_FIPS", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=on subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=on subprocess did not pass:\n%s", out)
	}
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

// ---------------------------------------------------------------------------
// SealParent
// ---------------------------------------------------------------------------

func TestSealParent_String(t *testing.T) {
	assert.Equal(t, "psrk", SealParentPSRK.String())
	assert.Equal(t, "ssrk", SealParentSSRK.String())
	assert.Equal(t, "invalid", SealParent(99).String())
}

func TestSealParent_Validate(t *testing.T) {
	require.NoError(t, SealParentPSRK.Validate())
	require.NoError(t, SealParentSSRK.Validate())

	err := SealParent(99).Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSealParent)
	var target *SealParentInvalidError
	require.ErrorAs(t, err, &target)
	assert.Equal(t, uint8(99), target.Value)
}

func TestParseSealParent(t *testing.T) {
	cases := []struct {
		in   string
		want SealParent
	}{
		{"", SealParentPSRK},
		{"psrk", SealParentPSRK},
		{"PSRK", SealParentPSRK},
		{"  ssrk  ", SealParentSSRK},
		{"SSRK", SealParentSSRK},
	}
	for _, tc := range cases {
		got, err := ParseSealParent(tc.in)
		require.NoError(t, err, "input %q", tc.in)
		assert.Equal(t, tc.want, got, "input %q", tc.in)
	}
}

func TestParseSealParent_Invalid(t *testing.T) {
	_, err := ParseSealParent("shared")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSealParent)
	var target *SealParentInvalidError
	require.ErrorAs(t, err, &target)
	assert.Equal(t, "shared", target.Raw)
}

// ---------------------------------------------------------------------------
// TPMSealerConfig
// ---------------------------------------------------------------------------

func TestTPMSealerConfig_SetDefaults(t *testing.T) {
	cfg := &TPMSealerConfig{}
	cfg.SetDefaults()
	assert.Equal(t, "sha256", cfg.PCRBank)
}

func TestTPMSealerConfig_SetDefaults_PreservesExplicitBank(t *testing.T) {
	cfg := &TPMSealerConfig{PCRBank: "sha384"}
	cfg.SetDefaults()
	assert.Equal(t, "sha384", cfg.PCRBank)
}

func TestTPMSealerConfig_Validate_Valid(t *testing.T) {
	cfg := &TPMSealerConfig{Parent: SealParentSSRK, PCRBank: "sha512"}
	require.NoError(t, cfg.Validate())
}

func TestTPMSealerConfig_Validate_EmptyBankAllowed(t *testing.T) {
	cfg := &TPMSealerConfig{Parent: SealParentPSRK}
	require.NoError(t, cfg.Validate())
}

func TestTPMSealerConfig_Validate_InvalidParent(t *testing.T) {
	cfg := &TPMSealerConfig{Parent: SealParent(7)}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSealParent)
}

func TestTPMSealerConfig_Validate_InvalidBank(t *testing.T) {
	cfg := &TPMSealerConfig{PCRBank: "sha3"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPCRBank)
}
