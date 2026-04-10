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

package services

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStorageService(t *testing.T) {
	svc := NewStorageService()
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestStorageService_SetContext(t *testing.T) {
	svc := NewStorageService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestStorageService_SetElevator(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)
	assert.NotNil(t, svc.elevator)
}

func TestStorageService_GetStatus(t *testing.T) {
	svc := NewStorageService()
	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)

	// Volume path should be populated from defaults.
	assert.NotEmpty(t, status.VolumePath)
	assert.NotEmpty(t, status.MountPoint)

	// No elevator set, so elevation should not be available.
	assert.False(t, status.ElevationAvailable)
}

func TestStorageService_GetStatus_FieldConsistency(t *testing.T) {
	svc := NewStorageService()
	status, err := svc.GetStatus()
	require.NoError(t, err)

	// When the volume does not exist, LUKS/mounted/open must be false.
	if !status.VolumeExists {
		assert.False(t, status.IsLUKS)
		assert.False(t, status.IsMounted)
		assert.False(t, status.IsOpen)
		assert.Zero(t, status.VolumeSizeBytes)
	}
}

func TestStorageService_GetStatus_ElevationAvailable(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.ElevationAvailable)
}

func TestStorageService_GetStatus_ElevationUnavailable(t *testing.T) {
	svc := NewStorageService()
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.ElevationAvailable)
}

func TestStorageService_GetStatus_ElevatorSetButUnavailable(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: false}
	svc.SetElevator(mock)
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.ElevationAvailable)
}

// --- CreateVolume validation tests ---

func TestStorageService_CreateVolume_InvalidSize_Zero(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 0, Passphrase: "strongpassphrase"})
	assert.True(t, errors.Is(err, ErrStorageInvalidSize))
}

func TestStorageService_CreateVolume_InvalidSize_Negative(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: -5, Passphrase: "strongpassphrase"})
	assert.True(t, errors.Is(err, ErrStorageInvalidSize))
}

func TestStorageService_CreateVolume_InvalidSize_TooLarge(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 101, Passphrase: "strongpassphrase"})
	assert.True(t, errors.Is(err, ErrStorageInvalidSize))
}

func TestStorageService_CreateVolume_WeakPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 1, Passphrase: "short"})
	assert.True(t, errors.Is(err, ErrStorageWeakPassphrase))
}

func TestStorageService_CreateVolume_EmptyPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 1, Passphrase: ""})
	assert.True(t, errors.Is(err, ErrStorageWeakPassphrase))
}

func TestStorageService_CreateVolume_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping root-requirement assertion")
		return
	}
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 1, Passphrase: "strongpassphrase"})
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

func TestStorageService_CreateVolume_BoundaryMin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping root-requirement assertion")
		return
	}
	svc := NewStorageService()
	// SizeGB=1 is valid, so it should pass validation and hit the root check.
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 1, Passphrase: "strongpassphrase"})
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

func TestStorageService_CreateVolume_BoundaryMax(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping root-requirement assertion")
		return
	}
	svc := NewStorageService()
	// SizeGB=100 is valid, so it should pass validation and hit the root check.
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 100, Passphrase: "strongpassphrase"})
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

func TestStorageService_CreateVolume_WithElevator(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, output: []byte(`{"status":"ok"}`)}
	svc.SetElevator(mock)
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 1, Passphrase: "strongpassphrase"})
	assert.NoError(t, err)

	// Check the subcommand args prefix.
	require.True(t, len(mock.lastArgs) >= 6, "expected at least 6 args, got %d", len(mock.lastArgs))
	assert.Equal(t, "luks2", mock.lastArgs[0])
	assert.Equal(t, "seal", mock.lastArgs[1])
	assert.Equal(t, "--size", mock.lastArgs[2])
	assert.Equal(t, "1G", mock.lastArgs[3])
	assert.Equal(t, "--skip-migrate", mock.lastArgs[4])
	assert.Equal(t, "--unseal", mock.lastArgs[5])
	// Verify explicit paths are passed to prevent sudo home dir issues.
	assert.Contains(t, mock.lastArgs, "--path")
	assert.Contains(t, mock.lastArgs, "--mount-point")

	assert.Equal(t, []byte("strongpassphrase\nstrongpassphrase\n"), mock.lastData)
}

func TestStorageService_CreateVolume_WithElevatorDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, err: ErrElevationDenied}
	svc.SetElevator(mock)
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 1, Passphrase: "strongpassphrase"})
	assert.True(t, errors.Is(err, ErrElevationDenied))
}

// --- UnlockVolume validation tests ---

func TestStorageService_UnlockVolume_EmptyPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.UnlockVolume("")
	assert.True(t, errors.Is(err, ErrStorageWeakPassphrase))
}

func TestStorageService_UnlockVolume_ShortPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.UnlockVolume("1234567")
	assert.True(t, errors.Is(err, ErrStorageWeakPassphrase))
}

func TestStorageService_UnlockVolume_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping root-requirement assertion")
		return
	}
	svc := NewStorageService()
	err := svc.UnlockVolume("validpassphrase")
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

func TestStorageService_UnlockVolume_WithElevator(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, output: []byte(`{"status":"ok"}`)}
	svc.SetElevator(mock)
	err := svc.UnlockVolume("validpassphrase")
	assert.NoError(t, err)

	// Check the subcommand args prefix.
	require.True(t, len(mock.lastArgs) >= 2, "expected at least 2 args, got %d", len(mock.lastArgs))
	assert.Equal(t, "luks2", mock.lastArgs[0])
	assert.Equal(t, "unseal", mock.lastArgs[1])
	// Verify explicit paths are passed to prevent sudo home dir issues.
	assert.Contains(t, mock.lastArgs, "--path")
	assert.Contains(t, mock.lastArgs, "--mount-point")

	assert.Equal(t, []byte("validpassphrase\n"), mock.lastData)
}

// --- LockVolume validation tests ---

func TestStorageService_LockVolume_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping root-requirement assertion")
		return
	}
	svc := NewStorageService()
	err := svc.LockVolume()
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

func TestStorageService_LockVolume_WithElevator(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, output: []byte(`{"status":"ok"}`)}
	svc.SetElevator(mock)
	err := svc.LockVolume()
	assert.NoError(t, err)

	// Check the subcommand args prefix.
	require.True(t, len(mock.lastArgs) >= 2, "expected at least 2 args, got %d", len(mock.lastArgs))
	assert.Equal(t, "luks2", mock.lastArgs[0])
	assert.Equal(t, "lock", mock.lastArgs[1])
	// Verify explicit paths are passed to prevent sudo home dir issues.
	assert.Contains(t, mock.lastArgs, "--path")
	assert.Contains(t, mock.lastArgs, "--mount-point")
}

// --- WipeVolume validation tests ---

func TestStorageService_WipeVolume_InvalidStandard_Empty(t *testing.T) {
	svc := NewStorageService()
	err := svc.WipeVolume("")
	assert.True(t, errors.Is(err, ErrStorageInvalidStandard))
}

func TestStorageService_WipeVolume_InvalidStandard_Unknown(t *testing.T) {
	svc := NewStorageService()
	err := svc.WipeVolume("gutmann")
	assert.True(t, errors.Is(err, ErrStorageInvalidStandard))
}

func TestStorageService_WipeVolume_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping root-requirement assertion")
		return
	}
	svc := NewStorageService()
	err := svc.WipeVolume("nist")
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

func TestStorageService_WipeVolume_ValidStandards_NotRejected(t *testing.T) {
	svc := NewStorageService()

	standards := []string{"nist", "dod3", "dod7"}
	for _, std := range standards {
		t.Run(std, func(t *testing.T) {
			err := svc.WipeVolume(std)
			// Valid standards should never return ErrStorageInvalidStandard.
			// They will fail with ErrStorageRequiresRoot or a LUKS error.
			assert.False(t, errors.Is(err, ErrStorageInvalidStandard),
				"standard %q should not be rejected as invalid", std)
		})
	}
}

func TestStorageService_WipeVolume_WithElevator(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, output: []byte(`{"status":"ok"}`)}
	svc.SetElevator(mock)
	err := svc.WipeVolume("nist")
	assert.NoError(t, err)

	// Check the subcommand args prefix.
	require.True(t, len(mock.lastArgs) >= 5, "expected at least 5 args, got %d", len(mock.lastArgs))
	assert.Equal(t, "luks2", mock.lastArgs[0])
	assert.Equal(t, "wipe", mock.lastArgs[1])
	assert.Equal(t, "--standard", mock.lastArgs[2])
	assert.Equal(t, "nist", mock.lastArgs[3])
	assert.Equal(t, "--force", mock.lastArgs[4])
	// Verify explicit paths are passed to prevent sudo home dir issues.
	assert.Contains(t, mock.lastArgs, "--path")
	assert.Contains(t, mock.lastArgs, "--mount-point")
}

func TestStorageService_WipeVolume_WithElevator_InvalidStandard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, output: []byte(`{"status":"ok"}`)}
	svc.SetElevator(mock)
	err := svc.WipeVolume("bogus")
	// Invalid standard should be caught before elevation.
	assert.True(t, errors.Is(err, ErrStorageInvalidStandard))
}

// --- Validation helper tests ---

func TestValidateVolumeSize(t *testing.T) {
	tests := []struct {
		name    string
		sizeGB  int
		wantErr error
	}{
		{name: "zero", sizeGB: 0, wantErr: ErrStorageInvalidSize},
		{name: "negative", sizeGB: -1, wantErr: ErrStorageInvalidSize},
		{name: "too_large", sizeGB: 101, wantErr: ErrStorageInvalidSize},
		{name: "min_valid", sizeGB: 1, wantErr: nil},
		{name: "max_valid", sizeGB: 100, wantErr: nil},
		{name: "mid_range", sizeGB: 50, wantErr: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVolumeSize(tc.sizeGB)
			if tc.wantErr != nil {
				assert.True(t, errors.Is(err, tc.wantErr))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		wantErr    error
	}{
		{name: "empty", passphrase: "", wantErr: ErrStorageWeakPassphrase},
		{name: "one_char", passphrase: "a", wantErr: ErrStorageWeakPassphrase},
		{name: "seven_chars", passphrase: "1234567", wantErr: ErrStorageWeakPassphrase},
		{name: "eight_chars", passphrase: "12345678", wantErr: nil},
		{name: "long_phrase", passphrase: "a very long secure passphrase", wantErr: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePassphrase(tc.passphrase)
			if tc.wantErr != nil {
				assert.True(t, errors.Is(err, tc.wantErr))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- runElevatedCmd tests ---

func TestStorageService_RunElevatedCmd_NoElevator(t *testing.T) {
	svc := NewStorageService()
	err := svc.runElevatedCmd([]string{"luks2", "seal"}, nil)
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

func TestStorageService_RunElevatedCmd_ElevatorUnavailable(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: false}
	svc.SetElevator(mock)
	err := svc.runElevatedCmd([]string{"luks2", "seal"}, nil)
	assert.True(t, errors.Is(err, ErrStorageRequiresRoot))
}

func TestStorageService_RunElevatedCmd_Success(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: true, output: []byte(`{"status":"ok"}`)}
	svc.SetElevator(mock)
	err := svc.runElevatedCmd([]string{"luks2", "seal", "--size", "1G"}, []byte("test1234\ntest1234\n"))
	assert.NoError(t, err)
	assert.Equal(t, []string{"luks2", "seal", "--size", "1G"}, mock.lastArgs)
}

func TestStorageService_RunElevatedCmd_ElevatorError(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: true, err: ErrElevationFailed}
	svc.SetElevator(mock)
	err := svc.runElevatedCmd([]string{"luks2", "seal", "--size", "1G"}, []byte("test1234\ntest1234\n"))
	assert.True(t, errors.Is(err, ErrElevationFailed))
}

// --- luksPathArgs tests ---

func TestLuksPathArgs_ReturnsPathAndMountPoint(t *testing.T) {
	args := luksPathArgs()

	// luksPathArgs depends on the user's home directory being resolvable.
	// On CI or minimal environments it may return nil, which is valid.
	if args == nil {
		t.Log("luksPathArgs returned nil (home directory not resolvable); skipping assertion")
		return
	}

	require.Len(t, args, 4, "expected 4 args: --path <p> --mount-point <m>")
	assert.Equal(t, "--path", args[0])
	assert.NotEmpty(t, args[1], "LUKS path must not be empty")
	assert.Equal(t, "--mount-point", args[2])
	assert.NotEmpty(t, args[3], "mount point must not be empty")
}

// --- WipeVolume elevated path with all valid standards ---

func TestStorageService_WipeVolume_AllStandardsElevated(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}

	standards := []string{"nist", "dod3", "dod7"}
	for _, std := range standards {
		t.Run(std, func(t *testing.T) {
			svc := NewStorageService()
			mock := &mockElevator{available: true}
			svc.SetElevator(mock)

			err := svc.WipeVolume(std)
			assert.NoError(t, err)

			require.True(t, len(mock.lastArgs) >= 5)
			assert.Equal(t, "luks2", mock.lastArgs[0])
			assert.Equal(t, "wipe", mock.lastArgs[1])
			assert.Equal(t, "--standard", mock.lastArgs[2])
			assert.Equal(t, std, mock.lastArgs[3])
			assert.Equal(t, "--force", mock.lastArgs[4])
		})
	}
}

// --- UnlockVolume elevated error propagation ---

func TestStorageService_UnlockVolume_ElevatorError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, err: ErrElevationFailed}
	svc.SetElevator(mock)

	err := svc.UnlockVolume("validpassphrase")
	assert.ErrorIs(t, err, ErrElevationFailed)
}

// --- LockVolume elevated error propagation ---

func TestStorageService_LockVolume_ElevatorError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, err: ErrElevationDenied}
	svc.SetElevator(mock)

	err := svc.LockVolume()
	assert.ErrorIs(t, err, ErrElevationDenied)
}

// --- CreateVolume stdin format ---

func TestStorageService_CreateVolume_StdinFormat(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 5, Passphrase: "mypassword"})
	assert.NoError(t, err)

	// CreateVolume sends the passphrase twice (for confirmation).
	assert.Equal(t, []byte("mypassword\nmypassword\n"), mock.lastData)
	assert.Equal(t, "5G", mock.lastArgs[3], "size arg must be formatted as <N>G")
}

// --- WipeVolume with nil stdin ---

func TestStorageService_WipeVolume_NoStdinData(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.WipeVolume("dod7")
	assert.NoError(t, err)
	assert.Nil(t, mock.lastData, "wipe should not send stdin data")
}

// --- LockVolume with nil stdin ---

func TestStorageService_LockVolume_NoStdinData(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.LockVolume()
	assert.NoError(t, err)
	assert.Nil(t, mock.lastData, "lock should not send stdin data")
}

// --- RunElevatedCmd passes nil stdin through ---

func TestStorageService_RunElevatedCmd_NilStdin(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.NoError(t, err)
	assert.Nil(t, mock.lastData)
}

// --- GetStatus is called multiple times consistently ---

func TestStorageService_GetStatus_Idempotent(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	status1, err1 := svc.GetStatus()
	require.NoError(t, err1)

	status2, err2 := svc.GetStatus()
	require.NoError(t, err2)

	assert.Equal(t, status1.VolumePath, status2.VolumePath)
	assert.Equal(t, status1.MountPoint, status2.MountPoint)
	assert.Equal(t, status1.ElevationAvailable, status2.ElevationAvailable)
}

// --- WipeStandards map coverage ---

func TestWipeStandards_AllMapped(t *testing.T) {
	expected := []string{"nist", "dod3", "dod7"}
	for _, name := range expected {
		_, ok := wipeStandards[name]
		assert.True(t, ok, "wipeStandards must contain %q", name)
	}
	assert.Len(t, wipeStandards, len(expected),
		"wipeStandards should not contain unexpected entries")
}

// --- Constants validation ---

func TestStorageConstants(t *testing.T) {
	assert.Equal(t, 8, minPassphraseLength)
	assert.Equal(t, 1, minVolumeSizeGB)
	assert.Equal(t, 100, maxVolumeSizeGB)
	assert.Equal(t, int64(1024*1024*1024), int64(bytesPerGB))
}
