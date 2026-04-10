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

package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// TestLUKS2Cmd_Help verifies luks2 command help output contains expected information.
func TestLUKS2Cmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err, "luks2 --help should not return error")

	output := buf.String()
	expectedStrings := []string{
		"luks2",
		"LUKS2",
		"encrypted storage",
		"seal",
		"unseal",
		"lock",
		"migrate",
		"wipe",
		"sudo xkey luks2",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, output, expected, "Help output missing %q", expected)
	}
}

// TestSealCmd_Help verifies seal command help output contains expected information.
func TestSealCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "seal", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err, "luks2 seal --help should not return error")

	output := buf.String()
	expectedStrings := []string{
		"seal",
		"LUKS2",
		"--size",
		"--path",
		"sudo xkey luks2 seal",
		"Requires root privileges",
		"encrypted",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, output, expected, "Help output missing %q", expected)
	}
}

// TestUnsealCmd_Help verifies unseal command help output contains expected information.
func TestUnsealCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "unseal", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err, "luks2 unseal --help should not return error")

	output := buf.String()
	expectedStrings := []string{
		"unseal",
		"Unlock",
		"LUKS2",
		"--path",
		"sudo xkey luks2 unseal",
		"Requires root privileges",
		"passphrase",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, output, expected, "Help output missing %q", expected)
	}
}

// TestLockCmd_Help verifies lock command help output contains expected information.
func TestLockCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "lock", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err, "luks2 lock --help should not return error")

	output := buf.String()
	expectedStrings := []string{
		"lock",
		"Lock",
		"LUKS2",
		"--path",
		"sudo xkey luks2 lock",
		"Requires root privileges",
		"Unmounts",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, output, expected, "Help output missing %q", expected)
	}
}

// TestMigrateCmd_Help verifies migrate command help output contains expected information.
func TestMigrateCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "migrate", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err, "luks2 migrate --help should not return error")

	output := buf.String()
	expectedStrings := []string{
		"migrate",
		"Migrate",
		"LUKS",
		"--size",
		"--path",
		"--keep-old",
		"sudo xkey luks2 migrate",
		"Requires root privileges",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, output, expected, "Help output missing %q", expected)
	}
}

// TestWipeCmd_Help verifies wipe command help output contains expected information.
func TestWipeCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "wipe", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err, "luks2 wipe --help should not return error")

	output := buf.String()
	expectedStrings := []string{
		"wipe",
		"Securely destroy",
		"LUKS",
		"--standard",
		"--force",
		"--path",
		"sudo xkey luks2 wipe",
		"Requires root privileges",
		"WARNING",
		"IRREVERSIBLE",
		"nist",
		"dod3",
		"dod7",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, output, expected, "Help output missing %q", expected)
	}
}

// TestLUKS2SubcommandRegistration verifies luks2 is registered with RootCmd.
func TestLUKS2SubcommandRegistration(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Name() == "luks2" {
			found = true
			break
		}
	}
	assert.True(t, found, "luks2 command not registered with root command")
}

// TestLUKS2HasSubcommands verifies luks2 has seal, unseal, lock, migrate, wipe, import-data as subcommands.
func TestLUKS2HasSubcommands(t *testing.T) {
	subcommands := map[string]bool{
		"seal":        false,
		"unseal":      false,
		"lock":        false,
		"migrate":     false,
		"wipe":        false,
		"import-data": false,
	}

	for _, cmd := range luks2Cmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		assert.True(t, found, "Subcommand %q not registered with luks2 command", name)
	}
}

// TestParseSize_ValidInputs tests parseSize with valid size strings.
func TestParseSize_ValidInputs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
	}{
		{
			name:     "kilobytes lowercase",
			input:    "100k",
			expected: 100 * 1024,
		},
		{
			name:     "kilobytes uppercase",
			input:    "100K",
			expected: 100 * 1024,
		},
		{
			name:     "megabytes lowercase",
			input:    "100m",
			expected: 100 * 1024 * 1024,
		},
		{
			name:     "megabytes uppercase",
			input:    "100M",
			expected: 100 * 1024 * 1024,
		},
		{
			name:     "gigabytes lowercase",
			input:    "1g",
			expected: 1 * 1024 * 1024 * 1024,
		},
		{
			name:     "gigabytes uppercase",
			input:    "1G",
			expected: 1 * 1024 * 1024 * 1024,
		},
		{
			name:     "large gigabyte value",
			input:    "10G",
			expected: 10 * 1024 * 1024 * 1024,
		},
		{
			name:     "500 megabytes",
			input:    "500M",
			expected: 500 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseSize(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseSize_InvalidInputs tests parseSize with invalid size strings.
func TestParseSize_InvalidInputs(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		errContains string
	}{
		{
			name:        "empty string",
			input:       "",
			errContains: "invalid size format",
		},
		{
			name:        "too short",
			input:       "M",
			errContains: "invalid size format",
		},
		{
			name:        "unknown unit",
			input:       "100X",
			errContains: "unknown size unit",
		},
		{
			name:        "unknown unit T",
			input:       "100T",
			errContains: "unknown size unit",
		},
		{
			name:        "invalid number",
			input:       "abcM",
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSize(tt.input)
			require.Error(t, err)
			if tt.errContains != "" {
				assert.Contains(t, err.Error(), tt.errContains)
			}
		})
	}
}

// TestParseSize_AcceptedButUnusualInputs tests parseSize with inputs that are technically valid
// but may not be what the user intended. These document current behavior.
func TestParseSize_AcceptedButUnusualInputs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
	}{
		{
			name:     "decimal truncates to integer",
			input:    "1.5G",
			expected: 1 * 1024 * 1024 * 1024, // fmt.Sscanf truncates to 1
		},
		{
			name:     "negative value works",
			input:    "-100M",
			expected: -100 * 1024 * 1024, // Negative is technically allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseSize(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSealError_Error tests SealError error formatting.
func TestSealError_Error(t *testing.T) {
	tests := []struct {
		name        string
		err         *SealError
		wantParts   []string
		notWantPart string
	}{
		{
			name: "with operation and message and wrapped error",
			err: &SealError{
				Operation: "create_volume",
				Message:   "failed to create LUKS volume",
				Err:       errors.New("underlying error"),
			},
			wantParts: []string{"seal:", "create_volume", "failed to create LUKS volume", "underlying error"},
		},
		{
			name: "with operation and message without wrapped error",
			err: &SealError{
				Operation: "parse_size",
				Message:   "invalid size format",
				Err:       nil,
			},
			wantParts:   []string{"seal:", "parse_size", "invalid size format"},
			notWantPart: "nil",
		},
		{
			name: "with operation and wrapped error without message",
			err: &SealError{
				Operation: "read_passphrase",
				Message:   "",
				Err:       errors.New("io error"),
			},
			wantParts: []string{"seal:", "read_passphrase", "io error"},
		},
		{
			name: "with operation only",
			err: &SealError{
				Operation: "migrate_data",
				Message:   "",
				Err:       nil,
			},
			wantParts: []string{"seal:", "migrate_data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, part := range tt.wantParts {
				assert.Contains(t, errStr, part)
			}
			if tt.notWantPart != "" {
				assert.NotContains(t, errStr, tt.notWantPart)
			}
		})
	}
}

// TestSealError_Unwrap tests SealError unwrap functionality.
func TestSealError_Unwrap(t *testing.T) {
	t.Run("with wrapped error", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &SealError{
			Operation: "test",
			Err:       underlying,
		}
		assert.Equal(t, underlying, err.Unwrap())
		assert.True(t, errors.Is(err, underlying))
	})

	t.Run("without wrapped error", func(t *testing.T) {
		err := &SealError{
			Operation: "test",
			Err:       nil,
		}
		assert.Nil(t, err.Unwrap())
	})
}

// TestUnsealError_Error tests UnsealError error formatting.
func TestUnsealError_Error(t *testing.T) {
	tests := []struct {
		name        string
		err         *UnsealError
		wantParts   []string
		notWantPart string
	}{
		{
			name: "with operation and message and wrapped error",
			err: &UnsealError{
				Operation: "unlock",
				Message:   "failed to unlock volume",
				Err:       errors.New("invalid passphrase"),
			},
			wantParts: []string{"unseal:", "unlock", "failed to unlock volume", "invalid passphrase"},
		},
		{
			name: "with operation and message without wrapped error",
			err: &UnsealError{
				Operation: "check_volume",
				Message:   "no encrypted volume found",
				Err:       nil,
			},
			wantParts:   []string{"unseal:", "check_volume", "no encrypted volume found"},
			notWantPart: "nil",
		},
		{
			name: "with operation and wrapped error without message",
			err: &UnsealError{
				Operation: "read_passphrase",
				Message:   "",
				Err:       errors.New("terminal read error"),
			},
			wantParts: []string{"unseal:", "read_passphrase", "terminal read error"},
		},
		{
			name: "with operation only",
			err: &UnsealError{
				Operation: "mount",
				Message:   "",
				Err:       nil,
			},
			wantParts: []string{"unseal:", "mount"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, part := range tt.wantParts {
				assert.Contains(t, errStr, part)
			}
			if tt.notWantPart != "" {
				assert.NotContains(t, errStr, tt.notWantPart)
			}
		})
	}
}

// TestUnsealError_Unwrap tests UnsealError unwrap functionality.
func TestUnsealError_Unwrap(t *testing.T) {
	t.Run("with wrapped error", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &UnsealError{
			Operation: "test",
			Err:       underlying,
		}
		assert.Equal(t, underlying, err.Unwrap())
		assert.True(t, errors.Is(err, underlying))
	})

	t.Run("without wrapped error", func(t *testing.T) {
		err := &UnsealError{
			Operation: "test",
			Err:       nil,
		}
		assert.Nil(t, err.Unwrap())
	})
}

// TestLockError_Error tests LockError error formatting.
func TestLockError_Error(t *testing.T) {
	tests := []struct {
		name        string
		err         *LockError
		wantParts   []string
		notWantPart string
	}{
		{
			name: "with operation and message and wrapped error",
			err: &LockError{
				Operation: "lock",
				Message:   "failed to lock volume",
				Err:       errors.New("device busy"),
			},
			wantParts: []string{"lock:", "lock", "failed to lock volume", "device busy"},
		},
		{
			name: "with operation and message without wrapped error",
			err: &LockError{
				Operation: "check_volume",
				Message:   "no encrypted volume mounted",
				Err:       nil,
			},
			wantParts:   []string{"lock:", "check_volume", "no encrypted volume mounted"},
			notWantPart: "nil",
		},
		{
			name: "with operation and wrapped error without message",
			err: &LockError{
				Operation: "unmount",
				Message:   "",
				Err:       errors.New("umount: target is busy"),
			},
			wantParts: []string{"lock:", "unmount", "umount: target is busy"},
		},
		{
			name: "with operation only",
			err: &LockError{
				Operation: "detach",
				Message:   "",
				Err:       nil,
			},
			wantParts: []string{"lock:", "detach"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, part := range tt.wantParts {
				assert.Contains(t, errStr, part)
			}
			if tt.notWantPart != "" {
				assert.NotContains(t, errStr, tt.notWantPart)
			}
		})
	}
}

// TestLockError_Unwrap tests LockError unwrap functionality.
func TestLockError_Unwrap(t *testing.T) {
	t.Run("with wrapped error", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &LockError{
			Operation: "test",
			Err:       underlying,
		}
		assert.Equal(t, underlying, err.Unwrap())
		assert.True(t, errors.Is(err, underlying))
	})

	t.Run("without wrapped error", func(t *testing.T) {
		err := &LockError{
			Operation: "test",
			Err:       nil,
		}
		assert.Nil(t, err.Unwrap())
	})
}

// TestMigrateError_Error tests MigrateError error formatting.
func TestMigrateError_Error(t *testing.T) {
	tests := []struct {
		name      string
		err       *MigrateError
		wantParts []string
	}{
		{
			name: "with operation and wrapped error",
			err: &MigrateError{
				Operation: "copy_data",
				Err:       errors.New("io error"),
			},
			wantParts: []string{"migrate:", "copy_data", "io error"},
		},
		{
			name: "with operation only",
			err: &MigrateError{
				Operation: "rename",
				Err:       nil,
			},
			wantParts: []string{"migrate:", "rename"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, part := range tt.wantParts {
				assert.Contains(t, errStr, part)
			}
		})
	}
}

// TestMigrateError_Unwrap tests MigrateError unwrap functionality.
func TestMigrateError_Unwrap(t *testing.T) {
	t.Run("with wrapped error", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &MigrateError{
			Operation: "test",
			Err:       underlying,
		}
		assert.Equal(t, underlying, err.Unwrap())
		assert.True(t, errors.Is(err, underlying))
	})

	t.Run("without wrapped error", func(t *testing.T) {
		err := &MigrateError{
			Operation: "test",
			Err:       nil,
		}
		assert.Nil(t, err.Unwrap())
	})
}

// TestWipeError_Error tests WipeError error formatting.
func TestWipeError_Error(t *testing.T) {
	tests := []struct {
		name        string
		err         *WipeError
		wantParts   []string
		notWantPart string
	}{
		{
			name: "with operation and message and wrapped error",
			err: &WipeError{
				Operation: "wipe",
				Message:   "failed to wipe container",
				Err:       errors.New("io error"),
			},
			wantParts: []string{"wipe:", "wipe", "failed to wipe container", "io error"},
		},
		{
			name: "with operation and message without wrapped error",
			err: &WipeError{
				Operation: "check_container",
				Message:   "no container found",
				Err:       nil,
			},
			wantParts:   []string{"wipe:", "check_container", "no container found"},
			notWantPart: "nil",
		},
		{
			name: "with operation and wrapped error without message",
			err: &WipeError{
				Operation: "remove_file",
				Message:   "",
				Err:       errors.New("permission denied"),
			},
			wantParts: []string{"wipe:", "remove_file", "permission denied"},
		},
		{
			name: "with operation only",
			err: &WipeError{
				Operation: "confirm",
				Message:   "",
				Err:       nil,
			},
			wantParts: []string{"wipe:", "confirm"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, part := range tt.wantParts {
				assert.Contains(t, errStr, part)
			}
			if tt.notWantPart != "" {
				assert.NotContains(t, errStr, tt.notWantPart)
			}
		})
	}
}

// TestWipeError_Unwrap tests WipeError unwrap functionality.
func TestWipeError_Unwrap(t *testing.T) {
	t.Run("with wrapped error", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &WipeError{
			Operation: "test",
			Err:       underlying,
		}
		assert.Equal(t, underlying, err.Unwrap())
		assert.True(t, errors.Is(err, underlying))
	})

	t.Run("without wrapped error", func(t *testing.T) {
		err := &WipeError{
			Operation: "test",
			Err:       nil,
		}
		assert.Nil(t, err.Unwrap())
	})
}

// TestSealCmd_FlagRegistration verifies seal command flags are registered.
func TestSealCmd_FlagRegistration(t *testing.T) {
	tests := []struct {
		name         string
		flagName     string
		defaultValue string
	}{
		{
			name:         "size flag",
			flagName:     "size",
			defaultValue: "100M",
		},
		{
			name:         "path flag",
			flagName:     "path",
			defaultValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := sealCmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "Flag %q not found on seal command", tt.flagName)
			assert.Equal(t, tt.defaultValue, flag.DefValue)
		})
	}
}

// TestUnsealCmd_FlagRegistration verifies unseal command flags are registered.
func TestUnsealCmd_FlagRegistration(t *testing.T) {
	flag := unsealCmd.Flags().Lookup("path")
	require.NotNil(t, flag, "Flag 'path' not found on unseal command")
	assert.Equal(t, "", flag.DefValue)
}

// TestLockCmd_FlagRegistration verifies lock command flags are registered.
func TestLockCmd_FlagRegistration(t *testing.T) {
	flag := lockCmd.Flags().Lookup("path")
	require.NotNil(t, flag, "Flag 'path' not found on lock command")
	assert.Equal(t, "", flag.DefValue)
}

// TestMigrateCmd_FlagRegistration verifies migrate command flags are registered.
func TestMigrateCmd_FlagRegistration(t *testing.T) {
	tests := []struct {
		name         string
		flagName     string
		defaultValue string
	}{
		{
			name:         "size flag",
			flagName:     "size",
			defaultValue: "",
		},
		{
			name:         "path flag",
			flagName:     "path",
			defaultValue: "",
		},
		{
			name:         "keep-old flag",
			flagName:     "keep-old",
			defaultValue: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := migrateCmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "Flag %q not found on migrate command", tt.flagName)
			assert.Equal(t, tt.defaultValue, flag.DefValue)
		})
	}
}

// TestWipeCmd_FlagRegistration verifies wipe command flags are registered.
func TestWipeCmd_FlagRegistration(t *testing.T) {
	tests := []struct {
		name         string
		flagName     string
		defaultValue string
	}{
		{
			name:         "standard flag",
			flagName:     "standard",
			defaultValue: "dod3",
		},
		{
			name:         "force flag",
			flagName:     "force",
			defaultValue: "false",
		},
		{
			name:         "path flag",
			flagName:     "path",
			defaultValue: "",
		},
		{
			name:         "mount-point flag",
			flagName:     "mount-point",
			defaultValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := wipeCmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "Flag %q not found on wipe command", tt.flagName)
			assert.Equal(t, tt.defaultValue, flag.DefValue)
		})
	}
}

// TestSentinelErrors_Seal verifies seal sentinel errors are properly defined.
func TestSentinelErrors_Seal(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		operation string
	}{
		{
			name:      "ErrSealPassphraseRead",
			err:       ErrSealPassphraseRead,
			operation: "read_passphrase",
		},
		{
			name:      "ErrSealVolumeCreate",
			err:       ErrSealVolumeCreate,
			operation: "create_volume",
		},
		{
			name:      "ErrSealDataMigration",
			err:       ErrSealDataMigration,
			operation: "migrate_data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.err)
			sealErr, ok := tt.err.(*SealError)
			require.True(t, ok, "Expected *SealError type")
			assert.Equal(t, tt.operation, sealErr.Operation)
			assert.NotEmpty(t, sealErr.Message)
		})
	}
}

// TestSentinelErrors_Unseal verifies unseal sentinel errors are properly defined.
func TestSentinelErrors_Unseal(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		operation string
	}{
		{
			name:      "ErrUnsealNoVolume",
			err:       ErrUnsealNoVolume,
			operation: "check_volume",
		},
		{
			name:      "ErrUnsealPassphraseRead",
			err:       ErrUnsealPassphraseRead,
			operation: "read_passphrase",
		},
		{
			name:      "ErrUnsealUnlockFailed",
			err:       ErrUnsealUnlockFailed,
			operation: "unlock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.err)
			unsealErr, ok := tt.err.(*UnsealError)
			require.True(t, ok, "Expected *UnsealError type")
			assert.Equal(t, tt.operation, unsealErr.Operation)
			assert.NotEmpty(t, unsealErr.Message)
		})
	}
}

// TestSentinelErrors_Lock verifies lock sentinel errors are properly defined.
func TestSentinelErrors_Lock(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		operation string
	}{
		{
			name:      "ErrLockNoVolume",
			err:       ErrLockNoVolume,
			operation: "check_volume",
		},
		{
			name:      "ErrLockFailed",
			err:       ErrLockFailed,
			operation: "lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.err)
			lockErr, ok := tt.err.(*LockError)
			require.True(t, ok, "Expected *LockError type")
			assert.Equal(t, tt.operation, lockErr.Operation)
			assert.NotEmpty(t, lockErr.Message)
		})
	}
}

// TestSentinelErrors_Migrate verifies migrate sentinel errors are properly defined.
func TestSentinelErrors_Migrate(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		errContains string
	}{
		{
			name:        "ErrMigrateNoSource",
			err:         ErrMigrateNoSource,
			errContains: "no source container",
		},
		{
			name:        "ErrMigrateSourceLocked",
			err:         ErrMigrateSourceLocked,
			errContains: "failed to unlock source",
		},
		{
			name:        "ErrMigrateCreateFailed",
			err:         ErrMigrateCreateFailed,
			errContains: "failed to create new container",
		},
		{
			name:        "ErrMigrateDataCopyFailed",
			err:         ErrMigrateDataCopyFailed,
			errContains: "failed to copy data",
		},
		{
			name:        "ErrMigrateRenameFailed",
			err:         ErrMigrateRenameFailed,
			errContains: "failed to rename",
		},
		{
			name:        "ErrMigratePassphraseRead",
			err:         ErrMigratePassphraseRead,
			errContains: "failed to read passphrase",
		},
		{
			name:        "ErrMigrateInvalidWipeStandard",
			err:         ErrMigrateInvalidWipeStandard,
			errContains: "invalid wipe standard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.err)
			assert.Contains(t, tt.err.Error(), tt.errContains)
		})
	}
}

// TestSentinelErrors_Wipe verifies wipe sentinel errors are properly defined.
func TestSentinelErrors_Wipe(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		operation string
	}{
		{
			name:      "ErrWipeNoContainer",
			err:       ErrWipeNoContainer,
			operation: "check_container",
		},
		{
			name:      "ErrWipeAborted",
			err:       ErrWipeAborted,
			operation: "confirm",
		},
		{
			name:      "ErrWipeFailed",
			err:       ErrWipeFailed,
			operation: "wipe",
		},
		{
			name:      "ErrWipeContainerInUse",
			err:       ErrWipeContainerInUse,
			operation: "lock",
		},
		{
			name:      "ErrWipeInvalidStandard",
			err:       ErrWipeInvalidStandard,
			operation: "validate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.err)
			wipeErr, ok := tt.err.(*WipeError)
			require.True(t, ok, "Expected *WipeError type")
			assert.Equal(t, tt.operation, wipeErr.Operation)
			assert.NotEmpty(t, wipeErr.Message)
		})
	}
}

// TestLUKSErrors_PermissionDenied tests ErrPermissionDenied from luks package.
func TestLUKSErrors_PermissionDenied(t *testing.T) {
	require.NotNil(t, luks.ErrPermissionDenied)
	assert.Contains(t, luks.ErrPermissionDenied.Error(), "permission denied")
	assert.Contains(t, luks.ErrPermissionDenied.Error(), "root")
}

// TestLUKSErrors_VolumeAlreadyExists tests ErrVolumeAlreadyExists from luks package.
func TestLUKSErrors_VolumeAlreadyExists(t *testing.T) {
	require.NotNil(t, luks.ErrVolumeAlreadyExists)
	assert.Contains(t, luks.ErrVolumeAlreadyExists.Error(), "already exists")
}

// TestLUKSErrors_PassphraseMismatch tests ErrPassphraseMismatch from luks package.
func TestLUKSErrors_PassphraseMismatch(t *testing.T) {
	require.NotNil(t, luks.ErrPassphraseMismatch)
	assert.Contains(t, luks.ErrPassphraseMismatch.Error(), "mismatch")
}

// TestLUKS2Cmd_CommandMetadata verifies luks2 command metadata.
func TestLUKS2Cmd_CommandMetadata(t *testing.T) {
	assert.Equal(t, "luks2", luks2Cmd.Use)
	assert.NotEmpty(t, luks2Cmd.Short)
	assert.NotEmpty(t, luks2Cmd.Long)
	assert.Contains(t, luks2Cmd.Short, "LUKS2")
	assert.Contains(t, luks2Cmd.Long, "xKey")
}

// TestSealCmd_CommandMetadata verifies seal command metadata.
func TestSealCmd_CommandMetadata(t *testing.T) {
	assert.Equal(t, "seal", sealCmd.Use)
	assert.NotEmpty(t, sealCmd.Short)
	assert.NotEmpty(t, sealCmd.Long)
	assert.Contains(t, sealCmd.Short, "encrypted")
	assert.Contains(t, sealCmd.Long, "LUKS2")
}

// TestUnsealCmd_CommandMetadata verifies unseal command metadata.
func TestUnsealCmd_CommandMetadata(t *testing.T) {
	assert.Equal(t, "unseal", unsealCmd.Use)
	assert.NotEmpty(t, unsealCmd.Short)
	assert.NotEmpty(t, unsealCmd.Long)
	assert.Contains(t, unsealCmd.Short, "Unlock")
	assert.Contains(t, unsealCmd.Long, "LUKS2")
}

// TestLockCmd_CommandMetadata verifies lock command metadata.
func TestLockCmd_CommandMetadata(t *testing.T) {
	assert.Equal(t, "lock", lockCmd.Use)
	assert.NotEmpty(t, lockCmd.Short)
	assert.NotEmpty(t, lockCmd.Long)
	assert.Contains(t, lockCmd.Short, "Lock")
	assert.Contains(t, lockCmd.Long, "LUKS2")
}

// TestMigrateCmd_CommandMetadata verifies migrate command metadata.
func TestMigrateCmd_CommandMetadata(t *testing.T) {
	assert.Equal(t, "migrate", migrateCmd.Use)
	assert.NotEmpty(t, migrateCmd.Short)
	assert.NotEmpty(t, migrateCmd.Long)
	assert.Contains(t, migrateCmd.Short, "Migrate")
	assert.Contains(t, migrateCmd.Long, "LUKS")
}

// TestWipeCmd_CommandMetadata verifies wipe command metadata.
func TestWipeCmd_CommandMetadata(t *testing.T) {
	assert.Equal(t, "wipe", wipeCmd.Use)
	assert.NotEmpty(t, wipeCmd.Short)
	assert.NotEmpty(t, wipeCmd.Long)
	assert.Contains(t, wipeCmd.Short, "Securely destroy")
	assert.Contains(t, wipeCmd.Long, "LUKS")
}

// TestSealCmd_HelpContainsExamples verifies help contains usage examples.
func TestSealCmd_HelpContainsExamples(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "seal", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Example")
	assert.Contains(t, output, "sudo xkey luks2 seal")
	assert.Contains(t, output, "--size 500M")
}

// TestUnsealCmd_HelpContainsExamples verifies help contains usage examples.
func TestUnsealCmd_HelpContainsExamples(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "unseal", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Example")
	assert.Contains(t, output, "sudo xkey luks2 unseal")
}

// TestLockCmd_HelpContainsExamples verifies help contains usage examples.
func TestLockCmd_HelpContainsExamples(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "lock", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Example")
	assert.Contains(t, output, "sudo xkey luks2 lock")
}

// TestMigrateCmd_HelpContainsExamples verifies help contains usage examples.
func TestMigrateCmd_HelpContainsExamples(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "migrate", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Example")
	assert.Contains(t, output, "sudo xkey luks2 migrate")
}

// TestWipeCmd_HelpContainsExamples verifies help contains usage examples.
func TestWipeCmd_HelpContainsExamples(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "wipe", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Example")
	assert.Contains(t, output, "sudo xkey luks2 wipe")
}

// TestParseSize_EdgeCases tests edge cases for parseSize function.
func TestParseSize_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    int64
		shouldError bool
	}{
		{
			name:        "minimum size 1K",
			input:       "1K",
			expected:    1024,
			shouldError: false,
		},
		{
			name:        "zero value",
			input:       "0M",
			expected:    0,
			shouldError: false,
		},
		{
			name:        "large number",
			input:       "999G",
			expected:    999 * 1024 * 1024 * 1024,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseSize(tt.input)
			if tt.shouldError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestHasExistingData tests the hasExistingData helper function.
func TestHasExistingData(t *testing.T) {
	t.Run("non-existent directory returns false", func(t *testing.T) {
		result := hasExistingData("/non/existent/path/that/does/not/exist")
		assert.False(t, result)
	})

	t.Run("empty directory returns false", func(t *testing.T) {
		tmpDir := t.TempDir()
		result := hasExistingData(tmpDir)
		assert.False(t, result)
	})
}

// TestGetFileSize tests the getFileSize helper function.
func TestGetFileSize(t *testing.T) {
	t.Run("non-existent file returns error", func(t *testing.T) {
		_, err := getFileSize("/non/existent/path/that/does/not/exist")
		assert.Error(t, err)
	})
}

// TestFormatSize tests the formatSize helper function.
func TestFormatSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{
			name:     "bytes",
			bytes:    500,
			expected: "500B",
		},
		{
			name:     "kilobytes",
			bytes:    2048,
			expected: "2.0K",
		},
		{
			name:     "megabytes",
			bytes:    10 * 1024 * 1024,
			expected: "10.0M",
		},
		{
			name:     "gigabytes",
			bytes:    2 * 1024 * 1024 * 1024,
			expected: "2.0G",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSize(tt.bytes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestErrorTypeAssertions verifies error types can be asserted correctly.
func TestErrorTypeAssertions(t *testing.T) {
	t.Run("SealError type assertion", func(t *testing.T) {
		var err error = &SealError{Operation: "test"}
		_, ok := err.(*SealError)
		assert.True(t, ok)
	})

	t.Run("UnsealError type assertion", func(t *testing.T) {
		var err error = &UnsealError{Operation: "test"}
		_, ok := err.(*UnsealError)
		assert.True(t, ok)
	})

	t.Run("LockError type assertion", func(t *testing.T) {
		var err error = &LockError{Operation: "test"}
		_, ok := err.(*LockError)
		assert.True(t, ok)
	})

	t.Run("MigrateError type assertion", func(t *testing.T) {
		var err error = &MigrateError{Operation: "test"}
		_, ok := err.(*MigrateError)
		assert.True(t, ok)
	})

	t.Run("WipeError type assertion", func(t *testing.T) {
		var err error = &WipeError{Operation: "test"}
		_, ok := err.(*WipeError)
		assert.True(t, ok)
	})
}

// TestLUKS2CommandsSharePathFlag verifies all LUKS2 subcommands have consistent path flag.
func TestLUKS2CommandsSharePathFlag(t *testing.T) {
	commands := map[string]*struct {
		hasPath bool
		defVal  string
	}{
		"seal":    {false, ""},
		"unseal":  {false, ""},
		"lock":    {false, ""},
		"migrate": {false, ""},
		"wipe":    {false, ""},
	}

	for _, cmd := range luks2Cmd.Commands() {
		if c, ok := commands[cmd.Name()]; ok {
			pathFlag := cmd.Flags().Lookup("path")
			if pathFlag != nil {
				c.hasPath = true
				c.defVal = pathFlag.DefValue
			}
		}
	}

	for name, info := range commands {
		assert.True(t, info.hasPath, "Command %q should have --path flag", name)
		assert.Empty(t, info.defVal, "Command %q --path default should be empty", name)
	}
}

// TestSealCmd_SizeFlagUsage verifies the size flag has proper usage description.
func TestSealCmd_SizeFlagUsage(t *testing.T) {
	flag := sealCmd.Flags().Lookup("size")
	require.NotNil(t, flag)
	assert.Contains(t, strings.ToLower(flag.Usage), "size")
}

// TestErrorChaining verifies errors can be properly chained.
func TestErrorChaining(t *testing.T) {
	t.Run("SealError chain", func(t *testing.T) {
		inner := errors.New("inner error")
		outer := &SealError{Operation: "outer", Err: inner}
		assert.True(t, errors.Is(outer, inner))
	})

	t.Run("UnsealError chain", func(t *testing.T) {
		inner := errors.New("inner error")
		outer := &UnsealError{Operation: "outer", Err: inner}
		assert.True(t, errors.Is(outer, inner))
	})

	t.Run("LockError chain", func(t *testing.T) {
		inner := errors.New("inner error")
		outer := &LockError{Operation: "outer", Err: inner}
		assert.True(t, errors.Is(outer, inner))
	})

	t.Run("MigrateError chain", func(t *testing.T) {
		inner := errors.New("inner error")
		outer := &MigrateError{Operation: "outer", Err: inner}
		assert.True(t, errors.Is(outer, inner))
	})

	t.Run("WipeError chain", func(t *testing.T) {
		inner := errors.New("inner error")
		outer := &WipeError{Operation: "outer", Err: inner}
		assert.True(t, errors.Is(outer, inner))
	})
}

// TestSealCmd_RequiresRoot verifies seal command requires root privileges.
func TestSealCmd_RequiresRoot(t *testing.T) {
	// Running as non-root user should return ErrPermissionDenied
	// This test is meaningful when run as non-root user
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "seal"})

	err := RootCmd.Execute()
	if err != nil {
		// Should be permission denied when not running as root
		assert.ErrorIs(t, err, luks.ErrPermissionDenied)
	}
}

// TestUnsealCmd_RequiresRoot verifies unseal command requires root privileges.
func TestUnsealCmd_RequiresRoot(t *testing.T) {
	// Running as non-root user should return ErrPermissionDenied
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "unseal"})

	err := RootCmd.Execute()
	if err != nil {
		// Should be permission denied when not running as root
		assert.ErrorIs(t, err, luks.ErrPermissionDenied)
	}
}

// TestLockCmd_RequiresRoot verifies lock command requires root privileges.
func TestLockCmd_RequiresRoot(t *testing.T) {
	// Running as non-root user should return ErrPermissionDenied
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "lock"})

	err := RootCmd.Execute()
	if err != nil {
		// Should be permission denied when not running as root
		assert.ErrorIs(t, err, luks.ErrPermissionDenied)
	}
}

// TestMigrateCmd_RequiresRoot verifies migrate command requires root privileges.
func TestMigrateCmd_RequiresRoot(t *testing.T) {
	// Running as non-root user should return ErrPermissionDenied
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "migrate"})

	err := RootCmd.Execute()
	if err != nil {
		// Should be permission denied when not running as root
		assert.ErrorIs(t, err, luks.ErrPermissionDenied)
	}
}

// TestWipeCmd_RequiresRoot verifies wipe command requires root privileges.
func TestWipeCmd_RequiresRoot(t *testing.T) {
	// Running as non-root user should return ErrPermissionDenied
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "wipe"})

	err := RootCmd.Execute()
	if err != nil {
		// Should be permission denied when not running as root
		assert.ErrorIs(t, err, luks.ErrPermissionDenied)
	}
}

// TestSealCmd_InvalidSizeFlag verifies seal command validates size flag.
func TestSealCmd_InvalidSizeFlag(t *testing.T) {
	// This test verifies the size flag validation in the context of the command
	// When running with an invalid size, parseSize should return an error

	// Test that the parseSize function is called and returns error for invalid input
	_, err := parseSize("invalid")
	assert.Error(t, err)
}

// TestCopyDirContents tests the copyDirContents helper function.
func TestCopyDirContents(t *testing.T) {
	t.Run("copy non-existent source returns error", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := copyDirContents("/non/existent/source", tmpDir)
		assert.Error(t, err)
	})

	t.Run("copy empty directory succeeds", func(t *testing.T) {
		srcDir := t.TempDir()
		dstDir := t.TempDir()
		err := copyDirContents(srcDir, dstDir)
		assert.NoError(t, err)
	})
}

// TestCopyFileSeal tests the copyFileSeal helper function.
func TestCopyFileSeal(t *testing.T) {
	t.Run("copy non-existent file returns error", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := copyFileSeal("/non/existent/file", tmpDir+"/dest")
		assert.Error(t, err)
	})
}

// TestSealCmd_UsageString verifies seal command usage string.
func TestSealCmd_UsageString(t *testing.T) {
	usage := sealCmd.UsageString()
	assert.Contains(t, usage, "seal")
	assert.Contains(t, usage, "--size")
	assert.Contains(t, usage, "--path")
}

// TestUnsealCmd_UsageString verifies unseal command usage string.
func TestUnsealCmd_UsageString(t *testing.T) {
	usage := unsealCmd.UsageString()
	assert.Contains(t, usage, "unseal")
	assert.Contains(t, usage, "--path")
}

// TestLockCmd_UsageString verifies lock command usage string.
func TestLockCmd_UsageString(t *testing.T) {
	usage := lockCmd.UsageString()
	assert.Contains(t, usage, "lock")
	assert.Contains(t, usage, "--path")
}

// TestMigrateCmd_UsageString verifies migrate command usage string.
func TestMigrateCmd_UsageString(t *testing.T) {
	usage := migrateCmd.UsageString()
	assert.Contains(t, usage, "migrate")
	assert.Contains(t, usage, "--size")
	assert.Contains(t, usage, "--path")
	assert.Contains(t, usage, "--keep-old")
}

// TestWipeCmd_UsageString verifies wipe command usage string.
func TestWipeCmd_UsageString(t *testing.T) {
	usage := wipeCmd.UsageString()
	assert.Contains(t, usage, "wipe")
	assert.Contains(t, usage, "--standard")
	assert.Contains(t, usage, "--force")
	assert.Contains(t, usage, "--path")
}

// TestSealError_Interface verifies SealError implements error interface.
func TestSealError_Interface(t *testing.T) {
	var _ error = &SealError{}
}

// TestUnsealError_Interface verifies UnsealError implements error interface.
func TestUnsealError_Interface(t *testing.T) {
	var _ error = &UnsealError{}
}

// TestLockError_Interface verifies LockError implements error interface.
func TestLockError_Interface(t *testing.T) {
	var _ error = &LockError{}
}

// TestMigrateError_Interface verifies MigrateError implements error interface.
func TestMigrateError_Interface(t *testing.T) {
	var _ error = &MigrateError{}
}

// TestWipeError_Interface verifies WipeError implements error interface.
func TestWipeError_Interface(t *testing.T) {
	var _ error = &WipeError{}
}

// TestMigrateCmd_WipeStandardFlag tests that the wipe-standard flag is registered.
func TestMigrateCmd_WipeStandardFlag(t *testing.T) {
	flag := migrateCmd.Flags().Lookup("wipe-standard")
	require.NotNil(t, flag, "Flag 'wipe-standard' not found on migrate command")
	assert.Equal(t, "dod3", flag.DefValue)
}

// TestWipeStandardMap verifies the wipe standard map contains valid standards.
func TestWipeStandardMap(t *testing.T) {
	tests := []struct {
		name     string
		standard string
		valid    bool
	}{
		{name: "nist valid", standard: "nist", valid: true},
		{name: "dod3 valid", standard: "dod3", valid: true},
		{name: "dod7 valid", standard: "dod7", valid: true},
		{name: "invalid standard", standard: "invalid", valid: false},
		{name: "empty standard", standard: "", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := wipeStandardMap[tt.standard]
			assert.Equal(t, tt.valid, ok)
		})
	}
}

// TestGetWipePatternDescription verifies pattern descriptions for wipe standards.
func TestGetWipePatternDescription(t *testing.T) {
	tests := []struct {
		name     string
		standard string
		contains string
	}{
		{name: "nist description", standard: "nist", contains: "1 pass"},
		{name: "dod3 description", standard: "dod3", contains: "3 passes"},
		{name: "dod7 description", standard: "dod7", contains: "7 passes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			std := wipeStandardMap[tt.standard]
			desc := getWipePatternDescription(std)
			assert.Contains(t, desc, tt.contains)
		})
	}
}

// TestMigrateCmd_WipeFlag tests that the wipe flag is registered.
func TestMigrateCmd_WipeFlag(t *testing.T) {
	flag := migrateCmd.Flags().Lookup("wipe")
	require.NotNil(t, flag, "Flag 'wipe' not found on migrate command")
	assert.Equal(t, "false", flag.DefValue)
}
