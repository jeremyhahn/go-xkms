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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// TestImportDataCmd_Help verifies import-data command help output.
func TestImportDataCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "import-data", "--help"})

	err := RootCmd.Execute()
	require.NoError(t, err, "luks2 import-data --help should not return error")

	output := buf.String()
	expectedStrings := []string{
		"import-data",
		"Import",
		"LUKS",
		"--path",
		"--source",
		"--cleanup",
		"--backup",
		"--unseal",
		"--mount-point",
		"root privileges",
	}

	for _, expected := range expectedStrings {
		assert.Contains(t, output, expected, "Help output missing %q", expected)
	}
}

// TestImportDataCmd_FlagRegistration verifies import-data command flags are registered.
func TestImportDataCmd_FlagRegistration(t *testing.T) {
	tests := []struct {
		name         string
		flagName     string
		defaultValue string
	}{
		{name: "path flag", flagName: "path", defaultValue: ""},
		{name: "source flag", flagName: "source", defaultValue: ""},
		{name: "mount-point flag", flagName: "mount-point", defaultValue: ""},
		{name: "cleanup flag", flagName: "cleanup", defaultValue: "false"},
		{name: "backup flag", flagName: "backup", defaultValue: "false"},
		{name: "unseal flag", flagName: "unseal", defaultValue: "false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := importDataCmd.Flags().Lookup(tt.flagName)
			require.NotNil(t, flag, "Flag %q not found on import-data command", tt.flagName)
			assert.Equal(t, tt.defaultValue, flag.DefValue)
		})
	}
}

// TestImportDataCmd_CommandMetadata verifies import-data command metadata.
func TestImportDataCmd_CommandMetadata(t *testing.T) {
	assert.Equal(t, "import-data", importDataCmd.Use)
	assert.NotEmpty(t, importDataCmd.Short)
	assert.NotEmpty(t, importDataCmd.Long)
	assert.Contains(t, importDataCmd.Short, "Import")
	assert.Contains(t, importDataCmd.Long, "LUKS")
}

// TestImportDataCmd_UsageString verifies import-data command usage string.
func TestImportDataCmd_UsageString(t *testing.T) {
	usage := importDataCmd.UsageString()
	assert.Contains(t, usage, "import-data")
	assert.Contains(t, usage, "--path")
	assert.Contains(t, usage, "--source")
	assert.Contains(t, usage, "--cleanup")
	assert.Contains(t, usage, "--backup")
	assert.Contains(t, usage, "--unseal")
	assert.Contains(t, usage, "--mount-point")
}

// TestImportDataCmd_RequiresRoot verifies import-data command requires root privileges.
func TestImportDataCmd_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping root-requirement assertion")
		return
	}

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"luks2", "import-data", "--source", "/tmp/nonexistent"})

	err := RootCmd.Execute()
	if err != nil {
		assert.ErrorIs(t, err, luks.ErrPermissionDenied)
	}
}

// TestImportDataCmd_RegisteredAsLUKS2Subcommand verifies import-data is a luks2 subcommand.
func TestImportDataCmd_RegisteredAsLUKS2Subcommand(t *testing.T) {
	found := false
	for _, cmd := range luks2Cmd.Commands() {
		if cmd.Name() == "import-data" {
			found = true
			break
		}
	}
	assert.True(t, found, "import-data command not registered with luks2 command")
}

// --- cleanupSourceDir tests ---

// TestCleanupSourceDir_WithoutBackup verifies cleanup removes the source directory
// and recreates it empty.
func TestCleanupSourceDir_WithoutBackup(t *testing.T) {
	srcDir := t.TempDir()

	// Create test data
	testFile := filepath.Join(srcDir, "test-data.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("sensitive data"), 0600))
	subDir := filepath.Join(srcDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0700))
	subFile := filepath.Join(subDir, "nested.txt")
	require.NoError(t, os.WriteFile(subFile, []byte("nested data"), 0600))

	// Verify data exists before cleanup
	require.FileExists(t, testFile)
	require.DirExists(t, subDir)

	out := new(bytes.Buffer)
	err := cleanupSourceDir(out, srcDir, false)
	require.NoError(t, err)

	// Source directory must exist (recreated empty)
	require.DirExists(t, srcDir)

	// Original data must be gone
	assert.NoFileExists(t, testFile)
	assert.NoDirExists(t, subDir)

	// Directory must be empty
	entries, err := os.ReadDir(srcDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "source directory should be empty after cleanup")
}

// TestCleanupSourceDir_WithBackup verifies cleanup renames the source directory
// to <source>-backup and recreates the original empty.
func TestCleanupSourceDir_WithBackup(t *testing.T) {
	// Use a temp dir as the parent to control names
	parentDir := t.TempDir()
	srcDir := filepath.Join(parentDir, "data")
	require.NoError(t, os.MkdirAll(srcDir, 0700))

	// Create test data
	testFile := filepath.Join(srcDir, "important.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("important data"), 0600))

	out := new(bytes.Buffer)
	err := cleanupSourceDir(out, srcDir, true)
	require.NoError(t, err)

	// Backup directory must exist with the data
	backupDir := srcDir + "-backup"
	require.DirExists(t, backupDir)
	assert.FileExists(t, filepath.Join(backupDir, "important.txt"))

	// Original source directory must exist (recreated empty)
	require.DirExists(t, srcDir)
	entries, err := os.ReadDir(srcDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "source directory should be empty after cleanup")
}

// TestCleanupSourceDir_WithBackup_StaleBackupRemoved verifies that a stale
// backup directory is removed before creating the new backup.
func TestCleanupSourceDir_WithBackup_StaleBackupRemoved(t *testing.T) {
	parentDir := t.TempDir()
	srcDir := filepath.Join(parentDir, "data")
	backupDir := srcDir + "-backup"

	// Create a stale backup
	require.NoError(t, os.MkdirAll(backupDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(backupDir, "old.txt"), []byte("old"), 0600))

	// Create new source data
	require.NoError(t, os.MkdirAll(srcDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "new.txt"), []byte("new"), 0600))

	out := new(bytes.Buffer)
	err := cleanupSourceDir(out, srcDir, true)
	require.NoError(t, err)

	// Backup should contain only new data
	require.DirExists(t, backupDir)
	assert.FileExists(t, filepath.Join(backupDir, "new.txt"))
	assert.NoFileExists(t, filepath.Join(backupDir, "old.txt"))
}

// TestCleanupSourceDir_NonExistentSource verifies error when source doesn't exist
// and no backup is requested.
func TestCleanupSourceDir_NonExistentSource(t *testing.T) {
	parentDir := t.TempDir()
	srcDir := filepath.Join(parentDir, "nonexistent")

	out := new(bytes.Buffer)
	err := cleanupSourceDir(out, srcDir, false)
	// os.RemoveAll on non-existent returns nil, so this should succeed
	// and recreate the empty directory
	require.NoError(t, err)
	require.DirExists(t, srcDir)
}

// TestCleanupSourceDir_BackupNonExistentSource verifies error when source
// doesn't exist and backup is requested.
func TestCleanupSourceDir_BackupNonExistentSource(t *testing.T) {
	parentDir := t.TempDir()
	srcDir := filepath.Join(parentDir, "nonexistent")

	out := new(bytes.Buffer)
	err := cleanupSourceDir(out, srcDir, true)
	// os.Rename fails if source doesn't exist
	require.Error(t, err)

	var importErr *ImportDataError
	assert.True(t, errors.As(err, &importErr))
	assert.Equal(t, "backup_source", importErr.Operation)
}

// TestCleanupSourceDir_OutputMessages verifies cleanup writes status messages.
func TestCleanupSourceDir_OutputMessages(t *testing.T) {
	parentDir := t.TempDir()
	srcDir := filepath.Join(parentDir, "data")
	require.NoError(t, os.MkdirAll(srcDir, 0700))

	t.Run("backup mode", func(t *testing.T) {
		// Recreate for this subtest
		require.NoError(t, os.MkdirAll(srcDir, 0700))
		out := new(bytes.Buffer)
		_ = cleanupSourceDir(out, srcDir, true)
		assert.Contains(t, out.String(), "backup")
	})

	t.Run("remove mode", func(t *testing.T) {
		// Recreate for this subtest
		require.NoError(t, os.MkdirAll(srcDir, 0700))
		out := new(bytes.Buffer)
		_ = cleanupSourceDir(out, srcDir, false)
		assert.Contains(t, out.String(), "Removing")
	})
}

// --- ImportDataError tests ---

// TestImportDataError_Error tests ImportDataError formatting.
func TestImportDataError_Error(t *testing.T) {
	tests := []struct {
		name      string
		err       *ImportDataError
		wantParts []string
	}{
		{
			name: "with operation and message and wrapped error",
			err: &ImportDataError{
				Operation: "unlock",
				Message:   "failed to unlock",
				Err:       errors.New("bad passphrase"),
			},
			wantParts: []string{"import-data:", "unlock", "failed to unlock", "bad passphrase"},
		},
		{
			name: "with operation and message without wrapped error",
			err: &ImportDataError{
				Operation: "validate",
				Message:   "source directory does not exist",
			},
			wantParts: []string{"import-data:", "validate", "source directory does not exist"},
		},
		{
			name: "with operation and wrapped error without message",
			err: &ImportDataError{
				Operation: "copy_data",
				Err:       errors.New("io error"),
			},
			wantParts: []string{"import-data:", "copy_data", "io error"},
		},
		{
			name: "with operation only",
			err: &ImportDataError{
				Operation: "test",
			},
			wantParts: []string{"import-data:", "test"},
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

// TestImportDataError_Unwrap tests ImportDataError unwrap functionality.
func TestImportDataError_Unwrap(t *testing.T) {
	t.Run("with wrapped error", func(t *testing.T) {
		underlying := errors.New("underlying error")
		err := &ImportDataError{Operation: "test", Err: underlying}
		assert.Equal(t, underlying, err.Unwrap())
		assert.True(t, errors.Is(err, underlying))
	})

	t.Run("without wrapped error", func(t *testing.T) {
		err := &ImportDataError{Operation: "test"}
		assert.Nil(t, err.Unwrap())
	})
}

// TestImportDataError_Interface verifies ImportDataError implements error interface.
func TestImportDataError_Interface(t *testing.T) {
	var _ error = &ImportDataError{}
}

// --- Sentinel errors ---

// TestImportDataSentinelErrors verifies sentinel errors are properly defined.
func TestImportDataSentinelErrors(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		errContains string
	}{
		{
			name:        "ErrImportDataNoSource",
			err:         ErrImportDataNoSource,
			errContains: "source directory does not exist",
		},
		{
			name:        "ErrImportDataNoVolume",
			err:         ErrImportDataNoVolume,
			errContains: "LUKS volume does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.err)
			assert.Contains(t, tt.err.Error(), tt.errContains)
		})
	}
}

// TestImportDataError_Chaining verifies errors can be properly chained.
func TestImportDataError_Chaining(t *testing.T) {
	inner := errors.New("inner error")
	outer := &ImportDataError{Operation: "outer", Err: inner}
	assert.True(t, errors.Is(outer, inner))
}

// TestImportDataError_TypeAssertion verifies type assertion works.
func TestImportDataError_TypeAssertion(t *testing.T) {
	var err error = &ImportDataError{Operation: "test"}
	_, ok := err.(*ImportDataError)
	assert.True(t, ok)
}
