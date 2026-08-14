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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Parent command structure ---

func TestBackupCmd_Structure(t *testing.T) {
	assert.NotNil(t, backupCmd)
	assert.Equal(t, "backup", backupCmd.Use)
	assert.NotEmpty(t, backupCmd.Short)
	assert.NotEmpty(t, backupCmd.Long)
}

// --- Create command structure ---

func TestBackupCreateCmd_Structure(t *testing.T) {
	assert.NotNil(t, backupCreateCmd)
	assert.Equal(t, "create", backupCreateCmd.Use)
	assert.NotEmpty(t, backupCreateCmd.Short)
	assert.NotEmpty(t, backupCreateCmd.Long)
	assert.NotNil(t, backupCreateCmd.RunE)
}

func TestBackupCreateCmd_Flags(t *testing.T) {
	flags := []string{"output", "password"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := backupCreateCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on create command", name)
		})
	}
}

func TestBackupCreateCmd_FlagDefaults(t *testing.T) {
	t.Run("output_default_empty", func(t *testing.T) {
		flag := backupCreateCmd.Flags().Lookup("output")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("password_default_empty", func(t *testing.T) {
		flag := backupCreateCmd.Flags().Lookup("password")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})
}

func TestBackupCreateCmd_OutputShorthand(t *testing.T) {
	flag := backupCreateCmd.Flags().ShorthandLookup("o")
	assert.NotNil(t, flag, "output flag should have -o shorthand")
	assert.Equal(t, "output", flag.Name)
}

// --- Restore command structure ---

func TestBackupRestoreCmd_Structure(t *testing.T) {
	assert.NotNil(t, backupRestoreCmd)
	assert.Equal(t, "restore <file>", backupRestoreCmd.Use)
	assert.NotEmpty(t, backupRestoreCmd.Short)
	assert.NotEmpty(t, backupRestoreCmd.Long)
	assert.NotNil(t, backupRestoreCmd.RunE)
}

func TestBackupRestoreCmd_Args(t *testing.T) {
	err := backupRestoreCmd.Args(backupRestoreCmd, []string{})
	assert.Error(t, err, "restore should require exactly 1 arg")

	err = backupRestoreCmd.Args(backupRestoreCmd, []string{"backup.xkb"})
	assert.NoError(t, err, "restore should accept exactly 1 arg")

	err = backupRestoreCmd.Args(backupRestoreCmd, []string{"a.xkb", "b.xkb"})
	assert.Error(t, err, "restore should reject more than 1 arg")
}

func TestBackupRestoreCmd_Flags(t *testing.T) {
	flags := []string{"password", "key"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := backupRestoreCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on restore command", name)
		})
	}
}

// --- List command structure ---

func TestBackupListCmd_Structure(t *testing.T) {
	assert.NotNil(t, backupListCmd)
	assert.Equal(t, "list", backupListCmd.Use)
	assert.NotEmpty(t, backupListCmd.Short)
	assert.NotEmpty(t, backupListCmd.Long)
	assert.NotNil(t, backupListCmd.RunE)
}

func TestBackupListCmd_EmptyDir(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	var buf bytes.Buffer
	backupListCmd.SetOut(&buf)

	err := runBackupList(backupListCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No backups found.")
}

func TestBackupListCmd_WithBackups(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Create the backup directory with some .xkb files
	backupDir := filepath.Join(tempDir, ".xkey", "backups")
	err := os.MkdirAll(backupDir, 0700)
	require.NoError(t, err)

	// Write test backup files
	files := []string{"backup-20250101-120000.xkb", "backup-20250201-090000.xkb"}
	for _, f := range files {
		err = os.WriteFile(filepath.Join(backupDir, f), []byte("test-data"), 0600)
		require.NoError(t, err)
	}

	// Write a non-backup file that should be excluded
	err = os.WriteFile(filepath.Join(backupDir, "notes.txt"), []byte("not a backup"), 0600)
	require.NoError(t, err)

	var buf bytes.Buffer
	backupListCmd.SetOut(&buf)

	err = runBackupList(backupListCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Backups (2)")
	assert.Contains(t, output, "FILE")
	assert.Contains(t, output, "DATE")
	assert.Contains(t, output, "SIZE")
	assert.Contains(t, output, "backup-20250101-120000.xkb")
	assert.Contains(t, output, "backup-20250201-090000.xkb")
	assert.NotContains(t, output, "notes.txt")
}

func TestBackupListCmd_NonExistentDir(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Don't create the backup directory
	var buf bytes.Buffer
	backupListCmd.SetOut(&buf)

	err := runBackupList(backupListCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No backups found.")
}

func TestBackupListCmd_OnlyNonXKBFiles(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	backupDir := filepath.Join(tempDir, ".xkey", "backups")
	err := os.MkdirAll(backupDir, 0700)
	require.NoError(t, err)

	// Write only non-.xkb files
	err = os.WriteFile(filepath.Join(backupDir, "readme.txt"), []byte("info"), 0600)
	require.NoError(t, err)

	var buf bytes.Buffer
	backupListCmd.SetOut(&buf)

	err = runBackupList(backupListCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No backups found.")
}

// --- Contents command structure ---

func TestBackupContentsCmd_Structure(t *testing.T) {
	assert.NotNil(t, backupContentsCmd)
	assert.Equal(t, "contents <file>", backupContentsCmd.Use)
	assert.NotEmpty(t, backupContentsCmd.Short)
	assert.NotEmpty(t, backupContentsCmd.Long)
	assert.NotNil(t, backupContentsCmd.RunE)
}

func TestBackupContentsCmd_Args(t *testing.T) {
	err := backupContentsCmd.Args(backupContentsCmd, []string{})
	assert.Error(t, err, "contents should require exactly 1 arg")

	err = backupContentsCmd.Args(backupContentsCmd, []string{"backup.xkb"})
	assert.NoError(t, err, "contents should accept exactly 1 arg")

	err = backupContentsCmd.Args(backupContentsCmd, []string{"a.xkb", "b.xkb"})
	assert.Error(t, err, "contents should reject more than 1 arg")
}

func TestBackupContentsCmd_Flags(t *testing.T) {
	flags := []string{"password", "key"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := backupContentsCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on contents command", name)
		})
	}
}

// --- Phone backup command structure ---

func TestBackupToDeviceCmd_Structure(t *testing.T) {
	assert.NotNil(t, backupToDeviceCmd)
	assert.Equal(t, "to-device", backupToDeviceCmd.Use)
	assert.NotEmpty(t, backupToDeviceCmd.Short)
	assert.NotEmpty(t, backupToDeviceCmd.Long)
	assert.NotNil(t, backupToDeviceCmd.RunE)
}

func TestBackupToDeviceCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := backupToDeviceCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on to-device command", name)
		})
	}
}

func TestBackupToDeviceCmd_FlagDefaults(t *testing.T) {
	t.Run("device_default_empty", func(t *testing.T) {
		flag := backupToDeviceCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := backupToDeviceCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

func TestBackupFromDeviceCmd_Structure(t *testing.T) {
	assert.NotNil(t, backupFromDeviceCmd)
	assert.Equal(t, "from-device", backupFromDeviceCmd.Use)
	assert.NotEmpty(t, backupFromDeviceCmd.Short)
	assert.NotEmpty(t, backupFromDeviceCmd.Long)
	assert.NotNil(t, backupFromDeviceCmd.RunE)
}

func TestBackupFromDeviceCmd_Flags(t *testing.T) {
	flags := []string{"device", "timeout"}
	for _, name := range flags {
		t.Run(name, func(t *testing.T) {
			flag := backupFromDeviceCmd.Flags().Lookup(name)
			assert.NotNil(t, flag, "flag %q should exist on from-device command", name)
		})
	}
}

func TestBackupFromDeviceCmd_FlagDefaults(t *testing.T) {
	t.Run("device_default_empty", func(t *testing.T) {
		flag := backupFromDeviceCmd.Flags().Lookup("device")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("timeout_default_60s", func(t *testing.T) {
		flag := backupFromDeviceCmd.Flags().Lookup("timeout")
		require.NotNil(t, flag)
		assert.Equal(t, "1m0s", flag.DefValue)
	})
}

// --- Error tests ---

func TestBackupErrors(t *testing.T) {
	tests := []struct {
		err      error
		contains string
	}{
		{ErrBackupCreateFailed, "backup: creation failed"},
		{ErrBackupRestoreFailed, "backup: restore failed"},
		{ErrBackupDecryptFailed, "backup: decryption failed"},
		{ErrBackupKeyRequired, "backup: password or key required"},
		{ErrBackupFileNotFound, "backup: file not found"},
		{ErrBackupToDeviceFailed, "backup: send to device failed"},
		{ErrBackupFromDeviceFailed, "backup: restore from device failed"},
	}

	for _, tc := range tests {
		t.Run(tc.contains, func(t *testing.T) {
			assert.NotNil(t, tc.err)
			assert.Equal(t, tc.contains, tc.err.Error())
			assert.Contains(t, tc.err.Error(), "backup:")
		})
	}
}

func TestBackupErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrBackupCreateFailed,
		ErrBackupRestoreFailed,
		ErrBackupDecryptFailed,
		ErrBackupKeyRequired,
		ErrBackupFileNotFound,
		ErrBackupToDeviceFailed,
		ErrBackupFromDeviceFailed,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// --- Helper function tests ---

func TestBackupFormatSizeEdgeCases(t *testing.T) {
	// formatSize is defined in migrate.go; additional edge cases for backup context
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"zero_bytes", 0, "0B"},
		{"boundary_kb", 1024, "1.0K"},
		{"boundary_mb", 1048576, "1.0M"},
		{"boundary_gb", 1073741824, "1.0G"},
		{"just_under_kb", 1023, "1023B"},
		{"just_under_mb", 1048575, "1024.0K"},
		{"fractional_kb", 1536, "1.5K"},
		{"fractional_mb", 1572864, "1.5M"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatSize(tc.bytes)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetBackupDir(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	dir, err := getBackupDir()
	require.NoError(t, err)

	expected := filepath.Join(tempDir, ".xkey", "backups")
	assert.Equal(t, expected, dir)
}

func TestDeriveKey(t *testing.T) {
	key := deriveKey("test-password")
	assert.Len(t, key, 32, "derived key should be 32 bytes")

	// SHA-256 is deterministic
	key2 := deriveKey("test-password")
	assert.Equal(t, key, key2, "same password should produce same key")

	// Different passwords produce different keys
	key3 := deriveKey("different-password")
	assert.NotEqual(t, key, key3, "different passwords should produce different keys")

	// Verify it matches raw SHA-256
	expected := sha256.Sum256([]byte("test-password"))
	assert.Equal(t, expected[:], key)
}

func TestDeriveKey_EmptyPassword(t *testing.T) {
	key := deriveKey("")
	assert.Len(t, key, 32, "empty password should still produce 32-byte key")

	expected := sha256.Sum256([]byte(""))
	assert.Equal(t, expected[:], key)
}

func TestGenerateRandomKey(t *testing.T) {
	key1, err := generateRandomKey()
	require.NoError(t, err)
	assert.Len(t, key1, 32, "random key should be 32 bytes")

	key2, err := generateRandomKey()
	require.NoError(t, err)
	assert.Len(t, key2, 32, "random key should be 32 bytes")

	// Two random keys should be different (extremely high probability)
	assert.NotEqual(t, key1, key2, "two random keys should differ")
}

func TestResolveDecryptionKey_Password(t *testing.T) {
	key, err := resolveDecryptionKey("mypassword", "")
	require.NoError(t, err)
	assert.Len(t, key, 32)

	expected := deriveKey("mypassword")
	assert.Equal(t, expected, key)
}

func TestResolveDecryptionKey_HexKey(t *testing.T) {
	// Generate a valid 32-byte hex key
	original := make([]byte, 32)
	for i := range original {
		original[i] = byte(i)
	}
	hexKey := hex.EncodeToString(original)

	key, err := resolveDecryptionKey("", hexKey)
	require.NoError(t, err)
	assert.Equal(t, original, key)
}

func TestResolveDecryptionKey_InvalidHex(t *testing.T) {
	_, err := resolveDecryptionKey("", "not-valid-hex")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
}

func TestResolveDecryptionKey_WrongKeyLength(t *testing.T) {
	shortKey := hex.EncodeToString(make([]byte, 16)) // 16 bytes, not 32
	_, err := resolveDecryptionKey("", shortKey)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestResolveDecryptionKey_NeitherProvided(t *testing.T) {
	_, err := resolveDecryptionKey("", "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupKeyRequired)
}

func TestResolveDecryptionKey_PasswordTakesPrecedence(t *testing.T) {
	// When both are provided, password should be used
	validHex := hex.EncodeToString(make([]byte, 32))
	key, err := resolveDecryptionKey("mypassword", validHex)
	require.NoError(t, err)

	expected := deriveKey("mypassword")
	assert.Equal(t, expected, key)
}

func TestGetHostname(t *testing.T) {
	name := getHostname()
	assert.NotEmpty(t, name, "hostname should not be empty")
}

// --- Command execution tests ---

// The three create tests below previously asserted the STUB behavior: they
// ran against an empty HOME and expected the output file to be a plaintext
// `backupManifest`. Backups are now real sealed envelopes over real store
// data, so each seeds the stores and asserts the file is ciphertext.

func TestBackupCreate_WithPassword(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	seedBackupStores(t, tempDir)

	outputFile := filepath.Join(tempDir, "test-backup.xkb")

	var buf bytes.Buffer
	backupCreateCmd.SetOut(&buf)

	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":   outputFile,
		"password": "test-password",
	})

	err := runBackupCreate(backupCreateCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "password-derived")
	assert.Contains(t, output, "Backup created")
	assert.Contains(t, output, outputFile)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	// The file must be a sealed envelope carrying ciphertext — not the
	// plaintext manifest the pre-fix implementation wrote. (The envelope is
	// itself JSON, so parsing it as a manifest "succeeds" with zero fields;
	// assert on the envelope shape and the absence of plaintext instead.)
	var envelope struct {
		Magic      string `json:"magic"`
		Ciphertext []byte `json:"ciphertext"`
	}
	require.NoError(t, json.Unmarshal(data, &envelope))
	assert.Equal(t, "XKBK", envelope.Magic, "backup file is not a sealed XKBK envelope")
	assert.NotEmpty(t, envelope.Ciphertext, "sealed envelope carries no ciphertext")
	assert.NotContains(t, string(data), "UnitTestEntry",
		"seeded secret leaked into the backup file in plaintext")
	assert.NotContains(t, string(data), "s3cret-value",
		"seeded password leaked into the backup file in plaintext")
}

func TestBackupCreate_WithRandomKey(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	seedBackupStores(t, tempDir)

	outputFile := filepath.Join(tempDir, "random-key-backup.xkb")

	var buf bytes.Buffer
	backupCreateCmd.SetOut(&buf)

	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":   outputFile,
		"password": "",
	})

	err := runBackupCreate(backupCreateCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Generated encryption key")
	assert.Contains(t, output, "Backup created")
}

func TestBackupCreate_DefaultOutput(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	seedBackupStores(t, tempDir)

	var buf bytes.Buffer
	backupCreateCmd.SetOut(&buf)

	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":   "",
		"password": "p",
	})

	err := runBackupCreate(backupCreateCmd, []string{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Backup created")
	assert.Contains(t, output, filepath.Join(".xkey", "backups"))
}

func TestBackupRestore_FileNotFound(t *testing.T) {
	var buf bytes.Buffer
	backupRestoreCmd.SetOut(&buf)

	require.NoError(t, backupRestoreCmd.Flags().Set("password", "test"))
	require.NoError(t, backupRestoreCmd.Flags().Set("key", ""))

	err := runBackupRestore(backupRestoreCmd, []string{"/nonexistent/backup.xkb"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupFileNotFound)
}

func TestBackupRestore_NoKey(t *testing.T) {
	tempDir := t.TempDir()
	backupFile := filepath.Join(tempDir, "test.xkb")
	err := os.WriteFile(backupFile, []byte("{}"), 0600)
	require.NoError(t, err)

	var buf bytes.Buffer
	backupRestoreCmd.SetOut(&buf)

	require.NoError(t, backupRestoreCmd.Flags().Set("password", ""))
	require.NoError(t, backupRestoreCmd.Flags().Set("key", ""))

	err = runBackupRestore(backupRestoreCmd, []string{backupFile})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupKeyRequired)
}

// TestBackupRestore_WithPassword previously fabricated a PLAINTEXT manifest
// and asserted that restore accepted it — the false-confidence bug itself (a
// hand-written file restored under any password). It now drives a real
// create→restore round trip and asserts the seeded data actually lands.
func TestBackupRestore_WithPassword(t *testing.T) {
	sourceHome := t.TempDir()
	t.Setenv("HOME", sourceHome)
	seedBackupStores(t, sourceHome)

	backupFile := filepath.Join(t.TempDir(), "test.xkb")

	var createBuf bytes.Buffer
	backupCreateCmd.SetOut(&createBuf)
	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":   backupFile,
		"password": "test-password",
	})
	require.NoError(t, runBackupCreate(backupCreateCmd, []string{}))

	// Restore into a SECOND clean home so we prove data movement, not
	// merely that the command exited zero.
	targetHome := t.TempDir()
	t.Setenv("HOME", targetHome)

	var buf bytes.Buffer
	backupRestoreCmd.SetOut(&buf)
	setBackupFlags(t, backupRestoreCmd, map[string]string{
		"password": "test-password",
		"key":      "",
	})

	require.NoError(t, runBackupRestore(backupRestoreCmd, []string{backupFile}))

	output := buf.String()
	assert.Contains(t, output, "Restoring from")
	assert.Contains(t, output, "Restore completed successfully")

	// The seeded entries must exist in the target home's stores.
	passwordStore, err := openPasswordStore(filepath.Join(backupTestDataDir(targetHome), backupPasswordStoreDir))
	require.NoError(t, err)
	defer func() { _ = passwordStore.Close() }()
	entries, err := passwordStore.List()
	require.NoError(t, err)
	require.NotEmpty(t, entries, "restore reported success but restored no passwords")
}

// TestBackupRestore_WrongPasswordRejected pins the security fix: a backup
// must not restore under the wrong password. The pre-fix code never
// decrypted, so it "succeeded" with any password at all.
func TestBackupRestore_WrongPasswordRejected(t *testing.T) {
	sourceHome := t.TempDir()
	t.Setenv("HOME", sourceHome)
	seedBackupStores(t, sourceHome)

	backupFile := filepath.Join(t.TempDir(), "sealed.xkb")

	var createBuf bytes.Buffer
	backupCreateCmd.SetOut(&createBuf)
	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":   backupFile,
		"password": "correct-horse",
	})
	require.NoError(t, runBackupCreate(backupCreateCmd, []string{}))

	targetHome := t.TempDir()
	t.Setenv("HOME", targetHome)

	var buf bytes.Buffer
	backupRestoreCmd.SetOut(&buf)
	setBackupFlags(t, backupRestoreCmd, map[string]string{
		"password": "definitely-wrong",
		"key":      "",
	})

	err := runBackupRestore(backupRestoreCmd, []string{backupFile})
	require.Error(t, err, "restore must reject an incorrect password")
	assert.NotContains(t, buf.String(), "Restore completed successfully")
}

func TestBackupRestore_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()

	backupFile := filepath.Join(tempDir, "bad.xkb")
	err := os.WriteFile(backupFile, []byte("not json"), 0600)
	require.NoError(t, err)

	var buf bytes.Buffer
	backupRestoreCmd.SetOut(&buf)

	require.NoError(t, backupRestoreCmd.Flags().Set("password", "test"))
	require.NoError(t, backupRestoreCmd.Flags().Set("key", ""))

	err = runBackupRestore(backupRestoreCmd, []string{backupFile})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
}

func TestBackupContents_FileNotFound(t *testing.T) {
	var buf bytes.Buffer
	backupContentsCmd.SetOut(&buf)

	require.NoError(t, backupContentsCmd.Flags().Set("password", "test"))
	require.NoError(t, backupContentsCmd.Flags().Set("key", ""))

	err := runBackupContents(backupContentsCmd, []string{"/nonexistent/backup.xkb"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupFileNotFound)
}

func TestBackupContents_NoKey(t *testing.T) {
	tempDir := t.TempDir()
	backupFile := filepath.Join(tempDir, "test.xkb")
	err := os.WriteFile(backupFile, []byte("{}"), 0600)
	require.NoError(t, err)

	var buf bytes.Buffer
	backupContentsCmd.SetOut(&buf)

	require.NoError(t, backupContentsCmd.Flags().Set("password", ""))
	require.NoError(t, backupContentsCmd.Flags().Set("key", ""))

	err = runBackupContents(backupContentsCmd, []string{backupFile})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupKeyRequired)
}

// TestBackupContents_WithPassword previously hand-wrote a PLAINTEXT manifest
// with invented counts and asserted they were echoed back — the stub never
// decrypted anything. It now inspects a real sealed backup and asserts the
// counts reflect the actually-archived data.
func TestBackupContents_WithPassword(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	seedBackupStores(t, home)

	backupFile := filepath.Join(t.TempDir(), "contents-test.xkb")

	var createBuf bytes.Buffer
	backupCreateCmd.SetOut(&createBuf)
	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":   backupFile,
		"password": "my-password",
	})
	require.NoError(t, runBackupCreate(backupCreateCmd, []string{}))

	var buf bytes.Buffer
	backupContentsCmd.SetOut(&buf)
	setBackupFlags(t, backupContentsCmd, map[string]string{
		"password": "my-password",
		"key":      "",
	})

	require.NoError(t, runBackupContents(backupContentsCmd, []string{backupFile}))

	output := buf.String()
	assert.Contains(t, output, "Backup Contents")
	assert.Contains(t, output, "contents-test.xkb")
	// seedBackupStores writes exactly one entry to each of the three stores.
	assert.Contains(t, output, "Trust certs:  1")
	assert.Contains(t, output, "OATH:         1")
	assert.Contains(t, output, "Passwords:    1")
}

// TestBackupContents_WrongPasswordRejected pins that inspection also requires
// the correct key — the stub echoed a plaintext manifest to anyone.
func TestBackupContents_WrongPasswordRejected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	seedBackupStores(t, home)

	backupFile := filepath.Join(t.TempDir(), "sealed-contents.xkb")

	var createBuf bytes.Buffer
	backupCreateCmd.SetOut(&createBuf)
	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":   backupFile,
		"password": "right-key",
	})
	require.NoError(t, runBackupCreate(backupCreateCmd, []string{}))

	var buf bytes.Buffer
	backupContentsCmd.SetOut(&buf)
	setBackupFlags(t, backupContentsCmd, map[string]string{
		"password": "wrong-key",
		"key":      "",
	})

	require.Error(t, runBackupContents(backupContentsCmd, []string{backupFile}),
		"contents must reject an incorrect password")
}

func TestBackupContents_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()

	backupFile := filepath.Join(tempDir, "bad.xkb")
	err := os.WriteFile(backupFile, []byte("not json"), 0600)
	require.NoError(t, err)

	var buf bytes.Buffer
	backupContentsCmd.SetOut(&buf)

	require.NoError(t, backupContentsCmd.Flags().Set("password", "test"))
	require.NoError(t, backupContentsCmd.Flags().Set("key", ""))

	err = runBackupContents(backupContentsCmd, []string{backupFile})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
}

// --- Command hierarchy tests ---

func TestBackupCmd_Subcommands(t *testing.T) {
	subcommands := backupCmd.Commands()

	// Collect subcommand names
	names := make(map[string]bool)
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["create"], "backup should have create subcommand")
	assert.True(t, names["restore"], "backup should have restore subcommand")
	assert.True(t, names["list"], "backup should have list subcommand")
	assert.True(t, names["contents"], "backup should have contents subcommand")
	assert.True(t, names["to-device"], "backup should have to-device subcommand")
	assert.True(t, names["from-device"], "backup should have from-device subcommand")
}

func TestBackupCmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Name() == "backup" {
			found = true
			break
		}
	}
	assert.True(t, found, "backup command should be registered on root")
}
