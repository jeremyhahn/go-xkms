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
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/spf13/cobra"
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
	flags := []string{"output", "password-stdin"}
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

	t.Run("password_stdin_default_false", func(t *testing.T) {
		flag := backupCreateCmd.Flags().Lookup("password-stdin")
		require.NotNil(t, flag)
		assert.Equal(t, "false", flag.DefValue)
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
	flags := []string{"password-stdin", "key-stdin"}
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
	flags := []string{"password-stdin", "key-stdin"}
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
		{ErrBackupKeyRequired, "backup: password (--password-stdin or XKEY_BACKUP_PASSWORD) or key (--key-stdin or XKEY_BACKUP_KEY) required"},
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

// TestBackupCommands_NoPasswordValueFlag pins go-xkms#1202: no backup
// command accepts the password as a flag value, which every other process on
// the host could read through 'ps'.
func TestBackupCommands_NoPasswordValueFlag(t *testing.T) {
	for _, cmd := range []*cobra.Command{
		backupCreateCmd, backupRestoreCmd, backupContentsCmd,
		backupToDeviceCmd, backupFromDeviceCmd,
	} {
		t.Run(cmd.Name(), func(t *testing.T) {
			assert.Nil(t, cmd.Flags().Lookup("password"), "--password value flag must not exist")
		})
	}
}

// TestBackupCommands_NoKeyValueFlag pins go-xkms#1209: no backup command
// accepts the hex key as a flag value, which every other process on the host
// could read through 'ps'.
func TestBackupCommands_NoKeyValueFlag(t *testing.T) {
	for _, cmd := range []*cobra.Command{backupRestoreCmd, backupContentsCmd, backupFromDeviceCmd} {
		t.Run(cmd.Name(), func(t *testing.T) {
			flag := cmd.Flags().Lookup("key")
			if flag != nil {
				assert.Equal(t, "bool", flag.Value.Type(), "--key must not be a value flag")
			}
			assert.NotNil(t, cmd.Flags().Lookup("key-stdin"), "--key-stdin flag must exist")
		})
	}
}

// TestResolveBackupCredential_KeyFromStdin pins the stdin source for the raw
// backup key: piped input, trimmed of its trailing newline, decodes to the
// same key resolveBackupCredential accepts from the environment.
func TestResolveBackupCredential_KeyFromStdin(t *testing.T) {
	raw, err := backup.GenerateKey()
	require.NoError(t, err)
	eb := sealTestEnvelope(t, raw)

	cmd := newBackupCredentialCmd(t)
	stubStdin(t, []byte(hex.EncodeToString(raw.Bytes())+"\n"), nil)
	require.NoError(t, cmd.Flags().Set("key-stdin", "true"))

	credential, err := resolveBackupCredential(cmd)
	require.NoError(t, err)
	defer credential.wipe()

	key, err := credential.keyFor(eb)
	require.NoError(t, err)
	assert.Equal(t, raw.Bytes(), key.Bytes())
}

// TestResolveBackupCredential_KeyStdinEmpty pins that an empty piped key is
// refused rather than silently treated as "no key supplied".
func TestResolveBackupCredential_KeyStdinEmpty(t *testing.T) {
	cmd := newBackupCredentialCmd(t)
	stubStdin(t, []byte("\n"), nil)
	require.NoError(t, cmd.Flags().Set("key-stdin", "true"))

	credential, err := resolveBackupCredential(cmd)
	assert.Nil(t, credential)
	assert.ErrorIs(t, err, ErrBackupKeyStdinEmpty)
}

// TestResolveBackupCredential_NoSourceRefused pins that "backup restore" and
// "backup contents" fail with ErrBackupKeyRequired when neither a password
// nor a key was supplied through any source.
func TestResolveBackupCredential_NoSourceRefused(t *testing.T) {
	cmd := newBackupCredentialCmd(t)
	credential, err := resolveBackupCredential(cmd)
	assert.Nil(t, credential)
	assert.ErrorIs(t, err, ErrBackupKeyRequired)
}

// oneBackupPassword is a backup.PasswordReader holding one entry, so a test
// can seal an envelope without seeding on-disk stores.
type oneBackupPassword struct{}

// List returns the single entry.
func (oneBackupPassword) List() ([]*backup.PasswordInfo, error) {
	info := &backup.PasswordInfo{ID: "id-1", Name: "entry"}
	if err := info.SetPassword("value"); err != nil {
		return nil, err
	}
	return []*backup.PasswordInfo{info}, nil
}

// newBackupCredentialCmd returns a command declaring the backup credential
// flags, isolated from the package-level commands.
func newBackupCredentialCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "credential-test"}
	backupPasswordSource.addFlags(cmd)
	backupKeySource.addFlags(cmd)
	var out bytes.Buffer
	cmd.SetOut(&out)
	t.Setenv(backupPasswordSource.envVar, "")
	t.Setenv(backupKeySource.envVar, "")
	return cmd
}

// sealTestEnvelope seals one trust-store certificate under key.
func sealTestEnvelope(t *testing.T, key *backup.Key) *backup.EncryptedBackup {
	t.Helper()
	svc, err := backup.NewService(&backup.Config{DeviceName: "test"},
		backup.WithPasswords(oneBackupPassword{}))
	require.NoError(t, err)
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)
	return eb
}

func TestResolveSealingKey_PasswordFromStdin(t *testing.T) {
	cmd := newBackupCredentialCmd(t)
	stubStdin(t, []byte("stdin-password\n"), nil)
	require.NoError(t, cmd.Flags().Set("password-stdin", "true"))

	key, err := resolveSealingKey(cmd, ErrBackupCreateFailed)
	require.NoError(t, err)
	defer key.Wipe()

	require.NotNil(t, key.KDF(), "a password key must carry its KDF record")
	derived, err := backup.DerivePasswordKey(key.KDF(), []byte("stdin-password"))
	require.NoError(t, err)
	assert.Equal(t, key.Bytes(), derived.Bytes(), "the trailing newline must not be part of the password")
}

func TestResolveSealingKey_PasswordFromEnv(t *testing.T) {
	cmd := newBackupCredentialCmd(t)
	setBackupPassword(t, "env-password")

	key, err := resolveSealingKey(cmd, ErrBackupCreateFailed)
	require.NoError(t, err)
	require.NotNil(t, key.KDF())
	assert.Contains(t, cmd.OutOrStdout().(*bytes.Buffer).String(), "password-derived")
}

func TestResolveSealingKey_RandomWhenNoPassword(t *testing.T) {
	cmd := newBackupCredentialCmd(t)

	key, err := resolveSealingKey(cmd, ErrBackupCreateFailed)
	require.NoError(t, err)
	assert.Nil(t, key.KDF())
	assert.Contains(t, cmd.OutOrStdout().(*bytes.Buffer).String(), hex.EncodeToString(key.Bytes()))
}

func TestResolveSealingKey_EmptyStdinRefused(t *testing.T) {
	cmd := newBackupCredentialCmd(t)
	stubStdin(t, []byte("\n"), nil)
	require.NoError(t, cmd.Flags().Set("password-stdin", "true"))

	key, err := resolveSealingKey(cmd, ErrBackupCreateFailed)
	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrBackupPasswordStdinEmpty)
}

func TestResolveSealingKey_StdinReadError(t *testing.T) {
	cmd := newBackupCredentialCmd(t)
	stubStdin(t, nil, errors.New("broken pipe"))
	require.NoError(t, cmd.Flags().Set("password-stdin", "true"))

	_, err := resolveSealingKey(cmd, ErrBackupCreateFailed)
	assert.ErrorIs(t, err, ErrBackupPasswordStdinRead)
}

func TestResolveBackupCredential_PasswordOpensEnvelope(t *testing.T) {
	sealing, err := backup.NewPasswordKey([]byte("open-me"))
	require.NoError(t, err)
	eb := sealTestEnvelope(t, sealing)

	cmd := newBackupCredentialCmd(t)
	setBackupPassword(t, "open-me")
	credential, err := resolveBackupCredential(cmd)
	require.NoError(t, err)
	defer credential.wipe()

	key, err := credential.keyFor(eb)
	require.NoError(t, err)
	assert.Equal(t, sealing.Bytes(), key.Bytes())
}

func TestResolveBackupCredential_HexKey(t *testing.T) {
	raw, err := backup.GenerateKey()
	require.NoError(t, err)
	eb := sealTestEnvelope(t, raw)

	cmd := newBackupCredentialCmd(t)
	t.Setenv(backupKeySource.envVar, hex.EncodeToString(raw.Bytes()))
	credential, err := resolveBackupCredential(cmd)
	require.NoError(t, err)

	key, err := credential.keyFor(eb)
	require.NoError(t, err)
	assert.Equal(t, raw.Bytes(), key.Bytes())
}

func TestResolveBackupCredential_PasswordTakesPrecedence(t *testing.T) {
	cmd := newBackupCredentialCmd(t)
	setBackupPassword(t, "wins")
	t.Setenv(backupKeySource.envVar, hex.EncodeToString(make([]byte, backup.KeySize)))

	credential, err := resolveBackupCredential(cmd)
	require.NoError(t, err)
	t.Cleanup(credential.wipe)
	require.NotNil(t, credential.password)
	assert.Equal(t, []byte("wins"), credential.password.Bytes())
	assert.Nil(t, credential.key)
}

func TestResolveBackupCredential_InvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		keyHex string
		want   error
	}{
		{"neither", "", ErrBackupKeyRequired},
		{"invalid hex", "not-valid-hex", ErrBackupDecryptFailed},
		{"short key", hex.EncodeToString(make([]byte, 16)), backup.ErrInvalidKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newBackupCredentialCmd(t)
			t.Setenv(backupKeySource.envVar, tt.keyHex)
			credential, err := resolveBackupCredential(cmd)
			assert.Nil(t, credential)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestBackupCredentialKeyFor_Refusals(t *testing.T) {
	pw, err := secure.NewBufferFromBytes([]byte("pw"))
	require.NoError(t, err)
	password := &backupCredential{password: pw}
	t.Cleanup(password.wipe)

	t.Run("legacy unsalted file", func(t *testing.T) {
		_, err := password.keyFor(&backup.EncryptedBackup{Magic: backup.BackupMagic, Version: 1})
		assert.ErrorIs(t, err, ErrBackupDecryptFailed)
		assert.ErrorIs(t, err, backup.ErrLegacyBackupFormat)
		assert.Contains(t, err.Error(), "re-create the backup")
	})

	t.Run("raw-key envelope", func(t *testing.T) {
		raw, err := backup.GenerateKey()
		require.NoError(t, err)
		_, err = password.keyFor(sealTestEnvelope(t, raw))
		assert.ErrorIs(t, err, backup.ErrNotPasswordSealed)
		assert.Contains(t, err.Error(), "--key")
	})

	t.Run("tampered kdf parameters", func(t *testing.T) {
		sealing, err := backup.NewPasswordKey([]byte("pw"))
		require.NoError(t, err)
		eb := sealTestEnvelope(t, sealing)
		params := *eb.KDF
		params.MemoryKiB = 8 * 1024
		eb.KDF = &params

		_, err = password.keyFor(eb)
		assert.ErrorIs(t, err, ErrBackupDecryptFailed)
		assert.ErrorIs(t, err, backup.ErrKeyDerivationFailed)
	})
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

	setBackupPassword(t, "test")
	setBackupKey(t, "")

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

	setBackupPassword(t, "")
	setBackupKey(t, "")

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
	passwordStore, err := openPasswordStore(filepath.Join(backupTestDataDir(targetHome), passwordStoreFeature))
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

	setBackupPassword(t, "test")
	setBackupKey(t, "")

	err = runBackupRestore(backupRestoreCmd, []string{backupFile})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
}

func TestBackupContents_FileNotFound(t *testing.T) {
	var buf bytes.Buffer
	backupContentsCmd.SetOut(&buf)

	setBackupPassword(t, "test")
	setBackupKey(t, "")

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

	setBackupPassword(t, "")
	setBackupKey(t, "")

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

	setBackupPassword(t, "test")
	setBackupKey(t, "")

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

// TestBackupRestore_LegacyUnsaltedFileRefused pins go-xkms#1202: a version 1
// file, keyed with an unsalted SHA-256 of the password, is refused with a
// typed error and never migrated.
func TestBackupRestore_LegacyUnsaltedFileRefused(t *testing.T) {
	backupFile := filepath.Join(t.TempDir(), "legacy.xkb")
	legacy, err := json.Marshal(map[string]any{
		"magic":      backup.BackupMagic,
		"version":    1,
		"nonce":      make([]byte, 24),
		"ciphertext": []byte("sealed-under-sha256-of-password"),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(backupFile, legacy, 0o600))

	var buf bytes.Buffer
	backupRestoreCmd.SetOut(&buf)
	setBackupFlags(t, backupRestoreCmd, map[string]string{"password": "legacy", "key": ""})

	err = runBackupRestore(backupRestoreCmd, []string{backupFile})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
	assert.ErrorIs(t, err, backup.ErrLegacyBackupFormat)
	assert.NotContains(t, buf.String(), "Restore completed")
}

// TestBackupCreate_PasswordStdinRoundTrip drives create and contents with
// the password on standard input and checks the file records the salted KDF.
func TestBackupCreate_PasswordStdinRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	seedBackupStores(t, home)
	setBackupPassword(t, "")

	backupFile := filepath.Join(t.TempDir(), "stdin.xkb")
	stubStdin(t, []byte("piped-password\n"), nil)

	var createBuf bytes.Buffer
	backupCreateCmd.SetOut(&createBuf)
	setBackupFlags(t, backupCreateCmd, map[string]string{"output": backupFile, "password-stdin": "true"})
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))

	encrypted, err := readEncryptedBackup(backupFile)
	require.NoError(t, err)
	require.NotNil(t, encrypted.KDF, "a password backup must record its KDF")
	assert.Equal(t, backup.BackupVersion, encrypted.Version)
	assert.NotEmpty(t, encrypted.KDF.Salt)

	// The password read for create was wiped after use; pipe it again.
	stubStdin(t, []byte("piped-password\n"), nil)
	var contentsBuf bytes.Buffer
	backupContentsCmd.SetOut(&contentsBuf)
	setBackupFlags(t, backupContentsCmd, map[string]string{"password-stdin": "true", "key": ""})
	require.NoError(t, runBackupContents(backupContentsCmd, []string{backupFile}))
	assert.Contains(t, contentsBuf.String(), "Passwords:    1")
}
