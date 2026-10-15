// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// asLUKSRoot runs a luks2 command past its root check against a temporary
// home. Every path these tests take is refused before a container is
// created, unlocked or attached to a loop device. The process itself must
// not be root, so the volume status checks on the way can only read.
func asLUKSRoot(t *testing.T) string {
	t.Helper()
	require.NotEqual(t, 0, os.Geteuid(), "this test must not run as root")
	root := useXKeyHomeFallback(t)
	withEUID(t, 0)

	saved := luksEnsureKeyring
	luksEnsureKeyring = func() error { return nil }
	t.Cleanup(func() { luksEnsureKeyring = saved })
	return root
}

// writeContainer writes a stand-in container file of size bytes.
func writeContainer(t *testing.T, path string, size int) []byte {
	t.Helper()
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i)
	}
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return content
}

func TestRunMigrate_UnknownWipeStandard(t *testing.T) {
	asLUKSRoot(t)
	migrateWipe, migrateWipeStandard = true, "rot13"

	_, err := runLUKSCmd(t, runMigrate)
	require.ErrorIs(t, err, ErrMigrateInvalidWipeStandard)
}

// TestRunMigrate_KeyringBlockedLeavesSourceInPlace pins the ordering the
// preflight exists for: a blocked keyring is refused before the source is
// locked or renamed.
func TestRunMigrate_KeyringBlockedLeavesSourceInPlace(t *testing.T) {
	root := asLUKSRoot(t)
	source := filepath.Join(root, "xkey.luks")
	content := writeContainer(t, source, 64)
	migrateSourcePath = source
	luksEnsureKeyring = func() error { return luks.ErrKeyringUnavailable }

	_, err := runLUKSCmd(t, runMigrate)
	require.ErrorIs(t, err, luks.ErrKeyringUnavailable)

	kept, readErr := os.ReadFile(source)
	require.NoError(t, readErr)
	assert.Equal(t, content, kept)
	assert.NoFileExists(t, source+".old")
}

func TestRunMigrate_NoSourceContainer(t *testing.T) {
	root := asLUKSRoot(t)

	t.Run("explicit source path", func(t *testing.T) {
		migrateSourcePath = filepath.Join(root, "missing.luks")
		_, err := runLUKSCmd(t, runMigrate)
		require.ErrorIs(t, err, ErrMigrateNoSource)
	})
	t.Run("home default", func(t *testing.T) {
		migrateSourcePath = ""
		_, err := runLUKSCmd(t, runMigrate)
		require.ErrorIs(t, err, ErrMigrateNoSource)
	})
	t.Run("resolved home", func(t *testing.T) {
		home, err := xhome.Resolve()
		require.NoError(t, err)
		resolvedHome = home
		migrateSourcePath = filepath.Join(root, "missing.luks")
		_, err = runLUKSCmd(t, runMigrate)
		require.ErrorIs(t, err, ErrMigrateNoSource)
	})
}

func TestRunMigrate_UnresolvableHome(t *testing.T) {
	asLUKSRoot(t)
	breakXKeyHome(t)
	migrateSourcePath = filepath.Join(t.TempDir(), "xkey.luks")

	_, err := runLUKSCmd(t, runMigrate)
	var resolveErr *xhome.ResolveError
	require.ErrorAs(t, err, &resolveErr)
}

func TestRunMigrate_InvalidSize(t *testing.T) {
	root := asLUKSRoot(t)
	migrateSourcePath = filepath.Join(root, "xkey.luks")
	writeContainer(t, migrateSourcePath, 64)
	migrateSize = "lots"

	_, err := runLUKSCmd(t, runMigrate)
	var migrateErr *MigrateError
	require.ErrorAs(t, err, &migrateErr)
	assert.Equal(t, "parse_size", migrateErr.Operation)
	assert.FileExists(t, migrateSourcePath)
}

func TestRunMigrate_PassphraseReadFailsBeforeRename(t *testing.T) {
	root := asLUKSRoot(t)
	migrateSourcePath = filepath.Join(root, "xkey.luks")
	writeContainer(t, migrateSourcePath, 64)
	closeStdin(t)

	out, err := runLUKSCmd(t, runMigrate)
	var migrateErr *MigrateError
	require.ErrorAs(t, err, &migrateErr)
	assert.Equal(t, "read_passphrase", migrateErr.Operation)
	assert.Contains(t, out, "Migration plan:")
	assert.FileExists(t, migrateSourcePath)
	assert.NoFileExists(t, migrateSourcePath+".old")
}

// TestRunMigrate_CreateFailureRestoresSource covers the rollback the
// migration owes the operator: once the source is renamed to .old, a new
// container that cannot be created must put the source back.
func TestRunMigrate_CreateFailureRestoresSource(t *testing.T) {
	root := asLUKSRoot(t)
	source := filepath.Join(root, "xkey.luks")
	content := writeContainer(t, source, 1024)
	migrateSourcePath = source
	// The new path is taken, so the container create refuses it.
	migratePath = filepath.Join(root, "taken.luks")
	writeContainer(t, migratePath, 1)
	pipeStdin(t, "old-passphrase\n")

	out, err := runLUKSCmd(t, runMigrate)
	require.ErrorIs(t, err, ErrMigrateCreateFailed)
	require.ErrorIs(t, err, luks.ErrVolumeAlreadyExists)

	restored, readErr := os.ReadFile(source)
	require.NoError(t, readErr)
	assert.Equal(t, content, restored)
	assert.NoFileExists(t, source+".old")

	assert.Contains(t, out, "Source:    "+source+" ("+formatSize(1024)+")")
	assert.Contains(t, out, "New:       "+migratePath+" ("+formatSize(2048)+")", "the default size doubles the source")
	assert.Contains(t, out, "Backup:    "+source+".old")
	assert.NotContains(t, out, "Migration complete")
}

func TestRunMigrate_ExplicitSizeIsPlanned(t *testing.T) {
	root := asLUKSRoot(t)
	migrateSourcePath = filepath.Join(root, "xkey.luks")
	writeContainer(t, migrateSourcePath, 1024)
	migratePath = filepath.Join(root, "taken.luks")
	writeContainer(t, migratePath, 1)
	migrateSize = "4M"
	pipeStdin(t, "old-passphrase\n")

	out, err := runLUKSCmd(t, runMigrate)
	require.ErrorIs(t, err, ErrMigrateCreateFailed)
	assert.Contains(t, out, "("+formatSize(4<<20)+")")
}

func TestRunMigrate_RenameFailureLeavesSource(t *testing.T) {
	root := asLUKSRoot(t)
	dir := filepath.Join(root, "readonly")
	require.NoError(t, os.Mkdir(dir, 0o755))
	migrateSourcePath = filepath.Join(dir, "xkey.luks")
	content := writeContainer(t, migrateSourcePath, 64)
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	pipeStdin(t, "old-passphrase\n")

	_, err := runLUKSCmd(t, runMigrate)
	require.ErrorIs(t, err, ErrMigrateRenameFailed)

	kept, readErr := os.ReadFile(migrateSourcePath)
	require.NoError(t, readErr)
	assert.Equal(t, content, kept)
}

func TestRunWipe_NoContainer(t *testing.T) {
	root := asLUKSRoot(t)
	wipeStandard = "nist"
	wipePath = filepath.Join(root, "missing.luks")

	_, err := runLUKSCmd(t, runWipe)
	require.ErrorIs(t, err, ErrWipeNoContainer)
}

// TestRunWipe_RequiresTypedConfirmation pins the guard in front of an
// irreversible destroy: anything but "DESTROY" leaves the container whole.
func TestRunWipe_RequiresTypedConfirmation(t *testing.T) {
	root := asLUKSRoot(t)
	wipeStandard, wipeForce = "dod3", false
	wipePath = filepath.Join(root, "xkey.luks")
	content := writeContainer(t, wipePath, 2048)

	for _, answer := range []string{"destroy\n", "yes\n", "\n"} {
		pipeStdin(t, answer)
		out, err := runLUKSCmd(t, runWipe)
		require.ErrorIs(t, err, ErrWipeAborted, "answer %q", answer)
		assert.Contains(t, out, "THIS ACTION CANNOT BE UNDONE")
		assert.Contains(t, out, "Container: "+wipePath)
		assert.Contains(t, out, "Size:      "+formatSize(2048))
		assert.Contains(t, out, "Pattern:   "+getWipePatternDescription(luks.StandardDoD3Pass))
	}

	kept, err := os.ReadFile(wipePath)
	require.NoError(t, err)
	assert.Equal(t, content, kept)
}

func TestRunWipe_ConfirmationReadFails(t *testing.T) {
	root := asLUKSRoot(t)
	wipeStandard, wipeForce = "nist", false
	wipePath = filepath.Join(root, "xkey.luks")
	writeContainer(t, wipePath, 16)
	closeStdin(t)

	_, err := runLUKSCmd(t, runWipe)
	var wipeErr *WipeError
	require.ErrorAs(t, err, &wipeErr)
	assert.Equal(t, "read_confirmation", wipeErr.Operation)
	assert.FileExists(t, wipePath)
}

func TestRunSeal_RefusesExistingContainer(t *testing.T) {
	root := asLUKSRoot(t)
	sealPath = filepath.Join(root, "xkey.luks")
	content := writeContainer(t, sealPath, 32)

	_, err := runLUKSCmd(t, runSeal)
	require.ErrorIs(t, err, luks.ErrVolumeAlreadyExists)

	kept, readErr := os.ReadFile(sealPath)
	require.NoError(t, readErr)
	assert.Equal(t, content, kept, "seal never overwrites a container")
}

func TestRunSeal_InvalidSize(t *testing.T) {
	root := asLUKSRoot(t)
	sealPath = filepath.Join(root, "xkey.luks")
	sealSize = "big"

	_, err := runLUKSCmd(t, runSeal)
	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "parse_size", sealErr.Operation)
	assert.NoFileExists(t, sealPath)
}

func TestRunSeal_PassphraseMismatchCreatesNothing(t *testing.T) {
	root := asLUKSRoot(t)
	sealPath = filepath.Join(root, "xkey.luks")
	sealSize = "64M"
	pipeStdin(t, "one\ntwo\n")

	_, err := runLUKSCmd(t, runSeal)
	require.ErrorIs(t, err, luks.ErrPassphraseMismatch)
	assert.NoFileExists(t, sealPath)
}

func TestRunUnseal_NoContainer(t *testing.T) {
	root := asLUKSRoot(t)
	unsealPath = filepath.Join(root, "missing.luks")

	_, err := runLUKSCmd(t, runUnseal)
	require.ErrorIs(t, err, ErrUnsealNoVolume)
}

// TestRunUnseal_AlreadyMountedIsNotAnError pins the idempotent case: a
// container whose mount point is already mounted reports where, and does
// not ask for the passphrase again.
func TestRunUnseal_AlreadyMountedIsNotAnError(t *testing.T) {
	root := asLUKSRoot(t)
	unsealPath = filepath.Join(root, "xkey.luks")
	writeContainer(t, unsealPath, 32)
	unsealMountPoint = "/"
	closeStdin(t)

	out, err := runLUKSCmd(t, runUnseal)
	require.NoError(t, err)
	assert.Contains(t, out, "already unlocked and mounted at /")
}

// isolateImportDataFlags restores the import-data flags after the test.
func isolateImportDataFlags(t *testing.T) {
	t.Helper()
	path, source, mount := importDataPath, importDataSource, importDataMountPoint
	cleanup, backup, unseal := importDataCleanup, importDataBackup, importDataUnseal
	t.Cleanup(func() {
		importDataPath, importDataSource, importDataMountPoint = path, source, mount
		importDataCleanup, importDataBackup, importDataUnseal = cleanup, backup, unseal
	})
}

func TestRunImportData_NoSourceData(t *testing.T) {
	root := asLUKSRoot(t)
	isolateImportDataFlags(t)
	importDataSource = filepath.Join(root, "empty")
	require.NoError(t, os.Mkdir(importDataSource, 0o755))
	importDataPath = filepath.Join(root, "xkey.luks")
	writeContainer(t, importDataPath, 32)

	_, err := runLUKSCmd(t, runImportData)
	require.ErrorIs(t, err, ErrImportDataNoSource)
}

func TestRunImportData_NoContainer(t *testing.T) {
	root := asLUKSRoot(t)
	isolateImportDataFlags(t)
	importDataSource = filepath.Join(root, "data")
	require.NoError(t, os.Mkdir(importDataSource, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(importDataSource, "keys.db"), []byte("k"), 0o600))
	importDataPath = filepath.Join(root, "missing.luks")

	_, err := runLUKSCmd(t, runImportData)
	require.ErrorIs(t, err, ErrImportDataNoVolume)
}

func TestRunImportData_PassphraseReadFails(t *testing.T) {
	root := asLUKSRoot(t)
	isolateImportDataFlags(t)
	importDataSource = filepath.Join(root, "data")
	require.NoError(t, os.Mkdir(importDataSource, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(importDataSource, "keys.db"), []byte("k"), 0o600))
	importDataPath = filepath.Join(root, "xkey.luks")
	writeContainer(t, importDataPath, 32)
	closeStdin(t)

	_, err := runLUKSCmd(t, runImportData)
	var importErr *ImportDataError
	require.ErrorAs(t, err, &importErr)
	assert.Equal(t, "read_passphrase", importErr.Operation)
	assert.FileExists(t, filepath.Join(importDataSource, "keys.db"), "source data is untouched")
}

// TestCheckLUKSVolume_RootWithoutTerminalFailsClosed covers startup as
// root with a locked container and no terminal to ask on: the passphrase
// read fails and startup stops instead of running on the plaintext home.
func TestCheckLUKSVolume_RootWithoutTerminalFailsClosed(t *testing.T) {
	asLUKSRoot(t)
	home, err := xhome.Resolve()
	require.NoError(t, err)
	resolvedHome = home
	writeContainer(t, home.LUKSPath(), 32)
	closeStdin(t)

	err = checkLUKSVolume()
	require.ErrorIs(t, err, ErrLUKSPassphraseRead)
	var configErr *ConfigError
	require.ErrorAs(t, err, &configErr)
	assert.Equal(t, "read_passphrase", configErr.Operation)
}
