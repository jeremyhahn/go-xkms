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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// pipeStdin replaces os.Stdin with a pipe carrying content for the duration
// of the test. The LUKS commands read passphrases straight from os.Stdin, so
// this is the only seam available for exercising their piped-input paths.
func pipeStdin(t *testing.T, content string) {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	_, err = w.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	previous := os.Stdin
	os.Stdin = r

	t.Cleanup(func() {
		os.Stdin = previous
		_ = r.Close()
	})
}

// isolateLUKSFlags resets every package-level LUKS command flag and restores
// them afterwards so tests do not leak state into each other.
func isolateLUKSFlags(t *testing.T) {
	t.Helper()

	saved := struct {
		sealSize, sealPath, sealMount           string
		sealUnseal, sealSkipMigrate             bool
		lockPath, lockMount                     string
		unsealPath, unsealMount                 string
		wipeStandard, wipePath, wipeMount       string
		wipeForce                               bool
		migrateSize, migratePath, migrateSource string
		migrateWipeStandard                     string
		migrateKeepOld, migrateWipeEnabled      bool
		home                                    any
	}{
		sealSize: sealSize, sealPath: sealPath, sealMount: sealMountPoint,
		sealUnseal: sealUnseal, sealSkipMigrate: sealSkipMigrate,
		lockPath: lockPath, lockMount: lockMountPoint,
		unsealPath: unsealPath, unsealMount: unsealMountPoint,
		wipeStandard: wipeStandard, wipePath: wipePath, wipeMount: wipeMountPoint,
		wipeForce:   wipeForce,
		migrateSize: migrateSize, migratePath: migratePath, migrateSource: migrateSourcePath,
		migrateWipeStandard: migrateWipeStandard,
		migrateKeepOld:      migrateKeepOld, migrateWipeEnabled: migrateWipe,
	}

	previousHome := resolvedHome

	t.Cleanup(func() {
		sealSize, sealPath, sealMountPoint = saved.sealSize, saved.sealPath, saved.sealMount
		sealUnseal, sealSkipMigrate = saved.sealUnseal, saved.sealSkipMigrate
		lockPath, lockMountPoint = saved.lockPath, saved.lockMount
		unsealPath, unsealMountPoint = saved.unsealPath, saved.unsealMount
		wipeStandard, wipePath, wipeMountPoint = saved.wipeStandard, saved.wipePath, saved.wipeMount
		wipeForce = saved.wipeForce
		migrateSize, migratePath, migrateSourcePath = saved.migrateSize, saved.migratePath, saved.migrateSource
		migrateWipeStandard = saved.migrateWipeStandard
		migrateKeepOld, migrateWipe = saved.migrateKeepOld, saved.migrateWipeEnabled
		resolvedHome = previousHome
	})
}

func runLUKSCmd(t *testing.T, run func(*cobra.Command, []string) error) (string, error) {
	t.Helper()

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := run(cmd, nil)
	return buf.String(), err
}

// --- copyDirContents / copyFileSeal ---

func TestCopyDirContents_PreservesTreeAndMode(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(src, "nested", "deeper"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "top.txt"), []byte("top"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(src, "nested", "mid.txt"), []byte("mid"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(src, "nested", "deeper", "leaf.txt"), []byte("leaf"), 0600))

	require.NoError(t, copyDirContents(src, dst))

	top, err := os.ReadFile(filepath.Join(dst, "top.txt"))
	require.NoError(t, err)
	assert.Equal(t, "top", string(top))

	leaf, err := os.ReadFile(filepath.Join(dst, "nested", "deeper", "leaf.txt"))
	require.NoError(t, err)
	assert.Equal(t, "leaf", string(leaf))

	info, err := os.Stat(filepath.Join(dst, "nested", "mid.txt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "file permissions must survive the copy")
}

func TestCopyDirContents_MissingSource(t *testing.T) {
	err := copyDirContents(filepath.Join(t.TempDir(), "absent"), t.TempDir())
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestCopyFileSeal_MissingSource(t *testing.T) {
	err := copyFileSeal(filepath.Join(t.TempDir(), "absent"), filepath.Join(t.TempDir(), "dst"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestCopyFileSeal_PreservesContentAndMode(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	dst := filepath.Join(t.TempDir(), "dst")
	require.NoError(t, os.WriteFile(src, []byte("secret"), 0600))

	require.NoError(t, copyFileSeal(src, dst))

	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "secret", string(data))

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestCopyFileSeal_RefusesSymlink proves that copyFileSeal refuses to
// follow a symlink rather than silently copying whatever it points at into
// the (unencrypted) staging directory.
func TestCopyFileSeal_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("outside data"), 0600))

	link := filepath.Join(dir, "link.txt")
	require.NoError(t, os.Symlink(target, link))

	dst := filepath.Join(dir, "dst.txt")
	err := copyFileSeal(link, dst)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSealSymlinkRefused)

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "copy_file", sealErr.Operation)

	_, statErr := os.Stat(dst)
	assert.True(t, os.IsNotExist(statErr), "the destination must not be created for a refused symlink")
}

// TestCopyDirContents_RefusesSymlink proves that a symlink encountered
// while walking a directory tree aborts the copy instead of dereferencing
// it into the staging copy.
func TestCopyDirContents_RefusesSymlink(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	target := filepath.Join(src, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("secret"), 0600))
	require.NoError(t, os.Symlink(target, filepath.Join(src, "link.txt")))

	err := copyDirContents(src, dst)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSealSymlinkRefused)
}

// --- volume construction from flags ---

func TestCreateSealVolume_FlagsOverrideDefaults(t *testing.T) {
	isolateLUKSFlags(t)
	dir := t.TempDir()

	sealPath = filepath.Join(dir, "custom.luks")
	sealMountPoint = filepath.Join(dir, "mnt")

	vol, err := createSealVolume()
	require.NoError(t, err)
	assert.Equal(t, sealPath, vol.LUKSPath)
	assert.Equal(t, sealMountPoint, vol.MountPoint)
}

func TestCreateLockVolume_FlagsOverrideDefaults(t *testing.T) {
	isolateLUKSFlags(t)
	dir := t.TempDir()

	lockPath = filepath.Join(dir, "custom.luks")
	lockMountPoint = filepath.Join(dir, "mnt")

	vol, err := createLockVolume()
	require.NoError(t, err)
	assert.Equal(t, lockPath, vol.LUKSPath)
	assert.Equal(t, lockMountPoint, vol.MountPoint)
}

func TestCreateUnsealVolume_FlagsOverrideDefaults(t *testing.T) {
	isolateLUKSFlags(t)
	dir := t.TempDir()

	unsealPath = filepath.Join(dir, "custom.luks")
	unsealMountPoint = filepath.Join(dir, "mnt")

	vol, err := createUnsealVolume()
	require.NoError(t, err)
	assert.Equal(t, unsealPath, vol.LUKSPath)
	assert.Equal(t, unsealMountPoint, vol.MountPoint)
}

func TestCreateWipeVolume_FlagsOverrideDefaults(t *testing.T) {
	isolateLUKSFlags(t)
	dir := t.TempDir()

	wipePath = filepath.Join(dir, "custom.luks")
	wipeMountPoint = filepath.Join(dir, "mnt")

	vol, err := createWipeVolume()
	require.NoError(t, err)
	assert.Equal(t, wipePath, vol.LUKSPath)
	assert.Equal(t, wipeMountPoint, vol.MountPoint)
}

func TestCreateVolumes_ExpandTilde(t *testing.T) {
	isolateLUKSFlags(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	sealPath = "~/tilde.luks"
	sealMountPoint = "~/tilde-mnt"

	vol, err := createSealVolume()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, "tilde.luks"), vol.LUKSPath)
	assert.Equal(t, filepath.Join(home, "tilde-mnt"), vol.MountPoint)
}

// --- passphrase readers (piped stdin) ---

func TestReadAndConfirmPassphrase_Matching(t *testing.T) {
	pipeStdin(t, "correct-horse\ncorrect-horse\n")

	var buf bytes.Buffer
	got, err := readAndConfirmPassphrase(&buf)
	require.NoError(t, err)
	assert.Equal(t, "correct-horse", got)
}

func TestReadAndConfirmPassphrase_Mismatch(t *testing.T) {
	pipeStdin(t, "one\ntwo\n")

	var buf bytes.Buffer
	_, err := readAndConfirmPassphrase(&buf)
	assert.ErrorIs(t, err, luks.ErrPassphraseMismatch)
}

func TestReadAndConfirmPassphrase_RejectsEmpty(t *testing.T) {
	pipeStdin(t, "\n\n")

	var buf bytes.Buffer
	_, err := readAndConfirmPassphrase(&buf)
	require.Error(t, err)

	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, "read_passphrase", sealErr.Operation)
	assert.Contains(t, err.Error(), "passphrase cannot be empty")
}

func TestReadUnsealPassphrase_Piped(t *testing.T) {
	pipeStdin(t, "correct-horse\n")

	var buf bytes.Buffer
	got, err := readUnsealPassphrase(&buf)
	require.NoError(t, err)
	assert.Equal(t, "correct-horse", got)
}

func TestReadUnsealPassphrase_EmptyPipeYieldsEmptyString(t *testing.T) {
	pipeStdin(t, "")

	var buf bytes.Buffer
	got, err := readUnsealPassphrase(&buf)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestReadMigratePassphrases_PipedReusesSamePassphrase(t *testing.T) {
	pipeStdin(t, "old-pass\n")

	var buf bytes.Buffer
	oldPass, newPass, err := readMigratePassphrases(&buf)
	require.NoError(t, err)
	assert.Equal(t, "old-pass", oldPass)
	assert.Equal(t, "old-pass", newPass,
		"piped migration must reuse the source passphrase for the new container")
}

// --- wipe ---

func TestGetWipePatternDescription_AllStandards(t *testing.T) {
	assert.Equal(t, "random (1 pass)", getWipePatternDescription(luks.StandardNIST))
	assert.Equal(t, "zeros → ones → random (3 passes)", getWipePatternDescription(luks.StandardDoD3Pass))
	assert.Equal(t, "(Z→O→R) + R + (Z→O→R) (7 passes)", getWipePatternDescription(luks.StandardDoD7Pass))
	assert.Equal(t, "custom", getWipePatternDescription(luks.WipeStandard(99)))
}

func TestWipeStandardMap_MatchesFlagHelp(t *testing.T) {
	// The --standard flag help promises exactly nist, dod3 and dod7.
	assert.Len(t, wipeStandardMap, 3)
	assert.Equal(t, luks.StandardNIST, wipeStandardMap["nist"])
	assert.Equal(t, luks.StandardDoD3Pass, wipeStandardMap["dod3"])
	assert.Equal(t, luks.StandardDoD7Pass, wipeStandardMap["dod7"])
}

// TestRunWipe_RejectsInvalidStandardBeforePrivilegeCheck verifies argument
// validation happens before the euid check, so a typo in --standard is
// reported as a usage error instead of being masked by "permission denied".
func TestRunWipe_RejectsInvalidStandardBeforePrivilegeCheck(t *testing.T) {
	isolateLUKSFlags(t)
	wipeStandard = "dod9"

	_, err := runLUKSCmd(t, runWipe)
	assert.ErrorIs(t, err, ErrWipeInvalidStandard)
	assert.NotErrorIs(t, err, luks.ErrPermissionDenied)
}

func TestRunWipe_RequiresRootForValidStandard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("this test suite must not be run as root")
	}
	isolateLUKSFlags(t)
	wipeStandard = "dod3"

	_, err := runLUKSCmd(t, runWipe)
	assert.ErrorIs(t, err, luks.ErrPermissionDenied)
}

// --- wipeContainerWithStandard (operates on a plain file; no root needed) ---

func TestWipeContainerWithStandard_OverwritesContent(t *testing.T) {
	tests := []struct {
		name     string
		standard luks.WipeStandard
	}{
		{"nist_single_pass", luks.StandardNIST},
		{"dod3_three_pass", luks.StandardDoD3Pass},
		{"dod7_seven_pass", luks.StandardDoD7Pass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "container.luks")
			original := bytes.Repeat([]byte("A"), 4096)
			require.NoError(t, os.WriteFile(path, original, 0600))

			require.NoError(t, wipeContainerWithStandard(path, tt.standard))

			wiped, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, len(original), len(wiped), "wipe must not change the file size")
			assert.NotEqual(t, original, wiped, "wipe must overwrite the original content")
		})
	}
}

func TestWipeContainerWithStandard_MissingFileIsError(t *testing.T) {
	err := wipeContainerWithStandard(filepath.Join(t.TempDir(), "missing.luks"), luks.StandardNIST)
	assert.Error(t, err)
}

// --- checkLUKSVolume gate ---

// TestCheckLUKSVolume_LockedNotRoot_ReturnsErrLUKSVolumeLocked verifies that
// a configured-but-unmounted LUKS volume causes the PersistentPreRunE gate
// to fail closed with the canonical xkmssdk.ErrLUKSVolumeLocked sentinel
// (the same one the GUI's StorageService.RequireUnlocked surfaces), so a
// caller can recognize a locked volume identically from either front end.
// The specific reason (missing root) remains reachable as the cause.
func TestCheckLUKSVolume_LockedNotRoot_ReturnsErrLUKSVolumeLocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("this test suite must not be run as root")
	}

	previousHome := resolvedHome
	t.Cleanup(func() { resolvedHome = previousHome })

	h := &xhome.Home{Root: t.TempDir()}
	require.NoError(t, os.WriteFile(h.LUKSPath(), []byte("fake luks container"), 0600))
	resolvedHome = h

	err := checkLUKSVolume()
	require.Error(t, err)
	assert.ErrorIs(t, err, xkmssdk.ErrLUKSVolumeLocked)
	assert.ErrorIs(t, err, luks.ErrPermissionDenied)
}

// TestCheckLUKSVolume_NoVolume_ReturnsNil verifies the gate is a no-op — the
// existing plain data directory is unaffected — when no LUKS container has
// been created for the resolved home.
func TestCheckLUKSVolume_NoVolume_ReturnsNil(t *testing.T) {
	previousHome := resolvedHome
	t.Cleanup(func() { resolvedHome = previousHome })

	resolvedHome = &xhome.Home{Root: t.TempDir()}

	assert.NoError(t, checkLUKSVolume())
}

// --- privilege gates ---

func TestLUKSCommands_RequireRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("this test suite must not be run as root")
	}
	isolateLUKSFlags(t)

	tests := []struct {
		name string
		run  func(*cobra.Command, []string) error
	}{
		{"seal", runSeal},
		{"unseal", runUnseal},
		{"lock", runLock},
		{"migrate", runMigrate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runLUKSCmd(t, tt.run)
			assert.ErrorIs(t, err, luks.ErrPermissionDenied)
			assert.Empty(t, out, "a privilege refusal must not emit partial progress output")
		})
	}
}

// --- error types ---
