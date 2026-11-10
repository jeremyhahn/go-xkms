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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// A lock that fails while a migration rolls back is reported, and the
// rollback still restores the original container.
func TestC704gMigrate_RollbackSurvivesLockFailures(t *testing.T) {
	tests := []struct {
		name     string
		fail     []string
		op       string
		warnings []string
	}{
		{
			name:     "unlock new",
			fail:     []string{"unlock xkey.luks", "lock xkey.luks.old"},
			op:       "unlock_new",
			warnings: []string{"Warning: could not lock old container"},
		},
		{
			name: "copy data",
			fail: []string{"copy xkey.luks", "lock xkey.luks.old", "lock xkey.luks"},
			op:   "copy_data",
			warnings: []string{
				"Warning: could not lock old container",
				"Warning: could not lock new container",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, content := c704cMigrate(t)
			for _, call := range tt.fail {
				host.fail[call] = errC704cHost
			}

			out, err := runLUKSCmd(t, runMigrate)
			c704cRequireOp(t, err, tt.op)
			for _, w := range tt.warnings {
				assert.Contains(t, out, w)
			}
			source, rerr := os.ReadFile(migrateSourcePath)
			require.NoError(t, rerr)
			assert.Equal(t, content, source, "the original container is restored")
			assert.NoFileExists(t, migrateSourcePath+".old")
		})
	}
}

// Locks that fail after the data is copied do not undo a migration that
// has already succeeded.
func TestC704gMigrate_FinalLockFailuresAreWarnings(t *testing.T) {
	host, _ := c704cMigrate(t)
	host.fail["lock xkey.luks.old"] = errC704cHost
	host.fail["lock xkey.luks"] = errC704cHost

	out, err := runLUKSCmd(t, runMigrate)
	require.NoError(t, err)
	assert.Contains(t, out, "Warning: could not lock old container")
	assert.Contains(t, out, "Warning: could not lock new container")
	assert.Contains(t, out, "Migration complete!")
	assert.NoFileExists(t, migrateSourcePath+".old")
}

// A failure to make the temporary mount points puts the source back.
func TestC704gMigrate_TempMountFailureRestoresTheSource(t *testing.T) {
	host, content := c704cMigrate(t)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))

	_, err := runLUKSCmd(t, runMigrate)
	var migErr *MigrateError
	require.ErrorAs(t, err, &migErr)
	assert.Equal(t, "create_temp_mount", migErr.Operation)
	assert.Equal(t, []string{"create xkey.luks"}, host.calls)
	source, rerr := os.ReadFile(migrateSourcePath)
	require.NoError(t, rerr)
	assert.Equal(t, content, source, "the original container is restored")
}

// TestC704gMigrate_UnrestorableSourceKeepsTheBackup covers a rollback whose
// rename back fails because something now occupies the source path: the
// migration still fails with the original operation, warns that the source
// was not restored, and leaves the original container intact at ".old".
func TestC704gMigrate_UnrestorableSourceKeepsTheBackup(t *testing.T) {
	tests := []struct {
		fail, op string
	}{
		{fail: "create xkey.luks", op: "create"},
		{fail: "unlock xkey.luks.old", op: "unlock_old"},
		{fail: "unlock xkey.luks", op: "unlock_new"},
		{fail: "copy xkey.luks", op: "copy_data"},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			host, content := c704cMigrate(t)
			host.fail[tt.fail] = errC704cHost
			host.before = map[string]func(){tt.fail: func() {
				// A non-empty directory at the source path refuses the
				// rename back over it.
				require.NoError(t, os.RemoveAll(migrateSourcePath))
				require.NoError(t, os.MkdirAll(migrateSourcePath, 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(migrateSourcePath, "occupant"), nil, 0o600))
			}}

			out, err := runLUKSCmd(t, runMigrate)
			c704cRequireOp(t, err, tt.op)
			assert.Contains(t, out, "Warning: could not restore original container")
			assert.NotContains(t, out, "Migration complete")
			backup, rerr := os.ReadFile(migrateSourcePath + ".old")
			require.NoError(t, rerr)
			assert.Equal(t, content, backup, "the original container survives as the backup")
		})
	}
}

// Without --source the container is the one in the xkey home, whether the
// home was resolved at startup or is resolved by the command.
func TestC704gMigrate_DefaultsToTheHomeContainer(t *testing.T) {
	for _, resolved := range []bool{true, false} {
		t.Run(map[bool]string{true: "resolved home", false: "unresolved home"}[resolved], func(t *testing.T) {
			_, _ = c704cMigrate(t)
			setVar(t, &migrateSourcePath, "")
			home, err := xhome.Resolve()
			require.NoError(t, err)
			if resolved {
				setVar(t, &resolvedHome, home)
			}
			vol, err := luks.NewVolume()
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Dir(vol.LUKSPath), 0o700))
			writeContainer(t, vol.LUKSPath, 512)

			out, err := runLUKSCmd(t, runMigrate)
			require.NoError(t, err)
			assert.Contains(t, out, "Source:    "+vol.LUKSPath)
			assert.Contains(t, out, "Migration complete!")
			assert.NoFileExists(t, vol.LUKSPath+".old")
		})
	}
}

// Without --source an unresolvable home refuses the migration.
func TestC704gMigrate_DefaultSourceWithUnresolvableHome(t *testing.T) {
	host, _ := c704cMigrate(t)
	setVar(t, &migrateSourcePath, "")
	breakXKeyHome(t)

	_, err := runLUKSCmd(t, runMigrate)
	assert.Error(t, err)
	assert.Empty(t, host.calls)
}

// An explicit source path still needs the xkey home for its mount point;
// an unresolvable home refuses the migration before anything is touched.
func TestC704gMigrate_SourcePathWithUnresolvableHome(t *testing.T) {
	host, content := c704cMigrate(t)
	useXKeyHomeFallback(t)
	breakXKeyHome(t)

	_, err := runLUKSCmd(t, runMigrate)
	var resolveErr *xhome.ResolveError
	require.ErrorAs(t, err, &resolveErr)
	assert.Empty(t, host.calls)
	source, rerr := os.ReadFile(migrateSourcePath)
	require.NoError(t, rerr)
	assert.Equal(t, content, source)
}
