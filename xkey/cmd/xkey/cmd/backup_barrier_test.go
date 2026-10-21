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

// Tests for "xkey backup create/restore" against a barrier-backed OATH store
// (go-xkms#134, go-xkms#148): the backup reads the same ciphertext the CLI
// and the GUI wrote, the sealed backup file never carries the plaintext
// secret, and the restored credential is readable again through a plain
// file store on the other side.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

func TestBackupLifecycle_BarrierBackedOATHStore(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)
	const barrierPassword = "backup-barrier-pw"
	initTestOATHBarrier(t, home, barrierPassword)

	// Add the OATH credential the same way an operator would: through the
	// barrier-backed CLI store, not by writing the fixture file directly.
	addCmd, _ := newDetachedOATHCmd(t, oathAddCmd)
	require.NoError(t, setFlagForTest(t, addCmd.Flags(), "name", "BarrierOATH"))
	require.NoError(t, setFlagForTest(t, addCmd.Flags(), "algorithm", "SHA256"))
	t.Setenv("XKEY_OATH_SECRET", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	require.NoError(t, setFlagForTest(t, addCmd.Flags(), "issuer", "Example"))
	t.Setenv("XKEY_BARRIER_PASSWORD", barrierPassword)
	require.NoError(t, runOATHAdd(addCmd, nil))

	// Trust store and password store are not barrier-aware yet (only OATH
	// is, go-xkms#134/#148), so point them at explicit plain-file locations
	// to opt out of the barrier-encrypted refusal for those two stores. An
	// explicit backup source must already exist (go-xkms#936), so create
	// both directories up front, the same as an operator who has used these
	// locations before but has nothing in them yet.
	trustStorePath := filepath.Join(dataDir, trustDataSubdir)
	passwordStorePath := filepath.Join(dataDir, passwordStoreFeature)
	require.NoError(t, os.MkdirAll(trustStorePath, 0700))
	require.NoError(t, os.MkdirAll(passwordStorePath, 0700))

	output := filepath.Join(home, "barrier-backup.xkb")
	setBackupFlags(t, backupCreateCmd, map[string]string{
		"output":           output,
		"password":         "correct-horse-battery-staple",
		"trust-store":      trustStorePath,
		"password-store":   passwordStorePath,
		"barrier-password": barrierPassword,
	})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))
	assert.Contains(t, createOut.String(), "OATH:         1")

	// The sealed backup file must never carry the plaintext secret.
	raw, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	assert.NotContains(t, string(raw), "BarrierOATH")

	// Restore into a second, barrier-free home.
	restoreHome := isolatedBackupHome(t)
	setBackupFlags(t, backupRestoreCmd, map[string]string{
		"password": "correct-horse-battery-staple",
		"key":      "",
	})
	var restoreOut bytes.Buffer
	backupRestoreCmd.SetOut(&restoreOut)
	require.NoError(t, runBackupRestore(backupRestoreCmd, []string{output}))
	assert.Contains(t, restoreOut.String(), "Restore completed successfully.")

	restoredOATH, err := oath.NewFileStore(filepath.Join(backupTestDataDir(restoreHome), oathStoreFilename))
	require.NoError(t, err)
	defer func() { _ = restoredOATH.Close() }()
	creds, err := restoredOATH.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "BarrierOATH", creds[0].Name)
	assert.Equal(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", secretText(creds[0]))
}

func TestResolveOATHBackupStore_BarrierInitialized_UsesBackendStore(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)
	const password = "resolve-oath-backup-pw"
	initTestOATHBarrier(t, home, password)

	setBackupFlags(t, backupCreateCmd, map[string]string{"barrier-password": password})

	store, displayPath, missing, err := resolveOATHBackupStore(backupCreateCmd, dataDir, "", true)
	require.NoError(t, err)
	require.False(t, missing)
	defer func() { _ = store.Close() }()

	assert.Equal(t, "barrier:oath/", displayPath)
	require.NoError(t, store.Add(withOATHSecret(&oath.Credential{
		ID:        "resolve-test",
		Name:      "ResolveTest",
		Type:      oath.TypeTOTP,
		Algorithm: oath.AlgorithmSHA256,
		Digits:    6,
		Period:    30,
	}, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")))

	raw := readStorageEntry(t, dataDir, "oath/resolve-test.json")
	assert.NotContains(t, string(raw), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
}

func TestResolveOATHBackupStore_ExplicitPathBypassesBarrier(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)
	initTestOATHBarrier(t, home, "irrelevant-password")

	// strict=false: this exercises the barrier-bypass wiring, not the
	// missing-source behavior covered in backup_sources_test.go, so the
	// explicit file is created on first open as a restore would.
	explicitPath := filepath.Join(t.TempDir(), "explicit-oath.json")
	store, displayPath, missing, err := resolveOATHBackupStore(backupCreateCmd, dataDir, explicitPath, false)
	require.NoError(t, err)
	require.False(t, missing)
	defer func() { _ = store.Close() }()

	assert.Equal(t, explicitPath, displayPath)

	// Writing through the returned store must land in the explicit plain
	// file, proving the barrier (initialized above) was never consulted.
	require.NoError(t, store.Add(withOATHSecret(&oath.Credential{
		ID:        "explicit-test",
		Name:      "ExplicitTest",
		Type:      oath.TypeTOTP,
		Algorithm: oath.AlgorithmSHA256,
		Digits:    6,
		Period:    30,
	}, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")))

	raw, err := os.ReadFile(explicitPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		"the plain file store must hold the secret in the historical format")
}

// TestResolveOATHBackupStore_DefaultMissing_StrictReportsMissing is the
// go-xkms#936 regression guard for the OATH default: in strict (read) mode,
// with no barrier initialized and no oath.json ever written, the store must
// come back reported missing rather than auto-created and silently empty.
func TestResolveOATHBackupStore_DefaultMissing_StrictReportsMissing(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	store, displayPath, missing, err := resolveOATHBackupStore(backupCreateCmd, dataDir, "", true)
	require.NoError(t, err)
	assert.Nil(t, store)
	assert.True(t, missing)
	assert.Equal(t, filepath.Join(dataDir, oathStoreFilename), displayPath)

	_, statErr := os.Stat(displayPath)
	assert.True(t, os.IsNotExist(statErr), "a strict read must never create the default it could not find")
}

// TestResolveOATHBackupStore_ExplicitPathMissing_StrictErrors is the
// go-xkms#936 regression guard for an explicit --oath-store: strict mode
// must refuse to read from a path the operator named that has never existed
// instead of silently creating it empty.
func TestResolveOATHBackupStore_ExplicitPathMissing_StrictErrors(t *testing.T) {
	home := isolatedBackupHome(t)
	dataDir := backupTestDataDir(home)

	explicitPath := filepath.Join(t.TempDir(), "never-created.json")
	store, _, missing, err := resolveOATHBackupStore(backupCreateCmd, dataDir, explicitPath, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupSourceMissing)
	assert.Nil(t, store)
	assert.False(t, missing)

	_, statErr := os.Stat(explicitPath)
	assert.True(t, os.IsNotExist(statErr), "a strict read must never create the path it could not find")
}
