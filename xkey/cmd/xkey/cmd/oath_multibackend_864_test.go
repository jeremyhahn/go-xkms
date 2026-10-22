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
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

const multiBackendTestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

var totpLine = regexp.MustCompile(`^\d{6}  \(expires in \d+s\)\n$`)

// useOATHBackendsConfig points the CLI's unified config at one PKCS#11
// backend, "token1", next to the always-present software backend.
func useOATHBackendsConfig(t *testing.T) {
	t.Helper()
	saved := loadedConfig
	t.Cleanup(func() { loadedConfig = saved })

	cfg := &xkeyconfig.Config{}
	cfg.Backends.Local = []xkeyconfig.LocalBackendConfig{{ID: "token1", Category: "pkcs11"}}
	loadedConfig = cfg
}

func addOATHCredential(t *testing.T, name, backend string) (string, error) {
	t.Helper()
	cmd, out := newDetachedOATHCmd(t, oathAddCmd)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", name))
	if backend != "" {
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "backend", backend))
	}
	// SHA-256, not the SHA-1 default: crypto/hmac refuses SHA-1 under
	// GODEBUG=fips140=only, and these tests are about backend routing.
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "algorithm", oath.AlgorithmSHA256))
	t.Setenv("XKEY_OATH_SECRET", multiBackendTestSecret)
	err := runOATHAdd(cmd, nil)
	return out.String(), err
}

func listOATHCredentials(t *testing.T) string {
	t.Helper()
	cmd, out := newDetachedOATHCmd(t, oathListCmd)
	require.NoError(t, runOATHList(cmd, nil))
	return out.String()
}

func generateOATHCode(t *testing.T, name string) string {
	t.Helper()
	cmd, out := newDetachedOATHCmd(t, oathGenerateCmd)
	require.NoError(t, runOATHGenerate(cmd, []string{name}))
	return out.String()
}

func removeOATHCredential(t *testing.T, name string) string {
	t.Helper()
	cmd, out := newDetachedOATHCmd(t, oathRemoveCmd)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "force", "true"))
	require.NoError(t, runOATHRemove(cmd, []string{name}))
	return out.String()
}

// roundTripTwoBackends adds one credential to the default backend and one to
// token1, then lists, generates and removes both through the composite store.
func roundTripTwoBackends(t *testing.T) {
	t.Helper()
	out, err := addOATHCredential(t, "GitHub", "")
	require.NoError(t, err)
	assert.Contains(t, out, "Added OATH credential: GitHub (backend software)")

	out, err = addOATHCredential(t, "VPN", "token1")
	require.NoError(t, err)
	assert.Contains(t, out, "Added OATH credential: VPN (backend token1)")

	listed := listOATHCredentials(t)
	assert.Regexp(t, `Name:      GitHub\n  Backend:   software\n`, listed)
	assert.Regexp(t, `Name:      VPN\n  Backend:   token1\n`, listed)

	assert.Regexp(t, totpLine, generateOATHCode(t, "GitHub"))
	assert.Regexp(t, totpLine, generateOATHCode(t, "VPN"))

	assert.Contains(t, removeOATHCredential(t, "VPN"), "Removed: VPN")
	assert.Contains(t, removeOATHCredential(t, "GitHub"), "Removed: GitHub")
	assert.Contains(t, listOATHCredentials(t), "No OATH credentials found.")
}

func TestOATH864_FileMode_RoundTripTwoBackends(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	useOATHBackendsConfig(t)

	roundTripTwoBackends(t)

	// Each backend keeps its own plain file beside the historical oath.json.
	dataDir := backupTestDataDir(home)
	assert.FileExists(t, filepath.Join(dataDir, oathStoreFilename))
	assert.FileExists(t, filepath.Join(dataDir, "oath@token1.json"))
}

func TestOATH864_BarrierMode_RoundTripTwoBackends(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	useOATHBackendsConfig(t)
	const password = "correct-horse-battery-staple"
	dataDir := initTestOATHBarrier(t, home, password)
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	_, err := addOATHCredential(t, "VPN", "token1")
	require.NoError(t, err)
	raw := readStorageEntry(t, dataDir, "oath@token1/vpn.json")
	assert.NotContains(t, string(raw), multiBackendTestSecret, "the barrier must hold only ciphertext")
	removeOATHCredential(t, "VPN")

	roundTripTwoBackends(t)
}

func TestOATH864_Add_UnknownBackendRefused(t *testing.T) {
	isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	useOATHBackendsConfig(t)

	_, err := addOATHCredential(t, "VPN", "nosuch")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOATHAddFailed)
	assert.ErrorIs(t, err, oath.ErrStoreNotFound)
	var backendErr *oath.BackendError
	require.ErrorAs(t, err, &backendErr)
	assert.Equal(t, "nosuch", backendErr.BackendID)
	assert.Contains(t, err.Error(), `"nosuch"`)
	assert.Contains(t, listOATHCredentials(t), "No OATH credentials found.")
}

func TestOATH864_ExistingDefaultBackendCredential(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())

	// A credential stored before multi-backend routing: in oath.json, with
	// no BackendID.
	legacy, err := oath.NewFileStore(filepath.Join(backupTestDataDir(home), oathStoreFilename))
	require.NoError(t, err)
	cred, err := oath.NewCredentialFromManualEntry("Legacy", "", multiBackendTestSecret)
	require.NoError(t, err)
	require.Empty(t, cred.BackendID)
	cred.Algorithm = oath.AlgorithmSHA256
	require.NoError(t, legacy.Add(cred))
	require.NoError(t, legacy.Close())

	useOATHBackendsConfig(t)
	assert.Regexp(t, `Name:      Legacy\n  Backend:   software\n`, listOATHCredentials(t))
	assert.Regexp(t, totpLine, generateOATHCode(t, "Legacy"))

	// A duplicate name is refused even when aimed at another backend.
	_, err = addOATHCredential(t, "Legacy", "token1")
	assert.ErrorIs(t, err, oath.ErrCredentialExists)
	assert.Contains(t, removeOATHCredential(t, "Legacy"), "Removed: Legacy")
}

func TestOATH864_ConfiguredDefaultBackend(t *testing.T) {
	isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	useOATHBackendsConfig(t)
	loadedConfig.Backends.Defaults = map[string]string{"oath": "token1"}

	out, err := addOATHCredential(t, "VPN", "")
	require.NoError(t, err)
	assert.Contains(t, out, "(backend token1)")
}

func TestOATH864_InvalidConfiguredBackendID(t *testing.T) {
	isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	useOATHBackendsConfig(t)
	loadedConfig.Backends.Local[0].ID = "../escape"

	_, err := addOATHCredential(t, "VPN", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, oath.ErrInvalidBackendID), "err = %v", err)
}

func TestOATH864_BackupRestoresBackendPartition(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	useOATHBackendsConfig(t)
	_, err := addOATHCredential(t, "VPN", "token1")
	require.NoError(t, err)

	output := filepath.Join(home, "partition.xkb")
	const passphrase = "correct-horse-battery-staple"
	setBackupFlags(t, backupCreateCmd, map[string]string{"output": output, "password": passphrase})
	var createOut bytes.Buffer
	backupCreateCmd.SetOut(&createOut)
	require.NoError(t, runBackupCreate(backupCreateCmd, nil))
	assert.Contains(t, createOut.String(), "OATH:         1")

	// Restore into a second, empty home: the credential lands back in the
	// token1 partition it was backed up from.
	restoreHome := isolatedBackupHome(t)
	setBackupFlags(t, backupRestoreCmd, map[string]string{"password": passphrase, "key": ""})
	var restoreOut bytes.Buffer
	backupRestoreCmd.SetOut(&restoreOut)
	require.NoError(t, runBackupRestore(backupRestoreCmd, []string{output}))
	assert.Contains(t, restoreOut.String(), "Restore completed successfully.")

	assert.FileExists(t, filepath.Join(backupTestDataDir(restoreHome), "oath@token1.json"))
	assert.Regexp(t, `Name:      VPN\n  Backend:   token1\n`, listOATHCredentials(t))
}

func TestOATH864_ExtensionServerListsEveryPartition(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	useOATHBackendsConfig(t)
	_, err := addOATHCredential(t, "VPN", "token1")
	require.NoError(t, err)

	oathSvc := services.NewOATHService(nil)
	closer, err := initPlainStores(backupTestDataDir(home), services.NewStaticPasswordService(nil), oathSvc)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, closer.Close()) })

	accounts, err := oathSvc.ListAccounts()
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, "VPN", accounts[0].Name)
	assert.Equal(t, "token1", accounts[0].BackendID)
}
