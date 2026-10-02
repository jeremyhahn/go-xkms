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

// Tests for the barrier-aware "xkey oath" store resolution (go-xkms#134,
// go-xkms#148): a barrier-backed store when a barrier is initialized, the
// historical plain file with one warning otherwise, and a typed refusal
// when an initialized barrier cannot be opened.

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// initTestOATHBarrier initializes a real passphrase barrier at the data
// directory beneath home, using the exact same storage layout
// openBarrierBackend (barrier_store.go) expects to unseal: the barrier's
// base backend rooted at dataDir, with its root key at
// dataDir/barrier/root_key. The barrier is left sealed on disk; each CLI
// command run creates its own BarrierService and unseals independently, the
// same way separate process invocations would.
func initTestOATHBarrier(t *testing.T, home, password string) string {
	t.Helper()

	dataDir := backupTestDataDir(home)
	require.NoError(t, os.MkdirAll(dataDir, 0700))

	svc := services.NewBarrierService(home, slog.Default())
	svc.SetDataDir(dataDir)
	require.NoError(t, svc.Initialize(password, string(xkms.StrategyPassphrase)))
	require.NoError(t, svc.Seal())

	return dataDir
}

// newDetachedOATHCmd builds a private copy of an oath subcommand's flags, the
// same way newOATHCmd (oath_run_test.go) does, but WITHOUT forcing --store.
// newOATHCmd cannot be reused here: it always sets --store, which is exactly
// the escape hatch that bypasses barrier auto-detection, and these tests
// need Flags().Changed("store") to stay false so openOATHStore's barrier
// decision actually runs. Operating on a detached copy (rather than the
// package-level oathAddCmd/oathListCmd) also keeps a --store or
// --barrier-password set in one test from leaking into another.
func newDetachedOATHCmd(t *testing.T, template *cobra.Command) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: template.Use, RunE: template.RunE}
	template.Flags().VisitAll(func(f *pflag.Flag) {
		cmd.Flags().AddFlag(&pflag.Flag{
			Name:     f.Name,
			Usage:    f.Usage,
			Value:    newFlagValue(f),
			DefValue: f.DefValue,
		})
	})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func TestRunOATHAdd_NoBarrier_WarnsAndUsesFileStore(t *testing.T) {
	home := isolatedBackupHome(t)
	// Changing the working directory must have no effect on where the store
	// lands: resolution goes through resolveDataDir (HOME-based), never the
	// process's cwd (go-xkms#929).
	t.Chdir(t.TempDir())
	logBuf := captureDefaultLog(t)

	cmd, out := newDetachedOATHCmd(t, oathAddCmd)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "Slack"))
	t.Setenv("XKEY_OATH_SECRET", "JBSWY3DPEHPK3PXP")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "issuer", "Slack"))

	require.NoError(t, runOATHAdd(cmd, nil))
	assert.Contains(t, out.String(), "Added OATH credential: Slack")

	logged := logBuf.String()
	assert.Contains(t, logged, "unencrypted at rest", "the CLI must warn when no barrier protects the store")
	assert.Contains(t, logged, "store=OATH")
	assert.Contains(t, logged, "xkey barrier init")

	// The credential lands in the historical plain file under the resolved
	// xkey data directory, readable without a barrier -- the no-barrier
	// default is unchanged, but it is no longer cwd-relative (go-xkms#929).
	storePath := filepath.Join(backupTestDataDir(home), oathStoreFilename)
	fs, err := oath.NewFileStore(storePath)
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()
	cred, err := fs.Get("slack")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", secretText(cred))
}

func TestRunOATHAdd_BarrierInitialized_WritesCiphertextNotPlaintext(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	const password = "correct-horse-battery-staple"
	dataDir := initTestOATHBarrier(t, home, password)

	addCmd, addOut := newDetachedOATHCmd(t, oathAddCmd)
	require.NoError(t, setFlagForTest(t, addCmd.Flags(), "name", "GitHub"))
	t.Setenv("XKEY_OATH_SECRET", "JBSWY3DPEHPK3PXP")
	require.NoError(t, setFlagForTest(t, addCmd.Flags(), "issuer", "GitHub"))
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	require.NoError(t, runOATHAdd(addCmd, nil))
	assert.Contains(t, addOut.String(), "Added OATH credential: GitHub")

	// The raw bytes barrier storage wrote to disk must never contain the
	// plaintext secret or the plaintext name.
	credFile := filepath.Join(dataDir, "oath", "github.json")
	raw, err := os.ReadFile(credFile)
	require.NoError(t, err, "the barrier-encrypted OATH entry must exist on disk")
	assert.NotContains(t, string(raw), "JBSWY3DPEHPK3PXP",
		"the on-disk file must never hold the plaintext secret")
	assert.NotContains(t, string(raw), "GitHub",
		"the on-disk file must not leak the plaintext name either")

	// A second, independent CLI invocation (its own BarrierService, exactly
	// like a separate process) must unseal and read the credential back.
	listCmd, listOut := newDetachedOATHCmd(t, oathListCmd)
	require.NoError(t, setFlagForTest(t, listCmd.Flags(), "secrets", "true"))
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	require.NoError(t, runOATHList(listCmd, nil))
	assert.Contains(t, listOut.String(), "Name:      GitHub")
	assert.Contains(t, listOut.String(), "Secret:    JBSWY3DPEHPK3PXP")
}

func TestRunOATHAdd_BarrierWrongPassword_TypedRefusal(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	initTestOATHBarrier(t, home, "correct-password")

	cmd, _ := newDetachedOATHCmd(t, oathAddCmd)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "GitHub"))
	t.Setenv("XKEY_OATH_SECRET", "JBSWY3DPEHPK3PXP")
	t.Setenv("XKEY_BARRIER_PASSWORD", "wrong-password")

	err := runOATHAdd(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOATHStoreOpenFailed)
	assert.ErrorIs(t, err, ErrBarrierStoreOpenFailed,
		"a barrier that exists but cannot be opened must be a typed refusal")

	// Nothing may have been written in the clear as a fallback.
	_, statErr := os.Stat(filepath.Join(backupTestDataDir(home), "oath", "github.json"))
	assert.True(t, os.IsNotExist(statErr), "a failed unseal must never fall back to writing plaintext")
}

func TestRunOATHAdd_BarrierNoPasswordSupplied_TypedRefusal(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())
	initTestOATHBarrier(t, home, "correct-password")

	// No --barrier-password, no --barrier-password-file, no
	// XKEY_BARRIER_PASSWORD, and no terminal to prompt on: resolveBarrierPassword
	// has nothing left to try.
	cmd, _ := newDetachedOATHCmd(t, oathAddCmd)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "GitHub"))
	t.Setenv("XKEY_OATH_SECRET", "JBSWY3DPEHPK3PXP")

	err := runOATHAdd(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOATHStoreOpenFailed)
	assert.ErrorIs(t, err, ErrBarrierStoreOpenFailed)
}

func TestRunOATHAdd_ExplicitStoreFlagBypassesBarrier(t *testing.T) {
	home := isolatedBackupHome(t)
	initTestOATHBarrier(t, home, "correct-password")

	store := oathStorePath(t)
	cmd, out := newOATHCmd(t, oathAddCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "Explicit"))
	t.Setenv("XKEY_OATH_SECRET", "JBSWY3DPEHPK3PXP")

	// No --barrier-password is supplied; this must still succeed because an
	// explicit --store bypasses barrier auto-detection entirely.
	require.NoError(t, runOATHAdd(cmd, nil))
	assert.Contains(t, out.String(), "Added OATH credential: Explicit")

	fs, err := oath.NewFileStore(store)
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()
	cred, err := fs.Get("explicit")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", secretText(cred))
}

// --- openOATHStore default resolution (go-xkms#929) ---

// TestOpenOATHStore_DefaultsUnderXKEYHome verifies that, with no --store
// override and no barrier, openOATHStore's plain-file fallback resolves to
// an absolute path under the resolved xkey data directory
// (<home>/.xkey/data/oath.json), never a path relative to the process's
// working directory.
func TestOpenOATHStore_DefaultsUnderXKEYHome(t *testing.T) {
	home := isolatedBackupHome(t)
	t.Chdir(t.TempDir())

	cmd, _ := newDetachedOATHCmd(t, oathAddCmd)

	store, err := openOATHStore(cmd, "")
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	want := filepath.Join(backupTestDataDir(home), oathStoreFilename)
	if !filepath.IsAbs(want) {
		t.Fatalf("want %q to be absolute", want)
	}

	// The store file itself is created lazily on first write (oath.FileStore);
	// prove the resolved path really is where writes land.
	cred := &oath.Credential{ID: "github", Name: "GitHub", Type: oath.TypeTOTP, Algorithm: "SHA1", Digits: 6, Period: 30}
	require.NoError(t, cred.SetSecret([]byte("JBSWY3DPEHPK3PXP")))
	require.NoError(t, store.Add(cred))

	_, statErr := os.Stat(want)
	assert.NoError(t, statErr, "expected the OATH store file under the resolved xkey data directory")
}

// TestOpenOATHStore_ErrorWhenHomeUnresolvable verifies that openOATHStore
// fails with a typed error, instead of falling back to a cwd-relative
// path, when the xkey home cannot be resolved or created.
func TestOpenOATHStore_ErrorWhenHomeUnresolvable(t *testing.T) {
	isolatedBackupHome(t)

	// A regular file, not a directory: XKEY_HOME can neither be used nor
	// created as a directory, and it takes precedence over $HOME.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	t.Setenv(xhome.EnvHome, blocker)

	cmd, _ := newDetachedOATHCmd(t, oathAddCmd)

	_, err := openOATHStore(cmd, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOATHStoreOpenFailed)
}
