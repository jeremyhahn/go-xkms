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
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// Truth-table tests for the command groups that adopted the shared
// data-dir chain in issue #381 (extension, trust, auth, browser, agent,
// backup). Each group's resolver is driven through every chain source it
// honours, in priority order, so a group that quietly regrows a private
// $HOME fallback fails here as well as at the grep gate below.

// isolatedExistingXKeyHome neutralises every chain source, creates a real
// xKey home under a private $HOME and returns its root (<HOME>/.xkey). It
// models a device the GUI or setup wizard has initialised, so the
// non-creating chain resolves without manufacturing anything.
func isolatedExistingXKeyHome(t *testing.T) string {
	t.Helper()

	isolateDataDirSources(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, ".xkey")
	require.NoError(t, os.MkdirAll(root, 0700))
	return root
}

// assertNoPath fails when path exists: read-side commands must never
// create state directories as a side effect of inspecting them.
func assertNoPath(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "a read must not create %s", path)
}

// unresolvableXKeyHome points XKEY_HOME beneath a regular file so neither
// chain variant can resolve or create a home.
func unresolvableXKeyHome(t *testing.T) {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker-file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	t.Setenv(xhome.EnvHome, filepath.Join(blocker, "nested"))
}

// writePairedExtensionFixture writes a pairing state file in the
// PairingVerifier's on-disk format declaring one paired origin.
func writePairedExtensionFixture(t *testing.T, statePath string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(statePath), 0700))
	states := map[string]nativemsg.PairingState{
		"chrome-extension://paired-fixture/": {
			IdentityKey: bytes.Repeat([]byte{0x42}, 32),
			PairedAt:    time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		},
	}
	data, err := json.Marshal(states)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(statePath, data, 0600))
}

// --- featureDataDir / featureDataDirExisting ---

func TestFeatureDataDir_EnvOverrideWins(t *testing.T) {
	isolateDataDirSources(t)
	t.Setenv("XKEY_DATA_DIR", "/env/data/")
	viper.Set("data_dir", "/viper/loses")

	got, err := featureDataDir("trust")
	require.NoError(t, err)
	assert.Equal(t, "/env/data/trust", got)
}

func TestFeatureDataDir_XHomeFallbackCreatesDataDirOnly(t *testing.T) {
	isolateDataDirSources(t)
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)

	got, err := featureDataDir("auth")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "data", "auth"), got)
	assert.DirExists(t, filepath.Join(root, "data"))
	assertNoPath(t, got)
}

func TestFeatureDataDir_UnresolvableHomeErrors(t *testing.T) {
	isolateDataDirSources(t)
	unresolvableXKeyHome(t)

	_, err := featureDataDir("auth")
	require.Error(t, err)
}

func TestFeatureDataDirExisting_ViperOverride(t *testing.T) {
	isolateDataDirSources(t)
	viper.Set("data_dir", "/viper/./data")

	got, err := featureDataDirExisting("extension")
	require.NoError(t, err)
	assert.Equal(t, "/viper/data/extension", got)
}

func TestFeatureDataDirExisting_DoesNotCreate(t *testing.T) {
	root := isolatedExistingXKeyHome(t)

	got, err := featureDataDirExisting("extension")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "data", "extension"), got)
	assertNoPath(t, filepath.Join(root, "data"))
}

func TestFeatureDataDirExisting_MissingHomeErrors(t *testing.T) {
	isolateDataDirSources(t)
	t.Setenv(xhome.EnvHome, filepath.Join(t.TempDir(), "missing"))

	_, err := featureDataDirExisting("extension")
	require.ErrorIs(t, err, xhome.ErrHomeNotResolved)
}

// --- extension ---

func TestExtensionPairingStatePath_TruthTable(t *testing.T) {
	root := isolatedExistingXKeyHome(t)
	xkeyHome := t.TempDir()

	tests := []struct {
		name string
		env  map[string]string
		vipr string
		want string
	}{
		{
			name: "XKEY_DATA_DIR beats XKEY_HOME and data_dir",
			env:  map[string]string{"XKEY_DATA_DIR": "/env/data", xhome.EnvHome: xkeyHome},
			vipr: "/viper/loses",
			want: "/env/data/extension/pairing.json",
		},
		{
			name: "data_dir beats XKEY_HOME",
			env:  map[string]string{xhome.EnvHome: xkeyHome},
			vipr: "/viper/data",
			want: "/viper/data/extension/pairing.json",
		},
		{
			name: "XKEY_HOME data directory",
			env:  map[string]string{xhome.EnvHome: xkeyHome},
			want: filepath.Join(xkeyHome, "data", "extension", "pairing.json"),
		},
		{
			name: "default ~/.xkey/data",
			want: filepath.Join(root, "data", "extension", "pairing.json"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XKEY_DATA_DIR", "")
			t.Setenv(xhome.EnvHome, "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			viper.Set("data_dir", tc.vipr)
			t.Cleanup(func() { viper.Set("data_dir", "") })

			got, err := extensionPairingStatePath()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRunExtensionPairStatus_ReadsPairingUnderXKeyDataDir(t *testing.T) {
	isolateDataDirSources(t)
	override := t.TempDir()
	t.Setenv("XKEY_DATA_DIR", override)
	writePairedExtensionFixture(t, filepath.Join(override, "extension", "pairing.json"))

	out, err := runDetached(t, runExtensionPairStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Paired")
	assert.Contains(t, out, "chrome-extension://paired-fixture/")
}

func TestRunExtensionPairStatus_ReadsPairingUnderXKeyHome(t *testing.T) {
	isolateDataDirSources(t)
	xkeyHome := t.TempDir()
	t.Setenv(xhome.EnvHome, xkeyHome)
	// A pairing left at the pre-#381 location must not be found once
	// XKEY_HOME points elsewhere: the group now follows the chain.
	t.Setenv("HOME", t.TempDir())
	writePairedExtensionFixture(t, filepath.Join(xkeyHome, "data", "extension", "pairing.json"))

	out, err := runDetached(t, runExtensionPairStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Paired")
}

func TestRunExtensionUnpair_RemovesPairingUnderXKeyDataDir(t *testing.T) {
	isolateDataDirSources(t)
	override := t.TempDir()
	t.Setenv("XKEY_DATA_DIR", override)
	statePath := filepath.Join(override, "extension", "pairing.json")
	writePairedExtensionFixture(t, statePath)

	out, err := runDetached(t, runExtensionUnpair)
	require.NoError(t, err)
	assert.Contains(t, out, "Extension unpaired successfully")

	verifier, err := nativemsg.NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.False(t, verifier.IsPaired(), "the override store must be the one unpaired")
}

func TestExtensionHostPairingDir_FollowsChainAndIsCreating(t *testing.T) {
	// The host is the one extension command allowed to create the pairing
	// directory; it resolves through the creating chain so the directory
	// lands where pair-status and the GUI will look for it.
	isolateDataDirSources(t)
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)

	pairingDir, err := featureDataDir(extensionDataSubdir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "data", "extension"), pairingDir)

	readPath, err := extensionPairingStatePath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(pairingDir, extensionPairingStateFile), readPath,
		"host and read commands must agree on one pairing store")
}

// TestExtensionReadCommands_MissingHomeFailWithoutCreating pins the read
// side to the non-creating chain. On a device with no xKey home, unpair
// and pair-status must report an unresolved home rather than resolve
// through the creating chain, manufacture ~/.xkey/data/extension and
// render the empty store as "Not paired" — a fresh install and a
// misresolved home have to stay distinguishable.
func TestExtensionReadCommands_MissingHomeFailWithoutCreating(t *testing.T) {
	reads := map[string]struct {
		run      func(*cobra.Command, []string) error
		sentinel error
	}{
		"pair-status": {runExtensionPairStatus, ErrExtensionPairStatusFailed},
		"unpair":      {runExtensionUnpair, ErrExtensionUnpairFailed},
	}
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			isolateDataDirSources(t)
			home := t.TempDir()
			t.Setenv("HOME", home)

			_, err := runDetached(t, read.run)
			require.ErrorIs(t, err, read.sentinel)
			require.ErrorIs(t, err, xhome.ErrHomeNotResolved)
			assertNoPath(t, filepath.Join(home, ".xkey"))
		})
	}
}

// --- trust ---

func TestTrustStoreDir_TruthTable(t *testing.T) {
	root := isolatedExistingXKeyHome(t)
	xkeyHome := t.TempDir()
	viper.Set("trust.store_path", "")
	t.Cleanup(func() { viper.Set("trust.store_path", "") })

	tests := []struct {
		name      string
		env       map[string]string
		dataDir   string
		storePath string
		want      string
	}{
		{
			name:      "trust.store_path beats everything",
			env:       map[string]string{"XKEY_DATA_DIR": "/env/data", xhome.EnvHome: xkeyHome},
			dataDir:   "/viper/data",
			storePath: "/explicit/store",
			want:      "/explicit/store",
		},
		{
			name:    "XKEY_DATA_DIR beats XKEY_HOME and data_dir",
			env:     map[string]string{"XKEY_DATA_DIR": "/env/data", xhome.EnvHome: xkeyHome},
			dataDir: "/viper/loses",
			want:    "/env/data/trust",
		},
		{
			name:    "data_dir beats XKEY_HOME",
			env:     map[string]string{xhome.EnvHome: xkeyHome},
			dataDir: "/viper/data",
			want:    "/viper/data/trust",
		},
		{
			name: "XKEY_HOME data directory",
			env:  map[string]string{xhome.EnvHome: xkeyHome},
			want: filepath.Join(xkeyHome, "data", "trust"),
		},
		{
			name: "default ~/.xkey/data",
			want: filepath.Join(root, "data", "trust"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XKEY_DATA_DIR", "")
			t.Setenv(xhome.EnvHome, "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			viper.Set("data_dir", tc.dataDir)
			viper.Set("trust.store_path", tc.storePath)
			t.Cleanup(func() {
				viper.Set("data_dir", "")
				viper.Set("trust.store_path", "")
			})

			got, err := trustStoreDir()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTrustStoreDir_UnresolvableHomeErrors(t *testing.T) {
	isolateDataDirSources(t)
	viper.Set("trust.store_path", "")
	unresolvableXKeyHome(t)

	_, err := trustStoreDir()
	require.Error(t, err)

	_, err = openTrustStore()
	require.ErrorIs(t, err, ErrTrustStoreOpen)
}

func TestOpenTrustStore_OpensStoreUnderXKeyDataDir(t *testing.T) {
	isolateDataDirSources(t)
	viper.Set("trust.store_path", "")
	override := t.TempDir()
	t.Setenv("XKEY_DATA_DIR", override)

	seeded, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(override, "trust"),
	})
	require.NoError(t, err)
	require.NoError(t, seeded.AddCertificate(pivTestCert(t, "override-anchor")))
	require.NoError(t, seeded.Close())

	store, err := openTrustStore()
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count, "the trust group must read the override store, not ~/.xkey/data/trust")
}

// --- browser ---

func TestRunBrowserLaunch_OpensTrustStoreThroughSharedResolver(t *testing.T) {
	// The launcher and the trust group must open the same store: with
	// XKEY_DATA_DIR set, the launcher's store is <override>/trust, which
	// it creates on open exactly as the trust group does.
	isolateDataDirSources(t)
	viper.Set("trust.store_path", "")
	override := t.TempDir()
	t.Setenv("XKEY_DATA_DIR", override)
	t.Setenv("HOME", t.TempDir())

	oldBinary := browserBinary
	browserBinary = ""
	t.Cleanup(func() { browserBinary = oldBinary })

	var out bytes.Buffer
	cmd := *browserLaunchCmd
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := runBrowserLaunch(&cmd, nil)
	require.Error(t, err, "an empty trust store must never launch a browser")
	if !errors.Is(err, ErrBrowserNoBrowsers) && !errors.Is(err, ErrBrowserLaunchFailed) {
		t.Fatalf("expected ErrBrowserNoBrowsers or ErrBrowserLaunchFailed, got %v", err)
	}

	expected, err := trustStoreDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(override, "trust"), expected)
	assert.DirExists(t, expected, "the launcher must have opened the shared store location")
}

func TestRunBrowserLaunch_UnresolvableHomeFails(t *testing.T) {
	isolateDataDirSources(t)
	viper.Set("trust.store_path", "")
	unresolvableXKeyHome(t)

	var out bytes.Buffer
	cmd := *browserLaunchCmd
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := runBrowserLaunch(&cmd, nil)
	require.ErrorIs(t, err, ErrBrowserLaunchFailed)
}

// --- auth ---

func TestAuthStoragePath_TruthTable(t *testing.T) {
	root := isolatedExistingXKeyHome(t)
	xkeyHome := t.TempDir()

	tests := []struct {
		name    string
		env     map[string]string
		dataDir string
		want    string
	}{
		{
			name:    "XKEY_DATA_DIR beats XKEY_HOME and data_dir",
			env:     map[string]string{"XKEY_DATA_DIR": "/env/data", xhome.EnvHome: xkeyHome},
			dataDir: "/viper/loses",
			want:    "/env/data/auth",
		},
		{
			name:    "data_dir beats XKEY_HOME",
			env:     map[string]string{xhome.EnvHome: xkeyHome},
			dataDir: "/viper/data",
			want:    "/viper/data/auth",
		},
		{
			name: "XKEY_HOME data directory",
			env:  map[string]string{xhome.EnvHome: xkeyHome},
			want: filepath.Join(xkeyHome, "data", "auth"),
		},
		{
			name: "default ~/.xkey/data",
			want: filepath.Join(root, "data", "auth"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XKEY_DATA_DIR", "")
			t.Setenv(xhome.EnvHome, "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			viper.Set("data_dir", tc.dataDir)
			t.Cleanup(func() { viper.Set("data_dir", "") })

			got, err := authStoragePath()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAuthStoragePath_UnresolvableHomeErrors(t *testing.T) {
	isolateDataDirSources(t)
	unresolvableXKeyHome(t)

	_, err := authStoragePath()
	require.Error(t, err)

	_, _, err = openServerRegistry(slog.Default())
	require.ErrorIs(t, err, ErrAuthStorageCreationFailed)
}

func TestOpenServerRegistry_UsesXKeyDataDir(t *testing.T) {
	isolateDataDirSources(t)
	override := t.TempDir()
	t.Setenv("XKEY_DATA_DIR", override)
	t.Setenv("HOME", t.TempDir())

	registry, cleanup, err := openServerRegistry(slog.Default())
	require.NoError(t, err)
	require.NotNil(t, registry)
	cleanup()

	assert.DirExists(t, filepath.Join(override, "auth"))
	assertNoPath(t, filepath.Join(os.Getenv("HOME"), ".xkey"))
}

// --- agent ---

func TestAgentDataDir_TruthTable(t *testing.T) {
	root := isolatedExistingXKeyHome(t)
	xkeyHome := t.TempDir()
	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })

	tests := []struct {
		name    string
		env     map[string]string
		dataDir string
		want    string
	}{
		{
			name:    "XKEY_DATA_DIR beats XKEY_HOME and data_dir",
			env:     map[string]string{"XKEY_DATA_DIR": "/env/data", xhome.EnvHome: xkeyHome},
			dataDir: "/viper/loses",
			want:    "/env/data/agent",
		},
		{
			name:    "data_dir beats XKEY_HOME",
			env:     map[string]string{xhome.EnvHome: xkeyHome},
			dataDir: "/viper/data",
			want:    "/viper/data/agent",
		},
		{
			name: "XKEY_HOME data directory",
			env:  map[string]string{xhome.EnvHome: xkeyHome},
			want: filepath.Join(xkeyHome, "data", "agent"),
		},
		{
			name: "default ~/.xkey/data",
			want: filepath.Join(root, "data", "agent"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XKEY_DATA_DIR", "")
			t.Setenv(xhome.EnvHome, "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			viper.Set("data_dir", tc.dataDir)
			t.Cleanup(func() { viper.Set("data_dir", "") })

			got, err := agentDataDir()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)

			stateFile, err := agentStateFile()
			require.NoError(t, err)
			assert.Equal(t, filepath.Join(tc.want, agentStateFileName), stateFile)
		})
	}
}

func TestAgentDataDir_UnresolvableHomeErrors(t *testing.T) {
	// No silent temporary-directory fallback: an unresolvable home is an
	// error for every agent path and for the commands built on them.
	isolateDataDirSources(t)
	unresolvableXKeyHome(t)

	_, err := agentDataDir()
	require.Error(t, err)
	_, err = agentStoreDir()
	require.Error(t, err)
	_, err = agentCertDir()
	require.Error(t, err)
	_, err = agentStateFile()
	require.Error(t, err)

	_, err = readAgentServerState()
	require.ErrorIs(t, err, ErrAgentStateRead)
	require.ErrorIs(t, removeAgentServerState(), ErrAgentStateRemove)

	// agent status consults the run-state file before the enrollment
	// store, so the unresolvable home surfaces as the state-read error
	// rather than as a fabricated "not running".
	_, err = runDetached(t, runAgentStatus)
	require.ErrorIs(t, err, ErrAgentStateRead)
}

// --- backup ---

func TestBackupDataDir_TruthTable(t *testing.T) {
	root := isolatedExistingXKeyHome(t)
	xkeyHome := t.TempDir()
	previous := resolvedHome
	resolvedHome = nil
	t.Cleanup(func() { resolvedHome = previous })

	tests := []struct {
		name    string
		env     map[string]string
		dataDir string
		want    string
	}{
		{
			name:    "XKEY_DATA_DIR beats XKEY_HOME and data_dir",
			env:     map[string]string{"XKEY_DATA_DIR": "/env/data", xhome.EnvHome: xkeyHome},
			dataDir: "/viper/loses",
			want:    "/env/data",
		},
		{
			name:    "data_dir beats XKEY_HOME",
			env:     map[string]string{xhome.EnvHome: xkeyHome},
			dataDir: "/viper/data",
			want:    "/viper/data",
		},
		{
			name: "XKEY_HOME data directory",
			env:  map[string]string{xhome.EnvHome: xkeyHome},
			want: filepath.Join(xkeyHome, "data"),
		},
		{
			name: "default ~/.xkey/data",
			want: filepath.Join(root, "data"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XKEY_DATA_DIR", "")
			t.Setenv(xhome.EnvHome, "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			viper.Set("data_dir", tc.dataDir)
			t.Cleanup(func() { viper.Set("data_dir", "") })

			got, err := backupDataDir()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestBackupDataDir_UnresolvableHomeErrors(t *testing.T) {
	isolateDataDirSources(t)
	unresolvableXKeyHome(t)

	_, err := backupDataDir()
	require.ErrorIs(t, err, ErrBackupStoreUnavailable)
}

// --- grep gate ---

// dataDirLiteralPatterns are the shapes of a hand-spelled xKey data
// directory. datadir.go is the only file allowed to know how the data
// directory is found; every other source must obtain it from the chain.
var dataDirLiteralPatterns = []*regexp.Regexp{
	// filepath.Join(home, ".xkey", "data", ...)
	regexp.MustCompile(`"\.xkey",\s*"data"`),
	// filepath.Join(xkeyDir, "data", "trust") — a literal data segment
	// spliced into a path.
	regexp.MustCompile(`"data",\s*"`),
	// const someSubdir = "data/feature" — the data segment smuggled into
	// a feature constant.
	regexp.MustCompile(`=\s*"data/`),
}

// homeRootLiteralPatterns match a command spelling the xKey home root by
// hand -- filepath.Join(home, ".xkey") -- the shape #381's gate did not
// model and that #442 found surviving in backup.go and device.go. The
// home root is xhome.Resolve().Root (or ResolveForUser under sudo); a
// literal here ignores XKEY_HOME and portable mode.
var homeRootLiteralPatterns = []*regexp.Regexp{
	// A quoted ".xkey" path segment. Prose such as "~/.xkey/backups" in a
	// help string does not match: the segment is not quoted on its own.
	regexp.MustCompile(`"\.xkey"`),
}

// scanCommandSources reports every line of a non-test command source
// (datadir.go excepted, it is the resolver) that matches one of patterns.
func scanCommandSources(t *testing.T, patterns []*regexp.Regexp) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	var violations []string
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == "datadir.go" {
			continue
		}
		scanned++
		content, err := os.ReadFile(name)
		require.NoError(t, err)
		for lineNo, line := range strings.Split(string(content), "\n") {
			for _, pattern := range patterns {
				if pattern.MatchString(line) {
					violations = append(violations,
						name+":"+strconv.Itoa(lineNo+1)+": "+strings.TrimSpace(line))
					break
				}
			}
		}
	}
	require.Greater(t, scanned, 0, "the gate must actually scan the command sources")
	return violations
}

// TestNoAdHocDataDirLiterals is the grep gate from issue #381: no command
// group may spell ~/.xkey/data (or <something>/data/<feature>) by hand.
// It scans the package sources on disk, so a regressed literal in any
// command file fails the suite even if no behavioural test covers it.
func TestNoAdHocDataDirLiterals(t *testing.T) {
	violations := scanCommandSources(t, dataDirLiteralPatterns)
	assert.Empty(t, violations,
		"hand-spelled data directory paths; resolve through datadir.go instead:\n%s",
		strings.Join(violations, "\n"))
}

// TestNoAdHocHomeRootLiterals is the companion gate from issue #442: no
// command may spell the xKey home root by hand either.
func TestNoAdHocHomeRootLiterals(t *testing.T) {
	violations := scanCommandSources(t, homeRootLiteralPatterns)
	assert.Empty(t, violations,
		"hand-spelled xKey home roots; resolve through xhome instead:\n%s",
		strings.Join(violations, "\n"))
}

// The home-root pattern must catch the two literals #442 removed and must
// not catch the help text that legitimately describes the default paths.
func TestHomeRootLiteralPatterns_MatchTheShapeAndNotProse(t *testing.T) {
	caught := []string{
		`return filepath.Join(home, ".xkey", "backups"), nil`,
		`configDir := filepath.Join(homeDir, ".xkey")`,
	}
	for _, line := range caught {
		assert.True(t, homeRootLiteralPatterns[0].MatchString(line), line)
	}
	prose := []string{
		`Long: "List all backup files in the default backup directory (~/.xkey/backups/).",`,
		`"Output file path (default: ~/.xkey/backups/backup-{timestamp}.xkb)")`,
	}
	for _, line := range prose {
		assert.False(t, homeRootLiteralPatterns[0].MatchString(line), line)
	}
}
