package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
)

// TestC704cProvision_BlankAgentNameRefuses proves an agent name of only
// whitespace is refused before any secret is read or state is created.
func TestC704cProvision_BlankAgentNameRefuses(t *testing.T) {
	home := isolateProvisionEnv(t)

	_, err := runProvisionCmd(t, happyPathSecrets(), "--home", home, "--agent", "   ")
	require.ErrorIs(t, err, ErrProvisionAgentNameRequired)

	entries, rerr := os.ReadDir(home)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "a refused provision leaves the home untouched")
}

// TestC704cProvision_InstallsTheChromeProfileManifest proves
// --chrome-profile-dir installs the native-messaging host manifest into
// that profile and reports where it was written.
func TestC704cProvision_InstallsTheChromeProfileManifest(t *testing.T) {
	home := isolateProvisionEnv(t)
	profileDir := t.TempDir()

	out, err := runProvisionCmd(t, happyPathSecrets(),
		"--home", home, "--agent", "chrome-agent", "--chrome-profile-dir", profileDir)
	require.NoError(t, err, "output: %s", out)

	matches, gerr := filepath.Glob(filepath.Join(profileDir, "*", "*.json"))
	require.NoError(t, gerr)
	require.Len(t, matches, 1, "exactly one host manifest is installed in the profile")
	assert.Contains(t, out, matches[0])

	data, rerr := os.ReadFile(matches[0])
	require.NoError(t, rerr)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(data, &manifest))
	launcher, ok := manifest["path"].(string)
	require.True(t, ok, "the manifest names its host launcher")
	assert.FileExists(t, launcher)
}

// TestC704cProvision_UnwritableChromeProfileFailsTheStep proves a profile
// directory that cannot hold the manifest fails provisioning at the
// chrome_extension step with the manifest-install cause.
func TestC704cProvision_UnwritableChromeProfileFailsTheStep(t *testing.T) {
	home := isolateProvisionEnv(t)
	profileDir := filepath.Join(t.TempDir(), "profile")
	require.NoError(t, os.WriteFile(profileDir, []byte("not a directory"), 0600))

	_, err := runProvisionCmd(t, happyPathSecrets(),
		"--home", home, "--agent", "chrome-agent", "--chrome-profile-dir", profileDir)
	require.ErrorIs(t, err, nativemsg.ErrManifestInstall)

	var stepErr *ProvisionError
	require.True(t, errors.As(err, &stepErr), "got: %v", err)
	assert.Equal(t, "chrome_extension", stepErr.Step)
}
