package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// writePlatformPCRsConfig points --config at a file naming tpm.platform-pcrs.
func writePlatformPCRsConfig(t *testing.T, pcrs string) {
	t.Helper()
	isolateConfigFlags(t)
	cfgFile = filepath.Join(t.TempDir(), "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("tpm:\n  platform-pcrs: "+pcrs+"\n"), 0600))
}

// TestTPMConfig_PlatformPCRsFromConfigFile proves the tpm commands seal to the
// config file's tpm.platform-pcrs, that --platform-pcrs overrides it, and
// that the SDK default applies when neither names a set.
func TestTPMConfig_PlatformPCRsFromConfigFile(t *testing.T) {
	isolateConfigFlags(t)
	loadedConfig = nil
	assert.Equal(t, xkms.DefaultPlatformPCRs(), configuredPlatformPCRs())

	writePlatformPCRsConfig(t, "[0, 7, 14]")
	require.NoError(t, initConfig())

	config, err := newTPMConfig("", true, 0)
	require.NoError(t, err)
	assert.Equal(t, xkms.TPMPCRSet{0, 7, 14}, config.PlatformPCRs)

	applyPCROverrides(config, "", nil, nil)
	assert.Equal(t, xkms.TPMPCRSet{0, 7, 14}, config.PlatformPCRs, "an unset flag keeps the config file's set")

	flagPCRs, err := parsePlatformPCRs("7,11")
	require.NoError(t, err)
	applyPCROverrides(config, "", nil, flagPCRs)
	assert.Equal(t, xkms.TPMPCRSet{7, 11}, config.PlatformPCRs, "--platform-pcrs overrides the config file")
}

// TestTPMConfig_PlatformPCRsRefused proves an invalid set is refused with
// PCRSet.Validate's typed error from both the config file and the flag.
func TestTPMConfig_PlatformPCRsRefused(t *testing.T) {
	writePlatformPCRsConfig(t, "[7, 16]")
	err := initConfig()
	var configErr *ConfigError
	require.ErrorAs(t, err, &configErr)
	assert.ErrorIs(t, err, xkms.ErrTPMPlatformPCRResettable)

	pcrs, err := parsePlatformPCRs("7,23")
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, xkms.ErrTPMPlatformPCRResettable)
}
