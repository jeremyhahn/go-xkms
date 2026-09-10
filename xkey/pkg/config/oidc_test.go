// Copyright (C) 2026 Jeremy Hahn
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultConfig_OIDCCallbackIsLoopback proves the defaults-layer value:
// the callback listener binds loopback (localhost: both families) on 8085,
// never every interface.
func TestDefaultConfig_OIDCCallbackIsLoopback(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "localhost", cfg.OIDC.CallbackHost)
	assert.Equal(t, 8085, cfg.OIDC.CallbackPort)
	require.NoError(t, cfg.Validate())
}

// TestValidate_OIDCCallbackPortRange proves that a port outside 1-65535 is
// refused with the key named, and that the bounds themselves are accepted.
func TestValidate_OIDCCallbackPortRange(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		cfg := DefaultConfig()
		cfg.OIDC.CallbackPort = port
		err := cfg.Validate()
		require.Error(t, err, "port %d", port)
		assert.ErrorIs(t, err, ErrConfigInvalid)
		assert.Contains(t, err.Error(), "oidc.callback_port")
	}
	for _, port := range []int{1, 65535} {
		cfg := DefaultConfig()
		cfg.OIDC.CallbackPort = port
		require.NoError(t, cfg.Validate(), "port %d", port)
	}
}

// TestLoadFromPath_OIDCCallback_FileThenEnvironment proves the three-path
// rule for the section: the file overrides the default, the environment
// overrides the file, and a key the environment does not name keeps its
// file value (#140, items 7 and 13).
func TestLoadFromPath_OIDCCallback_FileThenEnvironment(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("oidc:\n  callback_host: 10.0.0.5\n  callback_port: 9090\n"), 0600))

	fromFile, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5", fromFile.OIDC.CallbackHost)
	assert.Equal(t, 9090, fromFile.OIDC.CallbackPort)

	t.Setenv("XKEY_OIDC_CALLBACK_PORT", "9191")
	fromEnv, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5", fromEnv.OIDC.CallbackHost, "the file host survives an environment port")
	assert.Equal(t, 9191, fromEnv.OIDC.CallbackPort, "the environment port wins over the file")

	t.Setenv("XKEY_OIDC_CALLBACK_PORT", "70000")
	rejected, err := LoadFromPath(cfgPath)
	require.Error(t, err)
	assert.Nil(t, rejected)
	assert.ErrorIs(t, err, ErrConfigInvalid)
}
