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

// TestDefaultConfig_ListenerAddresses proves the defaults-layer values for
// the agent server and the pairing relay.
func TestDefaultConfig_ListenerAddresses(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, ":9443", cfg.Agent.ListenAddress)
	assert.Equal(t, "127.0.0.1:8444", cfg.Phone.RelayListenAddress,
		"the relay's built-in default is loopback-only (go-xkms#1306)")
	require.NoError(t, cfg.Validate())
}

// TestValidate_ListenerAddressesMustBeHostPort proves that each listener
// key is refused with the key named when it is not host:port or names no
// usable port (an empty or zero port would bind an ephemeral one), that
// every host:port shape with a port in 1-65535 is accepted, and that empty
// is accepted (the command then uses the built-in default).
func TestValidate_ListenerAddressesMustBeHostPort(t *testing.T) {
	set := map[string]func(*Config, string){
		"agent.listen_address":       func(c *Config, v string) { c.Agent.ListenAddress = v },
		"phone.relay_listen_address": func(c *Config, v string) { c.Phone.RelayListenAddress = v },
	}
	for key, apply := range set {
		for _, bad := range []string{"9443", "host", "fd00::1", "127.0.0.1:", ":", "127.0.0.1:0", "[::1]:0", ":65536", "host:abc"} {
			cfg := DefaultConfig()
			apply(cfg, bad)
			err := cfg.Validate()
			require.Error(t, err, "%s=%q", key, bad)
			assert.ErrorIs(t, err, ErrConfigInvalid)
			assert.Contains(t, err.Error(), key)
		}
		for _, good := range []string{"", ":9443", ":1", ":65535", "127.0.0.1:9443", "[fd00::1]:9443", "host.example.com:9443"} {
			cfg := DefaultConfig()
			apply(cfg, good)
			require.NoError(t, cfg.Validate(), "%s=%q", key, good)
		}
	}
}

// TestLoadFromPath_ListenerAddresses_FileThenEnvironment proves the
// three-path rule for the listener keys: file over default, environment
// over file, and validation of an environment value (#140).
func TestLoadFromPath_ListenerAddresses_FileThenEnvironment(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "xkey.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("agent:\n  listen_address: 10.0.0.5:9443\nphone:\n  relay_listen_address: 10.0.0.5:8444\n"), 0600))

	fromFile, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5:9443", fromFile.Agent.ListenAddress)
	assert.Equal(t, "10.0.0.5:8444", fromFile.Phone.RelayListenAddress)
	assert.Equal(t, "localhost", fromFile.OIDC.CallbackHost, "an omitted key keeps its default")

	t.Setenv("XKEY_AGENT_LISTEN_ADDRESS", "[::1]:9443")
	t.Setenv("XKEY_PHONE_RELAY_LISTEN_ADDRESS", "127.0.0.1:8444")
	fromEnv, err := LoadFromPath(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "[::1]:9443", fromEnv.Agent.ListenAddress)
	assert.Equal(t, "127.0.0.1:8444", fromEnv.Phone.RelayListenAddress)

	t.Setenv("XKEY_AGENT_LISTEN_ADDRESS", "9443")
	rejected, err := LoadFromPath(cfgPath)
	require.Error(t, err)
	assert.Nil(t, rejected)
	assert.ErrorIs(t, err, ErrConfigInvalid)
}
