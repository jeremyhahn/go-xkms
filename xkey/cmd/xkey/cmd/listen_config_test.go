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

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// withListenerConfig installs a loaded configuration carrying the given
// listener addresses for the test.
func withListenerConfig(t *testing.T, listen, relay string) {
	t.Helper()
	cfg := xkeyconfig.DefaultConfig()
	cfg.Agent.ListenAddress = listen
	cfg.Phone.RelayListenAddress = relay
	previous := loadedConfig
	loadedConfig = cfg
	t.Cleanup(func() { loadedConfig = previous })
}

// flagCmd returns a command carrying one string flag with an empty default.
func flagCmd(flag string) *cobra.Command {
	cmd := &cobra.Command{Use: "listen-test"}
	cmd.Flags().String(flag, "", "")
	return cmd
}

// TestListenerAddresses_BuiltInDefaultsWhenNothingLoaded proves that with no
// configuration loaded and no flag, each resolver yields the built-in
// default, which is the value the command bound before (#140).
func TestListenerAddresses_BuiltInDefaultsWhenNothingLoaded(t *testing.T) {
	previous := loadedConfig
	loadedConfig = nil
	t.Cleanup(func() { loadedConfig = previous })

	assert.Equal(t, ":9443", agentListenAddress(flagCmd("listen")))
	assert.Equal(t, ":8444", relayListenAddress(flagCmd("listen")))
}

// TestListenerAddresses_ConfigurationOverridesDefaults proves that the
// loaded agent and phone sections win over the built-in defaults, and that
// an empty configured value falls back to the built-in default rather than
// binding "".
func TestListenerAddresses_ConfigurationOverridesDefaults(t *testing.T) {
	withListenerConfig(t, "10.0.0.5:9443", "10.0.0.5:8444")
	assert.Equal(t, "10.0.0.5:9443", agentListenAddress(flagCmd("listen")))
	assert.Equal(t, "10.0.0.5:8444", relayListenAddress(flagCmd("listen")))

	withListenerConfig(t, "", "")
	assert.Equal(t, ":9443", agentListenAddress(flagCmd("listen")))
	assert.Equal(t, ":8444", relayListenAddress(flagCmd("listen")))
}

// TestListenerAddresses_FlagOverridesConfiguration proves that a flag the
// user set wins over the loaded section, and that a command without the
// flag still resolves the section.
func TestListenerAddresses_FlagOverridesConfiguration(t *testing.T) {
	withListenerConfig(t, "10.0.0.5:9443", "10.0.0.5:8444")

	cmd := flagCmd("listen")
	require.NoError(t, cmd.Flags().Set("listen", "[::1]:9443"))
	assert.Equal(t, "[::1]:9443", agentListenAddress(cmd))
	assert.Equal(t, "[::1]:9443", relayListenAddress(cmd))

	bare := &cobra.Command{Use: "bare"}
	assert.Equal(t, "10.0.0.5:9443", agentListenAddress(bare))
	assert.Equal(t, "10.0.0.5:8444", relayListenAddress(bare))
}

// TestListenerCommands_RegisterTheirFlagsWithConfigurationDefaults proves the
// real commands carry the flags with an empty default, so an unset flag
// means "from configuration" rather than a literal.
func TestListenerCommands_RegisterTheirFlagsWithConfigurationDefaults(t *testing.T) {
	for _, tc := range []struct {
		cmd  *cobra.Command
		flag string
	}{
		{agentStartCmd, "listen"},
		{deviceRelayCmd, "listen"},
	} {
		f := tc.cmd.Flags().Lookup(tc.flag)
		require.NotNil(t, f, "%s --%s", tc.cmd.Use, tc.flag)
		assert.Equal(t, "", f.DefValue, "%s --%s", tc.cmd.Use, tc.flag)
		assert.Contains(t, f.Usage, "host:port")
	}
}
