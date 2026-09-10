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
	"github.com/spf13/cobra"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// listenerConfig returns the loaded configuration's listener sections, or
// the built-in defaults when no configuration was loaded.
func listenerConfig() (xkeyconfig.AgentConfig, xkeyconfig.PhoneConfig) {
	defaults := xkeyconfig.DefaultConfig()
	if cfg := GetConfig(); cfg != nil {
		return cfg.Agent, cfg.Phone
	}
	return defaults.Agent, defaults.Phone
}

// configuredAddress returns the value of the named string flag on cmd when
// the user set it, and configured otherwise, so a flag overrides the
// configuration and the configuration overrides the built-in default. An
// empty configured value falls back to builtin, the defaults-layer value.
func configuredAddress(cmd *cobra.Command, flag, configured, builtin string) string {
	if f := cmd.Flags().Lookup(flag); f != nil && f.Changed {
		return f.Value.String()
	}
	if configured != "" {
		return configured
	}
	return builtin
}

// agentListenAddress resolves the address `xkey agent start` binds:
// --listen, else agent.listen_address, else the built-in default.
func agentListenAddress(cmd *cobra.Command) string {
	agentCfg, _ := listenerConfig()
	return configuredAddress(cmd, "listen", agentCfg.ListenAddress, xkeyconfig.DefaultConfig().Agent.ListenAddress)
}

// relayListenAddress resolves the address `xkey device relay` binds:
// --listen, else phone.relay_listen_address, else the built-in default.
func relayListenAddress(cmd *cobra.Command) string {
	_, phoneCfg := listenerConfig()
	return configuredAddress(cmd, "listen", phoneCfg.RelayListenAddress, xkeyconfig.DefaultConfig().Phone.RelayListenAddress)
}
