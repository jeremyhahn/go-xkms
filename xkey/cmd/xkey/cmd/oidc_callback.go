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
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
)

// OIDCCallbackPortError reports a --callback-port outside 1-65535.
type OIDCCallbackPortError struct {
	// Value is the flag value as given.
	Value string
}

// Error implements the error interface.
func (e *OIDCCallbackPortError) Error() string {
	return "oidc: --callback-port " + strconv.Quote(e.Value) + " must be between 1 and 65535"
}

// registerOIDCCallbackFlags defines --callback-host and --callback-port on
// fs. Their zero values mean "from configuration": resolveOIDCCallback only
// honours a flag the user set, so the loaded oidc section stays the default.
func registerOIDCCallbackFlags(fs *pflag.FlagSet) {
	defaults := xkeyconfig.DefaultConfig().OIDC
	fs.String("callback-host", "", "Host the local callback listener binds (default: oidc.callback_host, "+defaults.CallbackHost+")")
	fs.Int("callback-port", 0, "Port of the default redirect URL (default: oidc.callback_port, "+strconv.Itoa(defaults.CallbackPort)+")")
}

// resolveOIDCCallback returns the callback listener for cmd: the loaded
// configuration's oidc section (the built-in defaults when no configuration
// was loaded), overridden by --callback-host and --callback-port when set.
// A --callback-port outside 1-65535 is refused with OIDCCallbackPortError,
// the same bound oidc.callback_port has in the configuration.
func resolveOIDCCallback(cmd *cobra.Command) (oidc.Callback, error) {
	section := xkeyconfig.DefaultConfig().OIDC
	if cfg := GetConfig(); cfg != nil {
		section = cfg.OIDC
	}
	callback := oidc.Callback{Host: section.CallbackHost, Port: section.CallbackPort}
	if flag := cmd.Flags().Lookup("callback-host"); flag != nil && flag.Changed {
		callback.Host = flag.Value.String()
	}
	if flag := cmd.Flags().Lookup("callback-port"); flag != nil && flag.Changed {
		port, err := strconv.Atoi(flag.Value.String())
		if err != nil || port < 1 || port > 65535 {
			return oidc.Callback{}, &OIDCCallbackPortError{Value: flag.Value.String()}
		}
		callback.Port = port
	}
	return callback, nil
}
