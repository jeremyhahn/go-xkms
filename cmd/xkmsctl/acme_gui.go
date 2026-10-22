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

//go:build gui

package main

import (
	"io/fs"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	acmegui "github.com/jeremyhahn/go-xkms/sdk/go/acme/gui"
)

// acmeGUIAssetsDir is the build output directory inside the embedded admin
// frontend that the webview serves.
const acmeGUIAssetsDir = "dist"

// acmeGUITransports maps an --acme-server scheme to the transport name the
// admin GUI config records. acmeClientOptions has already refused every
// scheme missing from it.
var acmeGUITransports = map[string]string{
	"http":  "rest",
	"https": "rest",
	"grpc":  "grpc",
	"grpcs": "grpc",
	"quic":  "quic",
	"mcp":   "mcp",
	"mcps":  "mcp",
}

var acmeGUICmd = &cobra.Command{
	Use:   "gui",
	Short: "Open the ACME CA desktop admin GUI",
	Long: `Open the Wails desktop admin GUI for the ACME certificate authority.

The window talks to the ACME admin API at --acme-server with the same SDK
client and mTLS identity as every other acme subcommand; --tls-cert and
--tls-key are required, because the admin API authenticates the operator by
client certificate. The GUI's REST routes are served in-process to the
webview only: the command opens no listening socket.

Only built with -tags gui (make build-cli-gui).

Examples:
  xkmsctl --tls-cert admin.crt --tls-key admin.key --tls-ca ca.crt \
    acme --acme-server grpcs://ca.example.com:9443 gui`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := acmeGUI(getConfig()); err != nil {
			handleError(err)
		}
	},
}

func init() {
	acmeCmd.AddCommand(acmeGUICmd)
}

// ACMEGUIIdentityRequiredError is returned when `acme gui` is started without
// the mTLS client certificate and key that identify the operator to the ACME
// admin API.
type ACMEGUIIdentityRequiredError struct{}

// Error implements the error interface.
func (e *ACMEGUIIdentityRequiredError) Error() string {
	return "acme gui: --tls-cert and --tls-key are required: the ACME admin API " +
		"identifies the operator by mTLS client certificate"
}

// ACMEGUIAssetsError is returned when the embedded admin frontend cannot be
// opened.
type ACMEGUIAssetsError struct {
	Cause error
}

// Error implements the error interface.
func (e *ACMEGUIAssetsError) Error() string {
	return "acme gui: failed to open the embedded admin frontend: " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *ACMEGUIAssetsError) Unwrap() error { return e.Cause }

// acmeGUI connects to the ACME admin API and blocks until the window closes.
func acmeGUI(cfg *Config) error {
	guiCfg, err := acmeGUIConfig(cfg)
	if err != nil {
		return err
	}

	assets, err := fs.Sub(acmegui.AdminAssets, acmeGUIAssetsDir)
	if err != nil {
		return &ACMEGUIAssetsError{Cause: err}
	}

	client, err := newACMEClient(cfg)
	if err != nil {
		return err
	}
	defer closeAdminClientQuiet(client.Close)

	return acmegui.NewAdminApp(guiCfg, client, slog.Default()).Run(assets)
}

// acmeGUIConfig resolves the acme connection flags and the global mTLS
// identity into the admin GUI's config, refusing a missing server address or
// identity before any connection or window is opened.
func acmeGUIConfig(cfg *Config) (*acmegui.AdminGUIConfig, error) {
	address, _, err := acmeClientOptions(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return nil, &ACMEGUIIdentityRequiredError{}
	}

	guiCfg := acmegui.DefaultAdminGUIConfig()
	guiCfg.Transport = acmeGUITransport()
	guiCfg.Address = address
	guiCfg.TLSCert = cfg.TLSCert
	guiCfg.TLSKey = cfg.TLSKey
	guiCfg.TLSCA = cfg.TLSCACert
	return guiCfg, nil
}

// acmeGUITransport names the transport acmeClientOptions selected: the
// --acme-server scheme when it has one, else --acme-transport, else the SDK
// default (grpc).
func acmeGUITransport() string {
	if scheme, _, found := strings.Cut(acmeServerFlag, "://"); found {
		return acmeGUITransports[scheme]
	}
	if acmeTransportFlag != "" {
		return acmeTransportFlag
	}
	return "grpc"
}
