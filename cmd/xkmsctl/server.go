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

package main

import (
	"context"
	"fmt"
	"os"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// serverStatusCmd reports the xkmsd server health over the configured
// transport. It maps onto the SDK ConnectionService.Health surface, which
// every transport (rest, grpc, quic, mcp, unix, embedded) implements
// against the server's /health endpoint.
var serverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show xkmsd server status",
	Long: `Check the health of the xkmsd server over the configured transport
and display its status and version.

Examples:
  xkmsctl status
  xkmsctl status --transport rest --server https://xkms.example.com:8443`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		serverStatus(cfg, printer)
	},
}

// serverStatus checks server health via the SDK client.
func serverStatus(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd, checking health")

	resp, err := cl.Health(ctx)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrHealthCheckFailed, Err: err})
		return
	}

	printServerStatus(printer, resp)
}

// printServerStatus prints the server health response.
func printServerStatus(printer *Printer, resp *client.HealthResponse) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Server Status:\n")
		_, _ = fmt.Fprintf(printer.writer, "  Status:  %s\n", resp.Status)
		if resp.Version != "" {
			_, _ = fmt.Fprintf(printer.writer, "  Version: %s\n", resp.Version)
		}
		if resp.Message != "" {
			_, _ = fmt.Fprintf(printer.writer, "  Message: %s\n", resp.Message)
		}
	}
}

func init() {
	rootCmd.AddCommand(serverStatusCmd)
}
