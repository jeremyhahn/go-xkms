// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"strconv"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// algorithmsCmd reports the algorithms the server supports.
var algorithmsCmd = &cobra.Command{
	Use:   "algorithms",
	Short: "List the algorithms the server supports",
	Long: `List the cryptographic algorithms the server supports and which
backends provide each one.

The inventory reflects the server's compiled-in backends, so it answers "can
this deployment do X?" without generating a key. Discovery is unauthenticated.

Example:
  xkmsctl algorithms`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		listAlgorithms(cfg, printer)
	},
}

// listAlgorithms fetches and renders the algorithm inventory.
func listAlgorithms(cfg *Config, printer *Printer) {
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

	resp, err := cl.Algorithms(ctx)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListAlgorithmsFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	default:
		printAlgorithmGroup(printer, "Signing", resp.Signing)
		printAlgorithmGroup(printer, "Key encapsulation", resp.KeyEncapsulation)
	}
}

// printAlgorithmGroup renders one purpose-grouped section of the inventory.
func printAlgorithmGroup(printer *Printer, title string, algorithms []client.AlgorithmInfo) {
	_, _ = fmt.Fprintf(printer.writer, "%s:\n", title)
	if len(algorithms) == 0 {
		_, _ = fmt.Fprintf(printer.writer, "  (none)\n")
		return
	}
	for _, a := range algorithms {
		_, _ = fmt.Fprintf(printer.writer, "  %s", a.Algorithm)
		if a.PostQuantum {
			_, _ = fmt.Fprintf(printer.writer, " [post-quantum]")
		}
		if len(a.Curves) > 0 {
			_, _ = fmt.Fprintf(printer.writer, " curves=%s", strings.Join(a.Curves, ","))
		}
		if len(a.KeySizes) > 0 {
			sizes := make([]string, len(a.KeySizes))
			for i, s := range a.KeySizes {
				sizes[i] = strconv.Itoa(s)
			}
			_, _ = fmt.Fprintf(printer.writer, " sizes=%s", strings.Join(sizes, ","))
		}
		_, _ = fmt.Fprintf(printer.writer, " backends=%s\n", strings.Join(a.Backends, ","))
	}
}

func init() {
	rootCmd.AddCommand(algorithmsCmd)
}
