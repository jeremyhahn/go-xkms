// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

	"github.com/jeremyhahn/go-keychain/pkg/types"
	client "github.com/jeremyhahn/go-keychain/sdk/go"
	"github.com/spf13/cobra"
)

// backendsCmd represents the backends command
var backendsCmd = &cobra.Command{
	Use:   "backends",
	Short: "Manage and list available backends",
	Long:  `List available cryptographic backends and view their capabilities`,
}

// backendsListCmd lists all available backends
var backendsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available backends",
	Long:  `List all cryptographic backends available in this build`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		listBackends(cfg, printer)
	},
}

// listBackends lists backends using the SDK client
func listBackends(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychain service")

	resp, err := cl.ListBackends(ctx)
	if err != nil {
		handleError(fmt.Errorf("failed to list backends: %w", err))
		return
	}

	// Extract backend IDs
	backends := make([]string, len(resp.Backends))
	for i, be := range resp.Backends {
		backends[i] = be.ID
	}

	if err := printer.PrintBackendList(backends); err != nil {
		handleError(err)
	}
}

// backendsInfoCmd shows information about a specific backend
var backendsInfoCmd = &cobra.Command{
	Use:   "info <backend>",
	Short: "Show information about a specific backend",
	Long:  `Display detailed information and capabilities of a specific backend`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		backendName := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		backendInfo(cfg, printer, backendName)
	},
}

// backendInfo gets backend info using the SDK client
func backendInfo(cfg *Config, printer *Printer, backendName string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychain service")

	info, err := cl.GetBackend(ctx, backendName)
	if err != nil {
		handleError(fmt.Errorf("failed to get backend info: %w", err))
		return
	}

	// Convert SDK BackendInfo capabilities to types.Capabilities
	caps := convertBackendInfoToCapabilities(info)

	if err := printer.PrintBackendInfo(backendName, caps); err != nil {
		handleError(err)
	}
}

// convertBackendInfoToCapabilities converts SDK BackendInfo to types.Capabilities
func convertBackendInfoToCapabilities(info *client.BackendInfo) types.Capabilities {
	caps := types.Capabilities{
		HardwareBacked: info.HardwareBacked,
	}

	// Extract capabilities from map
	if val, ok := info.Capabilities["keys"].(bool); ok {
		caps.Keys = val
	}
	if val, ok := info.Capabilities["signing"].(bool); ok {
		caps.Signing = val
	}
	if val, ok := info.Capabilities["decryption"].(bool); ok {
		caps.Decryption = val
	}
	if val, ok := info.Capabilities["key_rotation"].(bool); ok {
		caps.KeyRotation = val
	}
	if val, ok := info.Capabilities["symmetric_encryption"].(bool); ok {
		caps.SymmetricEncryption = val
	}
	if val, ok := info.Capabilities["import"].(bool); ok {
		caps.Import = val
	}
	if val, ok := info.Capabilities["export"].(bool); ok {
		caps.Export = val
	}
	if val, ok := info.Capabilities["key_agreement"].(bool); ok {
		caps.KeyAgreement = val
	}
	if val, ok := info.Capabilities["ecies"].(bool); ok {
		caps.ECIES = val
	}

	return caps
}

func init() {
	backendsCmd.AddCommand(backendsListCmd)
	backendsCmd.AddCommand(backendsInfoCmd)
}
