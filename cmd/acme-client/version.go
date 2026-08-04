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
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version information variables set via ldflags at build time.
// Example: go build -ldflags "-X main.version=1.0.0 -X main.commit=abc123 -X main.buildDate=2025-01-01"
var (
	version   = "0.1.0"
	commit    = "none"
	buildDate = "unknown"
)

// versionCmd represents the version command.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long: `Display version information for the trusted-acme-client CLI.

Shows the version number, git commit hash, build date, and Go version
used to compile the binary.

Examples:
  trusted-acme-client version`,
	// Override PersistentPreRunE so version works without config
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

// runVersion executes the version command.
func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Printf("trusted-acme-client version %s (commit: %s, built: %s, go: %s)\n",
		version, commit, buildDate, runtime.Version())
	return nil
}
