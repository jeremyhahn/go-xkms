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

package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// Version information (injected at build time via -ldflags)
var (
	Version   = "dev"     // Set via -ldflags "-X github.com/jeremyhahn/go-keychain/internal/cli.Version=x.y.z"
	GitCommit = "unknown" // Set via -ldflags "-X github.com/jeremyhahn/go-keychain/internal/cli.GitCommit=abc123"
	BuildDate = "unknown" // Set via -ldflags "-X github.com/jeremyhahn/go-keychain/internal/cli.BuildDate=2025-01-15"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version information for the keychain CLI`,
	Run: func(cmd *cobra.Command, args []string) {
		printer := NewPrinter(getConfig().OutputFormat, os.Stdout)

		if getConfig().OutputFormat == "json" {
			_ = printer.printJSON(map[string]interface{}{
				"version":    Version,
				"commit":     GitCommit,
				"build_date": BuildDate,
				"go_version": runtime.Version(),
				"os":         runtime.GOOS,
				"arch":       runtime.GOARCH,
			})
		} else {
			fmt.Printf("keychain version %s\n", Version)
			fmt.Printf("Git commit: %s\n", GitCommit)
			fmt.Printf("Build date: %s\n", BuildDate)
			fmt.Printf("Go version: %s\n", runtime.Version())
			fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		}
	},
}
