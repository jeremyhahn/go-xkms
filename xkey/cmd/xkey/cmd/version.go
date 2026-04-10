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

package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Version information variables set via ldflags at build time.
// Example: go build -ldflags "-X github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd.Version=1.0.0"
var (
	// Version is the semantic version of the application.
	Version = "dev"

	// Commit is the git commit hash at build time.
	Commit = "none"

	// Date is the build timestamp.
	Date = "unknown"
)

// versionCmd represents the version command for displaying build information.
var versionCmd = &cobra.Command{
	Use:     "version",
	Aliases: []string{"v"},
	Short:   "Show version information",
	Long: `Display detailed version information for the xKey application.

This includes the semantic version, git commit hash, build date,
and runtime information about the Go version and operating system.

The version information is embedded at build time using ldflags:
  go build -ldflags "-X ...cmd.Version=1.0.0 -X ...cmd.Commit=abc123 -X ...cmd.Date=2025-01-31"`,
	Run: runVersion,
}

func init() {
	RootCmd.AddCommand(versionCmd)
}

// runVersion executes the version command logic.
func runVersion(cmd *cobra.Command, args []string) {
	fmt.Fprintln(cmd.OutOrStdout(), "xkey - xKey (go-xkms)")
	fmt.Fprintf(cmd.OutOrStdout(), "  Version:    %s\n", Version)
	fmt.Fprintf(cmd.OutOrStdout(), "  Git Commit: %s\n", Commit)
	fmt.Fprintf(cmd.OutOrStdout(), "  Built:      %s\n", Date)
	fmt.Fprintf(cmd.OutOrStdout(), "  Go Version: %s\n", runtime.Version())
	fmt.Fprintf(cmd.OutOrStdout(), "  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

// GetVersionInfo returns the version information as a formatted string.
// This is useful for programmatic access to version details.
func GetVersionInfo() string {
	return fmt.Sprintf("xkey %s (commit: %s, built: %s)", Version, Commit, Date)
}
