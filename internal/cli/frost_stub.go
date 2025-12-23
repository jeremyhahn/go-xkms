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

//go:build !frost

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(frostCmd)
}

var frostCmd = &cobra.Command{
	Use:   "frost",
	Short: "FROST threshold signature operations (not compiled)",
	Long:  `FROST threshold signature support is not compiled in. Build with -tags frost to enable.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stderr, "Error: FROST support not compiled in")
		fmt.Fprintln(os.Stderr, "Rebuild with: go build -tags frost")
		os.Exit(1)
	},
}
