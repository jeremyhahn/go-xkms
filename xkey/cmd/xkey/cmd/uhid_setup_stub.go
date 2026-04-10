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

//go:build !linux

package cmd

import (
	"github.com/spf13/cobra"
)

// uhidSetupCmd is a stub for non-Linux platforms.
var uhidSetupCmd = &cobra.Command{
	Use:    "setup",
	Short:  "Configure UHID device permissions (Linux only)",
	Hidden: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		return ErrUHIDNotLinux
	},
}

func init() {
	uhidCmd.AddCommand(uhidSetupCmd)
}
