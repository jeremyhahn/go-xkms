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

	"github.com/jeremyhahn/go-keychain/pkg/types"
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
		printer := NewPrinter(getConfig().OutputFormat, os.Stdout)

		backends := []string{
			"pkcs8",
			"pkcs11",
			"tpm2",
			"awskms",
			"gcpkms",
			"azurekv",
			"vault",
		}

		if err := printer.PrintBackendList(backends); err != nil {
			handleError(err)
		}
	},
}

// backendsInfoCmd shows information about a specific backend
var backendsInfoCmd = &cobra.Command{
	Use:   "info <backend>",
	Short: "Show information about a specific backend",
	Long:  `Display detailed information and capabilities of a specific backend`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		backendName := args[0]
		printer := NewPrinter(getConfig().OutputFormat, os.Stdout)

		// Get backend capabilities
		caps, err := getBackendCapabilities(backendName)
		if err != nil {
			handleError(fmt.Errorf("failed to get backend info: %w", err))
			return
		}

		if err := printer.PrintBackendInfo(backendName, caps); err != nil {
			handleError(err)
		}
	},
}

func init() {
	backendsCmd.AddCommand(backendsListCmd)
	backendsCmd.AddCommand(backendsInfoCmd)
}

// getBackendCapabilities returns the capabilities for a given backend
func getBackendCapabilities(backendName string) (types.Capabilities, error) {
	switch backendName {
	case "pkcs8":
		return types.Capabilities{
			Keys:                true,
			HardwareBacked:      false,
			Signing:             true,
			Decryption:          true,
			KeyRotation:         true,
			SymmetricEncryption: true,
			Import:              true,
			Export:              true,
			KeyAgreement:        true,
			ECIES:               true,
		}, nil
	case "pkcs11":
		return types.Capabilities{
			Keys:           true,
			HardwareBacked: true,
			Signing:        true,
			Decryption:     true,
			KeyRotation:    false,
			Import:         true,
			Export:         true,
		}, nil
	case "tpm2":
		return types.Capabilities{
			Keys:           true,
			HardwareBacked: true,
			Signing:        true,
			Decryption:     true,
			KeyRotation:    false,
			Import:         true,
			Export:         true,
		}, nil
	case "awskms", "gcpkms", "azurekv":
		return types.Capabilities{
			Keys:           true,
			HardwareBacked: true,
			Signing:        true,
			Decryption:     true,
			KeyRotation:    true,
			Import:         true,
		}, nil
	case "vault":
		return types.Capabilities{
			Keys:           true,
			HardwareBacked: false,
			Signing:        true,
			Decryption:     true,
			KeyRotation:    true,
			Import:         true,
			Export:         true,
		}, nil
	default:
		return types.Capabilities{}, fmt.Errorf("unknown backend: %s", backendName)
	}
}
