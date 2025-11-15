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

	"github.com/spf13/cobra"
)

var (
	// Global configuration
	globalConfig *Config
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "keychain",
	Short: "go-keychain CLI - Cryptographic key management tool",
	Long: `go-keychain CLI provides a command-line interface for managing
cryptographic keys across multiple backends including software,
hardware, and cloud-based key management systems.

Supported backends:
  - pkcs8:   PKCS#8 software keys
  - pkcs11:  PKCS#11 HSM keys
  - tpm2:    TPM 2.0 hardware keys
  - awskms:  AWS Key Management Service
  - gcpkms:  Google Cloud KMS
  - azurekv: Azure Key Vault
  - vault:   HashiCorp Vault`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Initialize global config
	globalConfig = NewConfig()

	// Persistent flags (available to all commands)
	rootCmd.PersistentFlags().StringVar(&globalConfig.ConfigFile, "config", "",
		"config file (default is $HOME/.keychain.yaml)")
	rootCmd.PersistentFlags().StringVar(&globalConfig.Backend, "backend", "pkcs8",
		"backend to use (pkcs8, pkcs11, tpm2, awskms, gcpkms, azurekv, vault)")
	rootCmd.PersistentFlags().StringVar(&globalConfig.KeyDir, "key-dir", "/tmp/keystore",
		"directory for key storage (for file-based backends)")
	rootCmd.PersistentFlags().StringVarP(&globalConfig.OutputFormat, "output", "o", "text",
		"output format (text, json, table)")
	rootCmd.PersistentFlags().BoolVarP(&globalConfig.Verbose, "verbose", "v", false,
		"verbose output")

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(backendsCmd)
	rootCmd.AddCommand(keyCmd)
	rootCmd.AddCommand(certCmd)
	rootCmd.AddCommand(tlsCmd)
}

// getConfig returns the global configuration
func getConfig() *Config {
	return globalConfig
}

// handleError prints an error and exits with code 1
func handleError(err error) {
	printer := NewPrinter(globalConfig.OutputFormat, os.Stderr)
	_ = printer.PrintError(err) // Error printing to stderr is best-effort
	os.Exit(1)
}

// printVerbose prints a message if verbose mode is enabled
func printVerbose(format string, args ...interface{}) {
	if globalConfig.Verbose {
		fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
	}
}
