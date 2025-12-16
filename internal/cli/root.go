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

By default, the CLI communicates with the keychaind daemon via Unix socket.
Use --local to bypass the daemon and access backends directly.

Supported backends:
  - software: Software-based keys (asymmetric + symmetric)
  - pkcs11:   PKCS#11 HSM keys
  - tpm2:     TPM 2.0 hardware keys
  - awskms:   AWS Key Management Service
  - gcpkms:   Google Cloud KMS
  - azurekv:  Azure Key Vault
  - vault:    HashiCorp Vault`,
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
	rootCmd.PersistentFlags().StringVar(&globalConfig.Backend, "backend", "software",
		"backend to use (software, pkcs11, tpm2, awskms, gcpkms, azurekv, vault)")
	rootCmd.PersistentFlags().StringVar(&globalConfig.KeyDir, "key-dir", "keychain-data/keys",
		"directory for key storage (for file-based backends)")
	rootCmd.PersistentFlags().StringVarP(&globalConfig.OutputFormat, "output", "o", "text",
		"output format (text, json, table)")
	rootCmd.PersistentFlags().BoolVarP(&globalConfig.Verbose, "verbose", "v", false,
		"verbose output")

	// Local mode flag - bypass daemon and use backend directly
	rootCmd.PersistentFlags().BoolVarP(&globalConfig.UseLocal, "local", "l", false,
		"use local backend directly (bypass keychaind daemon)")

	// Server connection flags
	rootCmd.PersistentFlags().StringVarP(&globalConfig.Server, "server", "s", "",
		"keychain server URL (default: keychain-data/keychain.sock)\n"+
			"Supported formats:\n"+
			"  unix:///path/to/socket.sock\n"+
			"  http://host:port or https://host:port (REST)\n"+
			"  grpc://host:port or grpcs://host:port (gRPC)\n"+
			"  quic://host:port (QUIC/HTTP3)")

	// TLS flags for remote connections
	rootCmd.PersistentFlags().BoolVar(&globalConfig.TLSInsecure, "tls-insecure", false,
		"skip TLS certificate verification (not recommended for production)")
	rootCmd.PersistentFlags().StringVar(&globalConfig.TLSCert, "tls-cert", "",
		"path to client certificate file for mTLS authentication")
	rootCmd.PersistentFlags().StringVar(&globalConfig.TLSKey, "tls-key", "",
		"path to client key file for mTLS authentication")
	rootCmd.PersistentFlags().StringVar(&globalConfig.TLSCACert, "tls-ca", "",
		"path to CA certificate file for server verification")

	// JWT token for authentication (obtained via 'user login' command)
	rootCmd.PersistentFlags().StringVar(&globalConfig.JWTToken, "token", "",
		"JWT token for server authentication (use 'user login' to obtain)")

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(backendsCmd)
	rootCmd.AddCommand(keyCmd)
	rootCmd.AddCommand(certCmd)
	rootCmd.AddCommand(tlsCmd)
	rootCmd.AddCommand(fido2Cmd)
	rootCmd.AddCommand(adminCmd)
	rootCmd.AddCommand(userCmd)
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
