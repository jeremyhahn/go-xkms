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
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global configuration
	globalConfig *Config

	// exitFunc is the function called to exit the program.
	// This can be overridden in tests to capture exit calls.
	exitFunc = os.Exit
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "xkmsctl",
	Short: "go-xkms CLI - Cryptographic key management tool",
	Long: `go-xkms CLI provides a command-line interface for managing
cryptographic keys across multiple backends including software,
hardware, and cloud-based key management systems.

By default, the CLI communicates with the xkmsd daemon via Unix socket.
Use --protocol to specify the communication protocol:
  - embedded: Direct backend access without daemon (local mode)
  - rest:     REST API over HTTP/HTTPS
  - grpc:     gRPC protocol
  - quic:     QUIC/HTTP3 protocol
  - mcp:      Model Context Protocol
  - unix:     Unix domain socket (default when server not specified)

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
		"config file (default is $HOME/.xkms.yaml)")
	rootCmd.PersistentFlags().StringVar(&globalConfig.Backend, "backend", "software",
		"backend to use (software, pkcs11, tpm2, awskms, gcpkms, azurekv, vault)")
	rootCmd.PersistentFlags().StringVar(&globalConfig.KeyDir, "key-dir", "xkms-data/keys",
		"directory for key storage (for file-based backends)")
	rootCmd.PersistentFlags().StringVarP(&globalConfig.OutputFormat, "output", "o", "text",
		"output format (text, json, table)")
	rootCmd.PersistentFlags().BoolVarP(&globalConfig.Verbose, "verbose", "v", false,
		"verbose output")

	// Protocol flag - specifies communication protocol with daemon
	rootCmd.PersistentFlags().StringVarP(&globalConfig.Protocol, "protocol", "P", "",
		"communication protocol (embedded, rest, grpc, quic, mcp, unix)\n"+
			"  embedded: direct backend access without daemon\n"+
			"  rest:     REST API over HTTP/HTTPS\n"+
			"  grpc:     gRPC protocol\n"+
			"  quic:     QUIC/HTTP3 protocol\n"+
			"  mcp:      Model Context Protocol\n"+
			"  unix:     Unix domain socket (default)")

	// Server connection flags
	rootCmd.PersistentFlags().StringVarP(&globalConfig.Server, "server", "s", "",
		"xkms server URL (default: xkms-data/xkms.sock)\n"+
			"Supported formats:\n"+
			"  unix:///path/to/socket.sock\n"+
			"  http://host:port or https://host:port (REST)\n"+
			"  grpc://host:port or grpcs://host:port (gRPC)\n"+
			"  quic://host:port (QUIC/HTTP3)")

	// TLS flags for remote connections
	rootCmd.PersistentFlags().StringVar(&globalConfig.TLSCert, "tls-cert", "",
		"path to client certificate file for mTLS authentication")
	rootCmd.PersistentFlags().StringVar(&globalConfig.TLSKey, "tls-key", "",
		"path to client key file for mTLS authentication")
	rootCmd.PersistentFlags().StringVar(&globalConfig.TLSCACert, "tls-ca", "",
		"path to CA certificate file for server verification")

	// JWT token for authentication (obtained via 'user login' command)
	rootCmd.PersistentFlags().StringVar(&globalConfig.JWTToken, "token", "",
		"JWT token for server authentication (use 'user login' to obtain)")

	// SPKI pin for trust-on-first-use bootstrap
	rootCmd.PersistentFlags().StringVar(&globalConfig.SPKIPin, "spki-pin", "",
		"hex-encoded SHA-256 SPKI pin for server certificate verification")

	// SO PIN for security officer operations
	rootCmd.PersistentFlags().StringVar(&globalConfig.SOPin, "so-pin", "",
		"security officer PIN for privileged operations")

	// PKCS#11 flags for mTLS client authentication via hardware tokens
	rootCmd.PersistentFlags().StringVar(&globalConfig.PKCS11Module, "pkcs11-module", "",
		"PKCS#11 shared object for mTLS client authentication (e.g., libxkey11.so)")
	rootCmd.PersistentFlags().IntVar(&globalConfig.PKCS11Slot, "pkcs11-slot", 0,
		"PKCS#11 slot ID for client certificate (default: 0)")
	rootCmd.PersistentFlags().StringVar(&globalConfig.PKCS11PIN, "pkcs11-pin", "",
		"PKCS#11 token PIN (prompted if omitted when --pkcs11-module is set)")

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(backendsCmd)
	rootCmd.AddCommand(keyCmd)
	rootCmd.AddCommand(certCmd)
	rootCmd.AddCommand(tlsCmd)
	rootCmd.AddCommand(fido2Cmd)
	rootCmd.AddCommand(adminCmd)
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(unsealDataCmd)
	rootCmd.AddCommand(canSealCmd)
	rootCmd.AddCommand(bootstrapCmd)
	rootCmd.AddCommand(pivCmd)
	rootCmd.AddCommand(barrierCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(credentialCmd)
	rootCmd.AddCommand(caCmd)
	rootCmd.AddCommand(pkcs11Cmd)
}

// getConfig returns the global configuration
func getConfig() *Config {
	return globalConfig
}

// handleError prints an error and exits with code 1.
// The exit behavior can be overridden in tests by setting exitFunc.
func handleError(err error) {
	printer := NewPrinter(globalConfig.OutputFormat, os.Stderr)
	_ = printer.PrintError(err) // Error printing to stderr is best-effort
	exitFunc(1)
}

// printVerbose prints a message if verbose mode is enabled
func printVerbose(format string, args ...interface{}) {
	if globalConfig.Verbose {
		fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
	}
}
