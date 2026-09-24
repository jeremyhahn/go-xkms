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
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// transportFlagUsage is the canonical help text for the --transport flag,
// kept identical across xkmsctl, qrdbctl, quicbaas, and platformctl.
const transportFlagUsage = "Client transport: rest, grpc, quic, mcp, unix, embedded"

var (
	// Global configuration
	globalConfig *Config

	// exitFunc is the function called to exit the program.
	// This can be overridden in tests to capture exit calls.
	exitFunc = os.Exit

	// pkcs11PINFlag holds the raw --pkcs11-pin flag value. pflag has no
	// *secure.Secret var type, so the flag binds to this plain string and
	// rootCmd's PersistentPreRunE seals it into globalConfig.PKCS11PIN
	// before any command runs.
	pkcs11PINFlag string
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "xkmsctl",
	Short: "go-xkms CLI - Cryptographic key management tool",
	Long: `go-xkms CLI provides a command-line interface for managing
cryptographic keys across multiple backends including software,
hardware, and cloud-based key management systems.

By default, the CLI communicates with the xkmsd daemon via Unix socket.
Use --transport to specify the client transport:
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
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		globalConfig.PKCS11PIN = pkcs11PINSecret(pkcs11PINFlag)
		return nil
	},
}

// pkcs11PINSecret seals s into a *secure.Secret for Config.PKCS11PIN. An
// empty s returns nil: no --pkcs11-pin was provided.
//
// rootCmd.PersistentPreRunE has no way to surface a sealing failure other
// than aborting every command, so a failure is logged and treated as "no
// PIN provided" rather than propagated, mirroring xkey's fido2PINSecret. In
// practice this path is unreachable: the underlying memguard allocator
// panics the whole process on allocation failure before NewSecret could
// return an error here.
func pkcs11PINSecret(s string) *secure.Secret {
	if s == "" {
		return nil
	}
	secret, err := secure.NewSecret([]byte(s))
	if err != nil {
		slog.Default().Error("xkmsctl: failed to seal --pkcs11-pin into protected memory", "error", err)
		return nil
	}
	return secret
}

// Execute runs the root command. It fails fast on a broken command tree
// (see initErrors in flags.go) rather than letting cobra dispatch into a
// command whose required-flag enforcement did not take effect.
func Execute() error {
	if len(initErrors) > 0 {
		return errors.Join(initErrors...)
	}
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

	// Transport flag - selects the SDK transport used to reach xkmsd.
	rootCmd.PersistentFlags().StringVar(&globalConfig.Protocol, "transport", DefaultTransport,
		transportFlagUsage)

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
	rootCmd.PersistentFlags().StringVar(&pkcs11PINFlag, "pkcs11-pin", "",
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
	// initCmd is registered in init.go's init() function; do not re-add.
	rootCmd.AddCommand(credentialCmd)
	rootCmd.AddCommand(caCmd)
	rootCmd.AddCommand(pkcs11Cmd)

	// Wire the locked canonical CLI surface per
	// docs/08-bootstrap-auth-architecture.md §6.
	configureCanonicalSurface()
}

// getConfig returns the global configuration
func getConfig() *Config {
	return globalConfig
}

// handleError prints an error and exits with code 1.
// The exit behavior can be overridden in tests by setting exitFunc.
func handleError(err error) {
	printer := NewPrinter(globalConfig.OutputFormat, os.Stderr)
	// Printing to stderr is best-effort: err is already the reason the
	// process is about to exit non-zero, and there is no more-authoritative
	// channel left to report a print failure on, so it is logged rather
	// than escalated.
	if perr := printer.PrintError(err); perr != nil {
		slog.Default().Debug("xkmsctl: failed to print error to stderr", "error", perr)
	}
	exitFunc(1)
}

// printVerbose prints a message if verbose mode is enabled
func printVerbose(format string, args ...interface{}) {
	if globalConfig.Verbose {
		fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
	}
}
