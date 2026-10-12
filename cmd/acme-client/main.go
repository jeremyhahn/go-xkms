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

// Package main implements the trusted-acme-client CLI binary for multi-account
// ACME certificate lifecycle management, including account registration,
// certificate request/renew/revoke, auto-renewal service, and TPM
// device enrollment and attestation.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "trusted-acme-client",
	Short: "Multi-account ACME client for trusted certificate management",
	Long: `trusted-acme-client is a CLI for managing ACME certificates across multiple
accounts with support for TPM-based device enrollment and attestation.

It communicates with ACME-compliant Certificate Authorities to:
  - Manage multiple ACME accounts with independent key configurations
  - Request, renew, and revoke certificates across accounts
  - Run an automatic certificate renewal service
  - Perform TPM device enrollment (enroll-01)
  - Perform TPM device attestation (device-attest-01)

Configuration is provided via a YAML config file that defines accounts,
certificates, storage backends, and challenge settings:
  - ~/.trusted-acme-client.yaml
  - ~/.config/trusted-acme-client/config.yaml
  - /etc/trusted-acme/client-config.yaml

Environment variables (ACME_CLIENT_*) override config file values.

Examples:
  # Register an account defined in config
  trusted-acme-client account register --name trusted-ca

  # Request a certificate defined in config
  trusted-acme-client cert request --name web-prod

  # Renew a managed certificate
  trusted-acme-client cert renew --name web-prod

  # Revoke a certificate
  trusted-acme-client cert revoke --name web-prod

  # Run auto-renewal service for all certificates
  trusted-acme-client service start

  # TPM device enrollment
  trusted-acme-client device enroll --device-id node-01

  # Show version
  trusted-acme-client version`,
	Run: func(cmd *cobra.Command, args []string) {
		if hasDisplay() {
			if err := runGUI(); err != nil {
				fmt.Fprintf(os.Stderr, "GUI error: %v\n", err)
				fmt.Println()
				_ = cmd.Help()
			}
			return
		}
		fmt.Println("trusted-acme-client: no subcommand specified and no display available.")
		fmt.Println()
		_ = cmd.Help()
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig()
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

// accountCmd is the parent command for ACME account management operations.
var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage ACME accounts",
}

// certCmd is the parent command for certificate management operations.
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage certificates",
}

// deviceCmd is the parent command for TPM device operations.
var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "TPM device operations",
}

// serviceCmd is the parent command for renewal service operations.
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Renewal service management",
}

func init() {
	pflags := rootCmd.PersistentFlags()

	pflags.StringP("config", "c", "", "config file path (default: ~/.trusted-acme-client.yaml)")
	pflags.String("log-level", "info", "log level (debug|info|warn|error)")
	pflags.String("log-format", "json", "log format (json|text)")

	_ = viper.BindPFlag("config", pflags.Lookup("config"))
	_ = viper.BindPFlag("logging.level", pflags.Lookup("log-level"))
	_ = viper.BindPFlag("logging.format", pflags.Lookup("log-format"))

	rootCmd.AddCommand(accountCmd)
	rootCmd.AddCommand(certCmd)
	rootCmd.AddCommand(deviceCmd)
	rootCmd.AddCommand(serviceCmd)
}

func main() {
	// Before anything constructs protected memory: a debugger or a same-user
	// process must not be able to read it through ptrace or /proc/<pid>/mem.
	if _, err := secure.HardenProcess(nil); err != nil {
		fmt.Fprintf(os.Stderr, "error: process hardening: %v\n", err)
		os.Exit(1)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
