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

// tlsCmd represents the TLS command
var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "TLS certificate operations",
	Long:  `Retrieve combined TLS certificates (key + certificate)`,
}

// tlsGetCmd retrieves a TLS certificate (key + cert)
var tlsGetCmd = &cobra.Command{
	Use:   "get <key-id>",
	Short: "Get a TLS certificate",
	Long:  `Retrieve a complete TLS certificate combining the private key and X.509 certificate`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Getting TLS certificate for key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Create certificate storage
		certStorage, err := cfg.CreateCertStorage()
		if err != nil {
			handleError(fmt.Errorf("failed to create cert storage: %w", err))
			return
		}

		// Build key attributes
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Get the private key
		key, err := be.GetKey(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get key: %w", err))
			return
		}

		// Get the certificate
		cert, err := certStorage.GetCert(keyID)
		if err != nil {
			handleError(fmt.Errorf("failed to get certificate: %w", err))
			return
		}

		// Get the certificate chain (optional)
		chain, err := certStorage.GetCertChain(keyID)
		if err != nil {
			// Chain is optional, just use the leaf certificate
			printVerbose("Certificate chain not found (this is OK): %v", err)
			chain = nil
		}

		printVerbose("Key algorithm: %s", attrs.KeyAlgorithm)
		printVerbose("Certificate Subject: %s", cert.Subject.String())
		if len(chain) > 0 {
			printVerbose("Certificate chain length: %d", len(chain))
		}

		// Print the TLS certificate info
		if err := printer.PrintTLSCertificate(key, cert, chain); err != nil {
			handleError(err)
		}
	},
}

func init() {
	// Add TLS subcommands
	tlsCmd.AddCommand(tlsGetCmd)

	// Flags for get command
	tlsGetCmd.Flags().String("key-type", "tls", "Key type")
	tlsGetCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	tlsGetCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	tlsGetCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
}
