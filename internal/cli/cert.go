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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// certCmd represents the certificate command
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage X.509 certificates",
	Long:  `Save, retrieve, delete, and manage X.509 certificates`,
}

// certSaveCmd saves a certificate
var certSaveCmd = &cobra.Command{
	Use:   "save <key-id> <cert-file>",
	Short: "Save a certificate",
	Long:  `Save an X.509 certificate to the certificate store`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		certFile := args[1]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Saving certificate for key: %s from file: %s", keyID, certFile)

		// Read the certificate file
		// #nosec G304 - Certificate file path from CLI argument
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			handleError(fmt.Errorf("failed to read certificate file: %w", err))
			return
		}

		// Parse PEM block
		block, _ := pem.Decode(certPEM)
		if block == nil {
			handleError(fmt.Errorf("failed to decode PEM block"))
			return
		}

		// Parse X.509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			handleError(fmt.Errorf("failed to parse certificate: %w", err))
			return
		}

		printVerbose("Certificate Subject: %s", cert.Subject.String())

		// Create certificate storage
		certStorage, err := cfg.CreateCertStorage()
		if err != nil {
			handleError(fmt.Errorf("failed to create cert storage: %w", err))
			return
		}

		// Save the certificate
		if err := certStorage.SaveCert(keyID, cert); err != nil {
			handleError(fmt.Errorf("failed to save certificate: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully saved certificate for key: %s", keyID)); err != nil {
			handleError(err)
		}
	},
}

// certGetCmd retrieves a certificate
var certGetCmd = &cobra.Command{
	Use:   "get <key-id>",
	Short: "Get a certificate",
	Long:  `Retrieve an X.509 certificate from the certificate store`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Getting certificate for key: %s", keyID)

		// Create certificate storage
		certStorage, err := cfg.CreateCertStorage()
		if err != nil {
			handleError(fmt.Errorf("failed to create cert storage: %w", err))
			return
		}

		// Get the certificate
		cert, err := certStorage.GetCert(keyID)
		if err != nil {
			handleError(fmt.Errorf("failed to get certificate: %w", err))
			return
		}

		printVerbose("Certificate Subject: %s", cert.Subject.String())

		if err := printer.PrintCertificate(cert); err != nil {
			handleError(err)
		}
	},
}

// certDeleteCmd deletes a certificate
var certDeleteCmd = &cobra.Command{
	Use:   "delete <key-id>",
	Short: "Delete a certificate",
	Long:  `Delete an X.509 certificate from the certificate store`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Deleting certificate for key: %s", keyID)

		// Create certificate storage
		certStorage, err := cfg.CreateCertStorage()
		if err != nil {
			handleError(fmt.Errorf("failed to create cert storage: %w", err))
			return
		}

		// Delete the certificate
		if err := certStorage.DeleteCert(keyID); err != nil {
			handleError(fmt.Errorf("failed to delete certificate: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully deleted certificate for key: %s", keyID)); err != nil {
			handleError(err)
		}
	},
}

// certListCmd lists all certificates
var certListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all certificates",
	Long:  `List all X.509 certificates in the certificate store`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Listing certificates")

		// Create certificate storage
		certStorage, err := cfg.CreateCertStorage()
		if err != nil {
			handleError(fmt.Errorf("failed to create cert storage: %w", err))
			return
		}

		// List certificates
		certIDs, err := certStorage.ListCerts()
		if err != nil {
			handleError(fmt.Errorf("failed to list certificates: %w", err))
			return
		}

		printVerbose("Found %d certificates", len(certIDs))

		if err := printer.PrintCertList(certIDs); err != nil {
			handleError(err)
		}
	},
}

// certExistsCmd checks if a certificate exists
var certExistsCmd = &cobra.Command{
	Use:   "exists <key-id>",
	Short: "Check if a certificate exists",
	Long:  `Check if an X.509 certificate exists in the certificate store`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Checking if certificate exists for key: %s", keyID)

		// Create certificate storage
		certStorage, err := cfg.CreateCertStorage()
		if err != nil {
			handleError(fmt.Errorf("failed to create cert storage: %w", err))
			return
		}

		// Check if certificate exists
		exists, err := certStorage.CertExists(keyID)
		if err != nil {
			handleError(fmt.Errorf("failed to check certificate existence: %w", err))
			return
		}

		if err := printer.PrintCertExists(keyID, exists); err != nil {
			handleError(err)
		}
	},
}

// certSaveChainCmd saves a certificate chain
var certSaveChainCmd = &cobra.Command{
	Use:   "save-chain <key-id> <cert-file>...",
	Short: "Save a certificate chain",
	Long:  `Save an X.509 certificate chain to the certificate store. Certificates should be ordered from leaf to root.`,
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		certFiles := args[1:]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Saving certificate chain for key: %s", keyID)

		// Parse all certificates
		chain := make([]*x509.Certificate, 0, len(certFiles))
		for i, certFile := range certFiles {
			printVerbose("Reading certificate %d from: %s", i+1, certFile)

			// Read the certificate file
			// #nosec G304 - Certificate file path from CLI argument
			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				handleError(fmt.Errorf("failed to read certificate file %s: %w", certFile, err))
				return
			}

			// Parse PEM block
			block, _ := pem.Decode(certPEM)
			if block == nil {
				handleError(fmt.Errorf("failed to decode PEM block from %s", certFile))
				return
			}

			// Parse X.509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				handleError(fmt.Errorf("failed to parse certificate from %s: %w", certFile, err))
				return
			}

			printVerbose("Certificate %d Subject: %s", i+1, cert.Subject.String())
			chain = append(chain, cert)
		}

		// Create certificate storage
		certStorage, err := cfg.CreateCertStorage()
		if err != nil {
			handleError(fmt.Errorf("failed to create cert storage: %w", err))
			return
		}

		// Save the certificate chain
		if err := certStorage.SaveCertChain(keyID, chain); err != nil {
			handleError(fmt.Errorf("failed to save certificate chain: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully saved certificate chain for key: %s (%d certificates)", keyID, len(chain))); err != nil {
			handleError(err)
		}
	},
}

// certGetChainCmd retrieves a certificate chain
var certGetChainCmd = &cobra.Command{
	Use:   "get-chain <key-id>",
	Short: "Get a certificate chain",
	Long:  `Retrieve an X.509 certificate chain from the certificate store`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Getting certificate chain for key: %s", keyID)

		// Create certificate storage
		certStorage, err := cfg.CreateCertStorage()
		if err != nil {
			handleError(fmt.Errorf("failed to create cert storage: %w", err))
			return
		}

		// Get the certificate chain
		chain, err := certStorage.GetCertChain(keyID)
		if err != nil {
			handleError(fmt.Errorf("failed to get certificate chain: %w", err))
			return
		}

		printVerbose("Retrieved %d certificates in chain", len(chain))

		if err := printer.PrintCertChain(chain); err != nil {
			handleError(err)
		}
	},
}

func init() {
	// Add certificate subcommands
	certCmd.AddCommand(certSaveCmd)
	certCmd.AddCommand(certGetCmd)
	certCmd.AddCommand(certDeleteCmd)
	certCmd.AddCommand(certListCmd)
	certCmd.AddCommand(certExistsCmd)
	certCmd.AddCommand(certSaveChainCmd)
	certCmd.AddCommand(certGetChainCmd)
}
