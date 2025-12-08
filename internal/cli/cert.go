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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-keychain/pkg/client"
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

		// Parse X.509 certificate to validate it
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			handleError(fmt.Errorf("failed to parse certificate: %w", err))
			return
		}

		printVerbose("Certificate Subject: %s", cert.Subject.String())

		// Use client or local storage based on --local flag
		if cfg.IsLocal() {
			saveCertLocal(cfg, printer, keyID, cert)
		} else {
			saveCertRemote(cfg, printer, keyID, string(certPEM))
		}
	},
}

// saveCertLocal saves a certificate using local storage
func saveCertLocal(cfg *Config, printer *Printer, keyID string, cert *x509.Certificate) {
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
}

// saveCertRemote saves a certificate using the client
func saveCertRemote(cfg *Config, printer *Printer, keyID, certPEM string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Save the certificate
	req := &client.SaveCertificateRequest{
		Backend:        cfg.Backend,
		KeyID:          keyID,
		CertificatePEM: certPEM,
	}

	if err := cl.SaveCertificate(ctx, req); err != nil {
		handleError(fmt.Errorf("failed to save certificate: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully saved certificate for key: %s", keyID)); err != nil {
		handleError(err)
	}
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

		// Use client or local storage based on --local flag
		if cfg.IsLocal() {
			getCertLocal(cfg, printer, keyID)
		} else {
			getCertRemote(cfg, printer, keyID)
		}
	},
}

// getCertLocal retrieves a certificate using local storage
func getCertLocal(cfg *Config, printer *Printer, keyID string) {
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
}

// getCertRemote retrieves a certificate using the client
func getCertRemote(cfg *Config, printer *Printer, keyID string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Get the certificate
	resp, err := cl.GetCertificate(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(fmt.Errorf("failed to get certificate: %w", err))
		return
	}

	// Parse the certificate
	block, _ := pem.Decode([]byte(resp.CertificatePEM))
	if block == nil {
		handleError(fmt.Errorf("failed to decode certificate PEM"))
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		handleError(fmt.Errorf("failed to parse certificate: %w", err))
		return
	}

	printVerbose("Certificate Subject: %s", cert.Subject.String())

	if err := printer.PrintCertificate(cert); err != nil {
		handleError(err)
	}
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

		// Use client or local storage based on --local flag
		if cfg.IsLocal() {
			deleteCertLocal(cfg, printer, keyID)
		} else {
			deleteCertRemote(cfg, printer, keyID)
		}
	},
}

// deleteCertLocal deletes a certificate using local storage
func deleteCertLocal(cfg *Config, printer *Printer, keyID string) {
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
}

// deleteCertRemote deletes a certificate using the client
func deleteCertRemote(cfg *Config, printer *Printer, keyID string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Delete the certificate
	if err := cl.DeleteCertificate(ctx, cfg.Backend, keyID); err != nil {
		handleError(fmt.Errorf("failed to delete certificate: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully deleted certificate for key: %s", keyID)); err != nil {
		handleError(err)
	}
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

		// Use client or local storage based on --local flag
		if cfg.IsLocal() {
			listCertsLocal(cfg, printer)
		} else {
			listCertsRemote(cfg, printer)
		}
	},
}

// listCertsLocal lists certificates using local storage
func listCertsLocal(cfg *Config, printer *Printer) {
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
}

// listCertsRemote lists certificates using the client
func listCertsRemote(cfg *Config, printer *Printer) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// List certificates
	resp, err := cl.ListCertificates(ctx, cfg.Backend)
	if err != nil {
		handleError(fmt.Errorf("failed to list certificates: %w", err))
		return
	}

	// Extract key IDs from certificates
	certIDs := make([]string, len(resp.Certificates))
	for i, cert := range resp.Certificates {
		certIDs[i] = cert.KeyID
	}

	printVerbose("Found %d certificates", len(certIDs))

	if err := printer.PrintCertList(certIDs); err != nil {
		handleError(err)
	}
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

		// Use client or local storage based on --local flag
		if cfg.IsLocal() {
			certExistsLocal(cfg, printer, keyID)
		} else {
			certExistsRemote(cfg, printer, keyID)
		}
	},
}

// certExistsLocal checks if a certificate exists using local storage
func certExistsLocal(cfg *Config, printer *Printer, keyID string) {
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
}

// certExistsRemote checks if a certificate exists using the client
func certExistsRemote(cfg *Config, printer *Printer, keyID string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Try to get the certificate - if it succeeds, it exists
	_, err = cl.GetCertificate(ctx, cfg.Backend, keyID)
	exists := err == nil

	if err := printer.PrintCertExists(keyID, exists); err != nil {
		handleError(err)
	}
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
		chainPEMs := make([]string, 0, len(certFiles))
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
			chainPEMs = append(chainPEMs, string(certPEM))
		}

		// Use client or local storage based on --local flag
		if cfg.IsLocal() {
			saveChainLocal(cfg, printer, keyID, chain)
		} else {
			saveChainRemote(cfg, printer, keyID, chainPEMs)
		}
	},
}

// saveChainLocal saves a certificate chain using local storage
func saveChainLocal(cfg *Config, printer *Printer, keyID string, chain []*x509.Certificate) {
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
}

// saveChainRemote saves a certificate chain using the client
func saveChainRemote(cfg *Config, printer *Printer, keyID string, chainPEMs []string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Save the certificate chain
	req := &client.SaveCertificateChainRequest{
		Backend:  cfg.Backend,
		KeyID:    keyID,
		ChainPEM: chainPEMs,
	}

	if err := cl.SaveCertificateChain(ctx, req); err != nil {
		handleError(fmt.Errorf("failed to save certificate chain: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully saved certificate chain for key: %s (%d certificates)", keyID, len(chainPEMs))); err != nil {
		handleError(err)
	}
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

		// Use client or local storage based on --local flag
		if cfg.IsLocal() {
			getChainLocal(cfg, printer, keyID)
		} else {
			getChainRemote(cfg, printer, keyID)
		}
	},
}

// getChainLocal retrieves a certificate chain using local storage
func getChainLocal(cfg *Config, printer *Printer, keyID string) {
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
}

// getChainRemote retrieves a certificate chain using the client
func getChainRemote(cfg *Config, printer *Printer, keyID string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Get the certificate chain
	resp, err := cl.GetCertificateChain(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(fmt.Errorf("failed to get certificate chain: %w", err))
		return
	}

	// Parse each certificate
	chain := make([]*x509.Certificate, 0, len(resp.ChainPEM))
	for i, certPEM := range resp.ChainPEM {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			handleError(fmt.Errorf("failed to decode certificate %d PEM", i+1))
			return
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			handleError(fmt.Errorf("failed to parse certificate %d: %w", i+1, err))
			return
		}
		chain = append(chain, cert)
	}

	printVerbose("Retrieved %d certificates in chain", len(chain))

	if err := printer.PrintCertChain(chain); err != nil {
		handleError(err)
	}
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
