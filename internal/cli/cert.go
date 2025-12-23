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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/client"
	"github.com/jeremyhahn/go-keychain/pkg/types"
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

// Helper functions for certificate generation

// generateCA creates a self-signed CA certificate
func generateCA(cn, org, ou, country, province, locality string, validityDays int, keyAlg string, keySize int) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate key pair
	privKey, err := generateKeyPair(keyAlg, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Build subject
	subject := pkix.Name{
		CommonName: cn,
	}
	if org != "" {
		subject.Organization = []string{org}
	}
	if ou != "" {
		subject.OrganizationalUnit = []string{ou}
	}
	if country != "" {
		subject.Country = []string{country}
	}
	if province != "" {
		subject.Province = []string{province}
	}
	if locality != "" {
		subject.Locality = []string{locality}
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	// Get public key
	pubKey := getPublicKey(privKey)

	// Self-sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privKey, nil
}

// issueCertificate creates a certificate signed by a CA
func issueCertificate(
	caCert *x509.Certificate, caKey interface{},
	cn, certType, org, ou, country, province, locality string,
	validityDays int, keyAlg string, keySize int,
	dnsNames []string, ipAddresses []net.IP, emailAddresses []string,
) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate key pair
	privKey, err := generateKeyPair(keyAlg, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Build subject
	subject := pkix.Name{
		CommonName: cn,
	}
	if org != "" {
		subject.Organization = []string{org}
	}
	if ou != "" {
		subject.OrganizationalUnit = []string{ou}
	}
	if country != "" {
		subject.Country = []string{country}
	}
	if province != "" {
		subject.Province = []string{province}
	}
	if locality != "" {
		subject.Locality = []string{locality}
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}

	// Set extended key usage based on certificate type
	switch strings.ToLower(certType) {
	case "server":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		// Add CN to DNS names if not already present
		if len(dnsNames) == 0 {
			template.DNSNames = []string{cn}
		}
	case "client":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.EmailAddresses = emailAddresses
		if len(emailAddresses) == 0 && strings.Contains(cn, "@") {
			template.EmailAddresses = []string{cn}
		}
	default:
		// Both server and client auth
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	// Get public key
	pubKey := getPublicKey(privKey)

	// Sign the certificate with CA
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, pubKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privKey, nil
}

// generateKeyPair generates a key pair based on the algorithm
func generateKeyPair(algorithm string, size int) (crypto.PrivateKey, error) {
	switch {
	case types.AlgorithmRSA.Equals(algorithm):
		if size < types.RSAKeySize2048 {
			size = types.RSAKeySize2048
		}
		return rsa.GenerateKey(rand.Reader, size)
	case types.AlgorithmECDSA.Equals(algorithm) || strings.EqualFold(algorithm, "ec"):
		var curve elliptic.Curve
		switch size {
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case types.AlgorithmEd25519.Equals(algorithm):
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		return privKey, err
	default:
		// Default to ECDSA P-256
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

// getPublicKey extracts the public key from a private key
func getPublicKey(privKey crypto.PrivateKey) crypto.PublicKey {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}

// splitAndTrim splits a comma-separated string and trims whitespace
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// certGenerateCACmd generates a Certificate Authority
var certGenerateCACmd = &cobra.Command{
	Use:   "generate-ca",
	Short: "Generate a Certificate Authority",
	Long: `Generate a self-signed Certificate Authority (CA) certificate.

This creates a new CA that can be used to sign server and client certificates.
The CA private key and certificate will be stored in the keychain.

Example:
  keychain cert generate-ca --cn "My Root CA" --org "My Company"
  keychain cert generate-ca --cn "My Root CA" --output ca.crt --key-output ca.key`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		cn, _ := cmd.Flags().GetString("cn")
		org, _ := cmd.Flags().GetString("org")
		ou, _ := cmd.Flags().GetString("ou")
		country, _ := cmd.Flags().GetString("country")
		province, _ := cmd.Flags().GetString("province")
		locality, _ := cmd.Flags().GetString("locality")
		validityDays, _ := cmd.Flags().GetInt("validity")
		keyAlg, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		outputFile, _ := cmd.Flags().GetString("output")
		keyOutputFile, _ := cmd.Flags().GetString("key-output")

		if cn == "" {
			handleError(fmt.Errorf("common name (--cn) is required"))
			return
		}

		printVerbose("Generating CA certificate for: %s", cn)

		// Generate CA using local keychain
		caCert, caKey, err := generateCA(cn, org, ou, country, province, locality, validityDays, keyAlg, keySize)
		if err != nil {
			handleError(fmt.Errorf("failed to generate CA: %w", err))
			return
		}

		// Output certificate
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})

		// Output private key
		keyBytes, err := x509.MarshalPKCS8PrivateKey(caKey)
		if err != nil {
			handleError(fmt.Errorf("failed to marshal private key: %w", err))
			return
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})

		// Write to files if specified
		if outputFile != "" {
			// #nosec G306 - Certificate files need to be readable
			if err := os.WriteFile(outputFile, certPEM, 0644); err != nil {
				handleError(fmt.Errorf("failed to write certificate: %w", err))
				return
			}
			printVerbose("Certificate written to: %s", outputFile)
		}

		if keyOutputFile != "" {
			// #nosec G306 - Key files should be protected
			if err := os.WriteFile(keyOutputFile, keyPEM, 0600); err != nil {
				handleError(fmt.Errorf("failed to write private key: %w", err))
				return
			}
			printVerbose("Private key written to: %s", keyOutputFile)
		}

		if err := printer.PrintSuccess("CA certificate generated successfully"); err != nil {
			handleError(err)
			return
		}

		if cfg.OutputFormat == "json" {
			result := map[string]interface{}{
				"success":       true,
				"subject":       caCert.Subject.String(),
				"issuer":        caCert.Issuer.String(),
				"serial":        caCert.SerialNumber.String(),
				"not_before":    caCert.NotBefore.Format("2006-01-02T15:04:05Z07:00"),
				"not_after":     caCert.NotAfter.Format("2006-01-02T15:04:05Z07:00"),
				"is_ca":         caCert.IsCA,
				"key_algorithm": keyAlg,
			}
			if outputFile != "" {
				result["cert_file"] = outputFile
			}
			if keyOutputFile != "" {
				result["key_file"] = keyOutputFile
			}
			if outputFile == "" {
				result["certificate"] = string(certPEM)
			}
			if keyOutputFile == "" {
				result["private_key"] = string(keyPEM)
			}
			if err := printer.PrintJSON(result); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("\nCA Certificate Details:\n")
			fmt.Printf("  Subject: %s\n", caCert.Subject.String())
			fmt.Printf("  Serial: %s\n", caCert.SerialNumber.String())
			fmt.Printf("  Valid From: %s\n", caCert.NotBefore.Format("2006-01-02"))
			fmt.Printf("  Valid Until: %s\n", caCert.NotAfter.Format("2006-01-02"))
			fmt.Printf("  Is CA: %t\n", caCert.IsCA)

			if outputFile == "" {
				fmt.Printf("\n--- CA Certificate (PEM) ---\n%s", string(certPEM))
			} else {
				fmt.Printf("\n  Certificate: %s\n", outputFile)
			}

			if keyOutputFile == "" {
				fmt.Printf("\n--- CA Private Key (PEM) ---\n%s", string(keyPEM))
				fmt.Printf("\nWARNING: Keep this private key secure!\n")
			} else {
				fmt.Printf("  Private Key: %s\n", keyOutputFile)
			}
		}
	},
}

// certIssueCmd issues a certificate signed by a CA
var certIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a certificate signed by a CA",
	Long: `Issue a new certificate signed by an existing CA.

This creates a server or client certificate signed by the specified CA.
You must provide the CA certificate and private key.

Examples:
  # Issue a server certificate
  keychain cert issue --ca-cert ca.crt --ca-key ca.key --cn server.example.com --type server

  # Issue a client certificate for mTLS
  keychain cert issue --ca-cert ca.crt --ca-key ca.key --cn client@example.com --type client

  # Issue with custom SANs
  keychain cert issue --ca-cert ca.crt --ca-key ca.key --cn myserver --dns "*.example.com,example.com" --ip "192.168.1.1"`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		caCertFile, _ := cmd.Flags().GetString("ca-cert")
		caKeyFile, _ := cmd.Flags().GetString("ca-key")
		cn, _ := cmd.Flags().GetString("cn")
		certType, _ := cmd.Flags().GetString("type")
		org, _ := cmd.Flags().GetString("org")
		ou, _ := cmd.Flags().GetString("ou")
		country, _ := cmd.Flags().GetString("country")
		province, _ := cmd.Flags().GetString("province")
		locality, _ := cmd.Flags().GetString("locality")
		validityDays, _ := cmd.Flags().GetInt("validity")
		keyAlg, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		dnsNames, _ := cmd.Flags().GetString("dns")
		ipAddrs, _ := cmd.Flags().GetString("ip")
		emails, _ := cmd.Flags().GetString("email")
		outputFile, _ := cmd.Flags().GetString("output")
		keyOutputFile, _ := cmd.Flags().GetString("key-output")

		if caCertFile == "" {
			handleError(fmt.Errorf("CA certificate file (--ca-cert) is required"))
			return
		}
		if caKeyFile == "" {
			handleError(fmt.Errorf("CA private key file (--ca-key) is required"))
			return
		}
		if cn == "" {
			handleError(fmt.Errorf("common name (--cn) is required"))
			return
		}

		printVerbose("Issuing %s certificate for: %s", certType, cn)

		// Load CA certificate
		caCertPEM, err := os.ReadFile(caCertFile)
		if err != nil {
			handleError(fmt.Errorf("failed to read CA certificate: %w", err))
			return
		}
		caCertBlock, _ := pem.Decode(caCertPEM)
		if caCertBlock == nil {
			handleError(fmt.Errorf("failed to decode CA certificate PEM"))
			return
		}
		caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
		if err != nil {
			handleError(fmt.Errorf("failed to parse CA certificate: %w", err))
			return
		}

		// Load CA private key
		caKeyPEM, err := os.ReadFile(caKeyFile)
		if err != nil {
			handleError(fmt.Errorf("failed to read CA private key: %w", err))
			return
		}
		caKeyBlock, _ := pem.Decode(caKeyPEM)
		if caKeyBlock == nil {
			handleError(fmt.Errorf("failed to decode CA private key PEM"))
			return
		}
		caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			// Try PKCS1 for RSA keys
			caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
			if err != nil {
				// Try EC private key
				caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
				if err != nil {
					handleError(fmt.Errorf("failed to parse CA private key: %w", err))
					return
				}
			}
		}

		// Parse SANs
		var dnsList []string
		if dnsNames != "" {
			dnsList = append(dnsList, splitAndTrim(dnsNames)...)
		}

		var ipList []net.IP
		if ipAddrs != "" {
			for _, ipStr := range splitAndTrim(ipAddrs) {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					handleError(fmt.Errorf("invalid IP address: %s", ipStr))
					return
				}
				ipList = append(ipList, ip)
			}
		}

		var emailList []string
		if emails != "" {
			emailList = splitAndTrim(emails)
		}

		// Issue certificate
		cert, key, err := issueCertificate(
			caCert, caKey,
			cn, certType, org, ou, country, province, locality,
			validityDays, keyAlg, keySize,
			dnsList, ipList, emailList,
		)
		if err != nil {
			handleError(fmt.Errorf("failed to issue certificate: %w", err))
			return
		}

		// Output certificate
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		// Output private key
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			handleError(fmt.Errorf("failed to marshal private key: %w", err))
			return
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})

		// Write to files if specified
		if outputFile != "" {
			// #nosec G306 - Certificate files need to be readable
			if err := os.WriteFile(outputFile, certPEM, 0644); err != nil {
				handleError(fmt.Errorf("failed to write certificate: %w", err))
				return
			}
			printVerbose("Certificate written to: %s", outputFile)
		}

		if keyOutputFile != "" {
			// #nosec G306 - Key files should be protected
			if err := os.WriteFile(keyOutputFile, keyPEM, 0600); err != nil {
				handleError(fmt.Errorf("failed to write private key: %w", err))
				return
			}
			printVerbose("Private key written to: %s", keyOutputFile)
		}

		if err := printer.PrintSuccess(fmt.Sprintf("%s certificate issued successfully", certType)); err != nil {
			handleError(err)
			return
		}

		if cfg.OutputFormat == "json" {
			result := map[string]interface{}{
				"success":       true,
				"type":          certType,
				"subject":       cert.Subject.String(),
				"issuer":        cert.Issuer.String(),
				"serial":        cert.SerialNumber.String(),
				"not_before":    cert.NotBefore.Format("2006-01-02T15:04:05Z07:00"),
				"not_after":     cert.NotAfter.Format("2006-01-02T15:04:05Z07:00"),
				"key_algorithm": keyAlg,
			}
			if len(cert.DNSNames) > 0 {
				result["dns_names"] = cert.DNSNames
			}
			if len(cert.IPAddresses) > 0 {
				ips := make([]string, len(cert.IPAddresses))
				for i, ip := range cert.IPAddresses {
					ips[i] = ip.String()
				}
				result["ip_addresses"] = ips
			}
			if len(cert.EmailAddresses) > 0 {
				result["email_addresses"] = cert.EmailAddresses
			}
			if outputFile != "" {
				result["cert_file"] = outputFile
			}
			if keyOutputFile != "" {
				result["key_file"] = keyOutputFile
			}
			if outputFile == "" {
				result["certificate"] = string(certPEM)
			}
			if keyOutputFile == "" {
				result["private_key"] = string(keyPEM)
			}
			if err := printer.PrintJSON(result); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("\nCertificate Details:\n")
			fmt.Printf("  Type: %s\n", certType)
			fmt.Printf("  Subject: %s\n", cert.Subject.String())
			fmt.Printf("  Issuer: %s\n", cert.Issuer.String())
			fmt.Printf("  Serial: %s\n", cert.SerialNumber.String())
			fmt.Printf("  Valid From: %s\n", cert.NotBefore.Format("2006-01-02"))
			fmt.Printf("  Valid Until: %s\n", cert.NotAfter.Format("2006-01-02"))
			if len(cert.DNSNames) > 0 {
				fmt.Printf("  DNS Names: %v\n", cert.DNSNames)
			}
			if len(cert.IPAddresses) > 0 {
				fmt.Printf("  IP Addresses: %v\n", cert.IPAddresses)
			}
			if len(cert.EmailAddresses) > 0 {
				fmt.Printf("  Email Addresses: %v\n", cert.EmailAddresses)
			}

			if outputFile == "" {
				fmt.Printf("\n--- Certificate (PEM) ---\n%s", string(certPEM))
			} else {
				fmt.Printf("\n  Certificate: %s\n", outputFile)
			}

			if keyOutputFile == "" {
				fmt.Printf("\n--- Private Key (PEM) ---\n%s", string(keyPEM))
				fmt.Printf("\nWARNING: Keep this private key secure!\n")
			} else {
				fmt.Printf("  Private Key: %s\n", keyOutputFile)
			}
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
	certCmd.AddCommand(certGenerateCACmd)
	certCmd.AddCommand(certIssueCmd)

	// generate-ca flags
	certGenerateCACmd.Flags().String("cn", "", "common name for the CA (required)")
	certGenerateCACmd.Flags().String("org", "Go Keychain", "organization name")
	certGenerateCACmd.Flags().String("ou", "", "organizational unit")
	certGenerateCACmd.Flags().String("country", "", "country code (e.g., US)")
	certGenerateCACmd.Flags().String("province", "", "state/province")
	certGenerateCACmd.Flags().String("locality", "", "city/locality")
	certGenerateCACmd.Flags().Int("validity", 3650, "validity period in days (default: 10 years)")
	certGenerateCACmd.Flags().String("key-algorithm", "ecdsa", "key algorithm: rsa, ecdsa, ed25519")
	certGenerateCACmd.Flags().Int("key-size", 256, "key size (RSA: 2048/4096, ECDSA: 256/384/521)")
	certGenerateCACmd.Flags().String("output", "", "output file for certificate (PEM)")
	certGenerateCACmd.Flags().String("key-output", "", "output file for private key (PEM)")
	_ = certGenerateCACmd.MarkFlagRequired("cn")

	// issue flags
	certIssueCmd.Flags().String("ca-cert", "", "CA certificate file (PEM)")
	certIssueCmd.Flags().String("ca-key", "", "CA private key file (PEM)")
	certIssueCmd.Flags().String("cn", "", "common name for the certificate (required)")
	certIssueCmd.Flags().String("type", "server", "certificate type: server, client")
	certIssueCmd.Flags().String("org", "", "organization name")
	certIssueCmd.Flags().String("ou", "", "organizational unit")
	certIssueCmd.Flags().String("country", "", "country code (e.g., US)")
	certIssueCmd.Flags().String("province", "", "state/province")
	certIssueCmd.Flags().String("locality", "", "city/locality")
	certIssueCmd.Flags().Int("validity", 365, "validity period in days (default: 1 year)")
	certIssueCmd.Flags().String("key-algorithm", "ecdsa", "key algorithm: rsa, ecdsa, ed25519")
	certIssueCmd.Flags().Int("key-size", 256, "key size (RSA: 2048/4096, ECDSA: 256/384/521)")
	certIssueCmd.Flags().String("dns", "", "DNS names (comma-separated)")
	certIssueCmd.Flags().String("ip", "", "IP addresses (comma-separated)")
	certIssueCmd.Flags().String("email", "", "email addresses (comma-separated)")
	certIssueCmd.Flags().String("output", "", "output file for certificate (PEM)")
	certIssueCmd.Flags().String("key-output", "", "output file for private key (PEM)")
	_ = certIssueCmd.MarkFlagRequired("ca-cert")
	_ = certIssueCmd.MarkFlagRequired("ca-key")
	_ = certIssueCmd.MarkFlagRequired("cn")
}
