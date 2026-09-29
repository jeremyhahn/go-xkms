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

	client "github.com/jeremyhahn/go-xkms/sdk/go"
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
			handleError(&WrappedError{Sentinel: ErrCertFileRead, Err: err})
			return
		}

		// Parse PEM block
		block, _ := pem.Decode(certPEM)
		if block == nil {
			handleError(ErrDecodePEMBlockFailed)
			return
		}

		// Parse X.509 certificate to validate it
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrParseCertificateFailed, Err: err})
			return
		}

		printVerbose("Certificate Subject: %s", cert.Subject.String())

		saveCert(cfg, printer, keyID, string(certPEM))
	},
}

// saveCert saves a certificate using the SDK client
func saveCert(cfg *Config, printer *Printer, keyID, certPEM string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	req := &client.SaveCertificateRequest{
		Backend:        cfg.Backend,
		KeyID:          keyID,
		CertificatePEM: certPEM,
	}

	if err := cl.SaveCertificate(ctx, req); err != nil {
		handleError(&WrappedError{Sentinel: ErrSaveCertificateFailed, Err: err})
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

		getCert(cfg, printer, keyID)
	},
}

// getCert retrieves a certificate using the SDK client
func getCert(cfg *Config, printer *Printer, keyID string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.GetCertificate(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetCertificateFailed, Err: err})
		return
	}

	// Parse the certificate
	block, _ := pem.Decode([]byte(resp.CertificatePEM))
	if block == nil {
		handleError(ErrDecodeCertificatePEMFailed)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrParseCertificateFailed, Err: err})
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

		deleteCert(cfg, printer, keyID)
	},
}

// deleteCert deletes a certificate using the SDK client
func deleteCert(cfg *Config, printer *Printer, keyID string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	if err := cl.DeleteCertificate(ctx, cfg.Backend, keyID); err != nil {
		handleError(&WrappedError{Sentinel: ErrDeleteCertificateFailed, Err: err})
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

		listCerts(cfg, printer)
	},
}

// listCerts lists certificates using the SDK client
func listCerts(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.ListCertificates(ctx, cfg.Backend)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListCertificatesFailed, Err: err})
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

		certExists(cfg, printer, keyID)
	},
}

// certExists checks if a certificate exists using the SDK client
func certExists(cfg *Config, printer *Printer, keyID string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	exists, err := cl.CertificateExists(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCheckCertificateExistenceFailed, Err: err})
		return
	}

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
		chainPEMs := make([]string, 0, len(certFiles))
		for i, certFile := range certFiles {
			printVerbose("Reading certificate %d from: %s", i+1, certFile)

			// Read the certificate file
			// #nosec G304 - Certificate file path from CLI argument
			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				handleError(&CertFileReadError{Path: certFile, Err: err})
				return
			}

			// Parse PEM block
			block, _ := pem.Decode(certPEM)
			if block == nil {
				handleError(&PEMBlockDecodeError{Path: certFile})
				return
			}

			// Parse X.509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				handleError(&CertFileParseError{Path: certFile, Err: err})
				return
			}

			printVerbose("Certificate %d Subject: %s", i+1, cert.Subject.String())
			chainPEMs = append(chainPEMs, string(certPEM))
		}

		saveChain(cfg, printer, keyID, chainPEMs)
	},
}

// saveChain saves a certificate chain using the SDK client
func saveChain(cfg *Config, printer *Printer, keyID string, chainPEMs []string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	req := &client.SaveCertificateChainRequest{
		Backend:  cfg.Backend,
		KeyID:    keyID,
		ChainPEM: chainPEMs,
	}

	if err := cl.SaveCertificateChain(ctx, req); err != nil {
		handleError(&WrappedError{Sentinel: ErrSaveCertificateChainFailed, Err: err})
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

		getChain(cfg, printer, keyID)
	},
}

// getChain retrieves a certificate chain using the SDK client
func getChain(cfg *Config, printer *Printer, keyID string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.GetCertificateChain(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetCertificateChainFailed, Err: err})
		return
	}

	// Parse each certificate
	chain := make([]*x509.Certificate, 0, len(resp.ChainPEM))
	for i, certPEM := range resp.ChainPEM {
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			handleError(&CertPEMDecodeError{Index: i + 1})
			return
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			handleError(&CertIndexParseError{Index: i + 1, Err: err})
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

// generateCA creates a self-signed CA certificate.
//
// Issuance itself is delegated to client.Issuer (pkg/ca.Issuer aliased
// through the SDK, per this package's rule against importing pkg/ directly):
// pkg/ca is the single implementer of certificate template construction and
// x509.CreateCertificate calls in go-xkms, and this offline, file-based CA
// command reaches it exactly like every other issuance path does, through
// the same canonical CA profile (client.NewCAProfile) that the platform root
// CA and tenant root CAs are issued with — so a change to that profile is
// observable here too.
func generateCA(cn, org, ou, country, province, locality string, validityDays int, keyAlg string, keySize int) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate key pair
	privKey, err := generateKeyPair(keyAlg, keySize)
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrKeyGenFailed, Err: err}
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, nil, &WrappedDetailError{Sentinel: ErrUnsupportedPrivateKeyType, Detail: fmt.Sprintf("%T", privKey)}
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrGenerateSerialNumberFailed, Err: err}
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

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	// A path length of 2 is this command's fixed policy for a locally
	// generated CA (matches the CLI's historical behavior); the canonical CA
	// profile treats it as a ceiling a caller may tighten but never widen.
	cert, err := (&client.Issuer{Signer: signer}).Issue(rand.Reader, &client.CertificateSpec{
		Serial:    serialNumber,
		Subject:   subject,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Profile:   client.NewCAProfile(),
		Request:   &client.TrustedCACertificateRequest{MaxPathLen: 2},
	})
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateCertificateFailed, Err: err}
	}

	return cert, privKey, nil
}

// issueCertificate creates a certificate signed by a CA.
//
// Like generateCA, issuance is delegated to client.Issuer so this command
// does not hand-roll a second x509.Certificate template and
// x509.CreateCertificate call. The profile is built with client.ProfileBuilder
// to reproduce this command's historical certificate shape exactly — in
// particular, these certificates carry no Basic Constraints extension,
// matching the CLI's long-standing (and CA/Browser-Forum-compliant) output
// for locally issued leaf certificates.
func issueCertificate(
	caCert *x509.Certificate, caKey interface{},
	cn, certType, org, ou, country, province, locality string,
	validityDays int, keyAlg string, keySize int,
	dnsNames []string, ipAddresses []net.IP, emailAddresses []string,
) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate key pair
	privKey, err := generateKeyPair(keyAlg, keySize)
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrKeyGenFailed, Err: err}
	}
	caSigner, ok := caKey.(crypto.Signer)
	if !ok {
		return nil, nil, &WrappedDetailError{Sentinel: ErrUnsupportedPrivateKeyType, Detail: fmt.Sprintf("%T", caKey)}
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrGenerateSerialNumberFailed, Err: err}
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

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	spec := &client.CertificateSpec{
		Serial:      serialNumber,
		Subject:     subject,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		PublicKey:   getPublicKey(privKey),
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	// The certificate shape comes from the canonical profiles the rest of the
	// platform issues with, not from a CLI-local copy. A near-identical local
	// profile is how the shapes drift apart: it would keep the same key usage
	// and EKU as client.NewServerProfile() until someone changed one of them,
	// and only the CLI would be left behind.
	//
	// This is a deliberate change to the CLI's output. It previously omitted
	// the Basic Constraints extension on leaf certificates; the canonical
	// profiles set it, so leaves now carry basicConstraints with cA=FALSE.
	// That is optional for end-entity certificates under RFC 5280 §4.2.1.9 and
	// under the CA/Browser Forum Baseline Requirements (which require only
	// that cA be FALSE when the extension is present), so both shapes are
	// valid; emitting it is the more explicit of the two and is what every
	// other issuance path in this project already produces.
	switch strings.ToLower(certType) {
	case "server":
		spec.Profile = client.NewServerProfile()
		// Add CN to DNS names if not already present
		if len(dnsNames) == 0 {
			spec.DNSNames = []string{cn}
		}
	case "client":
		spec.Profile = client.NewClientProfile()
		spec.EmailAddresses = emailAddresses
		if len(emailAddresses) == 0 && strings.Contains(cn, "@") {
			spec.EmailAddresses = []string{cn}
		}
	default:
		// Both server and client auth. There is no canonical dual-purpose
		// profile, so this composes one from the server profile's key usage
		// and both EKUs rather than restating them.
		serverProfile := client.NewServerProfile()
		spec.Profile = client.NewProfileBuilder("xkmsctl-server-and-client").
			WithKeyUsage(serverProfile.KeyUsage()).
			WithExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth).
			WithBasicConstraints(true).
			Build()
	}

	cert, err := (&client.Issuer{Signer: caSigner, Certificate: caCert}).Issue(rand.Reader, spec)
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateCertificateFailed, Err: err}
	}

	return cert, privKey, nil
}

// generateKeyPair generates a key pair based on the algorithm
func generateKeyPair(algorithm string, size int) (crypto.PrivateKey, error) {
	switch {
	case client.AlgorithmRSA.Equals(algorithm):
		if size < client.RSAKeySize2048 {
			size = client.RSAKeySize2048
		}
		// rsa.GenerateKey cannot be cancelled and its cost grows with the
		// cube of the modulus size, so an oversized --key-size pins this
		// CLI process's CPU core for minutes to hours; refused rather than
		// clamped, since a size this far outside the documented range
		// (2048/3072/4096) is more likely a mistake than an operator intent
		// this command should silently reinterpret (go-xkms#1260).
		if size > client.RSAKeySize4096 {
			return nil, ErrRSAKeySizeTooLarge
		}
		return rsa.GenerateKey(rand.Reader, size)
	case client.AlgorithmECDSA.Equals(algorithm) || strings.EqualFold(algorithm, "ec"):
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
	case client.AlgorithmEd25519.Equals(algorithm):
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
The CA private key and certificate will be stored in the xkms.

Example:
  xkmsctl cert generate-ca --cn "My Root CA" --org "My Company"
  xkmsctl cert generate-ca --cn "My Root CA" --output ca.crt --key-output ca.key`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		cn := fr.String("cn")
		org := fr.String("org")
		ou := fr.String("ou")
		country := fr.String("country")
		province := fr.String("province")
		locality := fr.String("locality")
		validityDays := fr.Int("validity")
		keyAlg := fr.String("key-algorithm")
		keySize := fr.Int("key-size")
		outputFile := fr.String("output")
		keyOutputFile := fr.String("key-output")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if cn == "" {
			handleError(ErrCommonNameRequired)
			return
		}

		printVerbose("Generating CA certificate for: %s", cn)

		// Generate CA using local xkms
		caCert, caKey, err := generateCA(cn, org, ou, country, province, locality, validityDays, keyAlg, keySize)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrGenerateCAFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrMarshalPrivateKeyFailed, Err: err})
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
				handleError(&WrappedError{Sentinel: ErrWriteCertificateFailed, Err: err})
				return
			}
			printVerbose("Certificate written to: %s", outputFile)
		}

		if keyOutputFile != "" {
			// #nosec G306 - Key files should be protected
			if err := os.WriteFile(keyOutputFile, keyPEM, 0600); err != nil {
				handleError(&WrappedError{Sentinel: ErrWritePrivateKeyFailed, Err: err})
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
  xkmsctl cert issue --ca-cert ca.crt --ca-key ca.key --cn server.example.com --type server

  # Issue a client certificate for mTLS
  xkmsctl cert issue --ca-cert ca.crt --ca-key ca.key --cn client@example.com --type client

  # Issue with custom SANs
  xkmsctl cert issue --ca-cert ca.crt --ca-key ca.key --cn myserver --dns "*.example.com,example.com" --ip "192.168.1.1"`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		caCertFile := fr.String("ca-cert")
		caKeyFile := fr.String("ca-key")
		cn := fr.String("cn")
		certType := fr.String("type")
		org := fr.String("org")
		ou := fr.String("ou")
		country := fr.String("country")
		province := fr.String("province")
		locality := fr.String("locality")
		validityDays := fr.Int("validity")
		keyAlg := fr.String("key-algorithm")
		keySize := fr.Int("key-size")
		dnsNames := fr.String("dns")
		ipAddrs := fr.String("ip")
		emails := fr.String("email")
		outputFile := fr.String("output")
		keyOutputFile := fr.String("key-output")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if caCertFile == "" {
			handleError(ErrCACertFileRequired)
			return
		}
		if caKeyFile == "" {
			handleError(ErrCAKeyFileRequired)
			return
		}
		if cn == "" {
			handleError(ErrCommonNameRequired)
			return
		}

		printVerbose("Issuing %s certificate for: %s", certType, cn)

		// Load CA certificate
		caCertPEM, err := os.ReadFile(caCertFile)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadCACertificateFailed, Err: err})
			return
		}
		caCertBlock, _ := pem.Decode(caCertPEM)
		if caCertBlock == nil {
			handleError(ErrDecodeCACertificatePEMFailed)
			return
		}
		caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrParseCACertificateFailed, Err: err})
			return
		}

		// Load CA private key
		caKeyPEM, err := os.ReadFile(caKeyFile)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadCAPrivateKeyFailed, Err: err})
			return
		}
		caKeyBlock, _ := pem.Decode(caKeyPEM)
		if caKeyBlock == nil {
			handleError(ErrDecodeCAPrivateKeyPEMFailed)
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
					handleError(&WrappedError{Sentinel: ErrParseCAPrivateKeyFailed, Err: err})
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
					handleError(&WrappedDetailError{Sentinel: ErrInvalidIPAddress, Detail: ipStr})
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
			handleError(&WrappedError{Sentinel: ErrIssueCertificateFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrMarshalPrivateKeyFailed, Err: err})
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
				handleError(&WrappedError{Sentinel: ErrWriteCertificateFailed, Err: err})
				return
			}
			printVerbose("Certificate written to: %s", outputFile)
		}

		if keyOutputFile != "" {
			// #nosec G306 - Key files should be protected
			if err := os.WriteFile(keyOutputFile, keyPEM, 0600); err != nil {
				handleError(&WrappedError{Sentinel: ErrWritePrivateKeyFailed, Err: err})
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
	certGenerateCACmd.Flags().String("org", "Go xKMS", "organization name")
	certGenerateCACmd.Flags().String("ou", "", "organizational unit")
	certGenerateCACmd.Flags().String("country", "", "country code (e.g., US)")
	certGenerateCACmd.Flags().String("province", "", "state/province")
	certGenerateCACmd.Flags().String("locality", "", "city/locality")
	certGenerateCACmd.Flags().Int("validity", 3650, "validity period in days (default: 10 years)")
	certGenerateCACmd.Flags().String("key-algorithm", "ecdsa", "key algorithm: rsa, ecdsa, ed25519")
	certGenerateCACmd.Flags().Int("key-size", 256, "key size (RSA: 2048/4096, ECDSA: 256/384/521)")
	certGenerateCACmd.Flags().String("output", "", "output file for certificate (PEM)")
	certGenerateCACmd.Flags().String("key-output", "", "output file for private key (PEM)")
	markFlagRequired(certGenerateCACmd, "cn")

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
	markFlagRequired(certIssueCmd, "ca-cert")
	markFlagRequired(certIssueCmd, "ca-key")
	markFlagRequired(certIssueCmd, "cn")
}
