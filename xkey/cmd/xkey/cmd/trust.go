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

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Trust command errors.
var (
	// ErrTrustStoreOpen indicates the trust store could not be opened.
	ErrTrustStoreOpen = errors.New("trust: failed to open trust store")

	// ErrTrustAddFailed indicates a certificate could not be added.
	ErrTrustAddFailed = errors.New("trust: failed to add certificate")

	// ErrTrustRemoveFailed indicates a certificate could not be removed.
	ErrTrustRemoveFailed = errors.New("trust: failed to remove certificate")

	// ErrTrustBootstrapFailed indicates the bootstrap operation failed.
	ErrTrustBootstrapFailed = errors.New("trust: bootstrap failed")

	// ErrTrustPEMFileRequired indicates a PEM file argument is required.
	ErrTrustPEMFileRequired = errors.New("trust: PEM file argument is required")

	// ErrTrustPEMReadFailed indicates the PEM file could not be read.
	ErrTrustPEMReadFailed = errors.New("trust: failed to read PEM file")

	// ErrTrustFingerprintRequired indicates a fingerprint argument is required.
	ErrTrustFingerprintRequired = errors.New("trust: fingerprint argument is required")

	// ErrTrustCertificateNotFound indicates the certificate was not found.
	ErrTrustCertificateNotFound = errors.New("trust: certificate not found")

	// ErrTrustListFailed indicates failure to list certificates.
	ErrTrustListFailed = errors.New("trust: failed to list certificates")

	// ErrTrustInvalidMethod indicates an invalid bootstrap method was specified.
	ErrTrustInvalidMethod = errors.New("trust: invalid bootstrap method")

	// ErrTrustClassifyFailed indicates a certificate reclassification failed.
	ErrTrustClassifyFailed = errors.New("trust: classify failed")

	// ErrTrustInstallFailed indicates a certificate could not be installed to the OS store.
	ErrTrustInstallFailed = errors.New("trust: failed to install certificate to OS store")

	// ErrTrustUninstallFailed indicates a certificate could not be removed from the OS store.
	ErrTrustUninstallFailed = errors.New("trust: failed to uninstall certificate from OS store")
)

// methodParser maps bootstrap method name strings to truststrap.Method values.
var methodParser = map[string]truststrap.Method{
	"dane":   truststrap.MethodDANE,
	"noise":  truststrap.MethodNoise,
	"spki":   truststrap.MethodSPKI,
	"direct": truststrap.MethodDirect,
}

// trustCmd is the parent command for trust store management.
var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Trust store management",
	Long: `Manage the xKey trust store for CA certificates.

The trust store holds CA certificates used for verifying certificate chains
during TLS connections, IDevID verification, phone attestation, and other
trust-related operations.

Certificates are stored as PEM files indexed by their SHA-256 fingerprint.

Examples:
  # List all trusted certificates
  xkey trust list

  # Add certificates from a PEM file
  xkey trust add /path/to/ca-bundle.pem

  # Add a certificate with purpose classification
  xkey trust add /path/to/tpm-ca.pem --purpose tpm-manufacturer --source "file:tpm-ca.pem"

  # Show certificate details
  xkey trust show <fingerprint>

  # Reclassify a certificate's purpose
  xkey trust classify <fingerprint> --purpose android-hardware

  # Remove a certificate
  xkey trust remove <fingerprint>

  # Bootstrap trust store from server
  xkey trust bootstrap --method dane,noise`,
}

// trustListCmd lists all trusted certificates.
var trustListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List trusted certificates",
	Long: `List all certificates in the trust store.

Displays a table with fingerprint, subject, purpose, source, algorithm, and
validity dates for each trusted certificate.

Examples:
  # List all trusted certificates
  xkey trust list`,
	RunE: runTrustList,
}

// trustAddCmd adds certificates from a PEM file.
var trustAddCmd = &cobra.Command{
	Use:   "add <pem-file>",
	Short: "Add certificates from PEM file",
	Long: `Add one or more CA certificates from a PEM-encoded file to the trust store.

The file may contain multiple PEM-encoded certificates. Certificates that
already exist in the store are silently skipped and reported separately.

Use --purpose to assign a specific purpose classification to all certificates
in the file. Use --source to record where the certificates came from.

Arguments:
  pem-file  Path to a PEM-encoded certificate file

Available purposes:
  general           Default/uncategorized
  tpm-manufacturer  TPM vendor root CA certificates
  android-hardware  Android hardware attestation root CAs
  user-ca           User-created CA certificates
  bootstrap-ca      CA certificates from bootstrap enrollment
  idevid-issuer     CA certificates that issue IDevID certificates

Examples:
  # Add a CA certificate
  xkey trust add /path/to/ca.pem

  # Add a certificate bundle with purpose
  xkey trust add /path/to/ca-bundle.pem --purpose tpm-manufacturer

  # Add with purpose and source
  xkey trust add /path/to/ca.pem --purpose user-ca --source "file:custom-ca.pem"`,
	Args: cobra.ExactArgs(1),
	RunE: runTrustAdd,
}

// trustRemoveCmd removes a certificate by fingerprint.
var trustRemoveCmd = &cobra.Command{
	Use:     "remove <fingerprint>",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a trusted certificate",
	Long: `Remove a certificate from the trust store by its SHA-256 fingerprint.

The fingerprint is a 64-character lowercase hex-encoded SHA-256 hash of the
certificate's DER encoding. Use 'xkey trust list' to find fingerprints.

Arguments:
  fingerprint  SHA-256 fingerprint of the certificate to remove

Examples:
  # Remove a certificate by fingerprint
  xkey trust remove a1b2c3d4e5f6...`,
	Args: cobra.ExactArgs(1),
	RunE: runTrustRemove,
}

// trustShowCmd shows detailed certificate information.
var trustShowCmd = &cobra.Command{
	Use:   "show <fingerprint>",
	Short: "Show certificate details",
	Long: `Show detailed information about a trusted certificate.

Displays subject, issuer, serial number, algorithm, key size or curve,
validity period, fingerprint, purpose, source, key usage, and extensions.

Arguments:
  fingerprint  SHA-256 fingerprint of the certificate to show

Examples:
  # Show certificate details
  xkey trust show a1b2c3d4e5f6...`,
	Args: cobra.ExactArgs(1),
	RunE: runTrustShow,
}

// trustBootstrapCmd bootstraps the trust store from a remote server.
var trustBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Bootstrap trust store from server",
	Long: `Bootstrap the trust store by retrieving CA certificates from a remote server.

Uses go-truststrap to fetch CA certificates using one or more bootstrap methods.
Methods are tried in priority order until one succeeds.

Available methods:
  dane    - DANE/TLSA DNS verification (strongest)
  noise   - Noise_NK protocol with pre-shared server key
  spki    - SPKI-pinned TLS with pre-shared pin hash
  direct  - Plain HTTPS using system trust store (weakest)

Configuration is read from the config file under the 'trust.bootstrap' section.
Use --method to override the method order from the command line.

Examples:
  # Bootstrap using configured method order
  xkey trust bootstrap

  # Bootstrap using only DANE
  xkey trust bootstrap --method dane

  # Bootstrap using DANE then Noise
  xkey trust bootstrap --method dane,noise

  # Bootstrap with custom timeout
  xkey trust bootstrap --timeout 30s`,
	RunE: runTrustBootstrap,
}

// trustClassifyCmd reclassifies a certificate's purpose.
var trustClassifyCmd = &cobra.Command{
	Use:   "classify <fingerprint> --purpose <purpose>",
	Short: "Reclassify a certificate's purpose",
	Long: `Change the purpose classification of a certificate in the trust store.

Available purposes:
  general           Default/uncategorized
  tpm-manufacturer  TPM vendor root CA certificates
  android-hardware  Android hardware attestation root CAs
  user-ca           User-created CA certificates
  bootstrap-ca      CA certificates from bootstrap enrollment
  idevid-issuer     CA certificates that issue IDevID certificates

Examples:
  # Classify a certificate as a TPM manufacturer CA
  xkey trust classify a1b2c3d4e5f6... --purpose tpm-manufacturer

  # Reclassify to user CA
  xkey trust classify a1b2c3d4e5f6... --purpose user-ca`,
	Args: cobra.ExactArgs(1),
	RunE: runTrustClassify,
}

// trustInstallCmd installs a certificate to the OS trust store.
var trustInstallCmd = &cobra.Command{
	Use:   "install <fingerprint>",
	Short: "Install certificate to OS trust store",
	Long: `Install a certificate from the xKey trust store into the operating system's
trust store, making it trusted system-wide.

On Linux, this writes the certificate to the distribution-specific CA certificate
directory and runs the appropriate update command:
  - Debian/Ubuntu: /usr/local/share/ca-certificates/xkey/ + update-ca-certificates
  - RHEL/Fedora:   /etc/pki/ca-trust/source/anchors/ + update-ca-trust
  - Arch Linux:    /etc/ca-certificates/trust-source/anchors/ + update-ca-trust

This command typically requires root/sudo privileges.

Arguments:
  fingerprint  SHA-256 fingerprint of the certificate to install

Examples:
  # Install a certificate to the OS trust store
  sudo xkey trust install a1b2c3d4e5f6...`,
	Args: cobra.ExactArgs(1),
	RunE: runTrustInstall,
}

// trustUninstallCmd removes a certificate from the OS trust store.
var trustUninstallCmd = &cobra.Command{
	Use:   "uninstall <fingerprint>",
	Short: "Remove certificate from OS trust store",
	Long: `Remove a certificate from the operating system's trust store.

This removes the certificate file from the OS-specific CA directory and
refreshes the system trust store. The certificate remains in xKey's
trust store but is no longer trusted system-wide.

This command typically requires root/sudo privileges.

Arguments:
  fingerprint  SHA-256 fingerprint of the certificate to uninstall

Examples:
  # Remove a certificate from the OS trust store
  sudo xkey trust uninstall a1b2c3d4e5f6...`,
	Args: cobra.ExactArgs(1),
	RunE: runTrustUninstall,
}

func init() {
	trustCmd.AddCommand(trustListCmd, trustAddCmd, trustRemoveCmd, trustShowCmd,
		trustBootstrapCmd, trustClassifyCmd, trustInstallCmd, trustUninstallCmd)

	// Add command flags
	trustAddCmd.Flags().String("purpose", "",
		"certificate purpose (general, tpm-manufacturer, android-hardware, user-ca, bootstrap-ca, idevid-issuer)")
	trustAddCmd.Flags().String("source", "",
		"source of the certificate (e.g., manual, url:..., file:...)")

	// Bootstrap flags
	trustBootstrapCmd.Flags().StringSlice("method", nil,
		"bootstrap methods to try (dane,noise,spki,direct)")
	trustBootstrapCmd.Flags().Duration("timeout", 60*time.Second,
		"overall timeout for bootstrap operation")

	// Classify flags
	trustClassifyCmd.Flags().String("purpose", "",
		"certificate purpose (required)")
	_ = trustClassifyCmd.MarkFlagRequired("purpose")

	RootCmd.AddCommand(trustCmd)
}

// openTrustStore creates a FileStore using config from viper.
// Uses trust.store_path if set, otherwise defaults to {homeDir}/.xkey/trust/.
func openTrustStore() (*truststore.FileStore, error) {
	storePath := viper.GetString("trust.store_path")
	if storePath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTrustStoreOpen, err)
		}
		storePath = filepath.Join(homeDir, ".xkey", "trust")
	}
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: storePath})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustStoreOpen, err)
	}
	return store, nil
}

// runTrustList executes the trust list command.
func runTrustList(cmd *cobra.Command, args []string) error {
	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	certs, err := store.Certificates()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustListFailed, err)
	}

	if len(certs) == 0 {
		fmt.Println("No trusted certificates found.")
		return nil
	}

	fmt.Printf("Trusted Certificates (%d):\n\n", len(certs))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "FINGERPRINT\tSUBJECT\tPURPOSE\tSOURCE\tALGORITHM\tNOT BEFORE\tNOT AFTER\n")

	for _, cert := range certs {
		fp := truststore.Fingerprint(cert)
		displayFP := fp
		if len(fp) > 16 {
			displayFP = fp[:16] + "..."
		}

		purpose := string(truststore.PurposeGeneral)
		source := ""
		meta, metaErr := store.Metadata(fp)
		if metaErr == nil && meta != nil {
			purpose = string(meta.Purpose)
			source = meta.Source
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			displayFP,
			cert.Subject.CommonName,
			purpose,
			source,
			cert.PublicKeyAlgorithm.String(),
			cert.NotBefore.Format(time.DateOnly),
			cert.NotAfter.Format(time.DateOnly),
		)
	}

	return w.Flush()
}

// runTrustAdd executes the trust add command.
func runTrustAdd(cmd *cobra.Command, args []string) error {
	pemFile := args[0]

	pemData, err := os.ReadFile(pemFile)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustPEMReadFailed, err)
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	purposeStr, _ := cmd.Flags().GetString("purpose")
	sourceStr, _ := cmd.Flags().GetString("source")

	var added int

	if purposeStr != "" || sourceStr != "" {
		var purpose truststore.CertPurpose
		if purposeStr != "" {
			var parseErr error
			purpose, parseErr = truststore.ParsePurpose(purposeStr)
			if parseErr != nil {
				return fmt.Errorf("%w: %v", ErrTrustAddFailed, parseErr)
			}
		}

		opts := &truststore.AddCertificateOptions{
			Purpose: purpose,
			Source:  sourceStr,
		}

		added, err = addPEMWithOptions(store, pemData, opts)
	} else {
		added, err = store.AddPEM(pemData)
	}

	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustAddFailed, err)
	}

	fmt.Fprintf(os.Stderr, "Importing certificates from %s\n", pemFile)
	fmt.Printf("Certificates added: %d\n", added)

	return nil
}

// addPEMWithOptions parses PEM-encoded certificate data and adds each
// certificate to the store with the specified metadata options. Certificates
// that already exist are silently skipped.
func addPEMWithOptions(store *truststore.FileStore, pemData []byte, opts *truststore.AddCertificateOptions) (int, error) {
	var added int
	rest := pemData

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return added, fmt.Errorf("%w: %v", ErrTrustAddFailed, err)
		}

		err = store.AddCertificateWithOptions(cert, opts)
		if err != nil {
			if errors.Is(err, truststore.ErrCertificateExists) {
				continue
			}
			return added, err
		}
		added++
	}

	return added, nil
}

// runTrustRemove executes the trust remove command.
func runTrustRemove(cmd *cobra.Command, args []string) error {
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	if err := store.RemoveCertificate(fingerprint); err != nil {
		if errors.Is(err, truststore.ErrCertificateNotFound) {
			return fmt.Errorf("%w: %s", ErrTrustCertificateNotFound, fingerprint)
		}
		return fmt.Errorf("%w: %v", ErrTrustRemoveFailed, err)
	}

	fmt.Printf("Certificate removed: %s\n", fingerprint)
	return nil
}

// runTrustShow executes the trust show command.
func runTrustShow(cmd *cobra.Command, args []string) error {
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	certs, err := store.Certificates()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustListFailed, err)
	}

	var cert *x509.Certificate
	for _, c := range certs {
		if truststore.Fingerprint(c) == fingerprint {
			cert = c
			break
		}
	}

	if cert == nil {
		return fmt.Errorf("%w: %s", ErrTrustCertificateNotFound, fingerprint)
	}

	fmt.Printf("Trusted Certificate Details\n")
	fmt.Printf("===========================\n\n")

	fmt.Printf("Subject:        %s\n", cert.Subject.String())
	fmt.Printf("Issuer:         %s\n", cert.Issuer.String())
	fmt.Printf("Serial Number:  %s\n", cert.SerialNumber.String())
	fmt.Printf("Algorithm:      %s\n", cert.PublicKeyAlgorithm.String())
	fmt.Printf("Key Info:       %s\n", formatPublicKeyInfo(cert))
	fmt.Printf("Signature:      %s\n", cert.SignatureAlgorithm.String())
	fmt.Printf("Not Before:     %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:      %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Fingerprint:    %s\n", fingerprint)

	meta, metaErr := store.Metadata(fingerprint)
	if metaErr == nil && meta != nil {
		fmt.Printf("Purpose:        %s\n", meta.Purpose)
		if meta.Source != "" {
			fmt.Printf("Source:         %s\n", meta.Source)
		}
		if len(meta.Tags) > 0 {
			fmt.Printf("Tags:           %s\n", strings.Join(meta.Tags, ", "))
		}
		fmt.Printf("System Install: %t\n", meta.SystemInstalled)
	}

	fmt.Printf("Is CA:          %t\n", cert.IsCA)

	if cert.KeyUsage != 0 {
		fmt.Printf("Key Usage:      %s\n", formatKeyUsage(cert.KeyUsage))
	}

	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("Ext Key Usage:  %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:      %s\n", strings.Join(cert.DNSNames, ", "))
	}

	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("Email:          %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("IP Addresses:   %s\n", strings.Join(ips, ", "))
	}

	if len(cert.URIs) > 0 {
		uris := make([]string, len(cert.URIs))
		for i, u := range cert.URIs {
			uris[i] = u.String()
		}
		fmt.Printf("URIs:           %s\n", strings.Join(uris, ", "))
	}

	return nil
}

// runTrustClassify executes the trust classify command to reclassify a
// certificate's purpose in the trust store.
func runTrustClassify(cmd *cobra.Command, args []string) error {
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))
	purposeStr, _ := cmd.Flags().GetString("purpose")
	if purposeStr == "" {
		return fmt.Errorf("%w: --purpose flag is required", ErrTrustClassifyFailed)
	}

	purpose, err := truststore.ParsePurpose(purposeStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustClassifyFailed, err)
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	if err := store.SetPurpose(fingerprint, purpose); err != nil {
		return fmt.Errorf("%w: %v", ErrTrustClassifyFailed, err)
	}

	fmt.Printf("Certificate %s classified as %s\n", fingerprint, purpose)
	return nil
}

// runTrustInstall installs a certificate from the trust store to the OS trust store.
func runTrustInstall(cmd *cobra.Command, args []string) error {
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Find the certificate in the trust store.
	certs, err := store.Certificates()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustInstallFailed, err)
	}

	var cert *x509.Certificate
	for _, c := range certs {
		if truststore.Fingerprint(c) == fingerprint {
			cert = c
			break
		}
	}
	if cert == nil {
		return fmt.Errorf("%w: %s", ErrTrustCertificateNotFound, fingerprint)
	}

	// Create the OS cert store.
	osCertStore, err := truststore.NewOSCertStore()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustInstallFailed, err)
	}

	// Use truncated fingerprint as label for the OS file.
	label := "xkey-" + fingerprint[:16]

	if err := osCertStore.Install(cert, label); err != nil {
		return fmt.Errorf("%w: %v", ErrTrustInstallFailed, err)
	}

	// Track the installation status in the trust store metadata.
	if err := store.SetSystemInstalled(fingerprint, true); err != nil {
		return fmt.Errorf("%w: failed to update metadata: %v", ErrTrustInstallFailed, err)
	}

	fmt.Printf("Certificate %s installed to OS trust store as %s\n", fingerprint, label)
	return nil
}

// runTrustUninstall removes a certificate from the OS trust store.
func runTrustUninstall(cmd *cobra.Command, args []string) error {
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Verify the certificate exists in the trust store.
	exists, err := store.Contains(fingerprint)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustUninstallFailed, err)
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrTrustCertificateNotFound, fingerprint)
	}

	// Create the OS cert store.
	osCertStore, err := truststore.NewOSCertStore()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustUninstallFailed, err)
	}

	label := "xkey-" + fingerprint[:16]

	if err := osCertStore.Remove(label); err != nil {
		return fmt.Errorf("%w: %v", ErrTrustUninstallFailed, err)
	}

	// Update the installation status in the trust store metadata.
	if err := store.SetSystemInstalled(fingerprint, false); err != nil {
		return fmt.Errorf("%w: failed to update metadata: %v", ErrTrustUninstallFailed, err)
	}

	fmt.Printf("Certificate %s removed from OS trust store\n", fingerprint)
	return nil
}

// runTrustBootstrap executes the trust bootstrap command.
func runTrustBootstrap(cmd *cobra.Command, args []string) error {
	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		timeout = 60 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	autoCfg, err := buildBootstrapConfig(cmd)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustBootstrapFailed, err)
	}

	fmt.Fprintf(os.Stderr, "Bootstrapping trust store...\n")

	resp, err := truststrap.AutoFetch(ctx, autoCfg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustBootstrapFailed, err)
	}

	if len(resp.BundlePEM) == 0 {
		fmt.Fprintf(os.Stderr, "No certificates returned from bootstrap server.\n")
		return nil
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	added, err := store.AddPEM(resp.BundlePEM)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustAddFailed, err)
	}

	fmt.Printf("Certificates imported: %d\n", added)
	return nil
}

// buildBootstrapConfig constructs an AutoConfig from viper configuration
// and command-line flags.
func buildBootstrapConfig(cmd *cobra.Command) (*truststrap.AutoConfig, error) {
	cfg := &truststrap.AutoConfig{}

	// Determine method order from flag or config.
	methods, err := cmd.Flags().GetStringSlice("method")
	if err == nil && len(methods) > 0 {
		order, parseErr := parseMethodOrder(methods)
		if parseErr != nil {
			return nil, parseErr
		}
		cfg.MethodOrder = order
	} else {
		configMethods := viper.GetStringSlice("trust.bootstrap.method_order")
		if len(configMethods) > 0 {
			order, parseErr := parseMethodOrder(configMethods)
			if parseErr != nil {
				return nil, parseErr
			}
			cfg.MethodOrder = order
		}
	}

	// Per-method timeout.
	perMethodStr := viper.GetString("trust.bootstrap.per_method_timeout")
	if perMethodStr != "" {
		d, parseErr := time.ParseDuration(perMethodStr)
		if parseErr == nil {
			cfg.PerMethodTimeout = d
		}
	}

	// DANE configuration.
	daneServerURL := viper.GetString("trust.bootstrap.dane.server_url")
	if daneServerURL != "" {
		cfg.DANE = &truststrap.DANEConfig{
			ServerURL: daneServerURL,
			Hostname:  viper.GetString("trust.bootstrap.dane.hostname"),
			DNSServer: viper.GetString("trust.bootstrap.dane.dns_server"),
		}
	}

	// Noise configuration.
	noiseServerAddr := viper.GetString("trust.bootstrap.noise.server_addr")
	if noiseServerAddr != "" {
		cfg.Noise = &truststrap.NoiseConfig{
			ServerAddr:      noiseServerAddr,
			ServerStaticKey: viper.GetString("trust.bootstrap.noise.server_key"),
		}
	}

	// SPKI configuration.
	spkiServerURL := viper.GetString("trust.bootstrap.spki.server_url")
	if spkiServerURL != "" {
		cfg.SPKI = &truststrap.SPKIConfig{
			ServerURL:     spkiServerURL,
			SPKIPinSHA256: viper.GetString("trust.bootstrap.spki.pin_sha256"),
		}
	}

	// Direct configuration.
	directServerURL := viper.GetString("trust.bootstrap.direct.server_url")
	if directServerURL != "" {
		cfg.Direct = &truststrap.DirectConfig{
			ServerURL: directServerURL,
		}
	}

	return cfg, nil
}

// parseMethodOrder converts a slice of method name strings to truststrap.Method
// values using map-based dispatch for O(1) lookup per method.
func parseMethodOrder(names []string) ([]truststrap.Method, error) {
	methods := make([]truststrap.Method, 0, len(names))
	for _, name := range names {
		m, ok := methodParser[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrTrustInvalidMethod, name)
		}
		methods = append(methods, m)
	}
	return methods, nil
}

// formatPublicKeyInfo returns a human-readable description of the certificate's
// public key, including key size for RSA or curve name for ECDSA/Ed25519.
func formatPublicKeyInfo(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", curveName(pub.Curve))
	case ed25519.PublicKey:
		return "Ed25519 256-bit"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

// curveNames maps elliptic curves to human-readable names.
var curveNames = map[elliptic.Curve]string{
	elliptic.P224(): "P-224",
	elliptic.P256(): "P-256",
	elliptic.P384(): "P-384",
	elliptic.P521(): "P-521",
}

// curveName returns a human-readable name for the given elliptic curve.
func curveName(curve elliptic.Curve) string {
	if name, ok := curveNames[curve]; ok {
		return name
	}
	return "Unknown"
}
