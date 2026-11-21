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
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
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

	// ErrTrustNoCertificates indicates a PEM file yielded no certificates at
	// all. It separates a parse failure or an empty file from an import whose
	// certificates were simply already present.
	ErrTrustNoCertificates = errors.New("trust: no certificates found in the PEM file")

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

// methodParser maps bootstrap method name strings to bootstrap.Mode values.
var methodParser = map[string]bootstrap.Mode{
	"dane":   bootstrap.ModeDANE,
	"noise":  bootstrap.ModeNoise,
	"spki":   bootstrap.ModeSPKI,
	"direct": bootstrap.ModeDirect,
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
validity dates for each trusted certificate. --purpose lists only the
certificates of one purpose; a certificate with no metadata counts as general.

Examples:
  # List all trusted certificates
  xkey trust list

  # List only TPM manufacturer roots
  xkey trust list --purpose tpm-manufacturer`,
	RunE: runTrustList,
}

// trustAddCmd adds certificates from a PEM file.
var trustAddCmd = &cobra.Command{
	Use:   "add <pem-file>",
	Short: "Add certificates from PEM file",
	Long: `Add one or more CA certificates from a PEM-encoded file to the trust store.

The file may contain multiple PEM-encoded certificates. Certificates that
already exist in the store are skipped and reported as a separate count, so a
zero added count is never confused with a parse failure or an empty file. A
file that yields no certificates at all is an error.

Use --purpose to assign a specific purpose classification to all certificates
in the file. Use --source to record where the certificates came from.

In server mode (an xkmsd endpoint is configured) the certificates are imported
into the server's trust-root store; the local store is not touched.

Arguments:
  pem-file  Path to a PEM-encoded certificate file

Available purposes:
  general           Default/uncategorized
  tpm-manufacturer  TPM vendor root CA certificates
  android-hardware  Android hardware attestation root CAs
  user-ca           User-created CA certificates
  bootstrap-ca      CA certificates from bootstrap enrollment
  idevid-issuer     CA certificates that issue IDevID certificates
  synced            Received from a paired device by sync; anchors nothing

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

In server mode (an xkmsd endpoint is configured) the certificate is removed
from the server's trust-root store; the local store is not touched.

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

With an xkmsd endpoint configured, the fetched bundle is imported into the
server's trust-root store (purpose bootstrap-ca, source platform:<host>)
and no local trust store is written.

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
  synced            Received from a paired device by sync; anchors nothing

With an xkmsd endpoint configured, classify changes the server's trust-root
store, never the local one. The server reclassifies a root only to synced
(quarantine), so --purpose synced is the only purpose accepted there; to give
a server root another purpose, remove it and add it again with --purpose.

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

With an xkmsd endpoint configured, the certificate is fetched from the
server's trust-root store (TrustRootGet), its fingerprint is checked against
the one given, and it is installed into the OS trust store; the local xKey
trust store is neither opened nor written.

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

With an xkmsd endpoint configured, only the OS trust store entry is removed:
neither the server nor the local xKey trust store is read, so a root the
server no longer holds can still be removed from the host.

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
	trustListCmd.Flags().String("purpose", "",
		"List only certificates of this purpose (general, tpm-manufacturer, android-hardware, user-ca, bootstrap-ca, idevid-issuer, image-signer, synced)")
	trustAddCmd.Flags().String("purpose", "",
		"certificate purpose (general, tpm-manufacturer, android-hardware, user-ca, bootstrap-ca, idevid-issuer, synced)")
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

// trustDataSubdir is the trust store directory beneath the xKey data
// directory, the same <dataDir>/trust the GUI opens.
const trustDataSubdir = "trust"

// trustStoreDir resolves the trust store directory. An explicit
// trust.store_path config value wins; otherwise the store lives at
// <dataDir>/trust with the data directory resolved through the CLI's
// single chain (featureDataDir), so XKEY_HOME, portable mode,
// XKEY_DATA_DIR and `data_dir` all apply. Every opener of the store —
// openTrustStore and the browser launcher — resolves through here so the
// path is spelled exactly once.
func trustStoreDir() (string, error) {
	if storePath := viper.GetString("trust.store_path"); storePath != "" {
		return storePath, nil
	}
	return featureDataDir(trustDataSubdir)
}

// openTrustStore creates a FileStore at the directory trustStoreDir
// resolves. The store constructor creates the directory on open for every
// caller, so read and write commands share this one creating opener.
func openTrustStore() (*truststore.FileStore, error) {
	storePath, err := trustStoreDir()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTrustStoreOpen, Cause: err}
	}
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: storePath})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrTrustStoreOpen, Cause: err}
	}
	return store, nil
}

// runTrustList executes the trust list command.
func runTrustList(cmd *cobra.Command, args []string) (err error) {
	// The filter is validated before either path so a typo never reaches
	// the server or reads as an empty store.
	purposeFilter, _ := cmd.Flags().GetString("purpose")
	if purposeFilter != "" {
		if _, parseErr := truststore.ParsePurpose(purposeFilter); parseErr != nil {
			return &SentinelCauseError{Sentinel: ErrTrustListFailed, Cause: parseErr}
		}
	}
	if resolveXKMSdURL() != "" {
		return runTrustListXKMSd(cmd, purposeFilter)
	}
	out := cmd.OutOrStdout()
	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	certs, err := store.Certificates()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustListFailed, Cause: err}
	}

	type listedCert struct {
		cert    *x509.Certificate
		fp      string
		purpose string
		source  string
	}
	listed := make([]listedCert, 0, len(certs))
	for _, cert := range certs {
		fp := truststore.Fingerprint(cert)
		purpose := string(truststore.PurposeGeneral)
		source := ""
		meta, metaErr := store.Metadata(fp)
		if metaErr == nil && meta != nil {
			purpose = string(meta.Purpose)
			source = meta.Source
		}
		if purposeFilter != "" && purpose != purposeFilter {
			continue
		}
		listed = append(listed, listedCert{cert: cert, fp: fp, purpose: purpose, source: source})
	}

	if len(listed) == 0 {
		_, _ = fmt.Fprintln(out, "No trusted certificates found.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Trusted Certificates (%d):\n\n", len(listed))

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "FINGERPRINT\tSUBJECT\tPURPOSE\tSOURCE\tALGORITHM\tNOT BEFORE\tNOT AFTER\n")

	for _, row := range listed {
		displayFP := row.fp
		if len(displayFP) > 16 {
			displayFP = displayFP[:16] + "..."
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			displayFP,
			row.cert.Subject.CommonName,
			row.purpose,
			row.source,
			row.cert.PublicKeyAlgorithm.String(),
			row.cert.NotBefore.Format(time.DateOnly),
			row.cert.NotAfter.Format(time.DateOnly),
		)
	}

	return w.Flush()
}

// runTrustAdd executes the trust add command.
func runTrustAdd(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	pemFile := args[0]

	pemData, err := os.ReadFile(pemFile)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustPEMReadFailed, Cause: err}
	}

	purposeStr, _ := cmd.Flags().GetString("purpose")
	sourceStr, _ := cmd.Flags().GetString("source")

	var purpose truststore.CertPurpose
	if purposeStr != "" {
		var parseErr error
		purpose, parseErr = truststore.ParsePurpose(purposeStr)
		if parseErr != nil {
			return &SentinelCauseError{Sentinel: ErrTrustAddFailed, Cause: parseErr}
		}
	}

	if resolveXKMSdURL() != "" {
		return runTrustAddXKMSd(cmd, pemFile, pemData, purposeStr, sourceStr)
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	var opts *truststore.AddCertificateOptions
	if purposeStr != "" || sourceStr != "" {
		opts = &truststore.AddCertificateOptions{
			Purpose: purpose,
			Source:  sourceStr,
		}
	}

	result, err := store.ImportPEM(pemData, opts)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustAddFailed, Cause: err}
	}
	if result.Added == 0 && result.Skipped == 0 {
		return &SentinelCauseError{Sentinel: ErrTrustAddFailed, Cause: ErrTrustNoCertificates}
	}

	fmt.Fprintf(os.Stderr, "Importing certificates from %s\n", pemFile)
	_, _ = fmt.Fprintf(out, "Certificates added: %d\n", result.Added)
	// A bare "added: 0" is indistinguishable from a parse failure, an empty
	// file, or a permissions problem. Reporting the skips tells the operator
	// the certificates were already there, as trust add --help promises.
	if result.Skipped > 0 {
		_, _ = fmt.Fprintf(out, "Certificates skipped (already present): %d\n", result.Skipped)
	}

	return nil
}

// runTrustRemove executes the trust remove command.
func runTrustRemove(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))

	if resolveXKMSdURL() != "" {
		return runTrustRemoveXKMSd(cmd, fingerprint)
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if err := store.RemoveCertificate(fingerprint); err != nil {
		if errors.Is(err, truststore.ErrCertificateNotFound) {
			return &DetailError{Err: ErrTrustCertificateNotFound, Detail: fmt.Sprintf(": %s", fingerprint)}
		}
		return &SentinelCauseError{Sentinel: ErrTrustRemoveFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Certificate removed: %s\n", fingerprint)
	return nil
}

// runTrustShow executes the trust show command.
func runTrustShow(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))
	if resolveXKMSdURL() != "" {
		return runTrustShowXKMSd(cmd, fingerprint)
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	certs, err := store.Certificates()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustListFailed, Cause: err}
	}

	var cert *x509.Certificate
	for _, c := range certs {
		if truststore.Fingerprint(c) == fingerprint {
			cert = c
			break
		}
	}

	if cert == nil {
		return &DetailError{Err: ErrTrustCertificateNotFound, Detail: fmt.Sprintf(": %s", fingerprint)}
	}

	_, _ = fmt.Fprintf(out, "Trusted Certificate Details\n")
	_, _ = fmt.Fprintf(out, "===========================\n\n")

	_, _ = fmt.Fprintf(out, "Subject:        %s\n", cert.Subject.String())
	_, _ = fmt.Fprintf(out, "Issuer:         %s\n", cert.Issuer.String())
	_, _ = fmt.Fprintf(out, "Serial Number:  %s\n", cert.SerialNumber.String())
	_, _ = fmt.Fprintf(out, "Algorithm:      %s\n", cert.PublicKeyAlgorithm.String())
	_, _ = fmt.Fprintf(out, "Key Info:       %s\n", formatPublicKeyInfo(cert))
	_, _ = fmt.Fprintf(out, "Signature:      %s\n", cert.SignatureAlgorithm.String())
	_, _ = fmt.Fprintf(out, "Not Before:     %s\n", cert.NotBefore.Format(time.RFC3339))
	_, _ = fmt.Fprintf(out, "Not After:      %s\n", cert.NotAfter.Format(time.RFC3339))
	_, _ = fmt.Fprintf(out, "Fingerprint:    %s\n", fingerprint)

	meta, metaErr := store.Metadata(fingerprint)
	if metaErr == nil && meta != nil {
		_, _ = fmt.Fprintf(out, "Purpose:        %s\n", meta.Purpose)
		if meta.Source != "" {
			_, _ = fmt.Fprintf(out, "Source:         %s\n", meta.Source)
		}
		if len(meta.Tags) > 0 {
			_, _ = fmt.Fprintf(out, "Tags:           %s\n", strings.Join(meta.Tags, ", "))
		}
		_, _ = fmt.Fprintf(out, "System Install: %t\n", meta.SystemInstalled)
	}

	_, _ = fmt.Fprintf(out, "Is CA:          %t\n", cert.IsCA)

	if cert.KeyUsage != 0 {
		_, _ = fmt.Fprintf(out, "Key Usage:      %s\n", formatKeyUsage(cert.KeyUsage))
	}

	if len(cert.ExtKeyUsage) > 0 {
		_, _ = fmt.Fprintf(out, "Ext Key Usage:  %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	if len(cert.DNSNames) > 0 {
		_, _ = fmt.Fprintf(out, "DNS Names:      %s\n", strings.Join(cert.DNSNames, ", "))
	}

	if len(cert.EmailAddresses) > 0 {
		_, _ = fmt.Fprintf(out, "Email:          %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		_, _ = fmt.Fprintf(out, "IP Addresses:   %s\n", strings.Join(ips, ", "))
	}

	if len(cert.URIs) > 0 {
		uris := make([]string, len(cert.URIs))
		for i, u := range cert.URIs {
			uris[i] = u.String()
		}
		_, _ = fmt.Fprintf(out, "URIs:           %s\n", strings.Join(uris, ", "))
	}

	return nil
}

// trustCommandContext returns the command's context, or a background context
// when the command runs outside Execute.
func trustCommandContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// trustRootDate formats an RFC 3339 timestamp from the server as a date,
// keeping the raw value when it does not parse.
func trustRootDate(value string) string {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return parsed.Format(time.DateOnly)
}

// runTrustListXKMSd lists the server's trust roots through TrustRootList.
// A server error is returned; the local store is never read instead.
func runTrustListXKMSd(cmd *cobra.Command, purpose string) (err error) {
	client, err := connectXKMSdClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	resp, err := client.TrustRootList(trustCommandContext(cmd), &transport.TrustRootListRequest{Purpose: purpose})
	if err != nil {
		return fmt.Errorf("TrustRootList: %w", err)
	}

	out := cmd.OutOrStdout()
	if len(resp.Roots) == 0 {
		_, _ = fmt.Fprintln(out, "No trusted certificates found.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Trusted Certificates (%d):\n\n", len(resp.Roots))

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(w, "FINGERPRINT\tSUBJECT\tPURPOSE\tSOURCE\tALGORITHM\tNOT BEFORE\tNOT AFTER\n")
	for _, root := range resp.Roots {
		displayFP := root.Fingerprint
		if len(displayFP) > 16 {
			displayFP = displayFP[:16] + "..."
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			displayFP,
			root.Subject,
			root.Purpose,
			root.Source,
			root.Algorithm,
			trustRootDate(root.NotBefore),
			trustRootDate(root.NotAfter),
		)
	}
	return w.Flush()
}

// runTrustShowXKMSd prints one of the server's trust roots through
// TrustRootGet. A server error is returned; the local store is never read
// instead.
func runTrustShowXKMSd(cmd *cobra.Command, fingerprint string) (err error) {
	client, err := connectXKMSdClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	root, err := client.TrustRootGet(trustCommandContext(cmd), &transport.TrustRootRequest{Fingerprint: fingerprint})
	if err != nil {
		return fmt.Errorf("TrustRootGet: %w", err)
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Trusted Certificate Details\n")
	_, _ = fmt.Fprintf(out, "===========================\n\n")
	_, _ = fmt.Fprintf(out, "Subject:        %s\n", root.Subject)
	_, _ = fmt.Fprintf(out, "Issuer:         %s\n", root.Issuer)
	_, _ = fmt.Fprintf(out, "Algorithm:      %s\n", root.Algorithm)
	_, _ = fmt.Fprintf(out, "Not Before:     %s\n", root.NotBefore)
	_, _ = fmt.Fprintf(out, "Not After:      %s\n", root.NotAfter)
	_, _ = fmt.Fprintf(out, "Fingerprint:    %s\n", root.Fingerprint)
	_, _ = fmt.Fprintf(out, "Purpose:        %s\n", root.Purpose)
	if root.Source != "" {
		_, _ = fmt.Fprintf(out, "Source:         %s\n", root.Source)
	}
	if root.AddedAt != "" {
		_, _ = fmt.Fprintf(out, "Added At:       %s\n", root.AddedAt)
	}
	return nil
}

// runTrustAddXKMSd imports the PEM roots into the server's trust-root store.
// An empty purpose lets the server classify each certificate. It never
// falls back to the local store.
func runTrustAddXKMSd(cmd *cobra.Command, pemFile string, pemData []byte, purpose, source string) (err error) {
	client, err := connectXKMSdClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	resp, err := client.TrustRootImport(trustCommandContext(cmd), &transport.TrustRootImportRequest{
		PEM:     string(pemData),
		Purpose: purpose,
		Source:  source,
	})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustAddFailed, Cause: fmt.Errorf("TrustRootImport: %w", err)}
	}
	if resp.Added == 0 && resp.Skipped == 0 {
		return &SentinelCauseError{Sentinel: ErrTrustAddFailed, Cause: ErrTrustNoCertificates}
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(os.Stderr, "Importing certificates from %s\n", pemFile)
	_, _ = fmt.Fprintf(out, "Certificates added: %d\n", resp.Added)
	if resp.Skipped > 0 {
		_, _ = fmt.Fprintf(out, "Certificates skipped (already present): %d\n", resp.Skipped)
	}
	return nil
}

// importTrustCertsXKMSd imports fetched certificates into the xkmsd
// trust-root store (docs/SPEC.md trust-roots: against a server xkey uses
// the server's store) and returns the server's added/skipped counts. It
// never opens the local FileStore.
func importTrustCertsXKMSd(cmd *cobra.Command, certs []*x509.Certificate, purpose, source string) (added, skipped int, err error) {
	var pemData []byte
	for _, cert := range certs {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}

	client, err := connectXKMSdClient(cmd)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	resp, err := client.TrustRootImport(trustCommandContext(cmd), &transport.TrustRootImportRequest{
		PEM:     string(pemData),
		Purpose: purpose,
		Source:  source,
	})
	if err != nil {
		return 0, 0, fmt.Errorf("TrustRootImport: %w", err)
	}
	return int(resp.Added), int(resp.Skipped), nil
}

// runTrustRemoveXKMSd deletes a root from the server's trust-root store. It
// never falls back to the local store.
func runTrustRemoveXKMSd(cmd *cobra.Command, fingerprint string) (err error) {
	client, err := connectXKMSdClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if err := client.TrustRootRemove(trustCommandContext(cmd), &transport.TrustRootRequest{Fingerprint: fingerprint}); err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustRemoveFailed, Cause: fmt.Errorf("TrustRootRemove: %w", err)}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate removed: %s\n", fingerprint)
	return nil
}

// runTrustClassifyXKMSd reclassifies a root in the xkmsd trust-root store.
// The server offers one reclassification, quarantine to synced; any other
// purpose is refused without a call and without touching the local store.
func runTrustClassifyXKMSd(cmd *cobra.Command, fingerprint string, purpose truststore.CertPurpose) (err error) {
	if purpose != truststore.PurposeSynced {
		return &DetailError{
			Err: ErrTrustClassifyFailed,
			Detail: fmt.Sprintf(": xkmsd reclassifies a root only to %s, by quarantine; to make it %s, remove it and add it again with --purpose %s",
				truststore.PurposeSynced, purpose, purpose),
		}
	}

	client, err := connectXKMSdClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	root, err := client.TrustRootQuarantine(trustCommandContext(cmd), &transport.TrustRootRequest{Fingerprint: fingerprint})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustClassifyFailed, Cause: fmt.Errorf("TrustRootQuarantine: %w", err)}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate %s classified as %s\n", fingerprint, root.Purpose)
	return nil
}

// osTrustLabel is the OS trust store label of a root: "xkey-" and the first
// 16 hex digits of its fingerprint.
func osTrustLabel(fingerprint string) string {
	if len(fingerprint) > 16 {
		fingerprint = fingerprint[:16]
	}
	return "xkey-" + fingerprint
}

// runTrustInstallXKMSd installs a root of the xkmsd trust-root store into
// the OS trust store. The certificate comes from TrustRootGet and must carry
// the requested fingerprint; the local store is neither opened nor written.
func runTrustInstallXKMSd(cmd *cobra.Command, fingerprint string) (err error) {
	client, err := connectXKMSdClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	root, err := client.TrustRootGet(trustCommandContext(cmd), &transport.TrustRootRequest{Fingerprint: fingerprint})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustInstallFailed, Cause: fmt.Errorf("TrustRootGet: %w", err)}
	}

	block, _ := pem.Decode([]byte(root.PEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return &DetailError{Err: ErrTrustInstallFailed, Detail: fmt.Sprintf(": server root %s has no CERTIFICATE PEM block", fingerprint)}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &DetailError{Err: ErrTrustInstallFailed, Detail: fmt.Sprintf(": server root %s: %v", fingerprint, err)}
	}
	if got := truststore.Fingerprint(cert); got != fingerprint {
		return &DetailError{Err: ErrTrustInstallFailed, Detail: fmt.Sprintf(": server returned certificate %s for %s", got, fingerprint)}
	}

	osCertStore, err := newOSCertStore()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustInstallFailed, Cause: err}
	}
	label := osTrustLabel(fingerprint)
	if err := osCertStore.Install(cert, label); err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustInstallFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate %s installed to OS trust store as %s\n", fingerprint, label)
	return nil
}

// runTrustUninstallXKMSd removes a root's OS trust store entry in server
// mode. It reads neither the server nor the local store, so a root the
// server no longer holds can still be removed from the host.
func runTrustUninstallXKMSd(cmd *cobra.Command, fingerprint string) error {
	osCertStore, err := newOSCertStore()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustUninstallFailed, Cause: err}
	}
	if err := osCertStore.Remove(osTrustLabel(fingerprint)); err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustUninstallFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Certificate %s removed from OS trust store\n", fingerprint)
	return nil
}

// runTrustClassify executes the trust classify command to reclassify a
// certificate's purpose in the trust store.
func runTrustClassify(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))
	purposeStr, _ := cmd.Flags().GetString("purpose")
	if purposeStr == "" {
		return &DetailError{Err: ErrTrustClassifyFailed, Detail: ": --purpose flag is required"}
	}

	purpose, err := truststore.ParsePurpose(purposeStr)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustClassifyFailed, Cause: err}
	}

	if resolveXKMSdURL() != "" {
		return runTrustClassifyXKMSd(cmd, fingerprint, purpose)
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if err := store.SetPurpose(fingerprint, purpose); err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustClassifyFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Certificate %s classified as %s\n", fingerprint, purpose)
	return nil
}

// runTrustInstall installs a certificate from the trust store to the OS trust store.
// newOSCertStore opens the operating system's certificate trust store for
// trust install, uninstall and fetch --install-system. Tests replace it so
// the flows run without root or a system store refresh.
var newOSCertStore = truststore.NewOSCertStore

func runTrustInstall(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))
	if resolveXKMSdURL() != "" {
		return runTrustInstallXKMSd(cmd, fingerprint)
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Find the certificate in the trust store.
	certs, err := store.Certificates()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustInstallFailed, Cause: err}
	}

	var cert *x509.Certificate
	for _, c := range certs {
		if truststore.Fingerprint(c) == fingerprint {
			cert = c
			break
		}
	}
	if cert == nil {
		return &DetailError{Err: ErrTrustCertificateNotFound, Detail: fmt.Sprintf(": %s", fingerprint)}
	}

	// Create the OS cert store.
	osCertStore, err := newOSCertStore()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustInstallFailed, Cause: err}
	}

	label := osTrustLabel(fingerprint)

	if err := osCertStore.Install(cert, label); err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustInstallFailed, Cause: err}
	}

	// Track the installation status in the trust store metadata.
	if err := store.SetSystemInstalled(fingerprint, true); err != nil {
		return &DetailError{Err: ErrTrustInstallFailed, Detail: fmt.Sprintf(": failed to update metadata: %v", err)}
	}

	_, _ = fmt.Fprintf(out, "Certificate %s installed to OS trust store as %s\n", fingerprint, label)
	return nil
}

// runTrustUninstall removes a certificate from the OS trust store.
func runTrustUninstall(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	fingerprint := strings.ToLower(strings.TrimSpace(args[0]))
	if resolveXKMSdURL() != "" {
		return runTrustUninstallXKMSd(cmd, fingerprint)
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Verify the certificate exists in the trust store.
	exists, err := store.Contains(fingerprint)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustUninstallFailed, Cause: err}
	}
	if !exists {
		return &DetailError{Err: ErrTrustCertificateNotFound, Detail: fmt.Sprintf(": %s", fingerprint)}
	}

	// Create the OS cert store.
	osCertStore, err := newOSCertStore()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustUninstallFailed, Cause: err}
	}

	label := osTrustLabel(fingerprint)

	if err := osCertStore.Remove(label); err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustUninstallFailed, Cause: err}
	}

	// Update the installation status in the trust store metadata.
	if err := store.SetSystemInstalled(fingerprint, false); err != nil {
		return &DetailError{Err: ErrTrustUninstallFailed, Detail: fmt.Sprintf(": failed to update metadata: %v", err)}
	}

	_, _ = fmt.Fprintf(out, "Certificate %s removed from OS trust store\n", fingerprint)
	return nil
}

// runTrustBootstrap executes the trust bootstrap command.
func runTrustBootstrap(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		timeout = 60 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	autoCfg, err := buildBootstrapConfig(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustBootstrapFailed, Cause: err}
	}

	fmt.Fprintf(os.Stderr, "Bootstrapping trust store...\n")

	resp, err := bootstrap.Fetch(ctx, *autoCfg)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustBootstrapFailed, Cause: err}
	}

	if len(resp.PEM) == 0 {
		fmt.Fprintf(os.Stderr, "No certificates returned from bootstrap server.\n")
		return nil
	}

	if resolveXKMSdURL() != "" {
		return runTrustBootstrapXKMSd(ctx, cmd, resp.PEM, bootstrapServer(autoCfg))
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// The bundle is filed under bootstrap-ca, never auto-classified: the
	// server chose it, and auto-classification would let it pick an
	// attestation purpose (#1312).
	//
	// Report skips for the same reason `trust add` does: re-running a
	// bootstrap against an already-trusted CA is the common case, and
	// "imported: 0" on its own reads as a failure.
	result, err := store.ImportPEM(resp.PEM, truststore.BootstrapImportOptions(bootstrapServer(autoCfg)))
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustAddFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Certificates imported: %d\n", result.Added)
	if result.Skipped > 0 {
		_, _ = fmt.Fprintf(out, "Certificates skipped (already present): %d\n", result.Skipped)
	}
	return nil
}

// runTrustBootstrapXKMSd files a fetched bootstrap bundle in the server's
// trust-root store with the same purpose and source the local path uses. ctx
// is the bootstrap --timeout context; the connect and the import run under
// its deadline.
func runTrustBootstrapXKMSd(ctx context.Context, cmd *cobra.Command, pemData []byte, server string) (err error) {
	client, err := connectXKMSdClientContext(ctx, cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	opts := truststore.BootstrapImportOptions(server)
	resp, err := client.TrustRootImport(ctx, &transport.TrustRootImportRequest{
		PEM:     string(pemData),
		Purpose: string(opts.Purpose),
		Source:  opts.Source,
	})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustBootstrapFailed, Cause: fmt.Errorf("TrustRootImport: %w", err)}
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Certificates imported: %d\n", resp.Added)
	if resp.Skipped > 0 {
		_, _ = fmt.Fprintf(out, "Certificates skipped (already present): %d\n", resp.Skipped)
	}
	return nil
}

// bootstrapServer names the server a bootstrap fetch reached, for the source
// recorded on the imported certificates. Only the Noise mode can succeed
// without a ServerURL, dialing its configured address instead.
func bootstrapServer(cfg *bootstrap.Config) string {
	if cfg.ServerURL == "" && cfg.Noise != nil {
		return cfg.Noise.ServerAddr
	}
	return cfg.ServerURL
}

// buildBootstrapConfig constructs a bootstrap.Config from viper configuration
// and command-line flags.
func buildBootstrapConfig(cmd *cobra.Command) (*bootstrap.Config, error) {
	cfg := &bootstrap.Config{Mode: bootstrap.ModeAuto}

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
		cfg.DANE = &bootstrap.DANEConfig{
			Hostname:  viper.GetString("trust.bootstrap.dane.hostname"),
			DNSServer: viper.GetString("trust.bootstrap.dane.dns_server"),
		}
	}

	// Noise configuration.
	noiseServerAddr := viper.GetString("trust.bootstrap.noise.server_addr")
	if noiseServerAddr != "" {
		cfg.Noise = &bootstrap.NoiseConfig{
			ServerAddr:      noiseServerAddr,
			ServerStaticKey: viper.GetString("trust.bootstrap.noise.server_key"),
		}
	}

	// SPKI configuration.
	spkiServerURL := viper.GetString("trust.bootstrap.spki.server_url")
	if spkiServerURL != "" {
		cfg.SPKI = &bootstrap.SPKIConfig{
			Pin: viper.GetString("trust.bootstrap.spki.pin_sha256"),
		}
	}

	// Direct configuration.
	directServerURL := viper.GetString("trust.bootstrap.direct.server_url")
	if directServerURL != "" {
		cfg.Direct = &bootstrap.DirectConfig{}
	}

	// bootstrap.Config carries one ServerURL shared by every mode (every mode
	// bootstraps the same xkms server). It must be set explicitly at
	// trust.bootstrap.server_url; bootstrap.Fetch returns
	// bootstrap.ErrServerURLRequired if it is empty.
	cfg.ServerURL = viper.GetString("trust.bootstrap.server_url")

	return cfg, nil
}

// parseMethodOrder converts a slice of method name strings to bootstrap.Mode
// values using map-based dispatch for O(1) lookup per method.
func parseMethodOrder(names []string) ([]bootstrap.Mode, error) {
	methods := make([]bootstrap.Mode, 0, len(names))
	for _, name := range names {
		m, ok := methodParser[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return nil, &DetailError{Err: ErrTrustInvalidMethod, Detail: fmt.Sprintf(": %q", name)}
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
