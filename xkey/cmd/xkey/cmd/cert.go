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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	xkmspkg "github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// Cert command errors.
var (
	// ErrCertServerRequired indicates the --server flag is required.
	ErrCertServerRequired = errors.New("cert: --server flag is required")

	// ErrCertCommonNameRequired indicates the --cn flag is required.
	ErrCertCommonNameRequired = errors.New("cert: --cn flag is required")

	// ErrCertCSRGenerationFailed indicates CSR generation failed.
	ErrCertCSRGenerationFailed = errors.New("cert: CSR generation failed")

	// ErrCertSigningFailed indicates the server failed to sign the CSR.
	ErrCertSigningFailed = errors.New("cert: server CSR signing failed")

	// ErrCertClientCreationFailed indicates the SDK client could not be created.
	ErrCertClientCreationFailed = errors.New("cert: SDK client creation failed")

	// ErrCertStorageFailed indicates the certificate could not be stored.
	ErrCertStorageFailed = errors.New("cert: certificate storage failed")

	// ErrCertNotFound indicates no certificate was found in the slot.
	ErrCertNotFound = errors.New("cert: no certificate found in slot")

	// ErrCertExportFailed indicates the certificate could not be exported.
	ErrCertExportFailed = errors.New("cert: certificate export failed")

	// ErrCertFileRequired indicates the --file flag is required.
	ErrCertFileRequired = errors.New("cert: --file flag is required")

	// ErrCertSignerUnavailable indicates the signer for the PIV slot could not be obtained.
	ErrCertSignerUnavailable = errors.New("cert: signer unavailable for PIV slot")

	// ErrCertParseFailed indicates the signed certificate could not be parsed.
	ErrCertParseFailed = errors.New("cert: failed to parse signed certificate")

	// ErrCertTrustRequired indicates that --spki-pin is required for server trust.
	ErrCertTrustRequired = errors.New("cert: --spki-pin is required to establish server trust")
)

// Default cert command configuration values.
const (
	defaultCertSlot    = "9a"
	defaultCertProfile = "client"
)

// certCmd is the parent command for client certificate management.
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Manage client certificates",
	Long: `Manage client certificates for mTLS authentication with xkms servers.

The cert commands handle the full certificate lifecycle: requesting a
certificate from a server CA, viewing certificate details, and exporting
certificates to files.

Certificate requests use the PIV slot key (default: 9a) to generate a CSR,
which is signed by the server's Certificate Authority. The signed certificate
is then stored in the PIV slot for mTLS client authentication.

Examples:
  # Request a client certificate from a server
  xkey cert request --server https://xkms.example.com:8443 --cn "user@example.com"

  # Request with SPKI pin for first-time trust establishment
  xkey cert request --server https://xkms.example.com:8443 --cn "user@example.com" \
    --spki-pin abc123def456

  # Show the current certificate in the default slot
  xkey cert show

  # Show certificate in a specific slot
  xkey cert show --slot 9c

  # Export certificate to a PEM file
  xkey cert export --file /tmp/client-cert.pem`,
}

// certRequestCmd requests a certificate from a server CA.
var certRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Request a certificate from a server CA",
	Long: `Request a client certificate from an xkms server's Certificate Authority.

This command performs the following steps:
  1. Loads the private key from the PIV slot (default: 9a)
  2. Generates a PKCS#10 Certificate Signing Request (CSR)
  3. Connects to the server using the SDK client
  4. Submits the CSR for signing by the server CA
  5. Stores the signed certificate in the PIV slot

The private key never leaves the local device. Only the CSR (containing the
public key) is sent to the server.

For first-time connections to a server, use --spki-pin to establish trust
via SPKI certificate pinning instead of relying on a CA chain.

Examples:
  # Basic certificate request
  xkey cert request --server https://xkms.example.com:8443 --cn "user@example.com"

  # Request with SPKI pin for trust bootstrapping
  xkey cert request --server https://xkms.example.com:8443 --cn "user@example.com" \
    --spki-pin abc123def456

  # Request using a specific PIV slot
  xkey cert request --server https://xkms.example.com:8443 --cn "John Doe" --slot 9c

  # Request with organization details
  xkey cert request --server https://xkms.example.com:8443 --cn "user@example.com" \
    --organization "ACME Corp"`,
	RunE: runCertRequest,
}

// certShowCmd shows the current certificate in a PIV slot.
var certShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current certificate details",
	Long: `Show detailed information about the certificate stored in a PIV slot.

Displays the certificate subject, issuer, serial number, validity period,
key algorithm, and key usage extensions.

Examples:
  # Show certificate in default slot (9a)
  xkey cert show

  # Show certificate in digital signature slot
  xkey cert show --slot 9c`,
	RunE: runCertShow,
}

// certExportCmd exports a certificate to a file.
var certExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export certificate to a PEM file",
	Long: `Export the certificate from a PIV slot to a PEM-encoded file.

The exported certificate can be used for manual trust configuration or
distribution to other systems.

Examples:
  # Export default slot certificate
  xkey cert export --file /tmp/client-cert.pem

  # Export from a specific slot
  xkey cert export --slot 9c --file /tmp/signing-cert.pem`,
	RunE: runCertExport,
}

func init() {
	// Register cert command with root
	RootCmd.AddCommand(certCmd)

	// Add subcommands
	certCmd.AddCommand(certRequestCmd)
	certCmd.AddCommand(certShowCmd)
	certCmd.AddCommand(certExportCmd)

	// Request command flags
	certRequestCmd.Flags().String("server", "", "xkms server URL (required)")
	certRequestCmd.Flags().String("slot", defaultCertSlot,
		"PIV slot to use for key and certificate (9a, 9c, 9d, 9e)")
	certRequestCmd.Flags().String("cn", "", "Common Name for the certificate subject (required)")
	certRequestCmd.Flags().String("organization", "", "Organization for the certificate subject")
	certRequestCmd.Flags().String("spki-pin", "",
		"SPKI SHA-256 pin for server certificate pinning (hex-encoded)")
	certRequestCmd.Flags().String("profile", defaultCertProfile,
		"Certificate profile (client, server)")
	certRequestCmd.Flags().Int("validity-days", 0,
		"Certificate validity in days (0 for server default)")

	// Show command flags
	certShowCmd.Flags().String("slot", defaultCertSlot,
		"PIV slot to read certificate from (9a, 9c, 9d, 9e)")

	// Export command flags
	certExportCmd.Flags().String("slot", defaultCertSlot,
		"PIV slot to export certificate from (9a, 9c, 9d, 9e)")
	certExportCmd.Flags().String("file", "", "Output file path (required)")
}

// runCertRequest executes the cert request command.
func runCertRequest(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// Parse and validate flags
	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrCertServerRequired
	}

	cn, _ := cmd.Flags().GetString("cn")
	if cn == "" {
		return ErrCertCommonNameRequired
	}

	slotStr, _ := cmd.Flags().GetString("slot")
	slot, err := validatePIVSlot(slotStr)
	if err != nil {
		return err
	}

	spkiPin, _ := cmd.Flags().GetString("spki-pin")
	profile, _ := cmd.Flags().GetString("profile")
	validityDays, _ := cmd.Flags().GetInt("validity-days")

	logger.Info("requesting client certificate",
		slog.String("server", serverURL),
		slog.String("slot", string(slot)),
		slog.String("cn", cn),
	)

	// Step 1: Ensure PIV is initialized for the configured backend.
	pivCfg := buildPIVConfig()
	if err := ensurePIVInitialized(pivCfg, logger); err != nil {
		return errors.Join(ErrCertSignerUnavailable, err)
	}

	// Step 2: Generate CSR using the PIV slot key via xkms.
	ctx := cmd.Context()
	csrResp, err := xkmspkg.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{
		Backend: string(pivCfg.Backend),
		Slot:    string(slot),
		Subject: cn,
	})
	if err != nil {
		return errors.Join(ErrCertCSRGenerationFailed, err)
	}
	csrPEM := csrResp.CSR

	logger.Info("CSR generated",
		slog.String("cn", cn),
		slog.Int("csr_bytes", len(csrPEM)),
	)

	// Step 3: Create SDK client with SPKI pin (required for trust establishment)
	if spkiPin == "" {
		return ErrCertTrustRequired
	}

	sdkOpts := []xkms.Option{
		xkms.WithProtocol(xkms.ProtocolREST),
		xkms.WithAddress(serverURL),
		xkms.WithTLSEnabled(true),
		xkms.WithSPKIPin(spkiPin),
	}

	client, err := xkms.NewWithOptions(sdkOpts...)
	if err != nil {
		return errors.Join(ErrCertClientCreationFailed, err)
	}
	defer func() { _ = client.Close() }()

	// Step 4: Submit CSR to server CA for signing
	resp, err := client.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:       csrPEM,
		Profile:      profile,
		ValidityDays: validityDays,
	})
	if err != nil {
		return errors.Join(ErrCertSigningFailed, err)
	}

	logger.Info("certificate signed by server CA",
		slog.String("serial", resp.SerialNumber),
	)

	// Step 5: Parse the signed certificate
	signedCert, err := parsePEMCertificate(resp.CertificatePEM)
	if err != nil {
		return errors.Join(ErrCertParseFailed, err)
	}

	// Step 6: Store the signed certificate in the PIV slot
	storage, err := createPIVStorage(pivCfg, logger)
	if err != nil {
		return errors.Join(ErrCertStorageFailed, err)
	}
	defer func() { _ = storage.Close() }()

	if err := storage.Store(slot, signedCert); err != nil {
		return errors.Join(ErrCertStorageFailed, err)
	}

	// Print certificate summary
	slotName := pivcert.SlotName(slot)
	fmt.Printf("Certificate issued and stored in slot %s (%s)\n\n", slot, slotName)
	fmt.Printf("  Subject:       %s\n", signedCert.Subject.String())
	fmt.Printf("  Issuer:        %s\n", signedCert.Issuer.String())
	fmt.Printf("  Serial Number: %s\n", signedCert.SerialNumber.String())
	fmt.Printf("  Not Before:    %s\n", signedCert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After:     %s\n", signedCert.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Key Algorithm: %s\n", signedCert.PublicKeyAlgorithm.String())

	return nil
}

// runCertShow executes the cert show command.
func runCertShow(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	slotStr, _ := cmd.Flags().GetString("slot")
	slot, err := validatePIVSlot(slotStr)
	if err != nil {
		return err
	}

	pivCfg := buildPIVConfig()
	storage, err := createPIVStorage(pivCfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

	cert, err := storage.Retrieve(slot)
	if err != nil {
		return errors.Join(ErrCertNotFound, err)
	}

	slotName := pivcert.SlotName(slot)
	fmt.Printf("Client Certificate - Slot %s (%s)\n", slot, slotName)
	fmt.Printf("==========================================\n\n")
	fmt.Printf("Subject:       %s\n", cert.Subject.String())
	fmt.Printf("Issuer:        %s\n", cert.Issuer.String())
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Printf("Not Before:    %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:     %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())
	fmt.Printf("Signature:     %s\n", cert.SignatureAlgorithm.String())

	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:     %s\n", strings.Join(cert.DNSNames, ", "))
	}

	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("Email:         %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	if cert.KeyUsage != 0 {
		fmt.Printf("Key Usage:     %s\n", formatKeyUsage(cert.KeyUsage))
	}

	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("Ext Key Usage: %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	fmt.Printf("Is CA:         %t\n", cert.IsCA)

	// Show expiration status
	now := time.Now()
	if now.After(cert.NotAfter) {
		fmt.Printf("\nStatus:        EXPIRED (expired %s ago)\n",
			now.Sub(cert.NotAfter).Round(time.Hour))
	} else {
		remaining := cert.NotAfter.Sub(now)
		days := int(remaining.Hours() / 24)
		fmt.Printf("\nStatus:        VALID (%d days remaining)\n", days)
	}

	return nil
}

// runCertExport executes the cert export command.
func runCertExport(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	slotStr, _ := cmd.Flags().GetString("slot")
	slot, err := validatePIVSlot(slotStr)
	if err != nil {
		return err
	}

	filePath, _ := cmd.Flags().GetString("file")
	if filePath == "" {
		return ErrCertFileRequired
	}

	pivCfg := buildPIVConfig()
	storage, err := createPIVStorage(pivCfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

	cert, err := storage.Retrieve(slot)
	if err != nil {
		return errors.Join(ErrCertNotFound, err)
	}

	// Encode certificate to PEM
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err := os.WriteFile(filePath, pemData, 0600); err != nil {
		return errors.Join(ErrCertExportFailed, err)
	}

	slotName := pivcert.SlotName(slot)
	fmt.Printf("Certificate exported from slot %s (%s) to %s\n", slot, slotName, filePath)
	fmt.Printf("  Subject: %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:  %s\n", cert.Issuer.String())
	fmt.Printf("  Expires: %s\n", cert.NotAfter.Format(time.RFC3339))

	return nil
}

// parsePEMCertificate parses a PEM-encoded certificate.
func parsePEMCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(bytes.TrimSpace(certPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrCertParseFailed)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: unexpected PEM type %q", ErrCertParseFailed, block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}
