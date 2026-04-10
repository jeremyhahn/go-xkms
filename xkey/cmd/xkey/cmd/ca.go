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
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// CA command errors.
var (
	// ErrCANotInitialized indicates the CA client is not initialized.
	ErrCANotInitialized = errors.New("ca: client not initialized")

	// ErrCAInfoFailed indicates failure to retrieve CA certificate info.
	ErrCAInfoFailed = errors.New("ca: failed to get CA info")

	// ErrCAIssueFailed indicates failure to issue a certificate.
	ErrCAIssueFailed = errors.New("ca: failed to issue certificate")

	// ErrCASignCSRFailed indicates failure to sign a CSR.
	ErrCASignCSRFailed = errors.New("ca: failed to sign CSR")

	// ErrCARevokeFailed indicates failure to revoke a certificate.
	ErrCARevokeFailed = errors.New("ca: failed to revoke certificate")

	// ErrCACRLFailed indicates failure to generate a CRL.
	ErrCACRLFailed = errors.New("ca: failed to generate CRL")

	// ErrCACheckRevocationFailed indicates failure to check revocation status.
	ErrCACheckRevocationFailed = errors.New("ca: failed to check revocation status")

	// ErrCABundleFailed indicates failure to retrieve the CA bundle.
	ErrCABundleFailed = errors.New("ca: failed to get CA bundle")

	// ErrCACSRReadFailed indicates failure to read the CSR file.
	ErrCACSRReadFailed = errors.New("ca: failed to read CSR file")

	// ErrCAOutputWriteFailed indicates failure to write output to file.
	ErrCAOutputWriteFailed = errors.New("ca: failed to write output file")

	// ErrCASerialRequired indicates a serial number argument is required.
	ErrCASerialRequired = errors.New("ca: serial number argument is required")

	// ErrCACommonNameRequired indicates --cn flag is required.
	ErrCACommonNameRequired = errors.New("ca: --cn flag is required")

	// ErrCAProfileRequired indicates --profile flag is required.
	ErrCAProfileRequired = errors.New("ca: --profile flag is required")

	// ErrCACSRRequired indicates --csr flag is required.
	ErrCACSRRequired = errors.New("ca: --csr flag is required")

	// ErrCASANParseFailed indicates failure to parse SAN entries.
	ErrCASANParseFailed = errors.New("ca: failed to parse SAN entry")

	// ErrCAInvalidReasonCode indicates an invalid revocation reason code.
	ErrCAInvalidReasonCode = errors.New("ca: invalid revocation reason code")
)

// reasonCodes maps human-readable reason code names to RFC 5280 integer values.
var reasonCodes = map[string]int{
	"unspecified":            0,
	"key-compromise":         1,
	"ca-compromise":          2,
	"affiliation-changed":    3,
	"superseded":             4,
	"cessation-of-operation": 5,
}

// getSDKClient returns a transport.Client connected to the xkms service.
func getSDKClient() (transport.Client, error) {
	// TODO: Initialize from config (embedded or remote mode)
	return nil, ErrCANotInitialized
}

// caCmd is the parent command for CA operations.
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Certificate Authority operations",
	Long: `Manage Certificate Authority operations through the xkms SDK.

The CA commands provide certificate lifecycle management including issuance,
revocation, CRL generation, and trust chain inspection. All operations are
performed through the SDK transport layer, which communicates with the
xkms daemon's built-in CA.

Examples:
  # Show CA certificate information
  xkey ca info

  # Issue a server certificate
  xkey ca issue --profile server --cn example.com --san "DNS:*.example.com,IP:10.0.0.1"

  # Issue a client certificate
  xkey ca issue --profile client --cn "user@example.com"

  # Sign an external CSR
  xkey ca sign-csr --csr request.csr --profile server

  # Revoke a certificate
  xkey ca revoke ABC123 --reason key-compromise

  # Generate a CRL
  xkey ca crl --output crl.pem

  # Check certificate revocation status
  xkey ca check-revocation ABC123

  # Get the CA trust bundle
  xkey ca bundle --output bundle.pem`,
}

// caInfoCmd retrieves CA certificate information.
var caInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Get CA certificate information",
	Long: `Display detailed information about the CA certificate.

Shows the CA certificate subject, issuer, serial number, validity period,
and whether the certificate is marked as a CA.

Examples:
  # Show CA certificate info
  xkey ca info`,
	RunE: runCAInfo,
}

// caIssueCmd issues a new certificate.
var caIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new certificate",
	Long: `Issue a new certificate from the CA.

Creates a new key pair and certificate signed by the CA. The certificate
profile determines the key usage and extended key usage fields.

Available profiles:
  server   TLS server certificate (ServerAuth)
  client   TLS client certificate (ClientAuth)
  idevid   IEEE 802.1AR device identity certificate

SANs are specified in the format TYPE:VALUE, separated by commas:
  DNS:example.com       DNS name
  IP:10.0.0.1           IP address
  Email:user@host.com   Email address

Available algorithms:
  ecdsa-p256    ECDSA with P-256 curve (default)
  ecdsa-p384    ECDSA with P-384 curve
  ecdsa-p521    ECDSA with P-521 curve
  rsa2048       RSA with 2048-bit key
  rsa4096       RSA with 4096-bit key
  ed25519       Ed25519

Examples:
  # Issue a server certificate
  xkey ca issue --profile server --cn example.com

  # Issue with SANs and custom validity
  xkey ca issue --profile server --cn example.com \
    --san "DNS:*.example.com,IP:10.0.0.1" --validity-days 365

  # Issue a client certificate
  xkey ca issue --profile client --cn "user@example.com"

  # Issue with specific algorithm
  xkey ca issue --profile server --cn example.com --algorithm ecdsa-p384`,
	RunE: runCAIssue,
}

// caSignCSRCmd signs a certificate signing request.
var caSignCSRCmd = &cobra.Command{
	Use:   "sign-csr",
	Short: "Sign a certificate signing request",
	Long: `Sign an existing PKCS#10 Certificate Signing Request (CSR).

Reads a PEM-encoded CSR file and produces a signed certificate. The optional
profile flag controls key usage and extended key usage fields applied to the
resulting certificate.

Examples:
  # Sign a CSR with default settings
  xkey ca sign-csr --csr request.csr

  # Sign with a profile and output to file
  xkey ca sign-csr --csr request.csr --profile server --output cert.pem`,
	RunE: runCASignCSR,
}

// caRevokeCmd revokes a certificate by serial number.
var caRevokeCmd = &cobra.Command{
	Use:   "revoke <serial>",
	Short: "Revoke a certificate",
	Long: `Revoke a certificate by its serial number.

The serial number is the certificate's unique identifier assigned during
issuance. Use 'xkey ca info' or check the issued certificate to find it.

Available reason codes:
  unspecified            (0) Default reason
  key-compromise         (1) Private key was compromised
  ca-compromise          (2) CA private key was compromised
  affiliation-changed    (3) Subject's affiliation changed
  superseded             (4) Certificate was replaced
  cessation-of-operation (5) Subject no longer operates

Arguments:
  serial  Serial number of the certificate to revoke

Examples:
  # Revoke with default reason (unspecified)
  xkey ca revoke ABC123

  # Revoke with a specific reason
  xkey ca revoke ABC123 --reason key-compromise`,
	Args: cobra.ExactArgs(1),
	RunE: runCARevoke,
}

// caCRLCmd generates a certificate revocation list.
var caCRLCmd = &cobra.Command{
	Use:     "crl",
	Aliases: []string{"gen-crl"},
	Short:   "Generate a Certificate Revocation List",
	Long: `Generate a PEM-encoded Certificate Revocation List (CRL).

The CRL contains all revoked certificates and is signed by the CA.
Output is written to stdout unless --output is specified.

Examples:
  # Generate CRL to stdout
  xkey ca crl

  # Generate CRL to file
  xkey ca crl --output crl.pem`,
	RunE: runCACRL,
}

// caCheckRevocationCmd checks if a certificate is revoked.
var caCheckRevocationCmd = &cobra.Command{
	Use:   "check-revocation <serial>",
	Short: "Check if a certificate is revoked",
	Long: `Check the revocation status of a certificate by its serial number.

Returns the revocation status and, if revoked, the reason code.

Arguments:
  serial  Serial number of the certificate to check

Examples:
  # Check revocation status
  xkey ca check-revocation ABC123`,
	Args: cobra.ExactArgs(1),
	RunE: runCACheckRevocation,
}

// caBundleCmd retrieves the CA certificate bundle.
var caBundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Get the CA certificate bundle",
	Long: `Retrieve the CA certificate bundle (trust chain).

Returns the full PEM-encoded certificate chain from the CA. This bundle
can be used to configure TLS trust for clients connecting to services
that use certificates issued by this CA.

Output is written to stdout unless --output is specified.

Examples:
  # Print bundle to stdout
  xkey ca bundle

  # Save bundle to file
  xkey ca bundle --output bundle.pem`,
	RunE: runCABundle,
}

func init() {
	caCmd.AddCommand(caInfoCmd, caIssueCmd, caSignCSRCmd, caRevokeCmd,
		caCRLCmd, caCheckRevocationCmd, caBundleCmd)

	// Issue command flags
	caIssueCmd.Flags().String("profile", "", "certificate profile (server, client, idevid)")
	caIssueCmd.Flags().String("cn", "", "common name for the certificate subject")
	caIssueCmd.Flags().String("organization", "", "organization for the certificate subject")
	caIssueCmd.Flags().String("san", "", "subject alternative names (comma-separated TYPE:VALUE pairs)")
	caIssueCmd.Flags().Int("validity-days", 0, "certificate validity in days (0 for CA default)")
	caIssueCmd.Flags().String("algorithm", "", "key algorithm (ecdsa-p256, ecdsa-p384, rsa2048, ed25519)")
	caIssueCmd.Flags().String("output", "", "output file path (default: stdout)")

	// Sign CSR command flags
	caSignCSRCmd.Flags().String("csr", "", "path to PEM-encoded CSR file")
	caSignCSRCmd.Flags().String("profile", "", "certificate profile (server, client)")
	caSignCSRCmd.Flags().Int("validity-days", 0, "certificate validity in days (0 for CA default)")
	caSignCSRCmd.Flags().String("output", "", "output file path (default: stdout)")

	// Revoke command flags
	caRevokeCmd.Flags().String("reason", "unspecified",
		"revocation reason (unspecified, key-compromise, ca-compromise, affiliation-changed, superseded, cessation-of-operation)")

	// CRL command flags
	caCRLCmd.Flags().String("output", "", "output file path (default: stdout)")

	// Bundle command flags
	caBundleCmd.Flags().String("output", "", "output file path (default: stdout)")

	RootCmd.AddCommand(caCmd)
}

// parseSANs parses a comma-separated SAN string into typed SAN entries.
// Each entry has the format TYPE:VALUE where TYPE is one of DNS, IP, or Email.
// Returns a slice of formatted SAN strings suitable for the transport request.
func parseSANs(sanStr string) ([]string, error) {
	if sanStr == "" {
		return nil, nil
	}

	parts := strings.Split(sanStr, ",")
	sans := make([]string, 0, len(parts))

	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}

		colonIdx := strings.Index(entry, ":")
		if colonIdx < 1 {
			return nil, fmt.Errorf("%w: missing TYPE: prefix in %q", ErrCASANParseFailed, entry)
		}

		sanType := strings.ToUpper(entry[:colonIdx])
		sanValue := entry[colonIdx+1:]

		if sanValue == "" {
			return nil, fmt.Errorf("%w: empty value in %q", ErrCASANParseFailed, entry)
		}

		switch sanType {
		case "DNS":
			sans = append(sans, "DNS:"+sanValue)
		case "IP":
			if net.ParseIP(sanValue) == nil {
				return nil, fmt.Errorf("%w: invalid IP address %q", ErrCASANParseFailed, sanValue)
			}
			sans = append(sans, "IP:"+sanValue)
		case "EMAIL":
			sans = append(sans, "Email:"+sanValue)
		default:
			return nil, fmt.Errorf("%w: unsupported SAN type %q", ErrCASANParseFailed, sanType)
		}
	}

	return sans, nil
}

// parseReasonCode converts a reason string to an RFC 5280 reason code integer.
func parseReasonCode(reason string) (int, error) {
	code, ok := reasonCodes[strings.ToLower(strings.TrimSpace(reason))]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrCAInvalidReasonCode, reason)
	}
	return code, nil
}

// writeOutput writes data to the specified file or stdout.
func writeOutput(outputPath string, data []byte) error {
	if outputPath == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrCAOutputWriteFailed, err)
	}
	fmt.Fprintf(os.Stderr, "Written to %s\n", outputPath)
	return nil
}

// runCAInfo executes the ca info command.
func runCAInfo(cmd *cobra.Command, args []string) error {
	client, err := getSDKClient()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCAInfoFailed, err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCAInfoFailed, err)
	}

	fmt.Printf("CA Certificate Information\n")
	fmt.Printf("==========================\n\n")
	fmt.Printf("Subject:       %s\n", resp.Subject)
	fmt.Printf("Issuer:        %s\n", resp.Issuer)
	fmt.Printf("Serial Number: %s\n", resp.SerialNumber)
	fmt.Printf("Not Before:    %s\n", resp.NotBefore)
	fmt.Printf("Not After:     %s\n", resp.NotAfter)
	fmt.Printf("Is CA:         %t\n", resp.IsCA)

	return nil
}

// runCAIssue executes the ca issue command.
func runCAIssue(cmd *cobra.Command, args []string) error {
	profile, _ := cmd.Flags().GetString("profile")
	if profile == "" {
		return ErrCAProfileRequired
	}

	cn, _ := cmd.Flags().GetString("cn")
	if cn == "" {
		return ErrCACommonNameRequired
	}

	organization, _ := cmd.Flags().GetString("organization")
	sanStr, _ := cmd.Flags().GetString("san")
	validityDays, _ := cmd.Flags().GetInt("validity-days")
	algorithm, _ := cmd.Flags().GetString("algorithm")
	outputPath, _ := cmd.Flags().GetString("output")

	sans, err := parseSANs(sanStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCAIssueFailed, err)
	}

	client, err := getSDKClient()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCAIssueFailed, err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		Profile:      profile,
		CommonName:   cn,
		Organization: organization,
		SANs:         sans,
		ValidityDays: validityDays,
		Algorithm:    algorithm,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCAIssueFailed, err)
	}

	fmt.Fprintf(os.Stderr, "Certificate issued: serial=%s\n", resp.SerialNumber)

	// Build output: certificate + chain + private key (if generated)
	var output []byte
	output = append(output, resp.CertificatePEM...)
	if len(resp.ChainPEM) > 0 {
		output = append(output, resp.ChainPEM...)
	}
	if len(resp.PrivateKeyPEM) > 0 {
		output = append(output, resp.PrivateKeyPEM...)
	}

	return writeOutput(outputPath, output)
}

// runCASignCSR executes the ca sign-csr command.
func runCASignCSR(cmd *cobra.Command, args []string) error {
	csrPath, _ := cmd.Flags().GetString("csr")
	if csrPath == "" {
		return ErrCACSRRequired
	}

	profile, _ := cmd.Flags().GetString("profile")
	validityDays, _ := cmd.Flags().GetInt("validity-days")
	outputPath, _ := cmd.Flags().GetString("output")

	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCACSRReadFailed, err)
	}

	client, err := getSDKClient()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCASignCSRFailed, err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:       csrPEM,
		Profile:      profile,
		ValidityDays: validityDays,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCASignCSRFailed, err)
	}

	fmt.Fprintf(os.Stderr, "CSR signed: serial=%s\n", resp.SerialNumber)

	var output []byte
	output = append(output, resp.CertificatePEM...)
	if len(resp.ChainPEM) > 0 {
		output = append(output, resp.ChainPEM...)
	}

	return writeOutput(outputPath, output)
}

// runCARevoke executes the ca revoke command.
func runCARevoke(cmd *cobra.Command, args []string) error {
	serial := strings.TrimSpace(args[0])

	reasonStr, _ := cmd.Flags().GetString("reason")
	reasonCode, err := parseReasonCode(reasonStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCARevokeFailed, err)
	}

	client, err := getSDKClient()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCARevokeFailed, err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: serial,
		Reason:       reasonCode,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCARevokeFailed, err)
	}

	if resp.Success {
		fmt.Printf("Certificate %s revoked successfully\n", serial)
	} else {
		fmt.Printf("Certificate %s revocation: %s\n", serial, resp.Message)
	}

	return nil
}

// runCACRL executes the ca crl command.
func runCACRL(cmd *cobra.Command, args []string) error {
	outputPath, _ := cmd.Flags().GetString("output")

	client, err := getSDKClient()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCACRLFailed, err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GenerateCRL(ctx, &transport.GenerateCRLRequest{})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCACRLFailed, err)
	}

	return writeOutput(outputPath, resp.CRLPEM)
}

// runCACheckRevocation executes the ca check-revocation command.
func runCACheckRevocation(cmd *cobra.Command, args []string) error {
	serial := strings.TrimSpace(args[0])

	client, err := getSDKClient()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCACheckRevocationFailed, err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: serial,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCACheckRevocationFailed, err)
	}

	if resp.Revoked {
		reasonName := reasonCodeName(resp.Reason)
		fmt.Printf("Certificate %s: REVOKED (reason: %s, code: %d)\n", serial, reasonName, resp.Reason)
	} else {
		fmt.Printf("Certificate %s: VALID (not revoked)\n", serial)
	}

	return nil
}

// runCABundle executes the ca bundle command.
func runCABundle(cmd *cobra.Command, args []string) error {
	outputPath, _ := cmd.Flags().GetString("output")

	client, err := getSDKClient()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCABundleFailed, err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	resp, err := client.GetCABundle(ctx, &transport.GetCABundleRequest{})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCABundleFailed, err)
	}

	return writeOutput(outputPath, resp.BundlePEM)
}

// reasonCodeName returns a human-readable name for an RFC 5280 reason code.
func reasonCodeName(code int) string {
	for name, c := range reasonCodes {
		if c == code {
			return name
		}
	}
	return "unknown"
}
