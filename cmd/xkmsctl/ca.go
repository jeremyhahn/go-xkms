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
	"fmt"
	"os"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// CA command flag variables
var (
	caIdentity     string
	caCSRFile      string
	caProfile      string
	caValidity     int
	caOutputFile   string
	caCommonName   string
	caOrg          string
	caSANs         string
	caAlgorithm    string
	caSerial       string
	caRevokeReason int
)

// caCmd represents the certificate authority command
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Manage Certificate Authority operations",
	Long:  `Interact with the XKMS Certificate Authority for certificate lifecycle management`,
}

// caBundleCmd retrieves the CA certificate bundle
var caBundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Get CA certificate bundle",
	Long:  `Retrieve the CA certificate bundle in PEM format`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()

		printVerbose("Retrieving CA certificate bundle")

		getCABundle(cfg)
	},
}

// getCABundle retrieves the CA certificate bundle using the SDK client
func getCABundle(cfg *Config) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.GetCABundle(ctx, &client.GetCABundleRequest{})
	if err != nil {
		handleError(fmt.Errorf("failed to get CA bundle: %w", err))
		return
	}

	fmt.Printf("%s", resp.BundlePEM)
}

// caCertificateCmd retrieves the CA certificate information
var caCertificateCmd = &cobra.Command{
	Use:   "certificate",
	Short: "Get CA certificate info",
	Long:  `Retrieve CA certificate details including subject, issuer, serial number, and validity`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Retrieving CA certificate info")

		getCACertificate(cfg, printer)
	},
}

// getCACertificate retrieves the CA certificate using the SDK client
func getCACertificate(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.GetCACertificate(ctx, &client.GetCACertificateRequest{
		Identity: caIdentity,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to get CA certificate: %w", err))
		return
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"subject":       resp.Subject,
			"issuer":        resp.Issuer,
			"serial_number": resp.SerialNumber,
			"not_before":    resp.NotBefore,
			"not_after":     resp.NotAfter,
			"is_ca":         resp.IsCA,
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("CA Certificate Details:\n")
		fmt.Printf("  Subject:       %s\n", resp.Subject)
		fmt.Printf("  Issuer:        %s\n", resp.Issuer)
		fmt.Printf("  Serial Number: %s\n", resp.SerialNumber)
		fmt.Printf("  Not Before:    %s\n", resp.NotBefore)
		fmt.Printf("  Not After:     %s\n", resp.NotAfter)
		fmt.Printf("  Is CA:         %t\n", resp.IsCA)
	}
}

// caSignCSRCmd signs a certificate signing request
var caSignCSRCmd = &cobra.Command{
	Use:   "sign-csr",
	Short: "Sign a CSR",
	Long: `Sign a Certificate Signing Request (CSR) using the CA.

Example:
  xkmsctl ca sign-csr --csr request.pem
  xkmsctl ca sign-csr --csr request.pem --profile server --validity 365
  xkmsctl ca sign-csr --csr request.pem --output signed.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Signing CSR from file: %s", caCSRFile)

		signCSR(cfg, printer)
	},
}

// signCSR signs a CSR using the SDK client
func signCSR(cfg *Config, printer *Printer) {
	// Read CSR file
	// #nosec G304 - CSR file path from CLI argument
	csrPEM, err := os.ReadFile(caCSRFile)
	if err != nil {
		handleError(fmt.Errorf("failed to read CSR file: %w", err))
		return
	}

	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.SignCSR(ctx, &client.SignCSRRequest{
		CSRPEM:       csrPEM,
		Profile:      caProfile,
		ValidityDays: caValidity,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to sign CSR: %w", err))
		return
	}

	// Write to file if output flag is set
	if caOutputFile != "" {
		// #nosec G306 - Certificate files need to be readable
		if err := os.WriteFile(caOutputFile, resp.CertificatePEM, 0644); err != nil {
			handleError(fmt.Errorf("failed to write certificate: %w", err))
			return
		}
		printVerbose("Signed certificate written to: %s", caOutputFile)
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"serial_number": resp.SerialNumber,
		}
		if caOutputFile != "" {
			result["cert_file"] = caOutputFile
		} else {
			result["certificate_pem"] = string(resp.CertificatePEM)
		}
		if len(resp.ChainPEM) > 0 {
			result["chain_pem"] = string(resp.ChainPEM)
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("Serial Number: %s\n", resp.SerialNumber)
		if caOutputFile == "" {
			fmt.Printf("%s", resp.CertificatePEM)
		} else {
			fmt.Printf("Certificate written to: %s\n", caOutputFile)
		}
	}
}

// caIssueCmd issues a new certificate
var caIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new certificate",
	Long: `Issue a new certificate from the CA with the specified parameters.

The CA generates the key pair and returns the certificate, chain, and private key.

Examples:
  xkmsctl ca issue --cn server.example.com --profile server
  xkmsctl ca issue --cn client@example.com --profile client --validity 365
  xkmsctl ca issue --cn myserver --sans "DNS:*.example.com,DNS:example.com,IP:192.168.1.1"
  xkmsctl ca issue --cn myserver --output server.pem --algorithm ecdsa-p256`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Issuing certificate for CN: %s", caCommonName)

		issueCACertificate(cfg, printer)
	},
}

// issueCACertificate issues a new certificate using the SDK client
func issueCACertificate(cfg *Config, printer *Printer) {
	// Parse SANs
	var sans []string
	if caSANs != "" {
		sans = splitAndTrimCA(caSANs)
	}

	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.IssueCertificate(ctx, &client.IssueCertificateRequest{
		CommonName:   caCommonName,
		Profile:      caProfile,
		Organization: caOrg,
		SANs:         sans,
		ValidityDays: caValidity,
		Algorithm:    caAlgorithm,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to issue certificate: %w", err))
		return
	}

	// Write certificate to file if output flag is set
	if caOutputFile != "" {
		// #nosec G306 - Certificate files need to be readable
		if err := os.WriteFile(caOutputFile, resp.CertificatePEM, 0644); err != nil {
			handleError(fmt.Errorf("failed to write certificate: %w", err))
			return
		}
		printVerbose("Certificate written to: %s", caOutputFile)

		// Write private key to separate file if key was generated
		if len(resp.PrivateKeyPEM) > 0 {
			keyFile := caOutputFile + ".key"
			// #nosec G306 - Key files should be protected
			if err := os.WriteFile(keyFile, resp.PrivateKeyPEM, 0600); err != nil {
				handleError(fmt.Errorf("failed to write private key: %w", err))
				return
			}
			printVerbose("Private key written to: %s", keyFile)
		}
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"serial_number": resp.SerialNumber,
		}
		if caOutputFile != "" {
			result["cert_file"] = caOutputFile
			if len(resp.PrivateKeyPEM) > 0 {
				result["key_file"] = caOutputFile + ".key"
			}
		} else {
			result["certificate_pem"] = string(resp.CertificatePEM)
			if len(resp.ChainPEM) > 0 {
				result["chain_pem"] = string(resp.ChainPEM)
			}
			if len(resp.PrivateKeyPEM) > 0 {
				result["private_key_pem"] = string(resp.PrivateKeyPEM)
			}
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("Serial Number: %s\n", resp.SerialNumber)
		if caOutputFile == "" {
			fmt.Printf("\n--- Certificate (PEM) ---\n%s", resp.CertificatePEM)
			if len(resp.ChainPEM) > 0 {
				fmt.Printf("\n--- Chain (PEM) ---\n%s", resp.ChainPEM)
			}
			if len(resp.PrivateKeyPEM) > 0 {
				fmt.Printf("\n--- Private Key (PEM) ---\n%s", resp.PrivateKeyPEM)
				fmt.Printf("\nWARNING: Keep this private key secure!\n")
			}
		} else {
			fmt.Printf("Certificate: %s\n", caOutputFile)
			if len(resp.PrivateKeyPEM) > 0 {
				fmt.Printf("Private Key: %s\n", caOutputFile+".key")
			}
		}
	}
}

// caRevokeCmd revokes a certificate
var caRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a certificate",
	Long: `Revoke a certificate by its serial number.

RFC 5280 reason codes:
  0 - Unspecified
  1 - Key Compromise
  2 - CA Compromise
  3 - Affiliation Changed
  4 - Superseded
  5 - Cessation of Operation
  6 - Certificate Hold
  8 - Remove from CRL
  9 - Privilege Withdrawn
  10 - AA Compromise

Example:
  xkmsctl ca revoke --serial 01AB23CD
  xkmsctl ca revoke --serial 01AB23CD --reason 1`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Revoking certificate with serial: %s", caSerial)

		revokeCACertificate(cfg, printer)
	},
}

// revokeCACertificate revokes a certificate using the SDK client
func revokeCACertificate(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.RevokeCertificate(ctx, &client.RevokeCertificateRequest{
		SerialNumber: caSerial,
		Reason:       caRevokeReason,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to revoke certificate: %w", err))
		return
	}

	if resp.Message != "" {
		if err := printer.PrintSuccess(resp.Message); err != nil {
			handleError(err)
		}
	} else {
		if err := printer.PrintSuccess(fmt.Sprintf("Successfully revoked certificate with serial: %s", caSerial)); err != nil {
			handleError(err)
		}
	}
}

// caCRLCmd generates a certificate revocation list
var caCRLCmd = &cobra.Command{
	Use:   "crl",
	Short: "Generate CRL",
	Long: `Generate a Certificate Revocation List (CRL) in PEM format.

Example:
  xkmsctl ca crl
  xkmsctl ca crl --output revoked.crl`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()

		printVerbose("Generating CRL")

		generateCRL(cfg)
	},
}

// generateCRL generates a CRL using the SDK client
func generateCRL(cfg *Config) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.GenerateCRL(ctx, &client.GenerateCRLRequest{})
	if err != nil {
		handleError(fmt.Errorf("failed to generate CRL: %w", err))
		return
	}

	// Write to file if output flag is set
	if caOutputFile != "" {
		// #nosec G306 - CRL files need to be readable
		if err := os.WriteFile(caOutputFile, resp.CRLPEM, 0644); err != nil {
			handleError(fmt.Errorf("failed to write CRL: %w", err))
			return
		}
		fmt.Printf("CRL written to: %s\n", caOutputFile)
		return
	}

	fmt.Printf("%s", resp.CRLPEM)
}

// caStatusCmd checks certificate revocation status
var caStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check certificate revocation status",
	Long: `Check whether a certificate has been revoked by its serial number.

Example:
  xkmsctl ca status --serial 01AB23CD`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Checking revocation status for serial: %s", caSerial)

		checkRevocationStatus(cfg, printer)
	},
}

// checkRevocationStatus checks if a certificate is revoked using the SDK client
func checkRevocationStatus(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to xkms service")

	resp, err := cl.IsRevoked(ctx, &client.IsRevokedRequest{
		SerialNumber: caSerial,
	})
	if err != nil {
		handleError(fmt.Errorf("failed to check revocation status: %w", err))
		return
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"serial_number": caSerial,
			"revoked":       resp.Revoked,
		}
		if resp.Revoked {
			result["reason"] = resp.Reason
		}
		if resp.Message != "" {
			result["message"] = resp.Message
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		if resp.Revoked {
			fmt.Printf("Certificate %s: REVOKED (reason: %d)\n", caSerial, resp.Reason)
		} else {
			fmt.Printf("Certificate %s: NOT REVOKED\n", caSerial)
		}
	}
}

// splitAndTrimCA splits a comma-separated string and trims whitespace.
// This is a local copy to avoid name collision with the function in cert.go.
func splitAndTrimCA(s string) []string {
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

func init() {
	// ca certificate flags
	caCertificateCmd.Flags().StringVar(&caIdentity, "identity", "", "CA identity/CN (empty for default CA)")

	// ca sign-csr flags
	caSignCSRCmd.Flags().StringVar(&caCSRFile, "csr", "", "path to CSR PEM file (required)")
	_ = caSignCSRCmd.MarkFlagRequired("csr")
	caSignCSRCmd.Flags().StringVar(&caProfile, "profile", "", "certificate profile (server, client, etc.)")
	caSignCSRCmd.Flags().IntVar(&caValidity, "validity", 0, "validity period in days (0 for CA default)")
	caSignCSRCmd.Flags().StringVar(&caOutputFile, "output", "", "output file for signed certificate (PEM)")

	// ca issue flags
	caIssueCmd.Flags().StringVar(&caCommonName, "cn", "", "common name for the certificate (required)")
	_ = caIssueCmd.MarkFlagRequired("cn")
	caIssueCmd.Flags().StringVar(&caProfile, "profile", "", "certificate profile (server, client, etc.)")
	caIssueCmd.Flags().StringVar(&caOrg, "org", "", "organization name")
	caIssueCmd.Flags().StringVar(&caSANs, "sans", "", "subject alternative names (comma-separated, e.g., DNS:example.com,IP:1.2.3.4)")
	caIssueCmd.Flags().IntVar(&caValidity, "validity", 0, "validity period in days (0 for CA default)")
	caIssueCmd.Flags().StringVar(&caAlgorithm, "algorithm", "", "key algorithm (ecdsa-p256, rsa2048, ed25519)")
	caIssueCmd.Flags().StringVar(&caOutputFile, "output", "", "output file for certificate (PEM)")

	// ca revoke flags
	caRevokeCmd.Flags().StringVar(&caSerial, "serial", "", "certificate serial number in hex (required)")
	_ = caRevokeCmd.MarkFlagRequired("serial")
	caRevokeCmd.Flags().IntVar(&caRevokeReason, "reason", 0, "RFC 5280 revocation reason code (default: 0 unspecified)")

	// ca crl flags
	caCRLCmd.Flags().StringVar(&caOutputFile, "output", "", "output file for CRL (PEM)")

	// ca status flags
	caStatusCmd.Flags().StringVar(&caSerial, "serial", "", "certificate serial number in hex (required)")
	_ = caStatusCmd.MarkFlagRequired("serial")

	// Add subcommands
	caCmd.AddCommand(caBundleCmd)
	caCmd.AddCommand(caCertificateCmd)
	caCmd.AddCommand(caSignCSRCmd)
	caCmd.AddCommand(caIssueCmd)
	caCmd.AddCommand(caRevokeCmd)
	caCmd.AddCommand(caCRLCmd)
	caCmd.AddCommand(caStatusCmd)
}
