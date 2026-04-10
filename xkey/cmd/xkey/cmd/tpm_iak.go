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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// IAKInfo holds information about the Initial Attestation Key
type IAKInfo struct {
	Handle             string `json:"handle"`
	Algorithm          string `json:"algorithm"`
	KeySize            int    `json:"key_size,omitempty"`
	Curve              string `json:"curve,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	HasCert            bool   `json:"has_certificate"`
	CertSubject        string `json:"certificate_subject,omitempty"`
	CertIssuer         string `json:"certificate_issuer,omitempty"`
	CertSerial         string `json:"certificate_serial,omitempty"`
	CertNotAfter       string `json:"certificate_not_after,omitempty"`
}

var (
	iakExportOutput   string
	iakCreateForce    bool
	iakCreateTemplate string
	iakCSROutput      string
	iakCSRSubject     string
)

// tpmIAKCmd represents the tpm iak command group
var tpmIAKCmd = &cobra.Command{
	Use:   "iak",
	Short: "Initial Attestation Key (IAK) operations",
	Long: `Initial Attestation Key (IAK) operations.

The Initial Attestation Key is a restricted signing key used for:
  - TPM attestation (quotes)
  - Key certification (TPM2_Certify)
  - Device identity attestation

Per TCG spec, an IAK must have these characteristics:
  - Restricted
  - Signing
  - Not-decrypting
  - FixedTPM

Subcommands:
  show   - Display IAK public key and certificate information
  create - Create a new IAK
  export - Export IAK certificate to a file
  csr    - Generate a CSR for IAK certificate`,
}

// tpmIAKShowCmd displays IAK information
var tpmIAKShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display IAK public key and certificate",
	Long: `Display the Initial Attestation Key public key and certificate information.

Shows:
  - Key handle and algorithm
  - Signature algorithm
  - Certificate details (if available)

Examples:
  # Show IAK information
  xkey tpm iak show

  # Show IAK information in JSON format
  xkey tpm iak show -o json`,
	RunE: runIAKShow,
}

// tpmIAKCreateCmd creates a new IAK
var tpmIAKCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new IAK",
	Long: `Create a new Initial Attestation Key.

This will create a restricted signing key suitable for attestation.
The key will be persisted at the IAK handle (default: 0x81010002).

Examples:
  # Create IAK with default settings (RSA 2048)
  xkey tpm iak create

  # Create IAK with RSA-PSS
  xkey tpm iak create --template rsa-pss

  # Create IAK with ECC P-256
  xkey tpm iak create --template ecc256

  # Force recreation of existing IAK
  xkey tpm iak create --force`,
	RunE: runIAKCreate,
}

// tpmIAKExportCmd exports the IAK certificate
var tpmIAKExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export IAK certificate to file",
	Long: `Export the Initial Attestation Key certificate to a PEM file.

The certificate proves the IAK is bound to a specific TPM.

Examples:
  # Export IAK certificate
  xkey tpm iak export --output iak-cert.pem

  # Export IAK certificate to stdout
  xkey tpm iak export --output -`,
	RunE: runIAKExport,
}

// tpmIAKCSRCmd generates a CSR for IAK certificate
var tpmIAKCSRCmd = &cobra.Command{
	Use:   "csr",
	Short: "Generate CSR for IAK certificate",
	Long: `Generate a Certificate Signing Request (CSR) for the IAK.

The CSR follows TCG-CSR-IDEVID format and includes:
  - IAK public key
  - EK certificate (for attestation)
  - TPM attestation data

Examples:
  # Generate IAK CSR
  xkey tpm iak csr --output iak.csr

  # Generate IAK CSR with custom subject
  xkey tpm iak csr --output iak.csr --subject "CN=device-001,O=Example"`,
	RunE: runIAKCSR,
}

func init() {
	// Add subcommands to iak command
	tpmIAKCmd.AddCommand(tpmIAKShowCmd)
	tpmIAKCmd.AddCommand(tpmIAKCreateCmd)
	tpmIAKCmd.AddCommand(tpmIAKExportCmd)
	tpmIAKCmd.AddCommand(tpmIAKCSRCmd)

	// Create flags
	tpmIAKCreateCmd.Flags().BoolVar(&iakCreateForce, "force", false,
		"Force recreation even if IAK already exists")
	tpmIAKCreateCmd.Flags().StringVar(&iakCreateTemplate, "template", "rsa2048",
		"Key template (rsa2048, rsa-pss, ecc256)")

	// Export flags
	tpmIAKExportCmd.Flags().StringVar(&iakExportOutput, "output", "",
		"Output file path (use '-' for stdout)")
	_ = tpmIAKExportCmd.MarkFlagRequired("output")

	// CSR flags
	tpmIAKCSRCmd.Flags().StringVar(&iakCSROutput, "output", "",
		"Output file path for CSR")
	tpmIAKCSRCmd.Flags().StringVar(&iakCSRSubject, "subject", "",
		"CSR subject (e.g., 'CN=device-001,O=Example')")
	_ = tpmIAKCSRCmd.MarkFlagRequired("output")
}

func runIAKShow(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get IAK attributes
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return fmt.Errorf("%w: IAK not found - run 'tpm provision' first", ErrKeyNotFound)
	}

	info := &IAKInfo{
		Handle:             fmt.Sprintf("0x%08x", iakAttrs.TPMAttributes.Handle),
		SignatureAlgorithm: iakAttrs.SignatureAlgorithm.String(),
	}

	// Determine algorithm and size
	switch iakAttrs.KeyAlgorithm {
	case x509.RSA:
		info.Algorithm = "RSA"
		if iakAttrs.RSAAttributes != nil {
			info.KeySize = iakAttrs.RSAAttributes.KeySize
		}
	case x509.ECDSA:
		info.Algorithm = "ECDSA"
		if iakAttrs.ECCAttributes != nil {
			info.Curve = iakAttrs.ECCAttributes.Curve.Params().Name
		}
	}

	// Try to get IAK certificate
	iakCert, err := tpm.IAKCertificate()
	if err == nil && iakCert != nil {
		info.HasCert = true
		info.CertSubject = iakCert.Subject.String()
		info.CertIssuer = iakCert.Issuer.String()
		info.CertSerial = iakCert.SerialNumber.String()
		info.CertNotAfter = iakCert.NotAfter.Format("2006-01-02 15:04:05 MST")
	}

	// Output based on format
	switch tpmCfg.outputFormat {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(info)
	default:
		return outputIAKText(info)
	}
}

func outputIAKText(info *IAKInfo) error {
	fmt.Println("Initial Attestation Key (IAK) Information")
	fmt.Println("==========================================")
	fmt.Println()

	fmt.Println("Key Details:")
	fmt.Printf("  Handle:              %s\n", info.Handle)
	fmt.Printf("  Algorithm:           %s\n", info.Algorithm)
	if info.KeySize > 0 {
		fmt.Printf("  Key Size:            %d bits\n", info.KeySize)
	}
	if info.Curve != "" {
		fmt.Printf("  Curve:               %s\n", info.Curve)
	}
	fmt.Printf("  Signature Algorithm: %s\n", info.SignatureAlgorithm)
	fmt.Println()

	if info.HasCert {
		fmt.Println("Certificate Details:")
		fmt.Printf("  Subject:    %s\n", info.CertSubject)
		fmt.Printf("  Issuer:     %s\n", info.CertIssuer)
		fmt.Printf("  Serial:     %s\n", info.CertSerial)
		fmt.Printf("  Not After:  %s\n", info.CertNotAfter)
	} else {
		fmt.Println("Certificate: Not available")
	}

	return nil
}

func runIAKCreate(cmd *cobra.Command, args []string) error {
	// Validate template
	switch iakCreateTemplate {
	case "rsa2048", "rsa-pss", "ecc256":
		// Valid
	default:
		return fmt.Errorf("%w: %s", ErrInvalidIAKTemplate, iakCreateTemplate)
	}

	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Check if IAK already exists
	if !iakCreateForce {
		if _, err := tpm.IAKAttributes(); err == nil {
			return fmt.Errorf("IAK already exists - use --force to recreate")
		}
	}

	// Get EK attributes for IAK creation
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return fmt.Errorf("EK not found - run 'tpm provision' first: %w", err)
	}

	// Create IAK
	fmt.Println("Creating Initial Attestation Key...")
	_, err = tpm.CreateIAK(ekAttrs, nil)
	if err != nil {
		return fmt.Errorf("failed to create IAK: %w", err)
	}

	fmt.Println("IAK created successfully")
	return nil
}

func runIAKExport(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get IAK certificate
	iakCert, err := tpm.IAKCertificate()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateNotFound, err)
	}

	// Encode as PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: iakCert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Output to file or stdout
	if iakExportOutput == "-" {
		fmt.Print(string(pemData))
		return nil
	}

	if err := os.WriteFile(iakExportOutput, pemData, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrExportFailed, err)
	}

	fmt.Printf("IAK certificate exported to: %s\n", iakExportOutput)
	return nil
}

func runIAKCSR(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get EK certificate
	ekCert, err := tpm.EKCertificate()
	if err != nil {
		fmt.Println("Warning: EK certificate not available, CSR will have limited attestation capability")
	}

	// Get IAK attributes
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return fmt.Errorf("IAK not found - run 'tpm provision' first: %w", err)
	}

	// Create TCG-CSR-IDEVID for IAK
	fmt.Println("Generating IAK CSR...")
	csr, err := tpm.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCSRGenerationFailed, err)
	}

	// Marshal CSR
	csrBytes, err := csr.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal CSR: %w", err)
	}

	// Write CSR to file
	if err := os.WriteFile(iakCSROutput, csrBytes, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrExportFailed, err)
	}

	fmt.Printf("IAK CSR written to: %s\n", iakCSROutput)
	return nil
}
