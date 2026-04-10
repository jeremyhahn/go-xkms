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

// IDevIDInfo holds information about the Initial Device Identity
type IDevIDInfo struct {
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
	idevidExportOutput   string
	idevidCreateForce    bool
	idevidCreateTemplate string
	idevidModel          string
	idevidSerial         string
	idevidCSROutput      string
	idevidCSRSubject     string
)

// tpmIDevIDCmd represents the tpm idevid command group
var tpmIDevIDCmd = &cobra.Command{
	Use:   "idevid",
	Short: "Initial Device Identifier (IDevID) operations",
	Long: `Initial Device Identifier (IDevID) operations.

The IDevID is a non-restricted signing key used for:
  - Device identity assertion
  - TLS client authentication
  - Device enrollment

Per TCG spec, an IDevID must have these characteristics:
  - Not-Restricted
  - Signing
  - Not-decrypting
  - FixedTPM

The IDevID is typically provisioned during device manufacturing
and contains the device's model and serial number.

Subcommands:
  show   - Display IDevID key and certificate information
  create - Create a new IDevID
  export - Export IDevID certificate to a file
  csr    - Generate a CSR for IDevID certificate`,
}

// tpmIDevIDShowCmd displays IDevID information
var tpmIDevIDShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display IDevID key and certificate",
	Long: `Display the Initial Device Identity key and certificate information.

Shows:
  - Key handle and algorithm
  - Signature algorithm
  - Certificate details (if available)

Examples:
  # Show IDevID information
  xkey tpm idevid show

  # Show IDevID information in JSON format
  xkey tpm idevid show -o json`,
	RunE: runIDevIDShow,
}

// tpmIDevIDCreateCmd creates a new IDevID
var tpmIDevIDCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new IDevID",
	Long: `Create a new Initial Device Identity key.

This will create a non-restricted signing key suitable for device identity.
The key will be persisted at the IDevID handle (default: 0x81020000).

The --model and --serial flags identify the device and are included
in the IDevID certificate subject.

Examples:
  # Create IDevID with default settings
  xkey tpm idevid create --model "device-01" --serial "ABC123"

  # Create IDevID with ECC P-256
  xkey tpm idevid create --template ecc256 --model "device-01" --serial "ABC123"

  # Force recreation of existing IDevID
  xkey tpm idevid create --force --model "device-01" --serial "ABC123"`,
	RunE: runIDevIDCreate,
}

// tpmIDevIDExportCmd exports the IDevID certificate
var tpmIDevIDExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export IDevID certificate to file",
	Long: `Export the Initial Device Identity certificate to a PEM file.

The certificate proves the device identity and TPM binding.

Examples:
  # Export IDevID certificate
  xkey tpm idevid export --output idevid-cert.pem

  # Export IDevID certificate to stdout
  xkey tpm idevid export --output -`,
	RunE: runIDevIDExport,
}

// tpmIDevIDCSRCmd generates a CSR for IDevID certificate
var tpmIDevIDCSRCmd = &cobra.Command{
	Use:   "csr",
	Short: "Generate CSR for IDevID certificate",
	Long: `Generate a Certificate Signing Request (CSR) for the IDevID.

The CSR follows TCG-CSR-IDEVID format and includes:
  - IDevID public key
  - EK certificate (for attestation)
  - IAK attestation of IDevID

Examples:
  # Generate IDevID CSR
  xkey tpm idevid csr --output idevid.csr

  # Generate IDevID CSR with custom subject
  xkey tpm idevid csr --output idevid.csr --subject "CN=device-001,O=Example"`,
	RunE: runIDevIDCSR,
}

func init() {
	// Add subcommands to idevid command
	tpmIDevIDCmd.AddCommand(tpmIDevIDShowCmd)
	tpmIDevIDCmd.AddCommand(tpmIDevIDCreateCmd)
	tpmIDevIDCmd.AddCommand(tpmIDevIDExportCmd)
	tpmIDevIDCmd.AddCommand(tpmIDevIDCSRCmd)

	// Create flags
	tpmIDevIDCreateCmd.Flags().BoolVar(&idevidCreateForce, "force", false,
		"Force recreation even if IDevID already exists")
	tpmIDevIDCreateCmd.Flags().StringVar(&idevidCreateTemplate, "template", "rsa2048",
		"Key template (rsa2048, rsa-pss, ecc256)")
	tpmIDevIDCreateCmd.Flags().StringVar(&idevidModel, "model", "",
		"Device model name")
	tpmIDevIDCreateCmd.Flags().StringVar(&idevidSerial, "serial", "",
		"Device serial number")
	_ = tpmIDevIDCreateCmd.MarkFlagRequired("model")
	_ = tpmIDevIDCreateCmd.MarkFlagRequired("serial")

	// Export flags
	tpmIDevIDExportCmd.Flags().StringVar(&idevidExportOutput, "output", "",
		"Output file path (use '-' for stdout)")
	_ = tpmIDevIDExportCmd.MarkFlagRequired("output")

	// CSR flags
	tpmIDevIDCSRCmd.Flags().StringVar(&idevidCSROutput, "output", "",
		"Output file path for CSR")
	tpmIDevIDCSRCmd.Flags().StringVar(&idevidCSRSubject, "subject", "",
		"CSR subject (e.g., 'CN=device-001,O=Example')")
	_ = tpmIDevIDCSRCmd.MarkFlagRequired("output")
}

func runIDevIDShow(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get IDevID attributes
	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return fmt.Errorf("%w: IDevID not found - create with 'tpm idevid create'", ErrKeyNotFound)
	}

	info := &IDevIDInfo{
		Handle:             fmt.Sprintf("0x%08x", idevidAttrs.TPMAttributes.Handle),
		SignatureAlgorithm: idevidAttrs.SignatureAlgorithm.String(),
	}

	// Determine algorithm and size
	switch idevidAttrs.KeyAlgorithm {
	case x509.RSA:
		info.Algorithm = "RSA"
		if idevidAttrs.RSAAttributes != nil {
			info.KeySize = idevidAttrs.RSAAttributes.KeySize
		}
	case x509.ECDSA:
		info.Algorithm = "ECDSA"
		if idevidAttrs.ECCAttributes != nil {
			info.Curve = idevidAttrs.ECCAttributes.Curve.Params().Name
		}
	}

	// Try to get IDevID certificate
	idevidCert, err := tpm.IDevIDCertificate()
	if err == nil && idevidCert != nil {
		info.HasCert = true
		info.CertSubject = idevidCert.Subject.String()
		info.CertIssuer = idevidCert.Issuer.String()
		info.CertSerial = idevidCert.SerialNumber.String()
		info.CertNotAfter = idevidCert.NotAfter.Format("2006-01-02 15:04:05 MST")
	}

	// Output based on format
	switch tpmCfg.outputFormat {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(info)
	default:
		return outputIDevIDText(info)
	}
}

func outputIDevIDText(info *IDevIDInfo) error {
	fmt.Println("Initial Device Identity (IDevID) Information")
	fmt.Println("=============================================")
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

func runIDevIDCreate(cmd *cobra.Command, args []string) error {
	// Validate template
	switch idevidCreateTemplate {
	case "rsa2048", "rsa-pss", "ecc256":
		// Valid
	default:
		return fmt.Errorf("%w: %s", ErrInvalidIDevIDTemplate, idevidCreateTemplate)
	}

	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Check if IDevID already exists
	if !idevidCreateForce {
		if _, err := tpm.IDevIDAttributes(); err == nil {
			return fmt.Errorf("IDevID already exists - use --force to recreate")
		}
	}

	// Get EK certificate for attestation
	ekCert, err := tpm.EKCertificate()
	if err != nil {
		fmt.Println("Warning: EK certificate not available, IDevID will have limited attestation capability")
	}

	// Get IAK attributes for signing IDevID
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return fmt.Errorf("IAK not found - run 'tpm provision' first: %w", err)
	}

	// Create IDevID
	fmt.Printf("Creating IDevID for %s (serial: %s)...\n", idevidModel, idevidSerial)
	_, _, err = tpm.CreateIDevID(iakAttrs, ekCert, nil)
	if err != nil {
		return fmt.Errorf("failed to create IDevID: %w", err)
	}

	fmt.Println("IDevID created successfully")
	return nil
}

func runIDevIDExport(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get IDevID certificate
	idevidCert, err := tpm.IDevIDCertificate()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateNotFound, err)
	}

	// Encode as PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: idevidCert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Output to file or stdout
	if idevidExportOutput == "-" {
		fmt.Print(string(pemData))
		return nil
	}

	if err := os.WriteFile(idevidExportOutput, pemData, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrExportFailed, err)
	}

	fmt.Printf("IDevID certificate exported to: %s\n", idevidExportOutput)
	return nil
}

func runIDevIDCSR(cmd *cobra.Command, args []string) error {
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

	// Get IAK attributes for signing
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return fmt.Errorf("IAK not found - run 'tpm provision' first: %w", err)
	}

	// Get IDevID attributes
	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return fmt.Errorf("IDevID not found - create with 'tpm idevid create' first: %w", err)
	}

	// Create TCG-CSR-IDEVID for IDevID
	fmt.Println("Generating IDevID CSR...")
	csr, err := tpm.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, idevidAttrs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCSRGenerationFailed, err)
	}

	// Marshal CSR
	csrBytes, err := csr.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal CSR: %w", err)
	}

	// Write CSR to file
	if err := os.WriteFile(idevidCSROutput, csrBytes, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrExportFailed, err)
	}

	fmt.Printf("IDevID CSR written to: %s\n", idevidCSROutput)
	return nil
}
