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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// KeyStatus represents the status of a TPM key
type KeyStatus struct {
	Name               string `json:"name"`
	Handle             string `json:"handle"`
	Present            bool   `json:"present"`
	Algorithm          string `json:"algorithm,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	Error              string `json:"error,omitempty"`
}

// CertStatus represents the status of a certificate
type CertStatus struct {
	Name      string `json:"name"`
	NVIndex   string `json:"nv_index"`
	Present   bool   `json:"present"`
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
	Error     string `json:"error,omitempty"`
}

// PlatformPolicyStatus represents platform policy configuration
type PlatformPolicyStatus struct {
	PCRBank      string `json:"pcr_bank"`
	GoldenPCRs   []uint `json:"golden_pcrs"`
	PlatformPCR  uint   `json:"platform_pcr"`
	PolicyDigest string `json:"policy_digest"`
	Configured   bool   `json:"configured"`
}

// PCRValueStatus represents a PCR value for status output
type PCRValueStatus struct {
	Index int    `json:"index"`
	Value string `json:"value"`
}

// TPMStatusOutput holds the complete TPM status
type TPMStatusOutput struct {
	Device          string               `json:"device"`
	Manufacturer    string               `json:"manufacturer"`
	VendorID        string               `json:"vendor_id"`
	Firmware        string               `json:"firmware"`
	Type            string               `json:"type"`
	Provisioned     bool                 `json:"provisioned"`
	Keys            []KeyStatus          `json:"keys"`
	Certificates    []CertStatus         `json:"certificates"`
	PlatformPolicy  PlatformPolicyStatus `json:"platform_policy"`
	GoldenPCRValues []PCRValueStatus     `json:"golden_pcr_values,omitempty"`
}

// tpmStatusCmd represents the tpm status command
var tpmStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display TPM provisioning status",
	Long: `Display comprehensive TPM provisioning status including:
  - Device information (manufacturer, firmware)
  - Key status for each key type (EK, SSRK, IAK, IDevID)
  - Certificate status (EK cert from NV RAM, IDevID cert)
  - Platform policy information (PCR bank, golden PCRs, policy digest)
  - Current PCR values for the golden PCRs

Examples:
  # Show TPM status in text format
  xkey tpm status

  # Show TPM status in JSON format
  xkey tpm status -o json

  # Show TPM status for simulator
  xkey tpm status --simulator`,
	RunE: runTPMStatus,
}

func init() {
	tpmCmd.AddCommand(tpmStatusCmd)
}

func runTPMStatus(cmd *cobra.Command, args []string) error {
	// Open TPM - don't require it to be initialized
	tpm, err := openTPMForProvisioning()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTPMDeviceNotFound, err)
	}
	defer tpm.Close()

	// Get fixed properties for device info
	props, err := tpm.FixedProperties()
	if err != nil {
		return fmt.Errorf("%w: failed to get TPM properties: %v", ErrTPMOperationFailed, err)
	}

	// Build status output
	status := buildTPMStatus(tpm, props)

	// Output based on format
	switch tpmCfg.outputFormat {
	case "json":
		return outputStatusJSON(status)
	default:
		return outputStatusText(status)
	}
}

func buildTPMStatus(tpm tpm2pkg.TrustedPlatformModule, props *tpm2pkg.PropertiesFixed) *TPMStatusOutput {
	config := tpm.Config()

	status := &TPMStatusOutput{
		Device:       tpm.Device(),
		Manufacturer: props.Manufacturer,
		VendorID:     strings.TrimSpace(props.VendorID),
		Firmware:     fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor),
	}

	// Determine TPM type
	if tpmCfg.useSimulator {
		status.Type = "Simulator"
	} else {
		status.Type = "Hardware"
	}

	// Build key status
	status.Keys = buildKeyStatus(tpm, config)

	// Build certificate status
	status.Certificates = buildCertStatus(tpm, config)

	// Check if provisioned (EK and SSRK present)
	for _, key := range status.Keys {
		if key.Name == "EK" && key.Present {
			status.Provisioned = true
			break
		}
	}
	for _, key := range status.Keys {
		if key.Name == "SSRK" && !key.Present {
			status.Provisioned = false
			break
		}
	}

	// Build platform policy status
	status.PlatformPolicy = buildPlatformPolicyStatus(tpm, config)

	// Get golden PCR values
	goldenPCRs := config.GoldenPCRs
	if len(goldenPCRs) == 0 {
		// Default golden PCRs
		goldenPCRs = []uint{0, 7, 9, 10}
	}

	pcrValues, err := tpm.ReadPCRs(goldenPCRs)
	if err == nil && len(pcrValues) > 0 {
		// Use the configured PCR bank, default to SHA256
		targetBank := strings.ToUpper(config.PlatformPCRBank)
		if targetBank == "" {
			targetBank = "SHA256"
		}

		for _, bank := range pcrValues {
			if strings.EqualFold(bank.Algorithm, targetBank) {
				for _, pcr := range bank.PCRs {
					status.GoldenPCRValues = append(status.GoldenPCRValues, PCRValueStatus{
						Index: int(pcr.ID),
						Value: hex.EncodeToString(pcr.Value),
					})
				}
				break
			}
		}
	}

	return status
}

func buildKeyStatus(tpm tpm2pkg.TrustedPlatformModule, config *tpm2pkg.Config) []KeyStatus {
	keys := make([]KeyStatus, 0, 4)

	// EK Status
	ekStatus := KeyStatus{
		Name:   "EK",
		Handle: fmt.Sprintf("0x%08X", config.EK.Handle),
	}
	if ekAttrs, err := tpm.EKAttributes(); err == nil {
		ekStatus.Present = true
		ekStatus.Algorithm = formatKeyAlgorithmFromAttrs(ekAttrs)
	} else {
		ekStatus.Error = simplifyError(err)
	}
	keys = append(keys, ekStatus)

	// SSRK Status
	ssrkStatus := KeyStatus{
		Name:   "SSRK",
		Handle: fmt.Sprintf("0x%08X", config.SSRK.Handle),
	}
	if ssrkAttrs, err := tpm.SSRKAttributes(); err == nil {
		ssrkStatus.Present = true
		ssrkStatus.Algorithm = formatKeyAlgorithmFromAttrs(ssrkAttrs)
	} else {
		ssrkStatus.Error = simplifyError(err)
	}
	keys = append(keys, ssrkStatus)

	// IAK Status
	iakStatus := KeyStatus{
		Name:   "IAK",
		Handle: fmt.Sprintf("0x%08X", config.IAK.Handle),
	}
	if iakAttrs, err := tpm.IAKAttributes(); err == nil {
		iakStatus.Present = true
		iakStatus.Algorithm = formatKeyAlgorithmFromAttrs(iakAttrs)
		if iakAttrs.SignatureAlgorithm != 0 {
			iakStatus.SignatureAlgorithm = iakAttrs.SignatureAlgorithm.String()
		}
	} else {
		iakStatus.Error = simplifyError(err)
	}
	keys = append(keys, iakStatus)

	// IDevID Status
	idevidStatus := KeyStatus{
		Name:   "IDevID",
		Handle: fmt.Sprintf("0x%08X", config.IDevID.Handle),
	}
	if idevidAttrs, err := tpm.IDevIDAttributes(); err == nil {
		idevidStatus.Present = true
		idevidStatus.Algorithm = formatKeyAlgorithmFromAttrs(idevidAttrs)
		if idevidAttrs.SignatureAlgorithm != 0 {
			idevidStatus.SignatureAlgorithm = idevidAttrs.SignatureAlgorithm.String()
		}
	} else {
		idevidStatus.Error = simplifyError(err)
	}
	keys = append(keys, idevidStatus)

	return keys
}

func buildCertStatus(tpm tpm2pkg.TrustedPlatformModule, config *tpm2pkg.Config) []CertStatus {
	certs := make([]CertStatus, 0, 2)

	// EK Certificate Status
	ekCertStatus := CertStatus{
		Name:    "EK Cert",
		NVIndex: fmt.Sprintf("0x%08X", config.EK.CertHandle),
	}
	if ekCert, err := tpm.EKCertificate(); err == nil && ekCert != nil {
		ekCertStatus.Present = true
		ekCertStatus.Subject = ekCert.Subject.String()
		ekCertStatus.Issuer = ekCert.Issuer.String()
		ekCertStatus.NotBefore = ekCert.NotBefore.Format("2006-01-02")
		ekCertStatus.NotAfter = ekCert.NotAfter.Format("2006-01-02")
	} else if err != nil {
		ekCertStatus.Error = simplifyError(err)
	}
	certs = append(certs, ekCertStatus)

	// IDevID Certificate Status
	idevidCertStatus := CertStatus{
		Name:    "IDevID Cert",
		NVIndex: fmt.Sprintf("0x%08X", config.IDevID.CertHandle),
	}
	if idevidCert, err := tpm.IDevIDCertificate(); err == nil && idevidCert != nil {
		idevidCertStatus.Present = true
		idevidCertStatus.Subject = idevidCert.Subject.String()
		idevidCertStatus.Issuer = idevidCert.Issuer.String()
		idevidCertStatus.NotBefore = idevidCert.NotBefore.Format("2006-01-02")
		idevidCertStatus.NotAfter = idevidCert.NotAfter.Format("2006-01-02")
	} else if err != nil {
		idevidCertStatus.Error = simplifyError(err)
	}
	certs = append(certs, idevidCertStatus)

	return certs
}

func buildPlatformPolicyStatus(tpm tpm2pkg.TrustedPlatformModule, config *tpm2pkg.Config) PlatformPolicyStatus {
	policyStatus := PlatformPolicyStatus{
		PCRBank:     config.PlatformPCRBank,
		PlatformPCR: config.PlatformPCR,
		GoldenPCRs:  config.GoldenPCRs,
	}

	if policyStatus.PCRBank == "" {
		policyStatus.PCRBank = "sha256"
	}

	if len(policyStatus.GoldenPCRs) == 0 {
		policyStatus.GoldenPCRs = []uint{0, 7, 9, 10}
	}

	// Try to get policy digest
	policyDigest, pdErr := tpm.PlatformPolicyDigest()
	if pdErr == nil && len(policyDigest.Buffer) > 0 {
		policyStatus.PolicyDigest = hex.EncodeToString(policyDigest.Buffer)
		policyStatus.Configured = true
	} else {
		policyStatus.PolicyDigest = "(not set)"
	}

	return policyStatus
}

// formatKeyAlgorithmFromAttrs formats the key algorithm from KeyAttributes
func formatKeyAlgorithmFromAttrs(attrs *types.KeyAttributes) string {
	if attrs == nil {
		return "Unknown"
	}

	algo := attrs.KeyAlgorithm.String()

	// Check for RSA attributes with key size
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
		return fmt.Sprintf("%s-%d", algo, attrs.RSAAttributes.KeySize)
	}

	// Check for ECC attributes with curve
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		curveName := attrs.ECCAttributes.Curve.Params().Name
		return fmt.Sprintf("%s-%s", algo, curveName)
	}

	return algo
}

func simplifyError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	// Simplify common TPM errors
	if strings.Contains(errStr, "0x18b") || strings.Contains(errStr, "handle") {
		return "not found"
	}
	if strings.Contains(errStr, "0x184") {
		return "not found"
	}
	if strings.Contains(errStr, "not initialized") {
		return "not initialized"
	}
	// Truncate long error messages
	if len(errStr) > 50 {
		return errStr[:47] + "..."
	}
	return errStr
}

func outputStatusJSON(status *TPMStatusOutput) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}

func outputStatusText(status *TPMStatusOutput) error {
	fmt.Println("TPM Provisioning Status")
	fmt.Println("=======================")
	fmt.Println()

	// Device info
	fmt.Printf("Device:          %s\n", status.Device)
	fmt.Printf("Manufacturer:    %s\n", status.Manufacturer)
	if status.VendorID != "" {
		fmt.Printf("Vendor ID:       %s\n", status.VendorID)
	}
	fmt.Printf("Firmware:        %s\n", status.Firmware)
	fmt.Printf("Type:            %s\n", status.Type)
	fmt.Printf("Provisioned:     %s\n", formatBoolStatus(status.Provisioned))
	fmt.Println()

	// Keys
	fmt.Println("Keys:")
	for _, key := range status.Keys {
		symbol := "x"
		stateText := "Not Present"
		if key.Present {
			symbol := "+"
			stateText = "Present"
			if key.Algorithm != "" {
				stateText += " (" + key.Algorithm
				if key.SignatureAlgorithm != "" {
					stateText += ", " + key.SignatureAlgorithm
				}
				stateText += ")"
			}
			fmt.Printf("  %-6s (%s): %s %s\n", key.Name, key.Handle, symbol, stateText)
		} else {
			if key.Error != "" && key.Error != "not found" {
				stateText = "Error: " + key.Error
			}
			fmt.Printf("  %-6s (%s): %s %s\n", key.Name, key.Handle, symbol, stateText)
		}
	}
	fmt.Println()

	// Certificates
	fmt.Println("Certificates:")
	for _, cert := range status.Certificates {
		symbol := "x"
		stateText := "Not Present"
		if cert.Present {
			symbol = "+"
			stateText = "Present"
			if cert.Subject != "" {
				// Truncate long subjects
				subject := cert.Subject
				if len(subject) > 40 {
					subject = subject[:37] + "..."
				}
				stateText += " (" + subject + ")"
			}
		} else if cert.Error != "" && cert.Error != "not found" {
			stateText = "Error: " + cert.Error
		}
		fmt.Printf("  %-12s (NV %s): %s %s\n", cert.Name, cert.NVIndex, symbol, stateText)
	}
	fmt.Println()

	// Platform Policy
	fmt.Println("Platform Policy:")
	fmt.Printf("  PCR Bank:        %s\n", status.PlatformPolicy.PCRBank)
	fmt.Printf("  Golden PCRs:     %v\n", status.PlatformPolicy.GoldenPCRs)
	fmt.Printf("  Platform PCR:    %d\n", status.PlatformPolicy.PlatformPCR)
	if status.PlatformPolicy.Configured {
		// Truncate long digest for display
		digest := status.PlatformPolicy.PolicyDigest
		if len(digest) > 32 {
			digest = digest[:32] + "..."
		}
		fmt.Printf("  Policy Digest:   %s\n", digest)
	} else {
		fmt.Printf("  Policy Digest:   %s\n", status.PlatformPolicy.PolicyDigest)
	}
	fmt.Println()

	// Golden PCR Values
	if len(status.GoldenPCRValues) > 0 {
		fmt.Printf("Current PCR Values (%s):\n", status.PlatformPolicy.PCRBank)
		for _, pcr := range status.GoldenPCRValues {
			// Truncate long values for display
			value := pcr.Value
			if len(value) > 64 {
				value = value[:64] + "..."
			}
			fmt.Printf("  PCR[%2d]: %s\n", pcr.Index, value)
		}
	}

	return nil
}

func formatBoolStatus(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// getKeyAlgorithmDetails extracts key algorithm details from TPM public key
func getKeyAlgorithmDetails(pub tpm2.TPMTPublic) string {
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		if rsaDetail, err := pub.Parameters.RSADetail(); err == nil {
			return fmt.Sprintf("RSA-%d", rsaDetail.KeyBits)
		}
		return "RSA"
	case tpm2.TPMAlgECC:
		if eccDetail, err := pub.Parameters.ECCDetail(); err == nil {
			switch eccDetail.CurveID {
			case tpm2.TPMECCNistP256:
				return "ECC-P256"
			case tpm2.TPMECCNistP384:
				return "ECC-P384"
			case tpm2.TPMECCNistP521:
				return "ECC-P521"
			default:
				return "ECC"
			}
		}
		return "ECC"
	default:
		return "Unknown"
	}
}
