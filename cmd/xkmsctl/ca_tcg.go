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
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// TCG CA command flag variables
var (
	tcgCommonName string
	tcgOrg        string
	tcgOutputFile string
	tcgEKPubFile  string
	tcgPubFile    string
	tcgCSRFile    string
	tcgPackedCSR  string

	// LAK (go-xkms#715) flag variables
	tcgLAKManufacturer string
	tcgLAKModel        string
	tcgLAKFirmware     string
	tcgLAKIAKCertFile  string
	tcgLAKCertifyInfo  string
	tcgLAKSignature    string
	tcgLAKSigAlgo      string
	tcgLAKPublicArea   string
	tcgLAKNonceFile    string
)

// caTCGCmd represents the TCG Certificate Authority command
var caTCGCmd = &cobra.Command{
	Use:   "tcg",
	Short: "TCG Certificate Authority operations",
	Long:  `Issue TCG device identity certificates and perform TPM device enrollment`,
}

// caTCGIssueEKCmd issues an Endorsement Key certificate
var caTCGIssueEKCmd = &cobra.Command{
	Use:   "issue-ek",
	Short: "Issue an EK certificate",
	Long: `Issue a Trusted Computing Group (TCG) Endorsement Key (EK) certificate.

The EK certificate attests to the identity and authenticity of a TPM's
Endorsement Key, establishing a hardware root of trust.

Examples:
  xkmsctl ca tcg issue-ek --cn "Device-001" --ek-pub ek_pub.der
  xkmsctl ca tcg issue-ek --cn "Device-001" --ek-pub ek_pub.der --org "Acme Corp" --output ek_cert.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Issuing EK certificate for CN: %s", tcgCommonName)

		issueEKCertificate(cfg, printer)
	},
}

// issueEKCertificate issues an EK certificate using the SDK client
func issueEKCertificate(cfg *Config, printer *Printer) {
	// Read EK public key file
	// #nosec G304 - EK public key file path from CLI argument
	ekPubDER, err := os.ReadFile(tcgEKPubFile)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrReadEKPublicKeyFileFailed, Err: err})
		return
	}

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

	resp, err := cl.IssueEKCertificate(ctx, &client.IssueEKCertificateRequest{
		CommonName:   tcgCommonName,
		Organization: tcgOrg,
		EKPublicKey:  ekPubDER,
	})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrIssueEKCertificateFailed, Err: err})
		return
	}

	// Write to file if output flag is set
	if tcgOutputFile != "" {
		// #nosec G306 - Certificate files need to be readable
		if err := os.WriteFile(tcgOutputFile, resp.CertificatePEM, 0644); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteEKCertificateFailed, Err: err})
			return
		}
		printVerbose("EK certificate written to: %s", tcgOutputFile)
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"serial_number": resp.SerialNumber,
		}
		if tcgOutputFile != "" {
			result["cert_file"] = tcgOutputFile
		} else {
			result["certificate_pem"] = string(resp.CertificatePEM)
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("EK Certificate Issued:\n")
		fmt.Printf("  Serial Number: %s\n", resp.SerialNumber)
		if tcgOutputFile == "" {
			fmt.Printf("\n%s", resp.CertificatePEM)
		} else {
			fmt.Printf("  Certificate:   %s\n", tcgOutputFile)
		}
	}
}

// caTCGIssueAKCmd issues an Attestation Key certificate
var caTCGIssueAKCmd = &cobra.Command{
	Use:   "issue-ak",
	Short: "Issue an AK certificate",
	Long: `Issue a Trusted Computing Group (TCG) Attestation Key (AK) certificate.

The AK certificate attests to the identity of a TPM's Attestation Key,
which is used for remote attestation and quoting operations.

Examples:
  xkmsctl ca tcg issue-ak --cn "Device-001-AK" --pub ak_pub.der
  xkmsctl ca tcg issue-ak --cn "Device-001-AK" --pub ak_pub.der --org "Acme Corp" --output ak_cert.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Issuing AK certificate for CN: %s", tcgCommonName)

		issueAKCertificate(cfg, printer)
	},
}

// issueAKCertificate issues an AK certificate using the SDK client
func issueAKCertificate(cfg *Config, printer *Printer) {
	// Read public key file
	// #nosec G304 - Public key file path from CLI argument
	pubDER, err := os.ReadFile(tcgPubFile)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrReadPublicKeyFileFailed, Err: err})
		return
	}

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

	resp, err := cl.IssueAKCertificate(ctx, &client.IssueAKCertificateRequest{
		CommonName:   tcgCommonName,
		Organization: tcgOrg,
		PublicKey:    pubDER,
	})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrIssueAKCertificateFailed, Err: err})
		return
	}

	// Write to file if output flag is set
	if tcgOutputFile != "" {
		// #nosec G306 - Certificate files need to be readable
		if err := os.WriteFile(tcgOutputFile, resp.CertificatePEM, 0644); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteAKCertificateFailed, Err: err})
			return
		}
		printVerbose("AK certificate written to: %s", tcgOutputFile)
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"serial_number": resp.SerialNumber,
		}
		if tcgOutputFile != "" {
			result["cert_file"] = tcgOutputFile
		} else {
			result["certificate_pem"] = string(resp.CertificatePEM)
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("AK Certificate Issued:\n")
		fmt.Printf("  Serial Number: %s\n", resp.SerialNumber)
		if tcgOutputFile == "" {
			fmt.Printf("\n%s", resp.CertificatePEM)
		} else {
			fmt.Printf("  Certificate:   %s\n", tcgOutputFile)
		}
	}
}

// caTCGSignCSRCmd signs a TCG-CSR-IDEVID
var caTCGSignCSRCmd = &cobra.Command{
	Use:   "sign-csr",
	Short: "Sign a TCG-CSR-IDEVID",
	Long: `Sign a packed TCG_CSR_IDEVID binary to issue IAK and IDevID certificates.

The TCG-CSR-IDEVID is a TCG-defined certificate signing request format
for device identity enrollment, containing both IAK and IDevID public keys.

Examples:
  xkmsctl ca tcg sign-csr --cn "Device-001" --csr tcg_csr.bin
  xkmsctl ca tcg sign-csr --cn "Device-001" --csr tcg_csr.bin --output /tmp/certs/`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Signing TCG-CSR-IDEVID for CN: %s", tcgCommonName)

		signTCGCSR(cfg, printer)
	},
}

// signTCGCSR signs a TCG-CSR-IDEVID using the SDK client
func signTCGCSR(cfg *Config, printer *Printer) {
	// Read packed TCG-CSR-IDEVID binary
	// #nosec G304 - TCG CSR file path from CLI argument
	csrData, err := os.ReadFile(tcgCSRFile)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrReadTCGCSRFileFailed, Err: err})
		return
	}

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

	resp, err := cl.SignTCGCSR(ctx, &client.SignTCGCSRRequest{
		CommonName:   tcgCommonName,
		Organization: tcgOrg,
		TCGCSR:       csrData,
	})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrSignTCGCSRFailed, Err: err})
		return
	}

	// Write to directory if output flag is set
	if tcgOutputFile != "" {
		if err := writeTCGCSROutput(tcgOutputFile, resp.IAKCertDER, resp.IDevIDCertDER); err != nil {
			handleError(err)
			return
		}
		printVerbose("Certificates written to: %s", tcgOutputFile)
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"iak_cert_size":    len(resp.IAKCertDER),
			"idevid_cert_size": len(resp.IDevIDCertDER),
		}
		if tcgOutputFile != "" {
			result["iak_cert_file"] = filepath.Join(tcgOutputFile, "iak_cert.der")
			result["idevid_cert_file"] = filepath.Join(tcgOutputFile, "idevid_cert.der")
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("TCG-CSR-IDEVID Signed:\n")
		fmt.Printf("  IAK Certificate:    %d bytes (DER)\n", len(resp.IAKCertDER))
		fmt.Printf("  IDevID Certificate: %d bytes (DER)\n", len(resp.IDevIDCertDER))
		if tcgOutputFile != "" {
			fmt.Printf("  IAK File:           %s\n", filepath.Join(tcgOutputFile, "iak_cert.der"))
			fmt.Printf("  IDevID File:        %s\n", filepath.Join(tcgOutputFile, "idevid_cert.der"))
		} else {
			// Print PEM-encoded certificates to stdout
			iakPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: resp.IAKCertDER,
			})
			idevPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: resp.IDevIDCertDER,
			})
			fmt.Printf("\n--- IAK Certificate (PEM) ---\n%s", iakPEM)
			fmt.Printf("\n--- IDevID Certificate (PEM) ---\n%s", idevPEM)
		}
	}
}

// writeTCGCSROutput writes IAK and IDevID DER certificates to the output directory.
func writeTCGCSROutput(dir string, iakDER, idevidDER []byte) error {
	// #nosec G301 - Output directory for certificates
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &WrappedError{Sentinel: ErrCreateOutputDirectoryFailed, Err: err}
	}

	iakPath := filepath.Join(dir, "iak_cert.der")
	// #nosec G306 - Certificate files need to be readable
	if err := os.WriteFile(iakPath, iakDER, 0644); err != nil {
		return &WrappedError{Sentinel: ErrWriteIAKCertificateFailed, Err: err}
	}

	idevidPath := filepath.Join(dir, "idevid_cert.der")
	// #nosec G306 - Certificate files need to be readable
	if err := os.WriteFile(idevidPath, idevidDER, 0644); err != nil {
		return &WrappedError{Sentinel: ErrWriteIDevIDCertificateFailed, Err: err}
	}

	return nil
}

// caTCGEnrollCmd performs full device enrollment
var caTCGEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll a TPM device",
	Long: `Perform full TCG device enrollment using a packed TCG_CSR_IDEVID.

This command performs the complete enrollment flow:
  1. Validates the packed CSR
  2. Issues IAK and IDevID certificates
  3. Creates a credential activation challenge
  4. Returns certificates and challenge for the device

Examples:
  xkmsctl ca tcg enroll --cn "Device-001" --packed-csr tcg_csr.bin
  xkmsctl ca tcg enroll --cn "Device-001" --packed-csr tcg_csr.bin --output /tmp/enrollment/`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Enrolling device for CN: %s", tcgCommonName)

		enrollDevice(cfg, printer)
	},
}

// enrollDevice performs full device enrollment using the SDK client
func enrollDevice(cfg *Config, printer *Printer) {
	// Read packed CSR binary
	// #nosec G304 - Packed CSR file path from CLI argument
	packedCSR, err := os.ReadFile(tcgPackedCSR)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrReadPackedCSRFileFailed, Err: err})
		return
	}

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

	resp, err := cl.EnrollDevice(ctx, &client.EnrollDeviceRequest{
		CommonName:   tcgCommonName,
		Organization: tcgOrg,
		PackedCSR:    packedCSR,
	})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrEnrollDeviceFailed, Err: err})
		return
	}

	// Write to directory if output flag is set
	if tcgOutputFile != "" {
		if err := writeEnrollmentOutput(tcgOutputFile, resp); err != nil {
			handleError(err)
			return
		}
		printVerbose("Enrollment output written to: %s", tcgOutputFile)
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"iak_cert_size":        len(resp.IAKCertDER),
			"idevid_cert_size":     len(resp.IDevIDCertDER),
			"credential_blob_size": len(resp.CredentialBlob),
			"has_challenge":        len(resp.EncryptedSecret) > 0,
		}
		if tcgOutputFile != "" {
			result["output_dir"] = tcgOutputFile
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("Device Enrollment Complete:\n")
		fmt.Printf("  IAK Certificate:    %d bytes (DER)\n", len(resp.IAKCertDER))
		fmt.Printf("  IDevID Certificate: %d bytes (DER)\n", len(resp.IDevIDCertDER))
		fmt.Printf("  Credential Blob:    %d bytes\n", len(resp.CredentialBlob))
		fmt.Printf("  Encrypted Secret:   %d bytes\n", len(resp.EncryptedSecret))
		if tcgOutputFile != "" {
			fmt.Printf("  Output Directory:   %s\n", tcgOutputFile)
		}
	}
}

// writeEnrollmentOutput writes enrollment artifacts to the output directory.
func writeEnrollmentOutput(dir string, resp *client.EnrollDeviceResponse) error {
	// #nosec G301 - Output directory for enrollment artifacts
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &WrappedError{Sentinel: ErrCreateOutputDirectoryFailed, Err: err}
	}

	iakPath := filepath.Join(dir, "iak_cert.der")
	// #nosec G306 - Certificate files need to be readable
	if err := os.WriteFile(iakPath, resp.IAKCertDER, 0644); err != nil {
		return &WrappedError{Sentinel: ErrWriteIAKCertificateFailed, Err: err}
	}

	idevidPath := filepath.Join(dir, "idevid_cert.der")
	// #nosec G306 - Certificate files need to be readable
	if err := os.WriteFile(idevidPath, resp.IDevIDCertDER, 0644); err != nil {
		return &WrappedError{Sentinel: ErrWriteIDevIDCertificateFailed, Err: err}
	}

	if len(resp.CredentialBlob) > 0 {
		blobPath := filepath.Join(dir, "credential_blob.bin")
		// #nosec G306 - Credential blob needs to be readable by device
		if err := os.WriteFile(blobPath, resp.CredentialBlob, 0644); err != nil {
			return &WrappedError{Sentinel: ErrWriteCredentialBlobFailed, Err: err}
		}
	}

	if len(resp.EncryptedSecret) > 0 {
		secretPath := filepath.Join(dir, "encrypted_secret.bin")
		// #nosec G306 - Encrypted secret needs to be readable by device
		if err := os.WriteFile(secretPath, resp.EncryptedSecret, 0644); err != nil {
			return &WrappedError{Sentinel: ErrWriteEncryptedSecretFailed, Err: err}
		}
	}

	return nil
}

// caTCGIssueLAKCmd issues a Local Attestation Key certificate
var caTCGIssueLAKCmd = &cobra.Command{
	Use:   "issue-lak",
	Short: "Issue a Local Attestation Key certificate",
	Long: `Issue a Local Attestation Key (LAK) certificate in the WebAuthn Level 2
section 8.3.1 "TPM Attestation Statement Certificate Requirements" profile
(go-xkms#715): an empty Subject, a critical subjectAltName carrying the TPM
manufacturer/model/firmware version, the tcg-kp-AIKCertificate EKU, and
Basic Constraints CA:false.

The LAK must already have been created on the device and certified under its
IAK via TPM2_Certify (` + "`xkey tpm lak create`" + `). This command submits that
evidence -- the IAK's own certificate, the raw TPM2_Certify certifyInfo and
signature, the LAK's public area, and the nonce the evidence echoes -- for
the CA to verify before issuing.

Examples:
  xkmsctl ca tcg issue-lak \
    --tpm-manufacturer id:49465800 --tpm-model NPCT6xx --tpm-firmware 7.2.3.1 \
    --iak-cert iak_cert.der --certify-info certify_info.bin --signature signature.bin \
    --signature-algorithm ECDSA-SHA256 --lak-public-area lak_pub_area.bin \
    --nonce nonce.bin --output lak_cert.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Issuing LAK certificate")

		issueLAKCertificate(cfg, printer)
	},
}

// issueLAKCertificate issues a LAK certificate using the SDK client
func issueLAKCertificate(cfg *Config, printer *Printer) {
	// #nosec G304 - IAK certificate file path from CLI argument
	iakCertDER, err := os.ReadFile(tcgLAKIAKCertFile)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrReadIAKCertificateFileFailed, Err: err})
		return
	}
	// #nosec G304 - certify info file path from CLI argument
	certifyInfo, err := os.ReadFile(tcgLAKCertifyInfo)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrReadCertifyInfoFileFailed, Err: err})
		return
	}
	// #nosec G304 - signature file path from CLI argument
	signature, err := os.ReadFile(tcgLAKSignature)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrReadSignatureFileFailed, Err: err})
		return
	}
	// #nosec G304 - LAK public area file path from CLI argument
	lakPublicArea, err := os.ReadFile(tcgLAKPublicArea)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrReadLAKPublicAreaFileFailed, Err: err})
		return
	}
	var nonce []byte
	if tcgLAKNonceFile != "" {
		// #nosec G304 - nonce file path from CLI argument
		nonce, err = os.ReadFile(tcgLAKNonceFile)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadNonceFileFailed, Err: err})
			return
		}
	}

	sigAlg, err := client.ParseSignatureAlgorithm(tcgLAKSigAlgo)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrInvalidSignatureAlgorithm, Err: err})
		return
	}

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

	resp, err := cl.IssueLAKCertificate(ctx, &client.IssueLAKCertificateRequest{
		TPMManufacturer:    tcgLAKManufacturer,
		TPMModel:           tcgLAKModel,
		TPMFirmwareVersion: tcgLAKFirmware,
		IAKCertificateDER:  iakCertDER,
		CertifyInfo:        certifyInfo,
		Signature:          signature,
		SignatureAlgorithm: int(sigAlg),
		LAKPublicArea:      lakPublicArea,
		Nonce:              nonce,
	})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrIssueLAKCertificateFailed, Err: err})
		return
	}

	if tcgOutputFile != "" {
		// #nosec G306 - Certificate files need to be readable
		if err := os.WriteFile(tcgOutputFile, resp.CertificatePEM, 0644); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteLAKCertificateFailed, Err: err})
			return
		}
		printVerbose("LAK certificate written to: %s", tcgOutputFile)
	}

	if cfg.OutputFormat == "json" {
		result := map[string]interface{}{
			"serial_number": resp.SerialNumber,
		}
		if tcgOutputFile != "" {
			result["cert_file"] = tcgOutputFile
		} else {
			result["certificate_pem"] = string(resp.CertificatePEM)
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("LAK Certificate Issued:\n")
		fmt.Printf("  Serial Number: %s\n", resp.SerialNumber)
		if tcgOutputFile == "" {
			fmt.Printf("\n%s", resp.CertificatePEM)
		} else {
			fmt.Printf("  Certificate:   %s\n", tcgOutputFile)
		}
	}
}

func init() {
	// ca tcg issue-ek flags
	caTCGIssueEKCmd.Flags().StringVar(&tcgCommonName, "cn", "", "common name for the EK certificate (required)")
	markFlagRequired(caTCGIssueEKCmd, "cn")
	caTCGIssueEKCmd.Flags().StringVar(&tcgEKPubFile, "ek-pub", "", "path to DER-encoded EK public key file (required)")
	markFlagRequired(caTCGIssueEKCmd, "ek-pub")
	caTCGIssueEKCmd.Flags().StringVar(&tcgOrg, "org", "", "organization name")
	caTCGIssueEKCmd.Flags().StringVar(&tcgOutputFile, "output", "", "output file for certificate (PEM)")

	// ca tcg issue-ak flags
	caTCGIssueAKCmd.Flags().StringVar(&tcgCommonName, "cn", "", "common name for the AK certificate (required)")
	markFlagRequired(caTCGIssueAKCmd, "cn")
	caTCGIssueAKCmd.Flags().StringVar(&tcgPubFile, "pub", "", "path to DER-encoded public key file (required)")
	markFlagRequired(caTCGIssueAKCmd, "pub")
	caTCGIssueAKCmd.Flags().StringVar(&tcgOrg, "org", "", "organization name")
	caTCGIssueAKCmd.Flags().StringVar(&tcgOutputFile, "output", "", "output file for certificate (PEM)")

	// ca tcg sign-csr flags
	caTCGSignCSRCmd.Flags().StringVar(&tcgCommonName, "cn", "", "common name for the device identity (required)")
	markFlagRequired(caTCGSignCSRCmd, "cn")
	caTCGSignCSRCmd.Flags().StringVar(&tcgCSRFile, "csr", "", "path to packed TCG_CSR_IDEVID binary file (required)")
	markFlagRequired(caTCGSignCSRCmd, "csr")
	caTCGSignCSRCmd.Flags().StringVar(&tcgOrg, "org", "", "organization name")
	caTCGSignCSRCmd.Flags().StringVar(&tcgOutputFile, "output", "", "output directory for certificate files (DER)")

	// ca tcg enroll flags
	caTCGEnrollCmd.Flags().StringVar(&tcgCommonName, "cn", "", "common name for the device (required)")
	markFlagRequired(caTCGEnrollCmd, "cn")
	caTCGEnrollCmd.Flags().StringVar(&tcgPackedCSR, "packed-csr", "", "path to packed TCG_CSR_IDEVID binary file (required)")
	markFlagRequired(caTCGEnrollCmd, "packed-csr")
	caTCGEnrollCmd.Flags().StringVar(&tcgOrg, "org", "", "organization name")
	caTCGEnrollCmd.Flags().StringVar(&tcgOutputFile, "output", "", "output directory for enrollment files")

	// ca tcg issue-lak flags
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKManufacturer, "tpm-manufacturer", "", "TCG TPM manufacturer code, e.g. id:49465800 (required)")
	markFlagRequired(caTCGIssueLAKCmd, "tpm-manufacturer")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKModel, "tpm-model", "", "TPM model string (required)")
	markFlagRequired(caTCGIssueLAKCmd, "tpm-model")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKFirmware, "tpm-firmware", "", "TPM firmware version (required)")
	markFlagRequired(caTCGIssueLAKCmd, "tpm-firmware")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKIAKCertFile, "iak-cert", "", "path to the device's IAK certificate (DER, required)")
	markFlagRequired(caTCGIssueLAKCmd, "iak-cert")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKCertifyInfo, "certify-info", "", "path to the raw TPM2_Certify certifyInfo (TPMS_ATTEST, required)")
	markFlagRequired(caTCGIssueLAKCmd, "certify-info")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKSignature, "signature", "", "path to the IAK's signature over certifyInfo (required)")
	markFlagRequired(caTCGIssueLAKCmd, "signature")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKSigAlgo, "signature-algorithm", "", "the IAK's X.509 signature algorithm, e.g. ECDSA-SHA256 (required)")
	markFlagRequired(caTCGIssueLAKCmd, "signature-algorithm")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKPublicArea, "lak-public-area", "", "path to the LAK's marshalled TPMT_PUBLIC (required)")
	markFlagRequired(caTCGIssueLAKCmd, "lak-public-area")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgLAKNonceFile, "nonce", "", "path to the qualifying data the evidence must echo")
	caTCGIssueLAKCmd.Flags().StringVar(&tcgOutputFile, "output", "", "output file for certificate (PEM)")

	// Add subcommands to caTCGCmd
	caTCGCmd.AddCommand(caTCGIssueEKCmd)
	caTCGCmd.AddCommand(caTCGIssueAKCmd)
	caTCGCmd.AddCommand(caTCGSignCSRCmd)
	caTCGCmd.AddCommand(caTCGEnrollCmd)
	caTCGCmd.AddCommand(caTCGIssueLAKCmd)

	// Wire caTCGCmd as subcommand of caCmd
	caCmd.AddCommand(caTCGCmd)
}
