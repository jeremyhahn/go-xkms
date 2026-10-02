// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// LAK certificate error types.
var (
	ErrLAKCertifyFailed      = errors.New("tpm: failed to certify LAK")
	ErrLAKCertImportFailed   = errors.New("tpm: failed to import LAK certificate")
	ErrLAKPublicKeyMismatch  = errors.New("tpm: certificate public key does not match LAK key")
	ErrLAKInvalidCertificate = errors.New("tpm: invalid certificate format")
)

var (
	lakCertifyInfoOutput string
	lakSignatureOutput   string
	lakPublicAreaOutput  string
	lakCertifyNonce      string
	lakCertImportPath    string
	lakCertImportForce   bool
)

// tpmLAKCertCmd represents the tpm lak cert command group.
var tpmLAKCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "LAK certificate operations",
	Long: `LAK certificate operations (go-xkms#715).

Manage the Local Attestation Key's WebAuthn Level 2 section 8.3.1 profile
certificate:
  - Certify the LAK under the IAK and export the TPM2_Certify evidence a CA
    needs to issue the certificate
  - Import the CA-issued certificate once received

Self-signed LAK certificates are not supported - use a proper CA (go-xkms
CA via 'xkmsctl ca tcg issue-lak', or an external CA) to issue certificates.

Subcommands:
  export  - Certify the LAK and export TPM2_Certify evidence
  import  - Import a CA-signed LAK certificate`,
}

// tpmLAKCertExportCmd certifies the LAK under the IAK and exports the
// TPM2_Certify evidence a CA needs to issue the LAK certificate.
var tpmLAKCertExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Certify the LAK and export TPM2_Certify evidence",
	Long: `Certify the Local Attestation Key under the Initial Attestation Key via
TPM2_Certify, and export the resulting evidence to files.

The three output files, together with the device's IAK certificate
('xkey tpm iak export'), the TPM manufacturer/model/firmware identifiers
('xkey tpm info'), and an optional nonce, are the evidence
'xkmsctl ca tcg issue-lak' submits to the CA to issue the LAK's WebAuthn
Level 2 section 8.3.1 profile certificate.

Examples:
  # Certify the LAK and export its evidence
  xkey tpm lak cert export \
    --certify-info lak-certify-info.bin \
    --signature lak-signature.bin \
    --public-area lak-public-area.bin

  # Certify the LAK with an explicit freshness nonce
  xkey tpm lak cert export \
    --certify-info lak-certify-info.bin \
    --signature lak-signature.bin \
    --public-area lak-public-area.bin \
    --nonce abc123`,
	RunE: runLAKCertExport,
}

// tpmLAKCertImportCmd imports a CA-signed LAK certificate.
var tpmLAKCertImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import signed LAK certificate",
	Long: `Import a CA-signed Local Attestation Key certificate.

This command imports a certificate that was issued by a Certificate
Authority (e.g. via 'xkmsctl ca tcg issue-lak') in the WebAuthn Level 2
section 8.3.1 profile. The certificate's public key must match the LAK
key in the TPM.

Self-signed certificates are NOT accepted.

Examples:
  # Import a CA-signed LAK certificate
  xkey tpm lak cert import --cert lak.crt

  # Force import (skip public key verification)
  xkey tpm lak cert import --cert lak.crt --force`,
	RunE: runLAKCertImport,
}

func init() {
	tpmLAKCmd.AddCommand(tpmLAKCertCmd)
	tpmLAKCertCmd.AddCommand(tpmLAKCertExportCmd)
	tpmLAKCertCmd.AddCommand(tpmLAKCertImportCmd)

	tpmLAKCertExportCmd.Flags().StringVar(&lakCertifyInfoOutput, "certify-info", "",
		"Output file for the raw TPM2_Certify certifyInfo (TPMS_ATTEST)")
	_ = tpmLAKCertExportCmd.MarkFlagRequired("certify-info")
	tpmLAKCertExportCmd.Flags().StringVar(&lakSignatureOutput, "signature", "",
		"Output file for the IAK's signature over certifyInfo")
	_ = tpmLAKCertExportCmd.MarkFlagRequired("signature")
	tpmLAKCertExportCmd.Flags().StringVar(&lakPublicAreaOutput, "public-area", "",
		"Output file for the LAK's marshalled TPMT_PUBLIC")
	_ = tpmLAKCertExportCmd.MarkFlagRequired("public-area")
	tpmLAKCertExportCmd.Flags().StringVar(&lakCertifyNonce, "nonce", "",
		"Hex-encoded qualifying data the evidence echoes")

	tpmLAKCertImportCmd.Flags().StringVar(&lakCertImportPath, "cert", "",
		"Path to PEM-encoded certificate file")
	_ = tpmLAKCertImportCmd.MarkFlagRequired("cert")
	tpmLAKCertImportCmd.Flags().BoolVar(&lakCertImportForce, "force", false,
		"Force import without public key verification")
}

func runLAKCertExport(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()

	var nonce []byte
	if lakCertifyNonce != "" {
		nonce, err = hex.DecodeString(lakCertifyNonce)
		if err != nil {
			return &DetailError{Err: ErrInvalidNonce, Detail: ": nonce must be hex-encoded"}
		}
	}

	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if _, err := tpm.LAKAttributes(); err != nil {
		return &WrappedError{Msg: "LAK not found - run 'tpm lak create' first", Err: err}
	}

	_, _ = fmt.Fprintln(out, "Certifying LAK under IAK...")
	result, err := tpm.CertifyLAK(nonce, nil)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrLAKCertifyFailed, Cause: err}
	}

	if err := os.WriteFile(lakCertifyInfoOutput, result.CertifyInfo, 0600); err != nil {
		return &SentinelCauseError{Sentinel: ErrExportFailed, Cause: err}
	}
	if err := os.WriteFile(lakSignatureOutput, result.Signature, 0600); err != nil {
		return &SentinelCauseError{Sentinel: ErrExportFailed, Cause: err}
	}
	if err := os.WriteFile(lakPublicAreaOutput, result.AttestedKeyPublicArea, 0600); err != nil {
		return &SentinelCauseError{Sentinel: ErrExportFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Certify info written to:    %s\n", lakCertifyInfoOutput)
	_, _ = fmt.Fprintf(out, "Signature written to:       %s\n", lakSignatureOutput)
	_, _ = fmt.Fprintf(out, "LAK public area written to: %s\n", lakPublicAreaOutput)
	_, _ = fmt.Fprintf(out, "Signature algorithm:        %s\n", result.SignatureAlgorithm.String())
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Submit this evidence, together with the device's IAK certificate")
	_, _ = fmt.Fprintln(out, "(xkey tpm iak export) and TPM manufacturer/model/firmware identifiers")
	_, _ = fmt.Fprintln(out, "(xkey tpm info), to 'xkmsctl ca tcg issue-lak' to obtain the LAK")
	_, _ = fmt.Fprintln(out, "certificate, then import it with 'xkey tpm lak cert import'.")

	return nil
}

func runLAKCertImport(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()

	pemData, err := os.ReadFile(lakCertImportPath)
	if err != nil {
		return &DetailError{Err: ErrLAKCertImportFailed, Detail: fmt.Sprintf(": failed to read certificate file: %v", err)}
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return &DetailError{Err: ErrLAKInvalidCertificate, Detail: ": failed to decode PEM data"}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &DetailError{Err: ErrLAKInvalidCertificate, Detail: fmt.Sprintf(": failed to parse certificate: %v", err)}
	}

	if cert.Subject.String() == cert.Issuer.String() {
		return &DetailError{Err: ErrLAKInvalidCertificate, Detail: ": self-signed certificates are not accepted - use a CA to issue LAK certificates"}
	}

	_, _ = fmt.Fprintln(out, "Certificate to import:")
	_, _ = fmt.Fprintf(out, "  Subject: %s\n", cert.Subject.String())
	_, _ = fmt.Fprintf(out, "  Issuer:  %s\n", cert.Issuer.String())
	_, _ = fmt.Fprintf(out, "  Serial:  %s\n", cert.SerialNumber.String())
	_, _ = fmt.Fprintln(out)

	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if _, err := tpm.LAKAttributes(); err != nil {
		return &WrappedError{Msg: "LAK not found - run 'tpm lak create' first", Err: err}
	}

	lakPubKey, err := tpm.LAK()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrKeyNotFound, Cause: err}
	}

	if !lakCertImportForce {
		if !publicKeysEqual(cert.PublicKey, lakPubKey) {
			return &DetailError{Err: ErrLAKPublicKeyMismatch, Detail: ": use --force to override"}
		}
		_, _ = fmt.Fprintln(out, "Public key verification: PASSED")
	} else {
		_, _ = fmt.Fprintln(out, "Public key verification: SKIPPED (--force)")
	}

	if err := tpm.ProvisionLAKCert(cert); err != nil {
		return &SentinelCauseError{Sentinel: ErrLAKCertImportFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "LAK certificate imported successfully")
	return nil
}
