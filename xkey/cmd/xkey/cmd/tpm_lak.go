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
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// LAK CLI error types.
var (
	ErrLAKAlreadyExists = errors.New("tpm: LAK already exists")
	ErrLAKCreateFailed  = errors.New("tpm: failed to create LAK")
)

// LAKInfo holds information about the Local Attestation Key (go-xkms#715).
type LAKInfo struct {
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

var lakCreateForce bool

// tpmLAKCmd represents the tpm lak command group.
var tpmLAKCmd = &cobra.Command{
	Use:   "lak",
	Short: "Local Attestation Key (LAK) operations",
	Long: `Local Attestation Key (LAK) operations (go-xkms#715).

The Local Attestation Key is a Restricted, Sign-only child of the Platform
SRK, certified by the device's IAK via TPM2_Certify. It carries a
certificate in the WebAuthn Level 2 section 8.3.1 "tpm" attestation
statement profile: an empty Subject, a critical TCG subjectAltName, and the
tcg-kp-AIKCertificate EKU -- never the TCG DevID Subject the IAK's own
certificate carries. xkey's TPM-backed WebAuthn/FIDO2 authenticator attests
every credential key with the LAK, not the IAK, so a strict relying party's
empty-Subject requirement is met without contradicting the IAK's TCG DevID
Subject requirement.

Subcommands:
  show   - Display LAK public key and certificate information
  create - Create a new LAK
  cert   - Certify the LAK and import its CA-issued certificate`,
}

// tpmLAKShowCmd displays LAK information.
var tpmLAKShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display LAK public key and certificate",
	Long: `Display the Local Attestation Key public key and certificate information.

Shows:
  - Key handle and algorithm
  - Signature algorithm
  - Certificate details (if available)

Examples:
  # Show LAK information
  xkey tpm lak show

  # Show LAK information in JSON format
  xkey tpm lak show -o json`,
	RunE: runLAKShow,
}

// tpmLAKCreateCmd creates a new LAK.
var tpmLAKCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new LAK",
	Long: `Create a new Local Attestation Key.

This creates a Restricted, Sign-only child key of the Platform SRK and
persists it at the LAK handle. The device's IAK must already be provisioned
-- run 'tpm provision' first -- since certifying the LAK (via 'tpm lak
cert export') requires it.

Examples:
  # Create the LAK
  xkey tpm lak create

  # Force recreation of an existing LAK
  xkey tpm lak create --force`,
	RunE: runLAKCreate,
}

func init() {
	tpmLAKCmd.AddCommand(tpmLAKShowCmd)
	tpmLAKCmd.AddCommand(tpmLAKCreateCmd)

	tpmLAKCreateCmd.Flags().BoolVar(&lakCreateForce, "force", false,
		"Force recreation even if LAK already exists")
}

func runLAKShow(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	lakAttrs, err := tpm.LAKAttributes()
	if err != nil {
		return &DetailError{Err: ErrKeyNotFound, Detail: ": LAK not found - run 'tpm lak create' first"}
	}

	info := &LAKInfo{
		Handle:             fmt.Sprintf("0x%08x", lakAttrs.TPMAttributes.Handle),
		SignatureAlgorithm: lakAttrs.SignatureAlgorithm.String(),
	}

	switch lakAttrs.KeyAlgorithm {
	case x509.RSA:
		info.Algorithm = "RSA"
		if lakAttrs.RSAAttributes != nil {
			info.KeySize = lakAttrs.RSAAttributes.KeySize
		}
	case x509.ECDSA:
		info.Algorithm = "ECDSA"
		if lakAttrs.ECCAttributes != nil {
			info.Curve = lakAttrs.ECCAttributes.Curve.Params().Name
		}
	}

	lakCert, err := tpm.LAKCertificate()
	if err == nil && lakCert != nil {
		info.HasCert = true
		info.CertSubject = lakCert.Subject.String()
		info.CertIssuer = lakCert.Issuer.String()
		info.CertSerial = lakCert.SerialNumber.String()
		info.CertNotAfter = lakCert.NotAfter.Format("2006-01-02 15:04:05 MST")
	}

	switch tpmCfg.outputFormat {
	case "json":
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(info)
	default:
		return outputLAKText(out, info)
	}
}

func outputLAKText(out io.Writer, info *LAKInfo) error {
	_, _ = fmt.Fprintln(out, "Local Attestation Key (LAK) Information")
	_, _ = fmt.Fprintln(out, "========================================")
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintln(out, "Key Details:")
	_, _ = fmt.Fprintf(out, "  Handle:              %s\n", info.Handle)
	_, _ = fmt.Fprintf(out, "  Algorithm:           %s\n", info.Algorithm)
	if info.KeySize > 0 {
		_, _ = fmt.Fprintf(out, "  Key Size:            %d bits\n", info.KeySize)
	}
	if info.Curve != "" {
		_, _ = fmt.Fprintf(out, "  Curve:               %s\n", info.Curve)
	}
	_, _ = fmt.Fprintf(out, "  Signature Algorithm: %s\n", info.SignatureAlgorithm)
	_, _ = fmt.Fprintln(out)

	if info.HasCert {
		_, _ = fmt.Fprintln(out, "Certificate Details:")
		_, _ = fmt.Fprintf(out, "  Subject:    %s\n", info.CertSubject)
		_, _ = fmt.Fprintf(out, "  Issuer:     %s\n", info.CertIssuer)
		_, _ = fmt.Fprintf(out, "  Serial:     %s\n", info.CertSerial)
		_, _ = fmt.Fprintf(out, "  Not After:  %s\n", info.CertNotAfter)
	} else {
		_, _ = fmt.Fprintln(out, "Certificate: Not available")
	}

	return nil
}

func runLAKCreate(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if !lakCreateForce {
		if _, err := tpm.LAKAttributes(); err == nil {
			return &MessageError{Msg: ErrLAKAlreadyExists.Error() + " - use --force to recreate"}
		}
	}

	if _, err := tpm.IAKAttributes(); err != nil {
		return &WrappedError{Msg: "IAK not found - run 'tpm provision' first", Err: err}
	}

	var ownerAuth xkms.Password
	if tpmCfg.hierarchyAuth != "" {
		ownerAuth, err = xkms.NewTPMStorePassword([]byte(tpmCfg.hierarchyAuth))
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrLAKCreateFailed, Cause: err}
		}
	}

	_, _ = fmt.Fprintln(out, "Creating Local Attestation Key...")
	if _, err := tpm.CreateLAK(ownerAuth, nil, lakCreateForce); err != nil {
		return &SentinelCauseError{Sentinel: ErrLAKCreateFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(out, "LAK created successfully")
	return nil
}
