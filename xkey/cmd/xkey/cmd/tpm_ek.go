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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/spf13/cobra"
)

var (
	ekExportOutput string
	ekUseEC        bool
	ekBackupOutput string
	ekRestoreInput string
	ekRestoreForce bool
)

// tpmEKCmd represents the tpm ek command group
var tpmEKCmd = &cobra.Command{
	Use:   "ek",
	Short: "Endorsement Key (EK) operations",
	Long: `Endorsement Key (EK) operations.

The Endorsement Key is a primary key in the TPM's endorsement hierarchy.
It is typically used for:
  - TPM identity and attestation
  - Encrypting data bound to the TPM
  - Credential activation during remote attestation

Subcommands:
  show   - Display EK public key and certificate information
  export - Export EK certificate to a file`,
}

// tpmEKShowCmd displays EK information
var tpmEKShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display EK public key and certificate",
	Long: `Display the Endorsement Key public key and certificate information.

Shows:
  - Key handle and algorithm
  - Key size or curve
  - Certificate details (if available)

By default, shows the RSA EK certificate. Use --ec to show the EC certificate.

Examples:
  # Show RSA EK information (default)
  xkey tpm ek show

  # Show EC EK information
  xkey tpm ek show --ec

  # Show EK information in JSON format
  xkey tpm ek show -o json`,
	RunE: runEKShow,
}

// tpmEKExportCmd exports the EK certificate
var tpmEKExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export EK certificate to file",
	Long: `Export the Endorsement Key certificate to a PEM file.

The certificate can be used for:
  - Remote attestation verification
  - TPM identity verification
  - Certificate chain validation

By default, exports the RSA EK certificate. Use --ec to export the EC certificate.

Examples:
  # Export RSA EK certificate (default)
  xkey tpm ek export --output ek-cert.pem

  # Export EC EK certificate
  xkey tpm ek export --ec --output ek-cert-ec.pem

  # Export EK certificate to stdout
  xkey tpm ek export --output -`,
	RunE: runEKExport,
}

// tpmEKBackupCmd backs up both EK certificates
var tpmEKBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup all EK certificates to files",
	Long: `Backup manufacturer Endorsement Key certificates to files.

This command saves BOTH RSA and EC EK certificates (if available) to a
specified directory. This is STRONGLY RECOMMENDED before running
'xkey tpm provision' as manufacturer certificates cannot be recovered
once deleted.

The backup creates:
  - <output>/ek-cert-rsa.pem  (RSA EK certificate)
  - <output>/ek-cert-ec.pem   (EC EK certificate, if available)

Examples:
  # Backup EK certificates to current directory
  xkey tpm ek backup --output .

  # Backup EK certificates to specific directory
  xkey tpm ek backup --output /backup/tpm/`,
	RunE: runEKBackup,
}

// tpmEKRestoreCmd restores an EK certificate from backup
var tpmEKRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore EK certificate from backup (CAUTION)",
	Long: `Restore an Endorsement Key certificate to TPM NV RAM.

Examples:
  # Restore RSA EK certificate
  xkey tpm ek restore --input ek-cert-rsa.pem

  # Restore EC EK certificate
  xkey tpm ek restore --ec --input ek-cert-ec.pem

  # Force restore without verification
  xkey tpm ek restore --input ek-cert-rsa.pem --force`,
	RunE: runEKRestore,
}

func init() {
	// Add subcommands to ek command
	tpmEKCmd.AddCommand(tpmEKShowCmd)
	tpmEKCmd.AddCommand(tpmEKExportCmd)
	tpmEKCmd.AddCommand(tpmEKBackupCmd)
	tpmEKCmd.AddCommand(tpmEKRestoreCmd)

	// Show flags
	tpmEKShowCmd.Flags().BoolVar(&ekUseEC, "ec", false,
		"Show EC EK certificate instead of RSA (default)")

	// Export flags
	tpmEKExportCmd.Flags().BoolVar(&ekUseEC, "ec", false,
		"Export EC EK certificate instead of RSA (default)")
	tpmEKExportCmd.Flags().StringVar(&ekExportOutput, "output", "",
		"Output file path (use '-' for stdout)")
	_ = tpmEKExportCmd.MarkFlagRequired("output")

	// Backup flags
	tpmEKBackupCmd.Flags().StringVar(&ekBackupOutput, "output", ".",
		"Output directory for backup files")

	// Restore flags
	tpmEKRestoreCmd.Flags().StringVar(&ekRestoreInput, "input", "",
		"Input PEM file containing EK certificate")
	tpmEKRestoreCmd.Flags().BoolVar(&ekUseEC, "ec", false,
		"Restore EC EK certificate instead of RSA (default)")
	tpmEKRestoreCmd.Flags().BoolVar(&ekRestoreForce, "force", false,
		"Force restore without public key verification")
	_ = tpmEKRestoreCmd.MarkFlagRequired("input")
}

func runEKShow(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get EK attributes
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyNotFound, err)
	}

	// Get EK certificate based on algorithm flag
	var ekCert *x509.Certificate
	if ekUseEC {
		ekCert, err = tpm.EKCertificateEC()
		// Update attributes to reflect EC key
		ekAttrs.KeyAlgorithm = x509.ECDSA
		ekAttrs.ECCAttributes = &types.ECCAttributes{
			Curve: elliptic.P256(),
		}
		ekAttrs.RSAAttributes = nil
	} else {
		ekCert, err = tpm.EKCertificateRSA()
	}

	// Output based on format
	switch tpmCfg.outputFormat {
	case "json":
		return outputEKJSON(ekAttrs, ekCert)
	default:
		return outputEKText(ekAttrs, ekCert)
	}
}

func outputEKText(ekAttrs *types.KeyAttributes, cert *x509.Certificate) error {
	// Use standard KeyAttributes formatting (matches xkmsctl output.go PrintKeyInfo)
	fmt.Println("Key Information:")
	fmt.Printf("  CN:        %s\n", ekAttrs.CN)
	fmt.Printf("  Type:      %s\n", ekAttrs.KeyType)
	fmt.Printf("  Algorithm: %s\n", ekAttrs.KeyAlgorithm)
	fmt.Printf("  Store:     %s\n", ekAttrs.StoreType)
	fmt.Printf("  Hash:      %s\n", ekAttrs.Hash)

	if ekAttrs.TPMAttributes != nil {
		fmt.Printf("  Handle:    0x%08X\n", ekAttrs.TPMAttributes.Handle)
		if ekAttrs.TPMAttributes.CertHandle != 0 {
			fmt.Printf("  Cert NV:   0x%08X\n", ekAttrs.TPMAttributes.CertHandle)
		}
	}

	if ekAttrs.RSAAttributes != nil {
		fmt.Printf("  RSA Size:  %d bits\n", ekAttrs.RSAAttributes.KeySize)
	}
	if ekAttrs.ECCAttributes != nil {
		fmt.Printf("  ECC Curve: %s\n", ekAttrs.ECCAttributes.Curve.Params().Name)
	}

	fmt.Println()

	if cert != nil {
		// Use certstore.ToString for detailed certificate output
		fmt.Print(certstore.ToString(cert))

		// Attempt EK certificate verification against TPM manufacturer roots
		fmt.Println()
		verifyEKCertificate(cert)
	} else {
		fmt.Println("Certificate: Not available")
	}

	return nil
}

func outputEKJSON(ekAttrs *types.KeyAttributes, cert *x509.Certificate) error {
	info := map[string]interface{}{
		"cn":        ekAttrs.CN,
		"type":      ekAttrs.KeyType.String(),
		"algorithm": ekAttrs.KeyAlgorithm.String(),
		"store":     ekAttrs.StoreType.String(),
		"hash":      ekAttrs.Hash,
	}

	if ekAttrs.TPMAttributes != nil {
		info["handle"] = fmt.Sprintf("0x%08X", ekAttrs.TPMAttributes.Handle)
		if ekAttrs.TPMAttributes.CertHandle != 0 {
			info["cert_handle"] = fmt.Sprintf("0x%08X", ekAttrs.TPMAttributes.CertHandle)
		}
	}

	if ekAttrs.RSAAttributes != nil {
		info["rsa_key_size"] = ekAttrs.RSAAttributes.KeySize
	}
	if ekAttrs.ECCAttributes != nil {
		info["ecc_curve"] = ekAttrs.ECCAttributes.Curve.Params().Name
	}

	if cert != nil {
		certInfo := map[string]interface{}{
			"subject":       cert.Subject.String(),
			"issuer":        cert.Issuer.String(),
			"serial_number": cert.SerialNumber.String(),
			"not_before":    cert.NotBefore.String(),
			"not_after":     cert.NotAfter.String(),
		}

		// Attempt EK certificate verification for JSON output
		result := verifyEKCertificateResult(cert)
		if result != nil {
			certInfo["verification"] = map[string]interface{}{
				"verified":     result.Verified,
				"trust_level":  string(result.TrustLevel),
				"issuer":       result.Issuer,
				"chain_length": result.ChainLength,
				"message":      result.Message,
			}
		}

		info["certificate"] = certInfo
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(info)
}

// verifyEKCertificate attempts to verify the EK certificate against TPM
// manufacturer roots in the trust store. It prints the verification result
// to stdout. If the trust store is unavailable or verification fails, it
// prints a warning rather than returning an error.
func verifyEKCertificate(cert *x509.Certificate) {
	result := verifyEKCertificateResult(cert)
	if result == nil {
		fmt.Println("EK Certificate Verification:")
		fmt.Println("  Status: Skipped (trust store not available)")
		return
	}

	fmt.Println("EK Certificate Verification:")
	if result.Verified {
		fmt.Println("  Status:      VERIFIED")
	} else {
		fmt.Println("  Status:      NOT VERIFIED")
	}
	fmt.Printf("  Trust Level: %s\n", result.TrustLevel)
	fmt.Printf("  Issuer:      %s\n", result.Issuer)
	fmt.Printf("  Chain:       %d certificate(s)\n", result.ChainLength)
	if result.Message != "" {
		fmt.Printf("  Message:     %s\n", result.Message)
	}
}

// verifyEKCertificateResult performs the actual EK certificate verification
// against the trust store. Returns nil if the trust store cannot be opened
// or the verifier cannot be created.
func verifyEKCertificateResult(cert *x509.Certificate) *xkeyAttestation.VerificationResult {
	store, err := openTrustStore()
	if err != nil {
		return nil
	}
	defer func() { _ = store.Close() }()

	// Create verifier with the trust store. Pass nil for embedded roots
	// loader since embedded TPM manufacturer roots are not yet available.
	verifier, err := xkeyAttestation.NewVerifier(store, nil)
	if err != nil {
		return nil
	}

	result, err := verifier.VerifyTPMAttestation(cert)
	if err != nil {
		// VerifyTPMAttestation returns a partial result even on error
		if result != nil {
			return result
		}
		return &xkeyAttestation.VerificationResult{
			Verified:    false,
			TrustLevel:  xkeyAttestation.TrustLevelUnknown,
			Subject:     cert.Subject.String(),
			Issuer:      cert.Issuer.String(),
			ChainLength: 1,
			Message:     fmt.Sprintf("verification failed: %v", err),
		}
	}

	return result
}

func runEKExport(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get EK certificate based on algorithm flag
	var ekCert *x509.Certificate
	if ekUseEC {
		ekCert, err = tpm.EKCertificateEC()
	} else {
		ekCert, err = tpm.EKCertificateRSA()
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateNotFound, err)
	}

	// Encode as PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ekCert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Output to file or stdout
	if ekExportOutput == "-" {
		fmt.Print(string(pemData))
		return nil
	}

	if err := os.WriteFile(ekExportOutput, pemData, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrExportFailed, err)
	}

	fmt.Printf("EK certificate exported to: %s\n", ekExportOutput)
	return nil
}

// getEKPublicKey extracts the public key from EK attributes
func getEKPublicKey(tpm interface{}) (interface{}, error) {
	type ekGetter interface {
		EK() (interface{}, error)
		EKRSA() (*rsa.PublicKey, error)
		EKECC() (*ecdsa.PublicKey, error)
	}

	if eg, ok := tpm.(ekGetter); ok {
		pub, err := eg.EK()
		if err != nil {
			return nil, err
		}
		if pub != nil {
			return pub, nil
		}
	}

	return nil, fmt.Errorf("unable to get EK public key")
}

func runEKBackup(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Ensure output directory exists
	if err := os.MkdirAll(ekBackupOutput, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	backupCount := 0

	// Backup RSA EK certificate
	rsaCert, rsaErr := tpm.EKCertificateRSA()
	if rsaErr == nil && rsaCert != nil {
		rsaPath := fmt.Sprintf("%s/ek-cert-rsa.pem", ekBackupOutput)
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rsaCert.Raw,
		}
		if err := os.WriteFile(rsaPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return fmt.Errorf("failed to write RSA EK certificate: %w", err)
		}
		fmt.Printf("RSA EK certificate backed up to: %s\n", rsaPath)
		fmt.Printf("  Issuer: %s\n", rsaCert.Issuer.CommonName)
		fmt.Printf("  Serial: %s\n", rsaCert.SerialNumber.String())
		backupCount++
	} else {
		fmt.Println("RSA EK certificate not available")
	}

	// Backup EC EK certificate
	ecCert, ecErr := tpm.EKCertificateEC()
	if ecErr == nil && ecCert != nil {
		ecPath := fmt.Sprintf("%s/ek-cert-ec.pem", ekBackupOutput)
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ecCert.Raw,
		}
		if err := os.WriteFile(ecPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return fmt.Errorf("failed to write EC EK certificate: %w", err)
		}
		fmt.Printf("EC EK certificate backed up to: %s\n", ecPath)
		fmt.Printf("  Issuer: %s\n", ecCert.Issuer.CommonName)
		fmt.Printf("  Serial: %s\n", ecCert.SerialNumber.String())
		backupCount++
	} else {
		fmt.Println("EC EK certificate not available")
	}

	if backupCount == 0 {
		return fmt.Errorf("no EK certificates available to backup")
	}

	fmt.Printf("\nBacked up %d EK certificate(s) to: %s\n", backupCount, ekBackupOutput)
	return nil
}

func runEKRestore(cmd *cobra.Command, args []string) error {
	// Read the certificate from file
	pemData, err := os.ReadFile(ekRestoreInput)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Parse PEM
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM data")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	fmt.Println("Certificate to restore:")
	fmt.Printf("  Subject: %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:  %s\n", cert.Issuer.CommonName)
	fmt.Printf("  Serial:  %s\n", cert.SerialNumber.String())
	fmt.Println()

	// Open TPM
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Verify certificate matches EK public key (unless forced)
	if !ekRestoreForce {
		var ekCert *x509.Certificate
		if ekUseEC {
			ekCert, err = tpm.EKCertificateEC()
		} else {
			ekCert, err = tpm.EKCertificateRSA()
		}

		if err == nil && ekCert != nil {
			// Compare public keys
			switch certKey := cert.PublicKey.(type) {
			case *rsa.PublicKey:
				if ekKey, ok := ekCert.PublicKey.(*rsa.PublicKey); ok {
					if certKey.N.Cmp(ekKey.N) != 0 || certKey.E != ekKey.E {
						return fmt.Errorf("certificate public key does not match TPM EK - use --force to override")
					}
				}
			case *ecdsa.PublicKey:
				if ekKey, ok := ekCert.PublicKey.(*ecdsa.PublicKey); ok {
					if certKey.X.Cmp(ekKey.X) != 0 || certKey.Y.Cmp(ekKey.Y) != 0 {
						return fmt.Errorf("certificate public key does not match TPM EK - use --force to override")
					}
				}
			}
			fmt.Println("Certificate public key matches TPM EK")
		}
	}

	fmt.Println()
	fmt.Println("WARNING: This will overwrite the current EK certificate in TPM NV RAM!")
	fmt.Println("         Make sure this is a valid manufacturer certificate.")
	fmt.Println()

	// Write certificate to NV RAM
	// Note: This requires hierarchy authorization
	hierarchyAuth := []byte(tpmCfg.hierarchyAuth)
	if err := tpm.WriteEKCert(block.Bytes); err != nil {
		return fmt.Errorf("failed to write EK certificate to NV RAM: %w", err)
	}

	_ = hierarchyAuth

	certType := "RSA"
	if ekUseEC {
		certType = "EC"
	}
	fmt.Printf("%s EK certificate restored successfully\n", certType)
	return nil
}
