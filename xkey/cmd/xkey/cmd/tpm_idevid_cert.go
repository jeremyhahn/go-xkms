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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/spf13/cobra"
)

// IDevID certificate error types
var (
	ErrIDevIDCSRExportFailed    = errors.New("tpm: failed to export IDevID CSR")
	ErrIDevIDCertImportFailed   = errors.New("tpm: failed to import IDevID certificate")
	ErrIDevIDPublicKeyMismatch  = errors.New("tpm: certificate public key does not match IDevID key")
	ErrIDevIDCSRSigningFailed   = errors.New("tpm: failed to sign IDevID CSR")
	ErrIDevIDInvalidCertificate = errors.New("tpm: invalid certificate format")
)

var (
	idevidCertOrg         string
	idevidCertOrgUnit     string
	idevidCertCountry     string
	idevidCertProvince    string
	idevidCertLocality    string
	idevidCSRExportOutput string
	idevidCertImportPath  string
	idevidCertImportForce bool
)

// tpmIDevIDCertCmd represents the tpm idevid cert command group
var tpmIDevIDCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "IDevID certificate operations",
	Long: `IDevID certificate management operations.

Manage the Initial Device Identity certificate:
  - Import CA-signed certificates for production use

IDevID certificates must be signed by a Certificate Authority.
Self-signed IDevID certificates are not supported - use a proper CA
(go-xkms CA, go-trusted-ca, or external CA) to issue certificates.

Subcommands:
  import  - Import a CA-signed IDevID certificate`,
}

// tpmIDevIDCSRExportPEMCmd exports an IDevID CSR in PEM format
var tpmIDevIDCSRExportPEMCmd = &cobra.Command{
	Use:   "export",
	Short: "Export IDevID CSR in PEM format",
	Long: `Export a Certificate Signing Request (CSR) for the IDevID key.

This generates a standard X.509 CSR in PEM format that can be submitted
to a Certificate Authority for signing. The CSR is signed using the
IDevID key in the TPM.

Unlike the default 'csr' command which generates TCG-CSR-IDEVID format,
this command generates a standard PEM-encoded CSR compatible with
traditional PKI systems.

Examples:
  # Export IDevID CSR to file
  xkey tpm idevid csr export --output idevid.csr

  # Export to stdout
  xkey tpm idevid csr export --output -`,
	RunE: runIDevIDCSRExportPEM,
}

// tpmIDevIDCertImportCmd imports a signed IDevID certificate
var tpmIDevIDCertImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import signed IDevID certificate",
	Long: `Import a CA-signed IDevID certificate.

This command imports a certificate that was signed by a Certificate
Authority. The certificate's public key must match the IDevID key
in the TPM.

Self-signed certificates are NOT accepted. The certificate must be
issued by a trusted CA (go-xkms CA, go-trusted-ca, Android CA,
or external CA with compatible endpoint).

Examples:
  # Import signed certificate
  xkey tpm idevid cert import --cert idevid.crt

  # Force import (skip public key verification)
  xkey tpm idevid cert import --cert idevid.crt --force`,
	RunE: runIDevIDCertImport,
}

func init() {
	// Add cert subcommand to idevid command
	tpmIDevIDCmd.AddCommand(tpmIDevIDCertCmd)

	// Add subcommands to cert command
	tpmIDevIDCertCmd.AddCommand(tpmIDevIDCertImportCmd)

	// Add csr export as subcommand of the existing csr command
	// This provides PEM format CSR export alongside TCG-CSR format
	tpmIDevIDCSRCmd.AddCommand(tpmIDevIDCSRExportPEMCmd)

	// CSR export flags
	tpmIDevIDCSRExportPEMCmd.Flags().StringVar(&idevidCSRExportOutput, "output", "",
		"Output file path for CSR (use '-' for stdout)")
	tpmIDevIDCSRExportPEMCmd.Flags().StringVar(&idevidCertOrg, "organization", "",
		"Organization name (overrides OpenSSL config)")
	tpmIDevIDCSRExportPEMCmd.Flags().StringVar(&idevidCertOrgUnit, "organizational-unit", "",
		"Organizational unit (overrides OpenSSL config)")
	tpmIDevIDCSRExportPEMCmd.Flags().StringVar(&idevidCertCountry, "country", "",
		"Country code (overrides OpenSSL config)")
	tpmIDevIDCSRExportPEMCmd.Flags().StringVar(&idevidCertProvince, "province", "",
		"State/Province (overrides OpenSSL config)")
	tpmIDevIDCSRExportPEMCmd.Flags().StringVar(&idevidCertLocality, "locality", "",
		"City/Locality (overrides OpenSSL config)")
	_ = tpmIDevIDCSRExportPEMCmd.MarkFlagRequired("output")

	// Cert import flags
	tpmIDevIDCertImportCmd.Flags().StringVar(&idevidCertImportPath, "cert", "",
		"Path to PEM-encoded certificate file")
	tpmIDevIDCertImportCmd.Flags().BoolVar(&idevidCertImportForce, "force", false,
		"Force import without public key verification")
	_ = tpmIDevIDCertImportCmd.MarkFlagRequired("cert")
}

func runIDevIDCSRExportPEM(cmd *cobra.Command, args []string) error {
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get IDevID attributes
	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return fmt.Errorf("%w: IDevID not found - create with 'tpm idevid create' first", ErrKeyNotFound)
	}

	// Get IDevID public key
	idevidPubKey, idevidErr := tpm.IDevID()
	if idevidErr != nil {
		return fmt.Errorf("%w: %v", ErrKeyNotFound, idevidErr)
	}
	if idevidPubKey == nil {
		return fmt.Errorf("%w: failed to get IDevID public key", ErrKeyNotFound)
	}

	// Build CSR subject: start with OpenSSL defaults
	caSubject := &ca.Subject{}
	if opensslCfg, _ := ca.LoadOpenSSLConfig(); opensslCfg != nil {
		caSubject.Organization = opensslCfg.Organization
		caSubject.OrganizationalUnit = opensslCfg.OrganizationalUnit
		caSubject.Country = opensslCfg.Country
		caSubject.Province = opensslCfg.Province
		caSubject.Locality = opensslCfg.Locality
	}

	// CN comes from IDevIDConfig
	cn := tpm.Config().IDevID.CN
	if cn == "" {
		// Fall back to model-serial format
		model := tpm.Config().IDevID.Model
		if model == "" {
			model = "tpm-device"
		}
		serial := tpm.Config().IDevID.Serial
		if serial == "" {
			serial = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		cn = fmt.Sprintf("%s-%s", model, serial)
	}
	caSubject.CommonName = cn

	// Apply CLI overrides for PKIX fields
	if idevidCertOrg != "" {
		caSubject.Organization = idevidCertOrg
	}
	if idevidCertOrgUnit != "" {
		caSubject.OrganizationalUnit = idevidCertOrgUnit
	}
	if idevidCertCountry != "" {
		caSubject.Country = idevidCertCountry
	}
	if idevidCertProvince != "" {
		caSubject.Province = idevidCertProvince
	}
	if idevidCertLocality != "" {
		caSubject.Locality = idevidCertLocality
	}

	// Convert to pkix.Name
	subject := caSubject.ToPkixName()

	// Determine signature algorithm
	var sigAlgo x509.SignatureAlgorithm
	switch idevidAttrs.KeyAlgorithm {
	case x509.RSA:
		if store.IsRSAPSS(idevidAttrs.SignatureAlgorithm) {
			sigAlgo = x509.SHA256WithRSAPSS
		} else {
			sigAlgo = x509.SHA256WithRSA
		}
	case x509.ECDSA:
		sigAlgo = x509.ECDSAWithSHA256
	default:
		return fmt.Errorf("%w: unsupported key algorithm: %v", ErrInvalidKeyAlgorithm, idevidAttrs.KeyAlgorithm)
	}

	// Create CSR template
	csrTemplate := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: sigAlgo,
	}

	fmt.Printf("Generating IDevID CSR for %s...\n", subject.CommonName)

	// Create TPM signer wrapper
	signer := &tpmSigner{
		tpm:      tpm,
		keyAttrs: idevidAttrs,
		pubKey:   idevidPubKey,
	}

	// Create the CSR using the TPM to sign
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, signer)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIDevIDCSRSigningFailed, err)
	}

	// Encode as PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Output to file or stdout
	if idevidCSRExportOutput == "-" {
		fmt.Print(string(pemData))
		return nil
	}

	if err := os.WriteFile(idevidCSRExportOutput, pemData, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrIDevIDCSRExportFailed, err)
	}

	fmt.Printf("IDevID CSR exported to: %s\n", idevidCSRExportOutput)
	return nil
}

func runIDevIDCertImport(cmd *cobra.Command, args []string) error {
	// Read certificate file
	pemData, err := os.ReadFile(idevidCertImportPath)
	if err != nil {
		return fmt.Errorf("%w: failed to read certificate file: %v", ErrIDevIDCertImportFailed, err)
	}

	// Parse PEM
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("%w: failed to decode PEM data", ErrIDevIDInvalidCertificate)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w: failed to parse certificate: %v", ErrIDevIDInvalidCertificate, err)
	}

	// Reject self-signed certificates
	if cert.Subject.String() == cert.Issuer.String() {
		return fmt.Errorf("%w: self-signed certificates are not accepted - use a CA to issue IDevID certificates", ErrIDevIDInvalidCertificate)
	}

	fmt.Println("Certificate to import:")
	fmt.Printf("  Subject: %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:  %s\n", cert.Issuer.String())
	fmt.Printf("  Serial:  %s\n", cert.SerialNumber.String())
	fmt.Println()

	// Open TPM
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Get IDevID public key
	idevidPubKey, idevidErr := tpm.IDevID()
	if idevidErr != nil {
		return fmt.Errorf("%w: %v", ErrKeyNotFound, idevidErr)
	}
	if idevidPubKey == nil {
		return fmt.Errorf("%w: IDevID not found - create with 'tpm idevid create' first", ErrKeyNotFound)
	}

	// Verify certificate public key matches IDevID (unless forced)
	if !idevidCertImportForce {
		if !publicKeysEqual(cert.PublicKey, idevidPubKey) {
			return fmt.Errorf("%w: use --force to override", ErrIDevIDPublicKeyMismatch)
		}
		fmt.Println("Public key verification: PASSED")
	} else {
		fmt.Println("Public key verification: SKIPPED (--force)")
	}

	// Store the certificate
	if err := tpm.ProvisionIDevIDCert(cert); err != nil {
		return fmt.Errorf("%w: %v", ErrIDevIDCertImportFailed, err)
	}

	fmt.Println()
	fmt.Println("IDevID certificate imported successfully")
	return nil
}

// tpmSigner implements crypto.Signer for TPM-based signing
type tpmSigner struct {
	tpm      tpmSignerInterface
	keyAttrs *types.KeyAttributes
	pubKey   crypto.PublicKey
}

// tpmSignerInterface defines the TPM methods needed for signing
type tpmSignerInterface interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Public returns the public key
func (s *tpmSigner) Public() crypto.PublicKey {
	return s.pubKey
}

// Sign signs the digest using the TPM
func (s *tpmSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Create TPM signer opts
	signerOpts := &store.SignerOpts{
		KeyAttributes: s.keyAttrs,
	}

	// Handle RSA-PSS if needed
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		signerOpts.PSSOptions = pssOpts
	}

	return s.tpm.Sign(rand, digest, signerOpts)
}
