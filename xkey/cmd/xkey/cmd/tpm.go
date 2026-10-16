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
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TPM error types
var (
	ErrTPMDeviceNotFound     = errors.New("tpm: device not found")
	ErrTPMNotInitialized     = errors.New("tpm: not initialized - run 'tpm provision' first")
	ErrTPMOperationFailed    = errors.New("tpm: operation failed")
	ErrInvalidPCRBank        = errors.New("tpm: invalid PCR bank specified")
	ErrInvalidPCRIndices     = errors.New("tpm: invalid PCR indices specified")
	ErrInvalidNonce          = errors.New("tpm: invalid nonce specified")
	ErrMissingOutputFile     = errors.New("tpm: output file path required")
	ErrCertificateNotFound   = errors.New("tpm: certificate not found")
	ErrKeyNotFound           = errors.New("tpm: key not found")
	ErrInvalidTemplate       = errors.New("tpm: invalid key template specified")
	ErrProvisioningFailed    = errors.New("tpm: provisioning failed")
	ErrCSRGenerationFailed   = errors.New("tpm: CSR generation failed")
	ErrExportFailed          = errors.New("tpm: export failed")
	ErrInvalidKeyAlgorithm   = errors.New("tpm: invalid key algorithm")
	ErrMissingHierarchyAuth  = errors.New("tpm: hierarchy authorization required")
	ErrInvalidEKTemplate     = errors.New("tpm: invalid EK template - must be rsa2048 or ecc256")
	ErrInvalidIAKTemplate    = errors.New("tpm: invalid IAK template - must be rsa2048, rsa-pss, or ecc256")
	ErrInvalidIDevIDTemplate = errors.New("tpm: invalid IDevID template - must be rsa2048, rsa-pss, or ecc256")
	ErrIDevIDExists          = errors.New("tpm: IDevID already exists - use --force to recreate")
	ErrIDevIDCertRemove      = errors.New("tpm: failed to remove the existing IDevID certificate")
)

// tpmConfig holds TPM-specific configuration
type tpmConfig struct {
	device        string
	useSimulator  bool
	verbose       bool
	outputFormat  string
	hierarchyAuth string
}

var tpmCfg = &tpmConfig{}

// tpmCmd represents the tpm command
var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "TPM 2.0 operations",
	Long: `TPM 2.0 operations for device attestation, provisioning, and key management.

This command group provides comprehensive access to TPM 2.0 functionality including:
  - TPM information and capabilities
  - Device provisioning (EK, SRK, IAK, IDevID)
  - Key management (EK, IAK, IDevID)
  - Platform attestation (quotes, PCR values)

Examples:
  # Show TPM information
  xkey tpm info

  # Provision TPM for xKey use
  xkey tpm provision

  # Display EK certificate
  xkey tpm ek show

  # Generate TPM quote for attestation
  xkey tpm quote --pcrs 0,1,7 --nonce abc123

  # Show PCR values
  xkey tpm pcrs --bank sha256`,
}

func init() {
	// Register TPM command with root
	RootCmd.AddCommand(tpmCmd)

	// Add persistent flags for TPM commands
	tpmCmd.PersistentFlags().StringVar(&tpmCfg.device, "device", "/dev/tpmrm0",
		"TPM device path")
	tpmCmd.PersistentFlags().BoolVar(&tpmCfg.useSimulator, "simulator", false,
		"Use TPM simulator instead of hardware TPM")
	tpmCmd.PersistentFlags().BoolVarP(&tpmCfg.verbose, "verbose", "v", false,
		"Enable verbose output")
	tpmCmd.PersistentFlags().StringVarP(&tpmCfg.outputFormat, "output", "o", "text",
		"Output format (text, json)")
	tpmCmd.PersistentFlags().StringVar(&tpmCfg.hierarchyAuth, "hierarchy-auth", "",
		"Hierarchy authorization password")

	// Add subcommands
	tpmCmd.AddCommand(tpmInfoCmd)
	tpmCmd.AddCommand(tpmInstallCmd)
	tpmCmd.AddCommand(tpmProvisionCmd)
	tpmCmd.AddCommand(tpmEKCmd)
	tpmCmd.AddCommand(tpmIAKCmd)
	tpmCmd.AddCommand(tpmIDevIDCmd)
	tpmCmd.AddCommand(tpmLAKCmd)
	tpmCmd.AddCommand(tpmQuoteCmd)
	tpmCmd.AddCommand(tpmPCRsCmd)
}

// openTPM, openTPMForEKCert, openTPMForEKRestore and
// openTPMForProvisioningWithPCROverrides are the TPM openers every `tpm`
// subcommand goes through; openTPMForEKCert and openTPMForEKRestore take the
// NV index an EK certificate is written to. They are variables so tests
// can route a sequence of subcommands through one provisioned simulator: the
// in-process simulator is re-manufactured, and so loses every key, on each
// open.
var (
	openTPM                                = openConfiguredTPM
	openTPMForEKCert                       = openConfiguredTPMForEKCert
	openTPMForEKRestore                    = openConfiguredTPMForEKRestore
	openTPMForProvisioningWithPCROverrides = openConfiguredTPMForProvisioningWithPCROverrides
)

// EK certificate NV indices from the TCG EK Credential Profile: the RSA 2048
// certificate is the default, the ECC NIST P-256 one is selected with --ec.
const (
	ekCertHandleRSA uint32 = 0x01C00002
	ekCertHandleEC  uint32 = 0x01C0000A
)

// openConfiguredTPM creates and initializes a TPM connection with the configured settings
func openConfiguredTPM() (xkms.TrustedPlatformModule, error) {
	return openConfiguredTPMForEKCert(ekCertHandleRSA)
}

// openConfiguredTPMForEKCert opens the TPM like openConfiguredTPM, but with
// ekCertHandle as the NV index the EK certificate is written to. A TPM with
// neither the EK nor a certificate at ekCertHandle is closed and reported as
// ErrTPMNotInitialized; no error is ever returned with an open TPM.
func openConfiguredTPMForEKCert(ekCertHandle uint32) (xkms.TrustedPlatformModule, error) {
	tpm, err := openConfiguredTPMForEKRestore(ekCertHandle)
	if err != nil {
		return nil, discardTPM(tpm, err)
	}
	return tpm, nil
}

// openConfiguredTPMForEKRestore opens the TPM like openConfiguredTPMForEKCert,
// except that a TPM with neither the EK nor a certificate at ekCertHandle is
// returned open together with ErrTPMNotInitialized: `ek restore --force`
// writes the certificate to such a TPM, and the caller must close it. Any
// other error closes the TPM and returns nil.
func openConfiguredTPMForEKRestore(ekCertHandle uint32) (xkms.TrustedPlatformModule, error) {
	config, err := newTPMConfig(tpmCfg.device, tpmCfg.useSimulator, ekCertHandle)
	if err != nil {
		return nil, err
	}

	tpm, err := xkms.NewTPM2(newTPMParams(config))
	if err != nil {
		if errors.Is(err, xkms.ErrTPMNotInitialized) {
			return tpm, ErrTPMNotInitialized
		}
		return nil, discardTPM(tpm, err)
	}

	return tpm, nil
}

// newTPMConfig is the configuration every `tpm` command opens the TPM
// with: the TCG RSA EK at 0x81010001, its certificate at ekCertHandle, and
// the shared SRK, IAK, IDevID and LAK at xkey's handles.
func newTPMConfig(device string, useSimulator bool, ekCertHandle uint32) (*xkms.TPMConfig, error) {
	hierarchyAuth, err := xkms.NewLiteralSecretValue(context.Background(), []byte(tpmCfg.hierarchyAuth))
	if err != nil {
		return nil, err
	}

	return &xkms.TPMConfig{
		Device:       device,
		UseSimulator: useSimulator,
		Hash:         "SHA-256",
		EK: &xkms.EKConfig{
			Handle:        0x81010001,
			CertHandle:    ekCertHandle,
			KeyAlgorithm:  "RSA",
			HierarchyAuth: hierarchyAuth,
		},
		SSRK: &xkms.SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: "RSA",
		},
		IAK: &xkms.IAKConfig{
			Handle:             0x81010002,
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA-PSS",
		},
		IDevID: &xkms.IDevIDConfig{
			Handle:             0x81020000,
			CertHandle:         0x01C90000,
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA-PSS",
			Model:              "xkey",
			Serial:             "001",
		},
		// LAK (go-xkms#715): a Restricted, Sign-only child of the Platform
		// SRK, certified by the IAK via TPM2_Certify. Its certificate is
		// stored in TPM NVRAM, like IDevID's, rather than the certificate
		// store -- xkey does not wire a CertificateStorer into TPMParams.
		LAK: &xkms.LAKConfig{
			Handle:             0x81010003,
			CertHandle:         0x01C00003,
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA-PSS",
		},
		PlatformPCRs:    xkms.DefaultPlatformPCRs(),
		PlatformPCRBank: xkms.PCRBankSHA256,
	}, nil
}

// newTPMParams wraps config with the logger the `tpm` commands log through.
func newTPMParams(config *xkms.TPMConfig) *xkms.TPMParams {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: getLogLevel(),
	}))
	return &xkms.TPMParams{
		Config: config,
		Logger: logger,
	}
}

// discardTPM closes a TPM an open helper is about to return err for and
// returns err, joined with any close failure. NewTPM2 hands back a live TPM
// with ErrTPMNotInitialized, and callers close only a TPM they got without
// an error, so an open helper that returned both would leak the device
// (go-xkms#704).
func discardTPM(tpm xkms.TrustedPlatformModule, err error) error {
	if tpm == nil {
		return err
	}
	if closeErr := tpm.Close(); closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return err
}

// openTPMForProvisioning creates a TPM connection that allows for unprovisioned TPMs
func openTPMForProvisioning() (xkms.TrustedPlatformModule, error) {
	return openTPMForProvisioningWithPCROverrides("", nil, nil)
}

// openConfiguredTPMForProvisioningWithPCROverrides creates a TPM connection for provisioning
// with optional PCR configuration overrides, using the `tpm` command group's
// own --device/--simulator flags (tpmCfg).
// - pcrBank: override the platform PCR bank (empty string uses default "sha256")
// - goldenPCRs: override which PCRs to include in golden measurement (nil uses config default)
// - platformPCRs: override the sealing PCR set (nil uses xkms.DefaultPlatformPCRs)
func openConfiguredTPMForProvisioningWithPCROverrides(pcrBank string, goldenPCRs, platformPCRs []uint) (xkms.TrustedPlatformModule, error) {
	return openTPMForProvisioningWithDeviceAndPCROverrides(tpmCfg.device, tpmCfg.useSimulator, pcrBank, goldenPCRs, platformPCRs)
}

// openTPMForProvisioningWithDeviceAndPCROverrides is the device-parameterized
// variant of openTPMForProvisioningWithPCROverrides. It exists so callers
// outside the `tpm` command group (e.g. `policy`, which has its own
// --tpm-device/--tpm-simulator flags) can open a TPM connection without
// depending on the `tpm` command's package-level tpmCfg flags.
func openTPMForProvisioningWithDeviceAndPCROverrides(device string, useSimulator bool, pcrBank string, goldenPCRs, platformPCRs []uint) (xkms.TrustedPlatformModule, error) {
	config, err := newTPMConfig(device, useSimulator, ekCertHandleRSA)
	if err != nil {
		return nil, err
	}

	// Apply overrides if provided
	config.GoldenPCRs = goldenPCRs
	if pcrBank != "" {
		config.PlatformPCRBank = strings.ToLower(pcrBank)
	}
	if platformPCRs != nil {
		config.PlatformPCRs = platformPCRs
	}

	// For provisioning, we accept ErrNotInitialized since we're about to initialize
	tpm, err := xkms.NewTPM2(newTPMParams(config))
	if err != nil && !errors.Is(err, xkms.ErrTPMNotInitialized) {
		return nil, discardTPM(tpm, err)
	}

	return tpm, nil
}

// getLogLevel returns the appropriate log level based on verbosity setting
func getLogLevel() slog.Level {
	if tpmCfg.verbose {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
