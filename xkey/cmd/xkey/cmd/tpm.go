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

// openTPM and openTPMForProvisioningWithPCROverrides are the TPM openers
// every `tpm` subcommand goes through. They are variables so tests can route
// a sequence of subcommands through one provisioned simulator: the in-process
// simulator is re-manufactured, and so loses every key, on each open.
var (
	openTPM                                = openConfiguredTPM
	openTPMForProvisioningWithPCROverrides = openConfiguredTPMForProvisioningWithPCROverrides
)

// openConfiguredTPM creates and initializes a TPM connection with the configured settings
func openConfiguredTPM() (xkms.TrustedPlatformModule, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: getLogLevel(),
	}))
	hierarchyAuth, err := xkms.NewLiteralSecretValue(context.Background(), []byte(tpmCfg.hierarchyAuth))
	if err != nil {
		return nil, err
	}

	config := &xkms.TPMConfig{
		Device:       tpmCfg.device,
		UseSimulator: tpmCfg.useSimulator,
		Hash:         "SHA-256",
		EK: &xkms.EKConfig{
			Handle:        0x81010001,
			CertHandle:    0x01C00002,
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
		PlatformPCR:     xkms.DefaultPlatformPCR,
		PlatformPCRBank: xkms.PCRBankSHA256,
	}

	params := &xkms.TPMParams{
		Config: config,
		Logger: logger,
	}

	tpm, err := xkms.NewTPM2(params)
	if err != nil {
		if errors.Is(err, xkms.ErrTPMNotInitialized) {
			return tpm, ErrTPMNotInitialized
		}
		return nil, err
	}

	return tpm, nil
}

// openTPMForProvisioning creates a TPM connection that allows for unprovisioned TPMs
func openTPMForProvisioning() (xkms.TrustedPlatformModule, error) {
	return openTPMForProvisioningWithPCROverrides("", nil, 0)
}

// openConfiguredTPMForProvisioningWithPCROverrides creates a TPM connection for provisioning
// with optional PCR configuration overrides, using the `tpm` command group's
// own --device/--simulator flags (tpmCfg).
// - pcrBank: override the platform PCR bank (empty string uses default "sha256")
// - goldenPCRs: override which PCRs to include in golden measurement (nil uses config default)
// - platformPCR: override which PCR to extend with golden measurement (0 uses xkms.DefaultPlatformPCR)
func openConfiguredTPMForProvisioningWithPCROverrides(pcrBank string, goldenPCRs []uint, platformPCR int) (xkms.TrustedPlatformModule, error) {
	return openTPMForProvisioningWithDeviceAndPCROverrides(tpmCfg.device, tpmCfg.useSimulator, pcrBank, goldenPCRs, platformPCR)
}

// openTPMForProvisioningWithDeviceAndPCROverrides is the device-parameterized
// variant of openTPMForProvisioningWithPCROverrides. It exists so callers
// outside the `tpm` command group (e.g. `policy`, which has its own
// --tpm-device/--tpm-simulator flags) can open a TPM connection without
// depending on the `tpm` command's package-level tpmCfg flags.
func openTPMForProvisioningWithDeviceAndPCROverrides(device string, useSimulator bool, pcrBank string, goldenPCRs []uint, platformPCR int) (xkms.TrustedPlatformModule, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: getLogLevel(),
	}))
	hierarchyAuth, err := xkms.NewLiteralSecretValue(context.Background(), []byte(tpmCfg.hierarchyAuth))
	if err != nil {
		return nil, err
	}

	// Set defaults
	effectivePCRBank := xkms.PCRBankSHA256
	effectivePlatformPCR := xkms.DefaultPlatformPCR

	// Apply overrides if provided
	if pcrBank != "" {
		effectivePCRBank = strings.ToLower(pcrBank)
	}
	if platformPCR > 0 {
		effectivePlatformPCR = uint(platformPCR)
	}

	config := &xkms.TPMConfig{
		Device:       device,
		UseSimulator: useSimulator,
		Hash:         "SHA-256",
		EK: &xkms.EKConfig{
			Handle:        0x81010001,
			CertHandle:    0x01C00002,
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
		// LAK (go-xkms#715): see openTPM's identical block for rationale.
		LAK: &xkms.LAKConfig{
			Handle:             0x81010003,
			CertHandle:         0x01C00003,
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA-PSS",
		},
		GoldenPCRs:      goldenPCRs,
		PlatformPCR:     effectivePlatformPCR,
		PlatformPCRBank: effectivePCRBank,
	}

	params := &xkms.TPMParams{
		Config: config,
		Logger: logger,
	}

	// For provisioning, we accept ErrNotInitialized since we're about to initialize
	tpm, err := xkms.NewTPM2(params)
	if err != nil {
		if errors.Is(err, xkms.ErrTPMNotInitialized) {
			// Return the TPM handle - it's valid for provisioning
			return tpm, nil
		}
		return nil, err
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
