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
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
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
	tpmCmd.AddCommand(tpmQuoteCmd)
	tpmCmd.AddCommand(tpmPCRsCmd)
}

// openTPM creates and initializes a TPM connection with the configured settings
func openTPM() (tpm2.TrustedPlatformModule, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: getLogLevel(),
	}))

	config := &tpm2.Config{
		Device:       tpmCfg.device,
		UseSimulator: tpmCfg.useSimulator,
		Hash:         "SHA-256",
		EK: &tpm2.EKConfig{
			Handle:        0x81010001,
			CertHandle:    0x01C00002,
			KeyAlgorithm:  "RSA",
			HierarchyAuth: tpmCfg.hierarchyAuth,
		},
		SSRK: &tpm2.SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: "RSA",
		},
		IAK: &tpm2.IAKConfig{
			Handle:             0x81010002,
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA-PSS",
		},
		IDevID: &tpm2.IDevIDConfig{
			Handle:             0x81020000,
			CertHandle:         0x01C90000,
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA-PSS",
			Model:              "xkey",
			Serial:             "001",
		},
		PlatformPCR:     16,
		PlatformPCRBank: "sha256",
	}

	params := &tpm2.Params{
		Config: config,
		Logger: logger,
	}

	tpm, err := tpm2.NewTPM2(params)
	if err != nil {
		if errors.Is(err, tpm2.ErrNotInitialized) {
			return tpm, ErrTPMNotInitialized
		}
		return nil, err
	}

	return tpm, nil
}

// openTPMForProvisioning creates a TPM connection that allows for unprovisioned TPMs
func openTPMForProvisioning() (tpm2.TrustedPlatformModule, error) {
	return openTPMForProvisioningWithPCROverrides("", nil, 0)
}

// openTPMForProvisioningWithPCROverrides creates a TPM connection for provisioning
// with optional PCR configuration overrides.
// - pcrBank: override the platform PCR bank (empty string uses default "sha256")
// - goldenPCRs: override which PCRs to include in golden measurement (nil uses config default)
// - platformPCR: override which PCR to extend with golden measurement (0 uses default 16)
func openTPMForProvisioningWithPCROverrides(pcrBank string, goldenPCRs []uint, platformPCR int) (tpm2.TrustedPlatformModule, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: getLogLevel(),
	}))

	// Set defaults
	effectivePCRBank := "sha256"
	effectivePlatformPCR := uint(16)

	// Apply overrides if provided
	if pcrBank != "" {
		effectivePCRBank = strings.ToLower(pcrBank)
	}
	if platformPCR > 0 {
		effectivePlatformPCR = uint(platformPCR)
	}

	config := &tpm2.Config{
		Device:       tpmCfg.device,
		UseSimulator: tpmCfg.useSimulator,
		Hash:         "SHA-256",
		EK: &tpm2.EKConfig{
			Handle:        0x81010001,
			CertHandle:    0x01C00002,
			KeyAlgorithm:  "RSA",
			HierarchyAuth: tpmCfg.hierarchyAuth,
		},
		SSRK: &tpm2.SRKConfig{
			Handle:       0x81000001,
			KeyAlgorithm: "RSA",
		},
		IAK: &tpm2.IAKConfig{
			Handle:             0x81010002,
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA-PSS",
		},
		IDevID: &tpm2.IDevIDConfig{
			Handle:             0x81020000,
			CertHandle:         0x01C90000,
			Hash:               "SHA-256",
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256-RSA-PSS",
			Model:              "xkey",
			Serial:             "001",
		},
		GoldenPCRs:      goldenPCRs,
		PlatformPCR:     effectivePlatformPCR,
		PlatformPCRBank: effectivePCRBank,
	}

	params := &tpm2.Params{
		Config: config,
		Logger: logger,
	}

	// For provisioning, we accept ErrNotInitialized since we're about to initialize
	tpm, err := tpm2.NewTPM2(params)
	if err != nil {
		if errors.Is(err, tpm2.ErrNotInitialized) {
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
