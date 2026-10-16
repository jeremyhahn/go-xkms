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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ProvisionResult holds the result of a provisioning operation
type ProvisionResult struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	EKCreated     bool   `json:"ek_created"`
	EKPreserved   bool   `json:"ek_preserved,omitempty"`
	SRKCreated    bool   `json:"srk_created"`
	IAKCreated    bool   `json:"iak_created"`
	IDevIDCreated bool   `json:"idevid_created,omitempty"`
}

var (
	provisionConfirm       bool
	provisionHierarchyAuth string
	installHierarchyAuth   string

	// PCR override flags for install command
	installPCRBank      string
	installGoldenPCRs   string
	installPlatformPCRs string

	// PCR override flags for provision command
	provisionPCRBank      string
	provisionGoldenPCRs   string
	provisionPlatformPCRs string
)

// tpmInstallCmd represents the tpm install command (safe)
var tpmInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Safely install xKey TPM keys (preserves manufacturer keys)",
	Long: `Safely install xKey TPM keys without clearing the TPM.

This command performs a SAFE installation that:
  * PRESERVES manufacturer Endorsement Key (EK) and certificate
  * Creates Shared Storage Root Key (SSRK) at 0x81000001 if not present
  * Creates Initial Attestation Key (IAK) at 0x81010002 if not present
  * Creates Initial Device Identity (IDevID) at 0x81020000 if not present
  * Sets hierarchy authorizations if not already set

This is the RECOMMENDED command for most users. It follows TCG TPM 2.0
Provisioning Guidance while preserving manufacturer-provisioned keys.

Examples:
  # Install with default settings (recommended)
  xkey tpm install

  # Install with hierarchy authorization password
  xkey tpm install --auth mypassword

  # Install using TPM simulator
  xkey tpm install --simulator

  # Install with custom PCR configuration
  xkey tpm install --pcr-bank sha256 --golden-pcrs 0,1,2,7 --platform-pcrs 7,11`,
	RunE: runTPMInstall,
}

// tpmProvisionCmd represents the tpm provision command (destructive)
var tpmProvisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Full TPM provisioning (DESTRUCTIVE - clears TPM)",
	Long: `Full TPM provisioning following TCG guidance.

+------------------------------------------------------------------------------+
|  WARNING: DESTRUCTIVE OPERATION                                              |
|                                                                              |
|  This command will CLEAR the TPM and create NEW keys:                        |
|    * DELETES manufacturer Endorsement Key (EK)                               |
|    * DELETES manufacturer EK certificate (CANNOT BE RESTORED)                |
|    * DELETES all existing persistent keys                                    |
|    * Creates new EK, SSRK, IAK, and IDevID                                   |
|                                                                              |
|  The manufacturer EK certificate is provisioned at the factory and           |
|  signed by the TPM manufacturer's CA. Once deleted, it CANNOT be             |
|  recovered. Some attestation use cases require manufacturer certificates.    |
|                                                                              |
|  For most users, 'xkey tpm install' is the RECOMMENDED alternative.          |
+------------------------------------------------------------------------------+

Use --confirm to acknowledge you understand this will destroy manufacturer keys.

Examples:
  # Full provisioning (requires confirmation)
  xkey tpm provision --confirm

  # Provision with hierarchy authorization password
  xkey tpm provision --confirm --auth mypassword

  # Provision with custom PCR configuration
  xkey tpm provision --confirm --pcr-bank sha256 --golden-pcrs 0,1,2,7 --platform-pcrs 7,11`,
	RunE: runTPMProvision,
}

func init() {
	// Install command flags
	tpmInstallCmd.Flags().StringVar(&installHierarchyAuth, "auth", "",
		"Hierarchy authorization password to set")
	tpmInstallCmd.Flags().StringVar(&installPCRBank, "pcr-bank", "",
		"Override the platform PCR bank (e.g., sha256, sha384)")
	tpmInstallCmd.Flags().StringVar(&installGoldenPCRs, "golden-pcrs", "",
		"Comma-separated list of PCR indices for golden measurement (e.g., \"0,1,2,7\")")
	tpmInstallCmd.Flags().StringVar(&installPlatformPCRs, "platform-pcrs", "",
		"Comma-separated sealing PCR set of the platform policy (default \"7,11\"; 16 and 23 are refused)")

	// Provision command flags
	tpmProvisionCmd.Flags().BoolVar(&provisionConfirm, "confirm", false,
		"Confirm that you want to destroy manufacturer keys (REQUIRED)")
	tpmProvisionCmd.Flags().StringVar(&provisionHierarchyAuth, "auth", "",
		"Hierarchy authorization password to set")
	tpmProvisionCmd.Flags().StringVar(&provisionPCRBank, "pcr-bank", "",
		"Override the platform PCR bank (e.g., sha256, sha384)")
	tpmProvisionCmd.Flags().StringVar(&provisionGoldenPCRs, "golden-pcrs", "",
		"Comma-separated list of PCR indices for golden measurement (e.g., \"0,1,2,7\")")
	tpmProvisionCmd.Flags().StringVar(&provisionPlatformPCRs, "platform-pcrs", "",
		"Comma-separated sealing PCR set of the platform policy (default \"7,11\"; 16 and 23 are refused)")
}

// parseGoldenPCRs parses a comma-separated string of PCR indices into a []uint slice
func parseGoldenPCRs(s string) ([]uint, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	result := make([]uint, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		val, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, &DetailError{Err: ErrInvalidPCRIndices, Detail: fmt.Sprintf(": invalid PCR index %q: %v", part, err)}
		}

		if val > 23 {
			return nil, &DetailError{Err: ErrInvalidPCRIndices, Detail: fmt.Sprintf(": PCR index %d out of range (0-23)", val)}
		}

		result = append(result, uint(val))
	}

	return result, nil
}

// parsePlatformPCRs parses a --platform-pcrs flag value into the sealing PCR
// set of the platform policy. An empty value returns nil, which takes
// xkms.DefaultPlatformPCRs; any other value must be a valid set, so PCR 16,
// PCR 23 and duplicates are refused here rather than at TPM open.
func parsePlatformPCRs(s string) ([]uint, error) {
	pcrs, err := parseGoldenPCRs(s)
	if err != nil || pcrs == nil {
		return pcrs, err
	}
	if err := xkms.TPMPCRSet(pcrs).Validate(); err != nil {
		return nil, err
	}
	return pcrs, nil
}

// validatePCRBank validates a PCR bank string
func validatePCRBank(bank string) error {
	if bank == "" {
		return nil
	}

	validBanks := map[string]bool{
		"sha1":   true,
		"sha256": true,
		"sha384": true,
		"sha512": true,
	}

	if !validBanks[strings.ToLower(bank)] {
		return &DetailError{Err: ErrInvalidPCRBank, Detail: fmt.Sprintf(": %q (valid: sha1, sha256, sha384, sha512)", bank)}
	}

	return nil
}

func runTPMInstall(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	// Validate PCR flags if provided
	if err := validatePCRBank(installPCRBank); err != nil {
		return err
	}

	goldenPCRs, err := parseGoldenPCRs(installGoldenPCRs)
	if err != nil {
		return err
	}
	platformPCRs, err := parsePlatformPCRs(installPlatformPCRs)
	if err != nil {
		return err
	}

	// Open TPM for provisioning with PCR overrides
	tpm, err := openTPMForProvisioningWithPCROverrides(installPCRBank, goldenPCRs, platformPCRs)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTPMDeviceNotFound, Cause: err}
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	result := &ProvisionResult{}

	// Check current state
	ekPresent := false
	if _, err := tpm.EKAttributes(); err == nil {
		ekPresent = true
	}

	srkPresent := false
	if _, err := tpm.SSRKAttributes(); err == nil {
		srkPresent = true
	}

	iakPresent := false
	if _, err := tpm.IAKAttributes(); err == nil {
		iakPresent = true
	}

	idevidPresent := false
	if _, err := tpm.IDevIDAttributes(); err == nil {
		idevidPresent = true
	}

	// If already fully provisioned, report status
	if ekPresent && srkPresent && iakPresent && idevidPresent {
		result.Success = true
		result.Message = "TPM is already fully installed with all xKey keys"
		result.EKPreserved = true
		result.SRKCreated = true
		result.IAKCreated = true
		result.IDevIDCreated = true
		return outputProvisionResult(out, result)
	}

	_, _ = fmt.Fprintln(out, "Installing xKey TPM keys (safe mode - preserves manufacturer keys)...")

	// Determine the authorization password
	var soPIN xkms.Password
	var pinErr error
	switch {
	case installHierarchyAuth != "":
		soPIN, pinErr = xkms.NewTPMStorePassword([]byte(installHierarchyAuth))
	case tpmCfg.hierarchyAuth != "":
		soPIN, pinErr = xkms.NewTPMStorePassword([]byte(tpmCfg.hierarchyAuth))
	}
	if pinErr != nil {
		return &SentinelCauseError{Sentinel: ErrProvisioningFailed, Cause: pinErr}
	}

	// Run Install (safe provisioning)
	if err := tpm.Install(soPIN, nil); err != nil {
		return &SentinelCauseError{Sentinel: ErrProvisioningFailed, Cause: err}
	}

	result.Success = true
	result.Message = "TPM installation completed successfully"
	result.EKPreserved = ekPresent
	result.EKCreated = !ekPresent
	result.SRKCreated = true
	result.IAKCreated = true
	result.IDevIDCreated = true

	return outputProvisionResult(out, result)
}

func runTPMProvision(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	// Require explicit confirmation
	if !provisionConfirm {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "+------------------------------------------------------------------------------+")
		_, _ = fmt.Fprintln(out, "|  WARNING: This operation will PERMANENTLY DESTROY manufacturer TPM keys!    |")
		_, _ = fmt.Fprintln(out, "|                                                                              |")
		_, _ = fmt.Fprintln(out, "|  The manufacturer EK certificate CANNOT be recovered after deletion.         |")
		_, _ = fmt.Fprintln(out, "|  Some enterprise attestation scenarios require manufacturer certificates.    |")
		_, _ = fmt.Fprintln(out, "|                                                                              |")
		_, _ = fmt.Fprintln(out, "|  Consider using 'xkey tpm install' instead (preserves manufacturer keys).    |")
		_, _ = fmt.Fprintln(out, "+------------------------------------------------------------------------------+")
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "To proceed, run with --confirm flag:")
		_, _ = fmt.Fprintln(out, "  xkey tpm provision --confirm")
		_, _ = fmt.Fprintln(out)
		return nil
	}

	// Validate PCR flags if provided
	if err := validatePCRBank(provisionPCRBank); err != nil {
		return err
	}

	goldenPCRs, err := parseGoldenPCRs(provisionGoldenPCRs)
	if err != nil {
		return err
	}
	platformPCRs, err := parsePlatformPCRs(provisionPlatformPCRs)
	if err != nil {
		return err
	}

	// Double-check with interactive prompt if running in a terminal
	if isTerminal() {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "FINAL WARNING: This will permanently destroy manufacturer TPM keys!")
		_, _ = fmt.Fprint(out, "Type 'DESTROY' to continue: ")

		reader := bufio.NewReader(cmd.InOrStdin())
		input, err := reader.ReadString('\n')
		if err != nil {
			return &WrappedError{Msg: "failed to read input", Err: err}
		}

		input = strings.TrimSpace(input)
		if input != "DESTROY" {
			_, _ = fmt.Fprintln(out, "Operation cancelled.")
			return nil
		}
	}

	// Open TPM for provisioning with PCR overrides
	tpm, err := openTPMForProvisioningWithPCROverrides(provisionPCRBank, goldenPCRs, platformPCRs)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTPMDeviceNotFound, Cause: err}
	}
	defer func() {
		if closeErr := tpm.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Performing FULL TPM provisioning (destructive)...")

	// Determine the authorization password
	var soPIN xkms.Password
	var pinErr error
	switch {
	case provisionHierarchyAuth != "":
		soPIN, pinErr = xkms.NewTPMStorePassword([]byte(provisionHierarchyAuth))
	case tpmCfg.hierarchyAuth != "":
		soPIN, pinErr = xkms.NewTPMStorePassword([]byte(tpmCfg.hierarchyAuth))
	}
	if pinErr != nil {
		return &SentinelCauseError{Sentinel: ErrProvisioningFailed, Cause: pinErr}
	}

	// Run full Provision (destructive)
	if err := tpm.Provision(soPIN); err != nil {
		return &SentinelCauseError{Sentinel: ErrProvisioningFailed, Cause: err}
	}

	result := &ProvisionResult{
		Success:       true,
		Message:       "TPM provisioning completed (manufacturer keys replaced)",
		EKCreated:     true,
		SRKCreated:    true,
		IAKCreated:    true,
		IDevIDCreated: true,
	}

	return outputProvisionResult(out, result)
}

func outputProvisionResult(out io.Writer, result *ProvisionResult) error {
	switch tpmCfg.outputFormat {
	case "json":
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	default:
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "Provisioning Result")
		_, _ = fmt.Fprintln(out, "===================")
		_, _ = fmt.Fprintf(out, "Success:        %t\n", result.Success)
		_, _ = fmt.Fprintf(out, "Message:        %s\n", result.Message)
		if result.EKPreserved {
			_, _ = fmt.Fprintf(out, "EK:             preserved (manufacturer)\n")
		} else {
			_, _ = fmt.Fprintf(out, "EK Created:     %t\n", result.EKCreated)
		}
		_, _ = fmt.Fprintf(out, "SRK Created:    %t\n", result.SRKCreated)
		_, _ = fmt.Fprintf(out, "IAK Created:    %t\n", result.IAKCreated)
		_, _ = fmt.Fprintf(out, "IDevID Created: %t\n", result.IDevIDCreated)
		return nil
	}
}

// isTerminal checks if stdin is a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
