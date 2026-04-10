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
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// PCRValue represents a single PCR value
type PCRValue struct {
	Index    int    `json:"index"`
	ValueHex string `json:"value_hex"`
}

// PCRBankOutput represents PCR values for a single bank
type PCRBankOutput struct {
	Algorithm string     `json:"algorithm"`
	PCRs      []PCRValue `json:"pcrs"`
}

// PCRsOutput holds all PCR values
type PCRsOutput struct {
	Banks []PCRBankOutput `json:"banks"`
}

var (
	pcrsBank    string
	pcrsIndices string
)

// tpmPCRsCmd represents the tpm pcrs command
var tpmPCRsCmd = &cobra.Command{
	Use:   "pcrs",
	Short: "Display PCR values",
	Long: `Display Platform Configuration Register (PCR) values.

PCRs contain measurements of the platform's boot and runtime state:
  - PCR 0:  BIOS/UEFI firmware code
  - PCR 1:  BIOS/UEFI firmware configuration
  - PCR 2:  Option ROMs
  - PCR 3:  Option ROM configuration
  - PCR 4:  MBR/IPL code
  - PCR 5:  MBR/IPL configuration
  - PCR 6:  State transitions and wake events
  - PCR 7:  Secure Boot policy
  - PCR 8:  OS-specific measurements
  - PCR 9:  Kernel command line
  - PCR 10: Linux IMA (file integrity)
  - PCR 11-15: Application-specific
  - PCR 16: Debug PCR
  - PCR 17-22: Trusted platform measurements
  - PCR 23: Application support

Examples:
  # Show all PCRs for all banks
  xkey tpm pcrs

  # Show PCRs for SHA256 bank only
  xkey tpm pcrs --bank sha256

  # Show specific PCR indices
  xkey tpm pcrs --indices 0,1,7,14

  # Show PCRs in JSON format
  xkey tpm pcrs -o json`,
	RunE: runTPMPCRs,
}

func init() {
	tpmPCRsCmd.Flags().StringVar(&pcrsBank, "bank", "",
		"PCR bank to display (sha1, sha256, sha384, sha512)")
	tpmPCRsCmd.Flags().StringVar(&pcrsIndices, "indices", "",
		"Comma-separated list of PCR indices (default: 0-23)")
}

func runTPMPCRs(cmd *cobra.Command, args []string) error {
	// Parse PCR indices
	var indices []uint
	var err error

	if pcrsIndices != "" {
		indices, err = parsePCRIndicesForPCRs(pcrsIndices)
		if err != nil {
			return err
		}
	} else {
		// Default to all PCRs
		indices = make([]uint, 24)
		for i := range indices {
			indices[i] = uint(i)
		}
	}

	// Validate bank if specified
	if pcrsBank != "" {
		switch strings.ToLower(pcrsBank) {
		case "sha1", "sha256", "sha384", "sha512":
			// Valid
		default:
			return fmt.Errorf("%w: invalid bank '%s' (valid: sha1, sha256, sha384, sha512)",
				ErrInvalidPCRBank, pcrsBank)
		}
	}

	// Open TPM
	tpm, err := openTPMForProvisioning()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Read PCRs
	banks, err := tpm.ReadPCRs(indices)
	if err != nil {
		return fmt.Errorf("%w: failed to read PCRs: %v", ErrTPMOperationFailed, err)
	}

	// Build output
	output := &PCRsOutput{
		Banks: make([]PCRBankOutput, 0),
	}

	for _, bank := range banks {
		// Filter by bank if specified
		if pcrsBank != "" && !strings.EqualFold(bank.Algorithm, pcrsBank) {
			continue
		}

		bankOutput := PCRBankOutput{
			Algorithm: bank.Algorithm,
			PCRs:      make([]PCRValue, 0, len(bank.PCRs)),
		}

		for _, pcr := range bank.PCRs {
			bankOutput.PCRs = append(bankOutput.PCRs, PCRValue{
				Index:    int(pcr.ID),
				ValueHex: hex.EncodeToString(pcr.Value),
			})
		}

		output.Banks = append(output.Banks, bankOutput)
	}

	// Output based on format
	switch tpmCfg.outputFormat {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	default:
		return outputPCRsText(output)
	}
}

func parsePCRIndicesForPCRs(pcrString string) ([]uint, error) {
	parts := strings.Split(pcrString, ",")
	pcrs := make([]uint, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for range (e.g., "0-7")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("%w: invalid range '%s'", ErrInvalidPCRIndices, part)
			}

			start, err := strconv.ParseUint(strings.TrimSpace(rangeParts[0]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid range start '%s'", ErrInvalidPCRIndices, rangeParts[0])
			}

			end, err := strconv.ParseUint(strings.TrimSpace(rangeParts[1]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid range end '%s'", ErrInvalidPCRIndices, rangeParts[1])
			}

			if start > end || end > 23 {
				return nil, fmt.Errorf("%w: invalid range %d-%d", ErrInvalidPCRIndices, start, end)
			}

			for i := start; i <= end; i++ {
				pcrs = append(pcrs, uint(i))
			}
		} else {
			idx, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid PCR index '%s'", ErrInvalidPCRIndices, part)
			}

			if idx > 23 {
				return nil, fmt.Errorf("%w: PCR index %d out of range (0-23)", ErrInvalidPCRIndices, idx)
			}

			pcrs = append(pcrs, uint(idx))
		}
	}

	if len(pcrs) == 0 {
		return nil, fmt.Errorf("%w: no valid PCR indices specified", ErrInvalidPCRIndices)
	}

	return pcrs, nil
}

func outputPCRsText(output *PCRsOutput) error {
	fmt.Println("Platform Configuration Registers (PCRs)")
	fmt.Println("=======================================")

	for _, bank := range output.Banks {
		fmt.Println()
		fmt.Printf("Bank: %s\n", bank.Algorithm)
		fmt.Println(strings.Repeat("-", 40+len(bank.Algorithm)))

		for _, pcr := range bank.PCRs {
			// Indicate special PCRs
			var description string
			switch pcr.Index {
			case 0:
				description = " (BIOS/UEFI firmware)"
			case 1:
				description = " (BIOS/UEFI configuration)"
			case 2:
				description = " (Option ROMs)"
			case 3:
				description = " (Option ROM config)"
			case 4:
				description = " (MBR/IPL code)"
			case 5:
				description = " (MBR/IPL config)"
			case 6:
				description = " (State transitions)"
			case 7:
				description = " (Secure Boot policy)"
			case 8:
				description = " (OS measurements)"
			case 9:
				description = " (Kernel cmdline)"
			case 10:
				description = " (Linux IMA)"
			case 16:
				description = " (Debug)"
			case 23:
				description = " (Application)"
			}

			// Truncate long values for display
			valueHex := pcr.ValueHex
			if len(valueHex) > 64 {
				valueHex = valueHex[:64] + "..."
			}

			fmt.Printf("  PCR[%2d]: %s%s\n", pcr.Index, valueHex, description)
		}
	}

	return nil
}
