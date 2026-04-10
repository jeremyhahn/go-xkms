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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// QuoteResult holds the result of a TPM quote operation
type QuoteResult struct {
	Quoted       string `json:"quoted"`
	QuotedHex    string `json:"quoted_hex"`
	Signature    string `json:"signature"`
	SignatureHex string `json:"signature_hex"`
	Nonce        string `json:"nonce"`
	NonceHex     string `json:"nonce_hex"`
	PCRs         string `json:"pcrs"`
	PCRsHex      string `json:"pcrs_hex"`
	HasEventLog  bool   `json:"has_event_log"`
	EventLogSize int    `json:"event_log_size,omitempty"`
}

var (
	quotePCRs       string
	quoteNonce      string
	quoteOutputFile string
	quoteIncludeLog bool
)

// tpmQuoteCmd represents the tpm quote command
var tpmQuoteCmd = &cobra.Command{
	Use:   "quote",
	Short: "Generate TPM quote for attestation",
	Long: `Generate a TPM quote for remote attestation.

A TPM quote is a signed statement from the TPM containing:
  - PCR values at the time of the quote
  - A nonce to prove freshness
  - A signature from the IAK

The quote can be verified by a remote party to attest to the
platform's configuration state.

Examples:
  # Generate quote for PCRs 0, 1, and 7
  xkey tpm quote --pcrs 0,1,7

  # Generate quote with specific nonce (hex)
  xkey tpm quote --pcrs 0,1,7 --nonce abc123

  # Generate quote and save to file
  xkey tpm quote --pcrs 0,1,7 --output quote.json

  # Generate quote including event log
  xkey tpm quote --pcrs 0,1,7,14 --include-log`,
	RunE: runTPMQuote,
}

func init() {
	tpmQuoteCmd.Flags().StringVar(&quotePCRs, "pcrs", "0,1,7",
		"Comma-separated list of PCR indices to include")
	tpmQuoteCmd.Flags().StringVar(&quoteNonce, "nonce", "",
		"Nonce value (hex-encoded, will be generated if not provided)")
	tpmQuoteCmd.Flags().StringVar(&quoteOutputFile, "output", "",
		"Output file path for quote data")
	tpmQuoteCmd.Flags().BoolVar(&quoteIncludeLog, "include-log", false,
		"Include event log in output (when available)")
}

func runTPMQuote(cmd *cobra.Command, args []string) error {
	// Parse PCR indices
	pcrs, err := parsePCRIndices(quotePCRs)
	if err != nil {
		return err
	}

	// Parse or generate nonce
	var nonce []byte
	if quoteNonce != "" {
		nonce, err = hex.DecodeString(quoteNonce)
		if err != nil {
			return fmt.Errorf("%w: nonce must be hex-encoded", ErrInvalidNonce)
		}
	}

	// Open TPM
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer tpm.Close()

	// Check for IAK
	if _, err := tpm.IAKAttributes(); err != nil {
		return fmt.Errorf("IAK not found - run 'tpm provision' first: %w", err)
	}

	// Generate quote
	fmt.Printf("Generating quote for PCRs: %v\n", pcrs)
	quote, err := tpm.Quote(pcrs, nonce)
	if err != nil {
		return fmt.Errorf("%w: failed to generate quote: %v", ErrTPMOperationFailed, err)
	}

	// Build result
	result := &QuoteResult{
		Quoted:       base64.StdEncoding.EncodeToString(quote.Quoted),
		QuotedHex:    hex.EncodeToString(quote.Quoted),
		Signature:    base64.StdEncoding.EncodeToString(quote.Signature),
		SignatureHex: hex.EncodeToString(quote.Signature),
		Nonce:        base64.StdEncoding.EncodeToString(quote.Nonce),
		NonceHex:     hex.EncodeToString(quote.Nonce),
		PCRs:         base64.StdEncoding.EncodeToString(quote.PCRs),
		PCRsHex:      hex.EncodeToString(quote.PCRs),
	}

	if len(quote.EventLog) > 0 {
		result.HasEventLog = true
		result.EventLogSize = len(quote.EventLog)
	}

	// Output to file if specified
	if quoteOutputFile != "" {
		return writeQuoteToFile(result, quote.EventLog)
	}

	// Output based on format
	switch tpmCfg.outputFormat {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	default:
		return outputQuoteText(result, pcrs)
	}
}

func parsePCRIndices(pcrString string) ([]uint, error) {
	parts := strings.Split(pcrString, ",")
	pcrs := make([]uint, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idx, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid PCR index '%s'", ErrInvalidPCRIndices, part)
		}

		if idx > 23 {
			return nil, fmt.Errorf("%w: PCR index %d out of range (0-23)", ErrInvalidPCRIndices, idx)
		}

		pcrs = append(pcrs, uint(idx))
	}

	if len(pcrs) == 0 {
		return nil, fmt.Errorf("%w: no valid PCR indices specified", ErrInvalidPCRIndices)
	}

	return pcrs, nil
}

func outputQuoteText(result *QuoteResult, pcrs []uint) error {
	fmt.Println()
	fmt.Println("TPM Quote")
	fmt.Println("=========")
	fmt.Println()

	fmt.Printf("PCRs:       %v\n", pcrs)
	fmt.Printf("Nonce:      %s\n", result.NonceHex)
	fmt.Println()

	fmt.Println("Quoted (TPMS_ATTEST):")
	fmt.Printf("  Hex:    %s\n", result.QuotedHex)
	fmt.Printf("  Base64: %s\n", result.Quoted)
	fmt.Println()

	fmt.Println("Signature:")
	fmt.Printf("  Hex:    %s\n", result.SignatureHex)
	fmt.Printf("  Base64: %s\n", result.Signature)
	fmt.Println()

	fmt.Println("PCR Values:")
	fmt.Printf("  Hex:    %s\n", result.PCRsHex)
	fmt.Printf("  Base64: %s\n", result.PCRs)
	fmt.Println()

	if result.HasEventLog {
		fmt.Printf("Event Log: Available (%d bytes)\n", result.EventLogSize)
	} else {
		fmt.Println("Event Log: Not available")
	}

	return nil
}

func writeQuoteToFile(result *QuoteResult, eventLog []byte) error {
	// Create output structure including event log if requested
	type QuoteOutput struct {
		QuoteResult
		EventLog string `json:"event_log,omitempty"`
	}

	output := QuoteOutput{
		QuoteResult: *result,
	}

	if quoteIncludeLog && len(eventLog) > 0 {
		output.EventLog = base64.StdEncoding.EncodeToString(eventLog)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal quote: %w", err)
	}

	// Write to file
	if err := os.WriteFile(quoteOutputFile, data, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrExportFailed, err)
	}

	fmt.Printf("Quote written to: %s\n", quoteOutputFile)
	return nil
}
