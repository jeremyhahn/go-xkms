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
	"io"
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
	out := cmd.OutOrStdout()
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
			return &DetailError{Err: ErrInvalidNonce, Detail: ": nonce must be hex-encoded"}
		}
	}

	// Open TPM
	tpm, err := openTPM()
	if err != nil {
		return err
	}
	defer func() { _ = tpm.Close() }()

	// Check for IAK
	if _, err := tpm.IAKAttributes(); err != nil {
		return &WrappedError{Msg: "IAK not found - run 'tpm provision' first", Err: err}
	}

	// Generate quote
	_, _ = fmt.Fprintf(out, "Generating quote for PCRs: %v\n", pcrs)
	quote, err := tpm.Quote(pcrs, nonce)
	if err != nil {
		return &DetailError{Err: ErrTPMOperationFailed, Detail: fmt.Sprintf(": failed to generate quote: %v", err)}
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
		return writeQuoteToFile(out, result, quote.EventLog)
	}

	// Output based on format
	switch tpmCfg.outputFormat {
	case "json":
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	default:
		return outputQuoteText(out, result, pcrs)
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
			return nil, &DetailError{Err: ErrInvalidPCRIndices, Detail: fmt.Sprintf(": invalid PCR index '%s'", part)}
		}

		if idx > 23 {
			return nil, &DetailError{Err: ErrInvalidPCRIndices, Detail: fmt.Sprintf(": PCR index %d out of range (0-23)", idx)}
		}

		pcrs = append(pcrs, uint(idx))
	}

	if len(pcrs) == 0 {
		return nil, &DetailError{Err: ErrInvalidPCRIndices, Detail: ": no valid PCR indices specified"}
	}

	return pcrs, nil
}

func outputQuoteText(out io.Writer, result *QuoteResult, pcrs []uint) error {
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "TPM Quote")
	_, _ = fmt.Fprintln(out, "=========")
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintf(out, "PCRs:       %v\n", pcrs)
	_, _ = fmt.Fprintf(out, "Nonce:      %s\n", result.NonceHex)
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintln(out, "Quoted (TPMS_ATTEST):")
	_, _ = fmt.Fprintf(out, "  Hex:    %s\n", result.QuotedHex)
	_, _ = fmt.Fprintf(out, "  Base64: %s\n", result.Quoted)
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintln(out, "Signature:")
	_, _ = fmt.Fprintf(out, "  Hex:    %s\n", result.SignatureHex)
	_, _ = fmt.Fprintf(out, "  Base64: %s\n", result.Signature)
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintln(out, "PCR Values:")
	_, _ = fmt.Fprintf(out, "  Hex:    %s\n", result.PCRsHex)
	_, _ = fmt.Fprintf(out, "  Base64: %s\n", result.PCRs)
	_, _ = fmt.Fprintln(out)

	if result.HasEventLog {
		_, _ = fmt.Fprintf(out, "Event Log: Available (%d bytes)\n", result.EventLogSize)
	} else {
		_, _ = fmt.Fprintln(out, "Event Log: Not available")
	}

	return nil
}

func writeQuoteToFile(out io.Writer, result *QuoteResult, eventLog []byte) error {
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
		return &WrappedError{Msg: "failed to marshal quote", Err: err}
	}

	// Write to file
	if err := os.WriteFile(quoteOutputFile, data, 0600); err != nil {
		return &SentinelCauseError{Sentinel: ErrExportFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Quote written to: %s\n", quoteOutputFile)
	return nil
}
