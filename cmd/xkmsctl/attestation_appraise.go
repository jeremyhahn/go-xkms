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

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// maxPCRIndex is the highest PCR index a TPM 2.0 quote selects.
const maxPCRIndex = 23

// pcrFlagValue collects --pcr values. It is repeatable and also takes a
// comma-separated list; an empty value clears it.
type pcrFlagValue struct {
	entries []string
}

func (v *pcrFlagValue) String() string { return strings.Join(v.entries, ",") }

func (v *pcrFlagValue) Set(value string) error {
	if value == "" {
		v.entries = nil
		return nil
	}
	v.entries = append(v.entries, strings.Split(value, ",")...)
	return nil
}

func (v *pcrFlagValue) Type() string { return "index=hex" }

// appraisePCRs holds the appraise verb's --pcr values.
var appraisePCRs = &pcrFlagValue{}

var attestationAppraiseCmd = &cobra.Command{
	Use:   "appraise",
	Short: "Appraise a TPM quote against stored reference values",
	Long: `Appraise TPM quote evidence against stored, signed reference values and
print the attestation result. The command exits 0 only when the result is
verified; otherwise it prints the result and exits non-zero. The CLI does not
parse the quote or the certificate; xkmsd does.

--pcr is <index>=<hex>, index 0-23, each index once; repeat the flag or give
a comma-separated list.

Example:
  xkmsctl attestation appraise --reference-values fw-2026 \
    --ak-cert ak.pem --quote quote.bin --signature quote.sig \
    --nonce 0a0b0c0d --pcr 0=<hex> --pcr 7=<hex> --event-log eventlog.bin`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		fr := newFlagReader(cmd)
		paths := appraisePaths{
			referenceValues: fr.String("reference-values"),
			akCert:          fr.String("ak-cert"),
			quote:           fr.String("quote"),
			signature:       fr.String("signature"),
			nonce:           fr.String("nonce"),
			eventLog:        fr.String("event-log"),
		}
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		req, err := appraiseRequest(paths, appraisePCRs.entries)
		if err != nil {
			handleError(err)
			return
		}
		var result *client.AttestationAppraisalResult
		runClientCall(getConfig(), "Appraising attestation quote against "+req.ReferenceValues, ErrAppraiseAttestationQuoteFailed,
			func(ctx context.Context, cl client.Client) (any, error) {
				res, callErr := cl.AppraiseAttestationQuote(ctx, req)
				result = res
				return res, callErr
			}, printAppraisalResult)
		if result != nil && !result.Verified {
			handleError(notVerifiedError(result))
		}
	},
}

// appraisePaths are the appraise verb's string flags.
type appraisePaths struct {
	referenceValues, akCert, quote, signature, nonce, eventLog string
}

// appraiseRequest checks every input and builds the request; nothing is sent
// until it succeeds.
func appraiseRequest(in appraisePaths, pcrs []string) (*client.AppraiseAttestationQuoteRequest, error) {
	if in.referenceValues == "" {
		return nil, fmt.Errorf("%w: --reference-values is required", ErrInvalidAppraiseFlags)
	}
	req := &client.AppraiseAttestationQuoteRequest{ReferenceValues: in.referenceValues}
	var err error
	if req.AKCertificatePEM, err = readAppraiseFile("ak-cert", in.akCert); err != nil {
		return nil, err
	}
	if req.Quote, err = readAppraiseFile("quote", in.quote); err != nil {
		return nil, err
	}
	if req.Signature, err = readAppraiseFile("signature", in.signature); err != nil {
		return nil, err
	}
	if in.eventLog != "" {
		if req.EventLog, err = readAppraiseFile("event-log", in.eventLog); err != nil {
			return nil, err
		}
	}
	if in.nonce == "" {
		return nil, fmt.Errorf("%w: --nonce is required", ErrInvalidAppraiseFlags)
	}
	if req.Nonce, err = hex.DecodeString(in.nonce); err != nil {
		return nil, fmt.Errorf("%w: --nonce is not hex: %w", ErrInvalidAppraiseFlags, err)
	}
	if req.PCRs, err = parseAppraisePCRs(pcrs); err != nil {
		return nil, err
	}
	return req, nil
}

// readAppraiseFile reads a required, non-empty evidence file.
func readAppraiseFile(flag, path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: --%s is required", ErrInvalidAppraiseFlags, flag)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrReadDataFileFailed, Err: err}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: --%s file %q is empty", ErrInvalidAppraiseFlags, flag, path)
	}
	return data, nil
}

// parseAppraisePCRs parses <index>=<hex> entries, index 0-23, each once.
func parseAppraisePCRs(entries []string) (map[uint32][]byte, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: at least one --pcr is required", ErrInvalidAppraiseFlags)
	}
	pcrs := make(map[uint32][]byte, len(entries))
	for _, entry := range entries {
		idxText, valueText, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("%w: --pcr %q is not <index>=<hex>", ErrInvalidAppraiseFlags, entry)
		}
		idx, err := strconv.ParseUint(idxText, 10, 32)
		if err != nil || idx > maxPCRIndex {
			return nil, fmt.Errorf("%w: --pcr %q: index must be 0-%d", ErrInvalidAppraiseFlags, entry, maxPCRIndex)
		}
		value, err := hex.DecodeString(valueText)
		if err != nil || len(value) == 0 {
			return nil, fmt.Errorf("%w: --pcr %q: value must be non-empty hex", ErrInvalidAppraiseFlags, entry)
		}
		if _, dup := pcrs[uint32(idx)]; dup {
			return nil, fmt.Errorf("%w: --pcr index %d given twice", ErrInvalidAppraiseFlags, idx)
		}
		pcrs[uint32(idx)] = value
	}
	return pcrs, nil
}

// notVerifiedError is the exit error of a result that is not verified.
func notVerifiedError(result *client.AttestationAppraisalResult) error {
	if result.CryptographicFailure {
		return fmt.Errorf("%w: cryptographic failure: evidence present and wrong", ErrAttestationNotVerified)
	}
	return ErrAttestationNotVerified
}

func printAppraisalResult(p *Printer, result any) {
	res, ok := result.(*client.AttestationAppraisalResult)
	if !ok || printJSONResult(p, result) {
		return
	}
	verdict := "verified"
	switch {
	case res.CryptographicFailure:
		verdict = "NOT verified (cryptographic failure)"
	case !res.Verified:
		verdict = "NOT verified"
	}
	lines := []string{
		"Appraisal: " + verdict,
		"Reference values: " + res.ReferenceValues,
		"Manifest ID: " + res.ManifestID,
		"Signer: " + res.Signer,
		"Baseline source: " + res.BaselineSource,
		"Appraised at: " + res.AppraisedAt.UTC().Format(time.RFC3339),
	}
	for _, check := range res.Checks {
		line := fmt.Sprintf("Check %s: %s", check.Name, check.Outcome)
		if check.Reason != "" {
			line += ": " + check.Reason
		}
		lines = append(lines, line)
	}
	if err := p.PrintMessage(strings.Join(lines, "\n")); err != nil {
		handleError(err)
	}
}

func init() {
	attestationCmd.AddCommand(attestationAppraiseCmd)

	flags := attestationAppraiseCmd.Flags()
	flags.String("reference-values", "", "Name of the stored reference values to appraise against (required)")
	flags.String("ak-cert", "", "Attestation-key certificate PEM file, leaf first (required)")
	flags.String("quote", "", "Marshaled TPMS_ATTEST file (required)")
	flags.String("signature", "", "Quote signature file (required)")
	flags.String("nonce", "", "Qualifying data the quote carries, hex (required)")
	flags.Var(appraisePCRs, "pcr", "PCR value <index>=<hex>, index 0-23; repeatable (at least one required)")
	flags.String("event-log", "", "TCG event log file (optional)")
}
