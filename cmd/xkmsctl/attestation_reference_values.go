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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// attestationReferenceValuesCmd groups the reference-value store verbs.
var attestationReferenceValuesCmd = &cobra.Command{
	Use:   "reference-values",
	Short: "Manage the Verifier's reference values",
	Long: `Manage the tenant's reference values: signed CoRIM manifests that name the
measurements the Verifier appraises evidence against. xkmsd verifies each
CoRIM's COSE_Sign1 signature against a reference-signer endorsement.`,
}

var attestationReferenceValuesPutCmd = &cobra.Command{
	Use:   "put <name>",
	Short: "Create or replace reference values",
	Long: `Create or replace reference values from a COSE_Sign1 signed CoRIM file
(--corim). The CLI does not parse the CoRIM; xkmsd verifies it.

Example:
  xkmsctl attestation reference-values put fw-2026 --corim fw.corim --repository oci.example/fw`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		corimPath := fr.String("corim")
		repository := fr.String("repository")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		req, err := referenceValuesPutRequest(args[0], corimPath, repository)
		if err != nil {
			handleError(err)
			return
		}
		runClientCall(getConfig(), "Putting attestation reference values "+args[0], ErrPutAttestationReferenceValuesFailed,
			func(ctx context.Context, cl client.Client) (any, error) {
				return cl.PutAttestationReferenceValues(ctx, req)
			}, printReferenceValuesPut)
	},
}

var attestationReferenceValuesGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Show reference values",
	Long: `Show one set of reference values by name.

Example:
  xkmsctl attestation reference-values get fw-2026`,
	Args: cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		req := &client.GetAttestationReferenceValuesRequest{Name: args[0]}
		runClientCall(getConfig(), "Getting attestation reference values "+args[0], ErrGetAttestationReferenceValuesFailed,
			func(ctx context.Context, cl client.Client) (any, error) {
				return cl.GetAttestationReferenceValues(ctx, req)
			}, printReferenceValues)
	},
}

var attestationReferenceValuesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the reference values",
	Long: `List the tenant's reference values.

Example:
  xkmsctl attestation reference-values list`,
	Args: cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		runClientCall(getConfig(), "Listing attestation reference values", ErrListAttestationReferenceValuesFailed,
			func(ctx context.Context, cl client.Client) (any, error) {
				return cl.ListAttestationReferenceValues(ctx)
			}, printReferenceValuesList)
	},
}

var attestationReferenceValuesDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete reference values",
	Long: `Delete reference values by name.

Example:
  xkmsctl attestation reference-values delete fw-2026`,
	Args: cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		name := args[0]
		runClientCall(getConfig(), "Deleting attestation reference values "+name, ErrDeleteAttestationReferenceValuesFailed,
			func(ctx context.Context, cl client.Client) (any, error) {
				return name, cl.DeleteAttestationReferenceValues(ctx, &client.DeleteAttestationReferenceValuesRequest{Name: name})
			}, printReferenceValuesDeleted)
	},
}

// referenceValuesPutRequest reads the signed CoRIM file and refuses a missing
// flag or an empty file before any call is made.
func referenceValuesPutRequest(name, corimPath, repository string) (*client.PutAttestationReferenceValuesRequest, error) {
	if corimPath == "" {
		return nil, fmt.Errorf("%w: --corim is required", ErrInvalidReferenceValuesFlags)
	}
	data, err := os.ReadFile(filepath.Clean(corimPath))
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrReadDataFileFailed, Err: err}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: --corim file %q is empty", ErrInvalidReferenceValuesFlags, corimPath)
	}
	return &client.PutAttestationReferenceValuesRequest{Name: name, SignedCoRIM: data, Repository: repository}, nil
}

// referenceValuesLine is the one-line text form of a record; it leaves out
// the CoRIM bytes.
func referenceValuesLine(rv *client.AttestationReferenceValues) string {
	pcrs := make([]string, 0, len(rv.PCRIndices))
	for _, i := range rv.PCRIndices {
		pcrs = append(pcrs, strconv.FormatUint(uint64(i), 10))
	}
	return fmt.Sprintf("%s\tmanifest=%s\tprofile=%s\tpcrs=%s\tnot-after=%s",
		rv.Name, rv.ManifestID, rv.Profile, strings.Join(pcrs, ","), formatReferenceValuesTime(rv.NotAfter))
}

func formatReferenceValuesTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func printReferenceValuesPut(p *Printer, result any) {
	rv, ok := result.(*client.AttestationReferenceValues)
	if !ok || printJSONResult(p, result) {
		return
	}
	printCallSuccess(p, fmt.Sprintf("Successfully put attestation reference values: %s (manifest %s)", rv.Name, rv.ManifestID))
}

func printReferenceValues(p *Printer, result any) {
	rv, ok := result.(*client.AttestationReferenceValues)
	if !ok || printJSONResult(p, result) {
		return
	}
	if err := p.PrintMessage(referenceValuesLine(rv)); err != nil {
		handleError(err)
	}
}

func printReferenceValuesList(p *Printer, result any) {
	resp, ok := result.(*client.ListAttestationReferenceValuesResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	if len(resp.ReferenceValues) == 0 {
		printCallSuccess(p, "No attestation reference values")
		return
	}
	for _, rv := range resp.ReferenceValues {
		if err := p.PrintMessage(referenceValuesLine(rv)); err != nil {
			handleError(err)
			return
		}
	}
}

func printReferenceValuesDeleted(p *Printer, result any) {
	name, ok := result.(string)
	if !ok || printJSONResult(p, map[string]string{"deleted": name}) {
		return
	}
	printCallSuccess(p, "Successfully deleted attestation reference values: "+name)
}

func init() {
	attestationCmd.AddCommand(attestationReferenceValuesCmd)
	attestationReferenceValuesCmd.AddCommand(attestationReferenceValuesPutCmd, attestationReferenceValuesGetCmd,
		attestationReferenceValuesListCmd, attestationReferenceValuesDeleteCmd)

	attestationReferenceValuesPutCmd.Flags().String("corim", "", "COSE_Sign1 signed CoRIM file (required)")
	attestationReferenceValuesPutCmd.Flags().String("repository", "", "Repository the reference values came from")
}
