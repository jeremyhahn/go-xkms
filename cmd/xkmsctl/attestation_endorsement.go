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

	"github.com/spf13/cobra"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// attestationCmd groups the attestation Verifier verbs.
var attestationCmd = &cobra.Command{
	Use:   "attestation",
	Short: "Manage the attestation Verifier",
	Long: `Manage the tenant's attestation Verifier: the endorsements (trust anchors)
and the signed CoRIM reference values it appraises evidence against, and
appraise a TPM quote against them (appraise).`,
}

// attestationEndorsementCmd groups the endorsement store verbs.
var attestationEndorsementCmd = &cobra.Command{
	Use:   "endorsement",
	Short: "Manage the Verifier's endorsements",
	Long: `Manage the tenant's endorsements: the AK roots that anchor attestation-key
certificates (kind ak-root) and the keys that sign CoRIM reference values
(kind reference-signer).`,
}

var attestationEndorsementPutCmd = &cobra.Command{
	Use:   "put <name>",
	Short: "Create or replace an endorsement",
	Long: `Create or replace an endorsement from a PEM file: a certificate (--cert) or a
public key (--public-key), exactly one. xkmsd validates the PEM.

Example:
  xkmsctl attestation endorsement put ak1 --kind ak-root --cert ak-root.pem`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		kind := fr.String("kind")
		certPath := fr.String("cert")
		keyPath := fr.String("public-key")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		req, err := endorsementPutRequest(args[0], kind, certPath, keyPath)
		if err != nil {
			handleError(err)
			return
		}
		runClientCall(getConfig(), "Putting attestation endorsement "+args[0], ErrPutAttestationEndorsementFailed,
			func(ctx context.Context, cl client.Client) (any, error) {
				return cl.PutAttestationEndorsement(ctx, req)
			}, printEndorsementPut)
	},
}

var attestationEndorsementListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the endorsements",
	Long: `List the tenant's endorsements, optionally of one kind.

Example:
  xkmsctl attestation endorsement list --kind reference-signer`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		fr := newFlagReader(cmd)
		kind := fr.String("kind")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if kind != "" {
			if err := checkEndorsementKind(kind); err != nil {
				handleError(err)
				return
			}
		}
		req := &client.ListAttestationEndorsementsRequest{Kind: client.AttestationEndorsementKind(kind)}
		runClientCall(getConfig(), "Listing attestation endorsements", ErrListAttestationEndorsementsFailed,
			func(ctx context.Context, cl client.Client) (any, error) {
				return cl.ListAttestationEndorsements(ctx, req)
			}, printEndorsementList)
	},
}

var attestationEndorsementDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an endorsement",
	Long: `Delete an endorsement by name.

Example:
  xkmsctl attestation endorsement delete ak1`,
	Args: cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		name := args[0]
		runClientCall(getConfig(), "Deleting attestation endorsement "+name, ErrDeleteAttestationEndorsementFailed,
			func(ctx context.Context, cl client.Client) (any, error) {
				return name, cl.DeleteAttestationEndorsement(ctx, &client.DeleteAttestationEndorsementRequest{Name: name})
			}, printEndorsementDeleted)
	},
}

// checkEndorsementKind refuses a kind other than ak-root or reference-signer.
func checkEndorsementKind(kind string) error {
	switch client.AttestationEndorsementKind(kind) {
	case client.AttestationEndorsementAKRoot, client.AttestationEndorsementReferenceSigner:
		return nil
	}
	return fmt.Errorf("%w: --kind %q is not %s or %s", ErrInvalidEndorsementFlags, kind,
		client.AttestationEndorsementAKRoot, client.AttestationEndorsementReferenceSigner)
}

// endorsementPutRequest checks the put flags and reads the one PEM file they
// name. It returns an error before any call is made.
func endorsementPutRequest(name, kind, certPath, keyPath string) (*client.PutAttestationEndorsementRequest, error) {
	if err := checkEndorsementKind(kind); err != nil {
		return nil, err
	}
	if (certPath == "") == (keyPath == "") {
		return nil, fmt.Errorf("%w: give exactly one of --cert and --public-key", ErrInvalidEndorsementFlags)
	}
	path := certPath
	if path == "" {
		path = keyPath
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrReadDataFileFailed, Err: err}
	}
	req := &client.PutAttestationEndorsementRequest{Name: name, Kind: client.AttestationEndorsementKind(kind)}
	if certPath != "" {
		req.CertificatePEM = data
	} else {
		req.PublicKeyPEM = data
	}
	return req, nil
}

func printEndorsementPut(p *Printer, result any) {
	resp, ok := result.(*client.AttestationEndorsement)
	if !ok || printJSONResult(p, result) {
		return
	}
	printCallSuccess(p, fmt.Sprintf("Successfully put attestation endorsement: %s (%s)", resp.Name, resp.Kind))
}

func printEndorsementList(p *Printer, result any) {
	resp, ok := result.(*client.ListAttestationEndorsementsResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	if len(resp.Endorsements) == 0 {
		printCallSuccess(p, "No attestation endorsements")
		return
	}
	for _, e := range resp.Endorsements {
		if err := p.PrintMessage(fmt.Sprintf("%s\t%s", e.Name, e.Kind)); err != nil {
			handleError(err)
			return
		}
	}
}

func printEndorsementDeleted(p *Printer, result any) {
	name, ok := result.(string)
	if !ok || printJSONResult(p, map[string]string{"deleted": name}) {
		return
	}
	printCallSuccess(p, "Successfully deleted attestation endorsement: "+name)
}

func init() {
	rootCmd.AddCommand(attestationCmd)
	attestationCmd.AddCommand(attestationEndorsementCmd)
	attestationEndorsementCmd.AddCommand(attestationEndorsementPutCmd, attestationEndorsementListCmd, attestationEndorsementDeleteCmd)

	attestationEndorsementPutCmd.Flags().String("kind", "", "Endorsement kind: ak-root or reference-signer (required)")
	attestationEndorsementPutCmd.Flags().String("cert", "", "PEM certificate file")
	attestationEndorsementPutCmd.Flags().String("public-key", "", "PEM public key file")
	attestationEndorsementListCmd.Flags().String("kind", "", "List only this kind: ak-root or reference-signer")
}
