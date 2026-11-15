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
	"encoding/base64"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

var keySigningKeyCmd = &cobra.Command{
	Use:   "signing-key",
	Short: "Sign with a repository's release signing key",
	Long: `Use the tenant's release signing key, or the key a repository names
instead, to sign release artifacts.`,
}

var keySigningKeySignCmd = &cobra.Command{
	Use:   "sign <repository> <corim-file>",
	Short: "Sign a release CoRIM with a repository's key",
	Long: `Sign an unsigned CoRIM with the repository's signing key (the tenant's
release key unless the repository names another) and print the base64 signed
CoRIM and the key that signed it. With --out the signed CoRIM is written to
the file instead.

Example:
  xkmsctl key signing-key sign acme/app corim.cbor --out corim.signed.cbor`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		signer := fr.String("signer")
		outPath := fr.String("out")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		corim, err := os.ReadFile(filepath.Clean(args[1]))
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadDataFileFailed, Err: err})
			return
		}
		cfg := getConfig()
		req := &client.SignReleaseCoRIMRequest{Repository: args[0], CoRIM: corim, SignerName: signer}
		runClientCall(cfg, "Signing a release CoRIM for "+args[0], ErrSignReleaseCoRIMFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.SignReleaseCoRIM(ctx, req)
		}, func(p *Printer, result any) { printReleaseCoRIM(p, result, outPath) })
	},
}

// printReleaseCoRIM prints the signed CoRIM in base64 with its key, or
// writes the CoRIM to outPath and prints the key.
func printReleaseCoRIM(p *Printer, result any, outPath string) {
	resp, ok := result.(*client.SignReleaseCoRIMResponse)
	if !ok {
		return
	}
	if outPath != "" {
		if err := os.WriteFile(filepath.Clean(outPath), resp.SignedCoRIM, 0o600); err != nil {
			handleError(&WrappedError{Sentinel: ErrSignReleaseCoRIMFailed, Err: err})
			return
		}
		if err := p.PrintMessage("Signed CoRIM written to " + outPath + " with key " + resp.KeyID); err != nil {
			handleError(err)
		}
		return
	}
	if p.format == OutputFormatJSON {
		if err := p.printJSON(map[string]any{
			"signed_corim": base64.StdEncoding.EncodeToString(resp.SignedCoRIM),
			"key_id":       resp.KeyID,
			"backend":      resp.Backend,
		}); err != nil {
			handleError(err)
		}
		return
	}
	if err := p.PrintMessage("Signed with key " + resp.KeyID); err != nil {
		handleError(err)
		return
	}
	if err := p.PrintSignature(base64.StdEncoding.EncodeToString(resp.SignedCoRIM), 0); err != nil {
		handleError(err)
	}
}

func init() {
	keyCmd.AddCommand(keySigningKeyCmd)
	keySigningKeyCmd.AddCommand(keySigningKeySignCmd)
	keySigningKeySignCmd.Flags().String("signer", "", "corim-meta signer name (default: the repository)")
	keySigningKeySignCmd.Flags().String("out", "", "Write the signed CoRIM to this file instead of printing it")
}
