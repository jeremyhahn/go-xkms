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
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// keyOTAImageCmd groups the per-board OTA image-signing key verbs.
var keyOTAImageCmd = &cobra.Command{
	Use:   "ota-image",
	Short: "Manage per-board OTA image-signing keys",
	Long: `Manage the ES256 key that signs a trusted-firmware board's OTA images.

Each board has one key, named ota-image-<board-id>. A board id is 1-63
characters of a-z, 0-9 and single inner hyphens. xkmsd refuses a malformed
board id and any algorithm other than ES256.`,
}

var keyOTAImageCreateCmd = &cobra.Command{
	Use:   "create <board-id>",
	Short: "Create a board's OTA image-signing key",
	Long: `Create the ES256 key that signs a board's OTA images.

Example:
  xkmsctl key ota-image create cm4 --backend software`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runOTAImageKeyCall(cmd, args[0], "Creating the OTA image key of board "+args[0], ErrCreateOTAImageKeyFailed,
			func(ctx context.Context, cl client.Client, req *client.OTAImageKeyRequest) (any, error) {
				return cl.CreateOTAImageKey(ctx, req)
			}, printOTAImageKeyCreated)
	},
}

var keyOTAImageRotateCmd = &cobra.Command{
	Use:   "rotate <board-id>",
	Short: "Rotate a board's OTA image-signing key",
	Long: `Rotate a board's OTA image-signing key to a new version. Images signed
with the previous version still verify.

Example:
  xkmsctl key ota-image rotate cm4 --backend software`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runOTAImageKeyCall(cmd, args[0], "Rotating the OTA image key of board "+args[0], ErrRotateOTAImageKeyFailed,
			func(ctx context.Context, cl client.Client, req *client.OTAImageKeyRequest) (any, error) {
				return cl.RotateOTAImageKey(ctx, req)
			}, printOTAImageKeyRotated)
	},
}

var keyOTAImageSignCmd = &cobra.Command{
	Use:   "sign <board-id> <image-file>",
	Short: "Sign an OTA image with a board's key",
	Long: `Sign an OTA image with the current version of a board's key and print
the base64 ES256 signature. With --digest the file holds the image's SHA-256
digest instead of the image.

Example:
  xkmsctl key ota-image sign cm4 firmware.bin --backend software`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		isDigest := fr.Bool("digest")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		data, err := os.ReadFile(filepath.Clean(args[1]))
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadDataFileFailed, Err: err})
			return
		}
		cfg := getConfig()
		runClientCall(cfg, "Signing an OTA image for board "+args[0], ErrSignOTAImageFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.SignOTAImage(ctx, &client.OTAImageSignRequest{Backend: cfg.Backend, BoardID: args[0], Data: data, DataIsDigest: isDigest})
		}, printOTAImageSignature)
	},
}

var keyOTAImageExportCmd = &cobra.Command{
	Use:   "export <board-id>",
	Short: "Export a board's OTA verification public key",
	Long: `Export the public half of the current version of a board's OTA
image-signing key: the raw X || Y, 64 bytes in hex, and the COSE_Key
(RFC 9052 §7, RFC 9053 §7.1.1) in base64. The private key never leaves
xkmsd. With --output json the bytes are base64 in the JSON fields.

Example:
  xkmsctl key ota-image export cm4 --backend software`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runOTAImageKeyCall(cmd, args[0], "Exporting the OTA image key of board "+args[0], ErrExportOTAImageKeyFailed,
			func(ctx context.Context, cl client.Client, req *client.OTAImageKeyRequest) (any, error) {
				return cl.ExportOTAImageKey(ctx, req)
			}, printOTAImageKeyExported)
	},
}

// runOTAImageKeyCall sends a create or rotate request for boardID, with the
// --algorithm flag, through runClientCall.
func runOTAImageKeyCall(cmd *cobra.Command, boardID, verbose string, failure error,
	call func(context.Context, client.Client, *client.OTAImageKeyRequest) (any, error), show func(*Printer, any)) {
	fr := newFlagReader(cmd)
	algorithm := fr.String("algorithm")
	if err := fr.Err(); err != nil {
		handleError(err)
		return
	}
	cfg := getConfig()
	req := &client.OTAImageKeyRequest{Backend: cfg.Backend, BoardID: boardID, Algorithm: algorithm}
	runClientCall(cfg, verbose, failure, func(ctx context.Context, cl client.Client) (any, error) {
		return call(ctx, cl, req)
	}, show)
}

func printOTAImageKeyCreated(p *Printer, result any) {
	resp, ok := result.(*client.GenerateKeyResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	printCallSuccess(p, "Successfully created OTA image key: "+resp.KeyID)
}

func printOTAImageKeyRotated(p *Printer, result any) {
	resp, ok := result.(*client.RotateKeyResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	printCallSuccess(p, fmt.Sprintf("Successfully rotated OTA image key: %s (current version %d)", resp.KeyID, resp.KeyVersion))
	if resp.CertificateReissueRequired {
		if err := p.PrintWarning(fmt.Sprintf("Key %s has a certificate, which still certifies the previous version: re-issue it for version %d", resp.KeyID, resp.KeyVersion)); err != nil {
			handleError(err)
		}
	}
}

func printOTAImageSignature(p *Printer, result any) {
	resp, ok := result.(*client.SignResponse)
	if !ok {
		return
	}
	if err := p.PrintSignature(base64.StdEncoding.EncodeToString(resp.Signature), resp.KeyVersion); err != nil {
		handleError(err)
	}
}

func printOTAImageKeyExported(p *Printer, result any) {
	resp, ok := result.(*client.ExportOTAImageKeyResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	printCallSuccess(p, fmt.Sprintf("OTA image key of board %s: %s (version %d, %s)", resp.BoardID, resp.KeyID, resp.KeyVersion, resp.Algorithm))
	for _, line := range []string{
		"Public key (X || Y, hex): " + hex.EncodeToString(resp.PublicKey),
		"COSE_Key (base64): " + base64.StdEncoding.EncodeToString(resp.COSEKey),
	} {
		if err := p.PrintMessage(line); err != nil {
			handleError(err)
			return
		}
	}
}

func init() {
	keyCmd.AddCommand(keyOTAImageCmd)
	keyOTAImageCmd.AddCommand(keyOTAImageCreateCmd, keyOTAImageRotateCmd, keyOTAImageSignCmd, keyOTAImageExportCmd)

	for _, cmd := range []*cobra.Command{keyOTAImageCreateCmd, keyOTAImageRotateCmd, keyOTAImageExportCmd} {
		cmd.Flags().String("algorithm", "ES256", "Key algorithm (ES256 is the only one accepted)")
	}
	keyOTAImageSignCmd.Flags().Bool("digest", false, "The file holds the image's SHA-256 digest, not the image")
}
