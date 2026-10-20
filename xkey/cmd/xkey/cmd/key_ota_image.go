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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// OTA image-key command errors.
var (
	// ErrOTAImageBoardIDRequired indicates an empty board id argument.
	ErrOTAImageBoardIDRequired = errors.New("ota-image: board id argument is required")

	// ErrOTAImageKeyCreateFailed indicates failure to create a board's key.
	ErrOTAImageKeyCreateFailed = errors.New("ota-image: failed to create OTA image key")

	// ErrOTAImageKeyRotateFailed indicates failure to rotate a board's key.
	ErrOTAImageKeyRotateFailed = errors.New("ota-image: failed to rotate OTA image key")

	// ErrOTAImageSignFailed indicates failure to sign an OTA image.
	ErrOTAImageSignFailed = errors.New("ota-image: failed to sign OTA image")

	// ErrOTAImageReadFailed indicates failure to read the image file.
	ErrOTAImageReadFailed = errors.New("ota-image: failed to read image file")

	// ErrOTAImageOutputFailed indicates failure to write a verb's output.
	ErrOTAImageOutputFailed = errors.New("ota-image: failed to write output")
)

// otaImageClientFactory connects the OTA image-key verbs to xkmsd. The keys
// live in the daemon, so the verbs are remote-mode only, like the CA verbs.
var otaImageClientFactory = connectXKMSdClient

// otaImageSignature is the JSON form of an OTA image signature, as xkmsctl
// prints it.
type otaImageSignature struct {
	Signature  string `json:"signature"`
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// keyCmd is the parent command for xkmsd key operations.
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Key operations on xkmsd",
	Long: `Manage keys held by xkmsd through the xkms SDK.

Server selection follows --xkmsd-url, then the XKMSD_URL environment
variable, then the xkmsd_url config key. The URL scheme picks the transport
(unix://, http://, https://, grpc://, grpcs://, quic://, mcp://, mcps://).
XKMSD_TOKEN supplies a bearer token; --tls-ca (or XKMSD_TLS_CA) supplies the
CA bundle used to verify TLS transports. --backend picks the key backend.`,
}

// keyOTAImageCmd is the parent command for per-board OTA image-signing keys.
var keyOTAImageCmd = &cobra.Command{
	Use:   "ota-image",
	Short: "Manage per-board OTA image-signing keys",
	Long: `Manage the ES256 key that signs a trusted-firmware board's OTA images.

Each board has one key, named ota-image-<board-id>. A board id is 1-63
characters of a-z, 0-9 and single inner hyphens. xkmsd refuses a malformed
board id and any algorithm other than ES256.`,
}

// keyOTAImageCreateCmd creates a board's OTA image-signing key.
var keyOTAImageCreateCmd = &cobra.Command{
	Use:   "create <board-id>",
	Short: "Create a board's OTA image-signing key",
	Long: `Create the ES256 key that signs a board's OTA images.

Example:
  xkey key ota-image create cm4 --backend software`,
	Args: cobra.ExactArgs(1),
	RunE: runKeyOTAImageCreate,
}

// keyOTAImageRotateCmd rotates a board's OTA image-signing key.
var keyOTAImageRotateCmd = &cobra.Command{
	Use:   "rotate <board-id>",
	Short: "Rotate a board's OTA image-signing key",
	Long: `Rotate a board's OTA image-signing key to a new version. Images signed
with the previous version still verify.

Example:
  xkey key ota-image rotate cm4 --backend software`,
	Args: cobra.ExactArgs(1),
	RunE: runKeyOTAImageRotate,
}

// keyOTAImageSignCmd signs an OTA image with a board's key.
var keyOTAImageSignCmd = &cobra.Command{
	Use:   "sign <board-id> <image-file>",
	Short: "Sign an OTA image with a board's key",
	Long: `Sign an OTA image with the current version of a board's key and print
the base64 ES256 signature. With --digest the file holds the image's SHA-256
digest instead of the image.

Example:
  xkey key ota-image sign cm4 firmware.bin --backend software`,
	Args: cobra.ExactArgs(2),
	RunE: runKeyOTAImageSign,
}

func init() {
	keyCmd.AddCommand(keyOTAImageCmd)
	keyOTAImageCmd.AddCommand(keyOTAImageCreateCmd, keyOTAImageRotateCmd, keyOTAImageSignCmd)

	keyCmd.PersistentFlags().String(tlsCAFlagName, "",
		"TLS CA certificate file used to verify the xkmsd server")

	for _, cmd := range []*cobra.Command{keyOTAImageCreateCmd, keyOTAImageRotateCmd} {
		cmd.Flags().String("algorithm", "ES256", "Key algorithm (ES256 is the only one accepted)")
	}
	keyOTAImageSignCmd.Flags().Bool("digest", false, "The file holds the image's SHA-256 digest, not the image")
	for _, cmd := range []*cobra.Command{keyOTAImageCreateCmd, keyOTAImageRotateCmd, keyOTAImageSignCmd} {
		cmd.Flags().Bool("json", false, "output the result as JSON")
	}

	RootCmd.AddCommand(keyCmd)
}

// runKeyOTAImageCreate executes the key ota-image create command.
func runKeyOTAImageCreate(cmd *cobra.Command, args []string) error {
	req, err := otaImageKeyRequest(cmd, args[0])
	if err != nil {
		return err
	}
	var resp *transport.GenerateKeyResponse
	err = callOTAImage(cmd, ErrOTAImageKeyCreateFailed, func(ctx context.Context, client transport.Client) (err error) {
		resp, err = client.CreateOTAImageKey(ctx, req)
		return err
	})
	if err != nil {
		return err
	}
	return printOTAImageResult(cmd, resp, "Successfully created OTA image key: "+resp.KeyID)
}

// runKeyOTAImageRotate executes the key ota-image rotate command.
func runKeyOTAImageRotate(cmd *cobra.Command, args []string) error {
	req, err := otaImageKeyRequest(cmd, args[0])
	if err != nil {
		return err
	}
	var resp *transport.RotateKeyResponse
	err = callOTAImage(cmd, ErrOTAImageKeyRotateFailed, func(ctx context.Context, client transport.Client) (err error) {
		resp, err = client.RotateOTAImageKey(ctx, req)
		return err
	})
	if err != nil {
		return err
	}
	message := fmt.Sprintf("Successfully rotated OTA image key: %s (current version %d)", resp.KeyID, resp.KeyVersion)
	if err := printOTAImageResult(cmd, resp, message); err != nil {
		return err
	}
	if !resp.CertificateReissueRequired {
		return nil
	}
	if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: Key %s has a certificate, which still certifies the previous version: re-issue it for version %d\n",
		resp.KeyID, resp.KeyVersion); err != nil {
		return &SentinelCauseError{Sentinel: ErrOTAImageOutputFailed, Cause: err}
	}
	return nil
}

// runKeyOTAImageSign executes the key ota-image sign command.
func runKeyOTAImageSign(cmd *cobra.Command, args []string) error {
	boardID := args[0]
	if boardID == "" {
		return ErrOTAImageBoardIDRequired
	}
	isDigest, err := commandFlagBool(cmd, "digest")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Clean(args[1]))
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOTAImageReadFailed, Cause: err}
	}
	req := &transport.OTAImageSignRequest{
		Backend:      viper.GetString("backend"),
		BoardID:      boardID,
		Data:         data,
		DataIsDigest: isDigest,
	}
	var resp *transport.SignResponse
	err = callOTAImage(cmd, ErrOTAImageSignFailed, func(ctx context.Context, client transport.Client) (err error) {
		resp, err = client.SignOTAImage(ctx, req)
		return err
	})
	if err != nil {
		return err
	}
	signature := otaImageSignature{
		Signature:  base64.StdEncoding.EncodeToString(resp.Signature),
		KeyVersion: resp.KeyVersion,
	}
	return printOTAImageResult(cmd, signature, signature.Signature)
}

// otaImageKeyRequest builds the create and rotate request for boardID.
func otaImageKeyRequest(cmd *cobra.Command, boardID string) (*transport.OTAImageKeyRequest, error) {
	if boardID == "" {
		return nil, ErrOTAImageBoardIDRequired
	}
	return &transport.OTAImageKeyRequest{
		Backend:   viper.GetString("backend"),
		BoardID:   boardID,
		Algorithm: commandFlagString(cmd, "algorithm"),
	}, nil
}

// callOTAImage connects to xkmsd, runs call and closes the client, wrapping
// any failure in the verb's sentinel.
func callOTAImage(cmd *cobra.Command, failure error, call func(context.Context, transport.Client) error) (err error) {
	client, err := otaImageClientFactory(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: failure, Cause: err}
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if err := call(context.Background(), client); err != nil {
		return &SentinelCauseError{Sentinel: failure, Cause: err}
	}
	return nil
}

// printOTAImageResult prints result as JSON under --json, else message.
func printOTAImageResult(cmd *cobra.Command, result any, message string) error {
	asJSON, err := commandFlagBool(cmd, "json")
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSON(cmd.OutOrStdout(), result)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), message); err != nil {
		return &SentinelCauseError{Sentinel: ErrOTAImageOutputFailed, Cause: err}
	}
	return nil
}
