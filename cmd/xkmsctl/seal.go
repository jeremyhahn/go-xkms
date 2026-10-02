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

package main

import (
	"context"
	"encoding/base64"
	"os"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/spf13/cobra"
)

// sealCmd seals data using the backend's sealing mechanism
var sealCmd = &cobra.Command{
	Use:   "seal <data>",
	Short: "Seal data using the backend's sealing mechanism",
	Long: `Seal (encrypt) data using the backend's sealing mechanism.
The data can be provided as a string argument, or use --data-file to read from a file.
The result is output as base64-encoded ciphertext.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		fr := newFlagReader(cmd)
		keyID := fr.String("key-id")
		dataFile := fr.String("data-file")
		aadStr := fr.String("aad")
		tpmPolicy := fr.String("tpm-policy")
		passwordFlag := fr.String("password")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		password, err := sealPassword(passwordFlag)
		if err != nil {
			handleError(err)
			return
		}
		defer password.Destroy()
		tpm := sealTPMParams{Policy: tpmPolicy, Password: password}

		// Get data from args or file
		var data []byte
		if len(args) > 0 {
			data = []byte(args[0])
		} else if dataFile != "" {
			var err error
			data, err = os.ReadFile(dataFile)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrReadDataFileFailed, Err: err})
				return
			}
		} else {
			handleError(ErrDataInputRequired)
			return
		}

		printVerbose("Sealing %d bytes of data", len(data))

		sealData(cfg, printer, keyID, data, []byte(aadStr), tpm)
	},
}

// sealTPMParams are the seal parameters of a TPM2 sealed object.
type sealTPMParams struct {
	// Policy names the TPM policy the sealed object is bound to.
	Policy string

	// Password is the sealed object's authorization value; nil for none.
	Password *secure.Secret
}

// unsealTPMParams are the unseal parameters of a TPM2 sealed object.
type unsealTPMParams struct {
	// Public and Private are the sealed object's areas, as seal output them.
	Public, Private []byte

	// Password is the sealed object's authorization value; nil for none.
	Password *secure.Secret
}

// sealPassword seals a --password value into protected memory as soon as it
// is read, so the authorization value is never held in a struct as a string.
// An empty value means the object has no password and yields nil.
func sealPassword(password string) (*secure.Secret, error) {
	if password == "" {
		return nil, nil
	}
	secret, err := secure.NewSecret([]byte(password))
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPasswordSealFailed, Err: err}
	}
	return secret, nil
}

// openPassword opens a sealed object's authorization value for the wire
// request, which carries it as client.SecretBytes. A nil password opens to
// nil. The caller owns the result and must Wipe it.
func openPassword(password *secure.Secret) (client.SecretBytes, error) {
	if password == nil {
		return nil, nil
	}
	buf, err := password.Open()
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPasswordOpenFailed, Err: err}
	}
	defer buf.Destroy()
	wire, err := secure.CopyOut(buf)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPasswordOpenFailed, Err: err}
	}
	return wire, nil
}

// sealData seals data using the SDK client (handles both embedded and remote protocols)
func sealData(cfg *Config, printer *Printer, keyID string, data, aad []byte, tpm sealTPMParams) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	password, err := openPassword(tpm.Password)
	if err != nil {
		handleError(err)
		return
	}
	defer secure.Wipe(password)

	// Prepare seal request
	req := &client.SealRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Data:      data,
		AAD:       aad,
		TPMPolicy: tpm.Policy,
		Password:  password,
	}

	// Seal the data
	resp, err := cl.Seal(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrSealDataFailed, Err: err})
		return
	}

	// Output the sealed data as base64
	result := map[string]interface{}{
		"backend":    resp.Backend,
		"ciphertext": base64.StdEncoding.EncodeToString(resp.Ciphertext),
	}
	if len(resp.Nonce) > 0 {
		result["nonce"] = base64.StdEncoding.EncodeToString(resp.Nonce)
	}
	if len(resp.Tag) > 0 {
		result["tag"] = base64.StdEncoding.EncodeToString(resp.Tag)
	}
	// A TPM2 sealed object is its public and private areas; unseal needs
	// both back (--tpm-public, --tpm-private).
	if len(resp.TPMPublic) > 0 {
		result["tpm_public"] = base64.StdEncoding.EncodeToString(resp.TPMPublic)
	}
	if len(resp.TPMPrivate) > 0 {
		result["tpm_private"] = base64.StdEncoding.EncodeToString(resp.TPMPrivate)
	}
	switch {
	case keyID != "":
		result["key_id"] = keyID
	case resp.KeyID != "":
		result["key_id"] = resp.KeyID
	}

	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

// unsealDataCmd unseals previously sealed data
var unsealDataCmd = &cobra.Command{
	Use:   "unseal <ciphertext>",
	Short: "Unseal previously sealed data",
	Long: `Unseal (decrypt) previously sealed data.
The ciphertext should be provided as base64-encoded string.
Use --nonce and --tag for algorithms that require them.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		fr := newFlagReader(cmd)
		keyID := fr.String("key-id")
		ciphertextStr := fr.String("ciphertext")
		ciphertextFile := fr.String("ciphertext-file")
		nonceStr := fr.String("nonce")
		tagStr := fr.String("tag")
		aadStr := fr.String("aad")
		tpmPublic := fr.String("tpm-public")
		tpmPrivate := fr.String("tpm-private")
		passwordFlag := fr.String("password")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		password, err := sealPassword(passwordFlag)
		if err != nil {
			handleError(err)
			return
		}
		defer password.Destroy()

		tpm, err := decodeUnsealTPMParams(tpmPublic, tpmPrivate, password)
		if err != nil {
			handleError(err)
			return
		}

		// Get ciphertext from args, flag, or file
		var ciphertextB64 string
		if len(args) > 0 {
			ciphertextB64 = args[0]
		} else if ciphertextStr != "" {
			ciphertextB64 = ciphertextStr
		} else if ciphertextFile != "" {
			data, err := os.ReadFile(ciphertextFile)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrReadCiphertextFileFailed, Err: err})
				return
			}
			ciphertextB64 = string(data)
		} else if len(tpm.Public) == 0 {
			handleError(ErrCiphertextInputRequired)
			return
		}

		// Decode base64 ciphertext
		ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrInvalidBase64Ciphertext, Err: err})
			return
		}

		// Decode optional nonce and tag
		var nonce, tag []byte
		if nonceStr != "" {
			nonce, err = base64.StdEncoding.DecodeString(nonceStr)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrInvalidBase64Nonce, Err: err})
				return
			}
		}
		if tagStr != "" {
			tag, err = base64.StdEncoding.DecodeString(tagStr)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrInvalidBase64Tag, Err: err})
				return
			}
		}

		printVerbose("Unsealing %d bytes of ciphertext", len(ciphertext))

		unsealData(cfg, printer, keyID, ciphertext, nonce, tag, []byte(aadStr), tpm)
	},
}

// decodeUnsealTPMParams decodes the base64 --tpm-public and --tpm-private
// areas of a TPM2 sealed object; both or neither must be given.
func decodeUnsealTPMParams(public, private string, password *secure.Secret) (unsealTPMParams, error) {
	params := unsealTPMParams{Password: password}
	if (public == "") != (private == "") {
		return params, ErrTPMAreasRequired
	}
	if public == "" {
		return params, nil
	}
	var err error
	if params.Public, err = base64.StdEncoding.DecodeString(public); err != nil {
		return params, &WrappedError{Sentinel: ErrInvalidBase64TPMArea, Err: err}
	}
	if params.Private, err = base64.StdEncoding.DecodeString(private); err != nil {
		return params, &WrappedError{Sentinel: ErrInvalidBase64TPMArea, Err: err}
	}
	return params, nil
}

// unsealData unseals data using the SDK client (handles both embedded and remote protocols)
func unsealData(cfg *Config, printer *Printer, keyID string, ciphertext, nonce, tag, aad []byte, tpm unsealTPMParams) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	password, err := openPassword(tpm.Password)
	if err != nil {
		handleError(err)
		return
	}
	defer secure.Wipe(password)

	// Prepare unseal request
	req := &client.UnsealRequest{
		Backend:    cfg.Backend,
		KeyID:      keyID,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
		AAD:        aad,
		TPMPublic:  tpm.Public,
		TPMPrivate: tpm.Private,
		Password:   password,
	}

	// Unseal the data
	resp, err := cl.Unseal(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrUnsealDataFailed, Err: err})
		return
	}

	// Output the plaintext
	result := map[string]interface{}{
		"plaintext": string(resp.Plaintext),
	}

	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

// canSealCmd checks if a backend supports sealing operations
var canSealCmd = &cobra.Command{
	Use:   "can-seal",
	Short: "Check if a backend supports sealing operations",
	Long:  `Check if the specified backend supports sealing (encryption) operations`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Checking sealing support for backend: %s", cfg.Backend)

		canSeal(cfg, printer)
	},
}

// canSeal checks sealing support using the SDK client (handles both embedded and remote protocols)
func canSeal(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")

	// Check sealing support
	resp, err := cl.CanSeal(ctx, cfg.Backend)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCheckSealingSupportFailed, Err: err})
		return
	}

	result := map[string]interface{}{
		"can_seal": resp.CanSeal,
		"backend":  resp.Backend,
	}

	if err := printer.PrintJSON(result); err != nil {
		handleError(err)
	}
}

func init() {
	// Seal command flags
	sealCmd.Flags().String("key-id", "", "Key ID to use for sealing (optional; on tpm2 it names the sealed object, and without it each seal creates a uniquely named object whose key_id is printed)")
	sealCmd.Flags().String("data-file", "", "File containing data to seal")
	sealCmd.Flags().String("aad", "", "Additional authenticated data (optional)")
	sealCmd.Flags().String("tpm-policy", "", "TPM policy a TPM2 sealed object is bound to: 'platform', a policy from 'xkmsctl tpm policy', or empty for none; a TPM2 seal needs a policy, a password or both")
	sealCmd.Flags().String("password", "", "Authorization value of a TPM2 sealed object; with a TPM policy it counts only inside the policy, without one it is the object's only protection")

	// Unseal command flags
	unsealDataCmd.Flags().String("key-id", "", "Key ID to use for unsealing (optional; required on tpm2: the key_id the seal printed)")
	unsealDataCmd.Flags().String("ciphertext", "", "Ciphertext in base64 (alternative to positional arg)")
	unsealDataCmd.Flags().String("ciphertext-file", "", "File containing ciphertext to unseal")
	unsealDataCmd.Flags().String("nonce", "", "Nonce/IV in base64 (if required)")
	unsealDataCmd.Flags().String("tag", "", "Authentication tag in base64 (if required)")
	unsealDataCmd.Flags().String("aad", "", "Additional authenticated data (optional)")
	unsealDataCmd.Flags().String("tpm-public", "", "TPM2 sealed object's public area in base64, as seal output it")
	unsealDataCmd.Flags().String("tpm-private", "", "TPM2 sealed object's private area in base64, as seal output it")
	unsealDataCmd.Flags().String("password", "", "Authorization value of a TPM2 sealed object (optional)")

	// can-seal has no additional flags beyond global backend flag
}
