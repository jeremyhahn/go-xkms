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
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

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

		sealData(cfg, printer, keyID, data, []byte(aadStr))
	},
}

// sealData seals data using the SDK client (handles both embedded and remote protocols)
func sealData(cfg *Config, printer *Printer, keyID string, data, aad []byte) {
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

	// Prepare seal request
	req := &client.SealRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
		Data:    data,
		AAD:     aad,
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
	if keyID != "" {
		result["key_id"] = keyID
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
		if err := fr.Err(); err != nil {
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
		} else {
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

		unsealData(cfg, printer, keyID, ciphertext, nonce, tag, []byte(aadStr))
	},
}

// unsealData unseals data using the SDK client (handles both embedded and remote protocols)
func unsealData(cfg *Config, printer *Printer, keyID string, ciphertext, nonce, tag, aad []byte) {
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

	// Prepare unseal request
	req := &client.UnsealRequest{
		Backend:    cfg.Backend,
		KeyID:      keyID,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
		AAD:        aad,
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
	sealCmd.Flags().String("key-id", "", "Key ID to use for sealing (optional)")
	sealCmd.Flags().String("data-file", "", "File containing data to seal")
	sealCmd.Flags().String("aad", "", "Additional authenticated data (optional)")

	// Unseal command flags
	unsealDataCmd.Flags().String("key-id", "", "Key ID to use for unsealing (optional)")
	unsealDataCmd.Flags().String("ciphertext", "", "Ciphertext in base64 (alternative to positional arg)")
	unsealDataCmd.Flags().String("ciphertext-file", "", "File containing ciphertext to unseal")
	unsealDataCmd.Flags().String("nonce", "", "Nonce/IV in base64 (if required)")
	unsealDataCmd.Flags().String("tag", "", "Authentication tag in base64 (if required)")
	unsealDataCmd.Flags().String("aad", "", "Additional authenticated data (optional)")

	// can-seal has no additional flags beyond global backend flag
}
