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
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/awnumar/memguard"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// The raw memguard import above is forced, not a convenience: go-truststrap
// v0.4.0-alpha's p256proto.{NewStaticKey,EncodeStaticKey,DecodeStaticKey} take
// a *memguard.LockedBuffer directly, and secure.Buffer wraps its LockedBuffer
// in an unexported field with no accessor -- correctly, since exposing it
// would hand back the handle the boundary exists to withhold. Filed as
// jeremyhahn/go-truststrap#60; secure-analyzer exemption until it lands.

// Operator-side key management for the FIPS-approved bootstrap suite,
// TSBOOT1_P256_AESGCM_SHA256, alongside the Noise_NK verbs in
// bootstrap_noise.go.
//
// These exist because a FIPS deployment cannot use the Noise verbs at all --
// Noise_NK mandates X25519, which SP 800-56A Rev. 3 does not approve -- and
// without a way to generate a persistent P-256 responder key the listener falls
// back to an ephemeral one that changes on every restart, breaking every client
// provisioned with the previous public key (go-xkms#269).
//
// The private-key file handling is deliberately not reimplemented here:
// writeNoiseKeyFile already refuses to overwrite, creates at 0600, and cleans
// up a partial write, and those properties matter identically for either
// suite's key.

// p256GenerateKeyCmd generates a new P-256 static keypair for the approved suite.
var p256GenerateKeyCmd = &cobra.Command{
	Use:   "generate-p256-key",
	Short: "Generate a new P-256 static keypair for the FIPS-approved bootstrap suite",
	Long: `Generate a new P-256 static keypair for the TSBOOT1_P256_AESGCM_SHA256
bootstrap suite.

This is the suite a FIPS build serves. Noise_NK mandates X25519, which
SP 800-56A Rev. 3 does not approve, so a FIPS build cannot run it and this key
is the only one such a server has to offer.

The private key is written, hex-encoded, to the file named by --output, which
is created with 0600 permissions and must not already exist. It is never
printed: stdout is read by terminal scrollback, shell history, pipes and CI
logs, none of which can be wiped. The public key is displayed for distribution
to clients, which pin it as the server's responder key.

There is no config field to point the server at this file: the bootstrap
listener's own key is barrier-sealed, or persisted at a fixed path inside
its data directory, never config-supplied. To use a key generated here
instead of one the server generates for itself, place this file at
<storage.path>/bootstrap-noise-p256.key before the server's first boot --
that is the exact path the no-barrier custody path reads.`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFile, _ := cmd.Flags().GetString("output")
		generateP256Key(outputFile)
	},
}

// p256ShowKeyCmd shows the public key from a P-256 private key.
var p256ShowKeyCmd = &cobra.Command{
	Use:   "show-p256-key",
	Short: "Show the public key from a P-256 bootstrap static key",
	Long: `Derive and display the uncompressed public point from a P-256 static
private key file or hex string. This is the value clients pin as the server's
responder key for the TSBOOT1_P256_AESGCM_SHA256 suite.`,
	Run: func(cmd *cobra.Command, args []string) {
		keyFile, _ := cmd.Flags().GetString("key-file")
		keyHex, _ := cmd.Flags().GetString("key-hex")
		showP256Key(keyFile, keyHex)
	},
}

// generateP256Key generates a P-256 static keypair and writes the private half
// to outputFile, mirroring generateNoiseKey.
func generateP256Key(outputFile string) {
	if outputFile == "" {
		handleError(ErrOutputFileRequired)
		return
	}

	key, err := bootstrap.GenerateP256StaticKey()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGenerateKeyFailed, Err: err})
		return
	}
	defer key.Destroy()

	// The hex encoding is as sensitive as the scalar it encodes, so it gets a
	// guard-paged, swap-locked buffer outside the Go heap. The SDK's encoder
	// takes the LockedBuffer itself rather than a slice of it, which is why
	// this differs from the Noise path in shape but not in intent.
	buf := memguard.NewBuffer(bootstrap.P256HexKeySize + 1)
	defer buf.Destroy()

	if err := bootstrap.EncodeP256StaticKey(buf, key); err != nil {
		handleError(&WrappedError{Sentinel: ErrEncodeKeyFailed, Err: err})
		return
	}
	encoded := buf.Bytes()
	encoded[bootstrap.P256HexKeySize] = '\n'

	publicHex := hex.EncodeToString(key.PublicBytes())

	if err := writeNoiseKeyFile(outputFile, encoded); err != nil {
		handleError(&WrappedError{Sentinel: ErrWriteKeyFileFailed, Err: err})
		return
	}

	fmt.Printf("Private key written to: %s\n", outputFile)
	fmt.Printf("Public key:  %s\n", publicHex)
}

// showP256Key derives and prints the public point from a stored private key.
func showP256Key(keyFile, keyHex string) {
	var hexKey []byte

	switch {
	case keyFile != "":
		data, err := os.ReadFile(keyFile)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadKeyFileFailed, Err: err})
			return
		}
		// The file bytes are ours to wipe once decoded; TrimSpace returns a
		// subslice of the same backing array, so wiping data covers both.
		defer secure.Wipe(data)
		hexKey = bytes.TrimSpace(data)
	case keyHex != "":
		// --key-hex came in on the command line and is already visible in the
		// process table and shell history, so there is nothing left to
		// protect in this copy.
		hexKey = []byte(keyHex)
	default:
		handleError(ErrKeyInputRequired)
		return
	}

	if len(hexKey) != bootstrap.P256HexKeySize {
		handleError(&WrappedError{
			Sentinel: ErrDecodeKeyFailed,
			Err:      fmt.Errorf("key is %d hex characters, want %d", len(hexKey), bootstrap.P256HexKeySize),
		})
		return
	}

	// NewBufferFromBytes wipes hexKey as it copies it into protected memory.
	protected := memguard.NewBufferFromBytes(hexKey)
	defer protected.Destroy()

	key, err := bootstrap.DecodeP256StaticKey(protected)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrDecodeKeyFailed, Err: err})
		return
	}
	defer key.Destroy()

	fmt.Printf("Public key: %s\n", hex.EncodeToString(key.PublicBytes()))
}
