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

//go:build frost

package main

import (
	"bytes"
	"io"
	"os"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/spf13/cobra"
)

// frostPassphraseFlagStdin, frostPassphraseFlagFile and frostPassphraseEnvVar
// name the three sources of the passphrase that encrypts the local FROST
// wrapping key (go-xkms#1324). There is deliberately no flag that takes the
// passphrase as a value: a flag value is visible to every process on the
// host through /proc and lands in shell history.
const (
	frostPassphraseFlagStdin = "passphrase-stdin"
	frostPassphraseFlagFile  = "passphrase-file"
	frostPassphraseEnvVar    = "XKMS_FROST_PASSPHRASE"
)

// frostPassphraseUsage is the operator-facing description of the passphrase
// sources, embedded in the long help of every FROST verb that takes one.
const frostPassphraseUsage = `This command seals or unseals this participant's secret share, so it needs
the FROST passphrase. Supply it one of three ways, in precedence order:

  --passphrase-stdin       read the passphrase from standard input
  --passphrase-file <path> read the passphrase from a file
  XKMS_FROST_PASSPHRASE    environment variable

One trailing newline is removed from stdin and file input.`

// addFrostPassphraseFlags declares the passphrase flags resolveFrostPassphrase
// reads on every FROST verb that seals or unseals a secret share.
func addFrostPassphraseFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(frostPassphraseFlagStdin, false, "read the FROST passphrase from standard input")
	cmd.Flags().String(frostPassphraseFlagFile, "", "read the FROST passphrase from this file")
	cmd.MarkFlagsMutuallyExclusive(frostPassphraseFlagStdin, frostPassphraseFlagFile)
}

// resolveFrostPassphrase returns the FROST passphrase from the source the
// command was given -- standard input, a file, or XKMS_FROST_PASSPHRASE, in
// that order -- held in protected memory as a client.Password. The caller
// must Clear it when done.
//
// It returns ErrFrostPassphraseRequired when no source was supplied and
// ErrFrostPassphraseEmpty when the chosen source held nothing.
func resolveFrostPassphrase(cmd *cobra.Command) (client.Password, error) {
	raw, err := readFrostPassphrase(cmd)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(raw)

	passphrase := trimLineEnding(raw)
	if len(passphrase) == 0 {
		return nil, ErrFrostPassphraseEmpty
	}
	return client.NewPassword(passphrase)
}

// readFrostPassphrase reads the raw passphrase bytes from the
// highest-precedence source the command was given.
func readFrostPassphrase(cmd *cobra.Command) ([]byte, error) {
	fr := newFlagReader(cmd)
	fromStdin := fr.Bool(frostPassphraseFlagStdin)
	path := fr.String(frostPassphraseFlagFile)
	if err := fr.Err(); err != nil {
		return nil, err
	}

	if fromStdin {
		data, err := io.ReadAll(secretStdin)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrReadFrostPassphraseFailed, Err: err}
		}
		return data, nil
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrReadFrostPassphraseFailed, Err: err}
		}
		return data, nil
	}

	if value, ok := os.LookupEnv(frostPassphraseEnvVar); ok {
		return []byte(value), nil
	}
	return nil, ErrFrostPassphraseRequired
}

// trimLineEnding removes one trailing "\n" or "\r\n" -- the line ending an
// `echo` or an editor appends -- and nothing else, so a passphrase that
// deliberately ends in whitespace survives intact.
func trimLineEnding(b []byte) []byte {
	if line, ok := bytes.CutSuffix(b, []byte("\n")); ok {
		return bytes.TrimSuffix(line, []byte("\r"))
	}
	return b
}
