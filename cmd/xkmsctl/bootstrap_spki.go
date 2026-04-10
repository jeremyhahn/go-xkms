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
	"github.com/spf13/cobra"
)

// spkiCmd represents the spki subcommand group under bootstrap
var spkiCmd = &cobra.Command{
	Use:   "spki",
	Short: "SPKI pin management",
	Long:  `Tools for computing and verifying SPKI (Subject Public Key Info) SHA-256 pins.`,
}

// spkiShowPinCmd computes the SPKI SHA-256 pin from a TLS certificate file
var spkiShowPinCmd = &cobra.Command{
	Use:   "show-pin",
	Short: "Compute SPKI SHA-256 pin from a TLS certificate file",
	Long: `Compute and display the SHA-256 hash of the SubjectPublicKeyInfo (SPKI)
from a TLS certificate. This pin is used for SPKI-pinned TLS bootstrap.

The pin is computed from a PEM certificate file (--cert-file). To obtain the
server's certificate, use: openssl s_client -connect host:port </dev/null | openssl x509 > cert.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		certFile, _ := cmd.Flags().GetString("cert-file")
		showSPKIPin(certFile)
	},
}

func init() {
	// Register SPKI subcommands
	spkiCmd.AddCommand(spkiShowPinCmd)

	// Flags for show-pin
	spkiShowPinCmd.Flags().String("cert-file", "", "path to PEM certificate file")
}
