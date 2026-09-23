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
	"crypto/x509"
	"encoding/pem"
	"os"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// tlsCmd represents the TLS command
var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "TLS certificate operations",
	Long:  `Retrieve TLS certificates and their chains`,
}

// tlsGetCmd retrieves a TLS certificate and its chain
var tlsGetCmd = &cobra.Command{
	Use:   "get <key-id>",
	Short: "Get a TLS certificate",
	Long: `Retrieve the X.509 certificate and chain for a TLS key.

The private key never leaves the backend that holds it: this command
returns the certificate and chain only.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		getTLSCert(cfg, printer, keyID)
	},
}

// getTLSCert retrieves a TLS certificate and its chain through the SDK
// client. The private key is intentionally never requested: it stays in
// the backend that holds it.
func getTLSCert(cfg *Config, printer *Printer, keyID string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkms service")
	printVerbose("Getting TLS certificate for key: %s", keyID)

	resp, err := cl.GetTLSCertificate(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetCertificateFailed, Err: err})
		return
	}

	block, _ := pem.Decode([]byte(resp.CertificatePEM))
	if block == nil {
		handleError(ErrDecodeCertificatePEMFailed)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrParseCertificateFailed, Err: err})
		return
	}

	chain := make([]*x509.Certificate, 0, len(resp.ChainPEM))
	for _, chainPEM := range resp.ChainPEM {
		chainCert, err := client.DecodeCertificatePEM([]byte(chainPEM))
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrParseCertificateFailed, Err: err})
			return
		}
		chain = append(chain, chainCert)
	}

	printVerbose("Certificate Subject: %s", cert.Subject.String())
	if len(chain) > 0 {
		printVerbose("Certificate chain length: %d", len(chain))
	}

	if err := printer.PrintTLSCertificate(cert, chain); err != nil {
		handleError(err)
	}
}

func init() {
	// Add TLS subcommands
	tlsCmd.AddCommand(tlsGetCmd)
}
