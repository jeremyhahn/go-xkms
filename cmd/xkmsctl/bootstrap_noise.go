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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	noiseproto "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// noiseCmd represents the noise command group
var noiseCmd = &cobra.Command{
	Use:   "noise",
	Short: "Noise protocol key management",
	Long:  `Manage Noise protocol static keys and compute SPKI pins for secure bootstrap.`,
}

// noiseGenerateKeyCmd generates a new Noise static keypair
var noiseGenerateKeyCmd = &cobra.Command{
	Use:   "generate-key",
	Short: "Generate a new Noise static keypair",
	Long: `Generate a new Curve25519 static keypair for the Noise protocol.
The private key is output in hex encoding and should be stored securely.
The public key is also displayed for distribution to clients.`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFile, _ := cmd.Flags().GetString("output")
		generateNoiseKey(outputFile)
	},
}

// noiseShowKeyCmd shows the public key from a private key
var noiseShowKeyCmd = &cobra.Command{
	Use:   "show-key",
	Short: "Show public key from a Noise static key",
	Long:  `Derive and display the public key from a Noise static private key file or hex string.`,
	Run: func(cmd *cobra.Command, args []string) {
		keyFile, _ := cmd.Flags().GetString("key-file")
		keyHex, _ := cmd.Flags().GetString("key-hex")
		showNoiseKey(keyFile, keyHex)
	},
}

// noiseShowSPKIPinCmd computes the SPKI SHA-256 pin from a TLS certificate
var noiseShowSPKIPinCmd = &cobra.Command{
	Use:   "show-spki-pin",
	Short: "Compute SPKI SHA-256 pin from a TLS certificate file",
	Long: `Compute and display the SHA-256 hash of the SubjectPublicKeyInfo (SPKI)
from a server's TLS certificate. This pin is used for SPKI-pinned TLS bootstrap.

The pin is computed from a PEM certificate file (--cert-file). To obtain the
server's certificate, use: openssl s_client -connect host:port </dev/null | openssl x509 > cert.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		certFile, _ := cmd.Flags().GetString("cert-file")
		showSPKIPin(certFile)
	},
}

func generateNoiseKey(outputFile string) {
	key, err := noiseproto.GenerateStaticKey()
	if err != nil {
		handleError(fmt.Errorf("failed to generate key: %w", err))
		return
	}

	privateHex := noiseproto.EncodeStaticKey(key)
	publicHex := hex.EncodeToString(key.Public)

	if outputFile != "" {
		// Write private key to file
		if err := os.WriteFile(outputFile, []byte(privateHex+"\n"), 0600); err != nil {
			handleError(fmt.Errorf("failed to write key file: %w", err))
			return
		}
		fmt.Printf("Private key written to: %s\n", outputFile)
		fmt.Printf("Public key:  %s\n", publicHex)
	} else {
		fmt.Printf("Private key: %s\n", privateHex)
		fmt.Printf("Public key:  %s\n", publicHex)
	}
}

func showNoiseKey(keyFile, keyHex string) {
	var hexKey string

	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			handleError(fmt.Errorf("failed to read key file: %w", err))
			return
		}
		hexKey = strings.TrimSpace(string(data))
	} else if keyHex != "" {
		hexKey = keyHex
	} else {
		handleError(fmt.Errorf("either --key-file or --key-hex is required"))
		return
	}

	key, err := noiseproto.DecodeStaticKey(hexKey)
	if err != nil {
		handleError(fmt.Errorf("failed to decode key: %w", err))
		return
	}

	fmt.Printf("Public key: %s\n", hex.EncodeToString(key.Public))
}

func showSPKIPin(certFile string) {
	if certFile == "" {
		handleError(fmt.Errorf("--cert-file is required"))
		return
	}

	// Read PEM certificate file
	data, err := os.ReadFile(certFile)
	if err != nil {
		handleError(fmt.Errorf("failed to read certificate file: %w", err))
		return
	}

	// Parse PEM
	block, _ := pem.Decode(data)
	if block == nil {
		handleError(fmt.Errorf("no PEM data found in file"))
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		handleError(fmt.Errorf("failed to parse certificate: %w", err))
		return
	}

	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fmt.Printf("SPKI SHA-256 pin: %s\n", hex.EncodeToString(pin[:]))
	fmt.Printf("Subject:          %s\n", cert.Subject.String())
	fmt.Printf("Issuer:           %s\n", cert.Issuer.String())
	fmt.Printf("Not Before:       %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Not After:        %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
}
