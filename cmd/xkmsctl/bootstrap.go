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
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/spf13/cobra"
)

// bootstrapCmd represents the bootstrap parent command group
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Secure CA bundle bootstrapping",
	Long:  `Bootstrap commands for securely obtaining CA certificates using DANE/TLSA, Noise, SPKI pinning, Direct HTTPS, or automatic method selection.`,
}

// bootstrapAutoCmd runs automatic bootstrap using configured methods
var bootstrapAutoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Auto-bootstrap using configured methods",
	Long: `Automatically try bootstrap methods in priority order: DANE, Noise, SPKI, Direct.

Each method that is configured (via flags or config file) will be tried in order.
The first method that succeeds returns the CA bundle.

Direct is a last-resort fallback that uses standard HTTPS with the system trust
store. It requires the server to already have a certificate trusted by a public
CA or one installed in the OS trust store.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, _ := cmd.Flags().GetString("server-url")
		daneHostname, _ := cmd.Flags().GetString("dane-hostname")
		daneDNSServer, _ := cmd.Flags().GetString("dane-dns-server")
		noiseKey, _ := cmd.Flags().GetString("noise-key")
		noiseAddr, _ := cmd.Flags().GetString("noise-addr")
		spkiPin, _ := cmd.Flags().GetString("spki-pin")
		directEnabled, _ := cmd.Flags().GetBool("direct")
		bundlePath, _ := cmd.Flags().GetString("bundle-path")
		bundleOutput, _ := cmd.Flags().GetString("bundle-output")

		params := &autoBootstrapParams{
			serverURL:     serverURL,
			daneHostname:  daneHostname,
			daneDNSServer: daneDNSServer,
			noiseKey:      noiseKey,
			noiseAddr:     noiseAddr,
			spkiPin:       spkiPin,
			directEnabled: directEnabled,
			bundlePath:    bundlePath,
			bundleOutput:  bundleOutput,
		}
		return runAutoBootstrap(params)
	},
}

// autoBootstrapParams holds all parameters for the auto-bootstrap operation.
type autoBootstrapParams struct {
	serverURL     string
	daneHostname  string
	daneDNSServer string
	noiseKey      string
	noiseAddr     string
	spkiPin       string
	directEnabled bool
	bundlePath    string
	bundleOutput  string
}

// runAutoBootstrap delegates to truststrap.AutoFetch, which tries each
// configured bootstrap method in DefaultMethodOrder (DANE, Noise, SPKI,
// Direct) and returns the first successful result.
func runAutoBootstrap(params *autoBootstrapParams) error {
	if params.serverURL == "" {
		return ErrBootstrapServerURLRequired
	}

	cfg := buildAutoConfig(params)
	if cfg == nil {
		return ErrNoBootstrapMethodConfigured
	}

	printVerbose("Auto-bootstrap from: %s", params.serverURL)

	ctx := context.Background()
	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAllBootstrapMethodsFailed, err)
	}

	printVerbose("Bootstrap succeeded (%d bytes)", len(resp.BundlePEM))
	return writeCABundle(resp.BundlePEM, params.bundleOutput)
}

// buildAutoConfig maps CLI flags to a truststrap.AutoConfig. Returns nil
// if no methods are configured.
func buildAutoConfig(params *autoBootstrapParams) *truststrap.AutoConfig {
	logger := bootstrapLogger()
	cfg := &truststrap.AutoConfig{
		Logger: logger,
	}

	hasMethod := false

	if params.daneHostname != "" {
		cfg.DANE = &truststrap.DANEConfig{
			ServerURL: params.serverURL,
			Hostname:  params.daneHostname,
			DNSServer: params.daneDNSServer,
			Logger:    logger,
		}
		hasMethod = true
	}

	if params.noiseKey != "" {
		noiseAddr := params.noiseAddr
		if noiseAddr == "" {
			noiseAddr = deriveNoiseAddr(params.serverURL)
		}
		cfg.Noise = &truststrap.NoiseConfig{
			ServerAddr:      noiseAddr,
			ServerStaticKey: params.noiseKey,
			Logger:          logger,
		}
		hasMethod = true
	}

	if params.spkiPin != "" {
		cfg.SPKI = &truststrap.SPKIConfig{
			ServerURL:     params.serverURL,
			SPKIPinSHA256: params.spkiPin,
			Logger:        logger,
		}
		hasMethod = true
	}

	if params.directEnabled {
		cfg.Direct = &truststrap.DirectConfig{
			ServerURL:  params.serverURL,
			BundlePath: params.bundlePath,
			Logger:     logger,
		}
		hasMethod = true
	}

	if !hasMethod {
		return nil
	}
	return cfg
}

// writeCABundle writes the PEM-encoded CA bundle to the specified output
// file, or to stdout if no output file is specified.
func writeCABundle(bundlePEM []byte, outputPath string) error {
	if outputPath == "" {
		fmt.Println("# CA bundle obtained via bootstrap")
		_, err := os.Stdout.Write(bundlePEM)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrBootstrapBundleWrite, err)
		}
		return nil
	}

	if err := os.WriteFile(outputPath, bundlePEM, 0600); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrBootstrapBundleWrite, outputPath, err)
	}

	fmt.Printf("CA bundle written to %s\n", outputPath)
	return nil
}

// deriveNoiseAddr extracts host from a URL and appends the default Noise
// bootstrap port (8445). For example, "https://kms.example.com:8443"
// becomes "kms.example.com:8445".
func deriveNoiseAddr(serverURL string) string {
	// Strip the scheme prefix.
	addr := serverURL
	if idx := strings.Index(addr, "://"); idx >= 0 {
		addr = addr[idx+3:]
	}
	// Strip any path.
	if idx := strings.Index(addr, "/"); idx >= 0 {
		addr = addr[:idx]
	}
	// Replace the port with the default Noise port (8445).
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		addr = addr[:idx]
	}
	return addr + ":8445"
}

// bootstrapLogger returns a slog.Logger configured for bootstrap operations.
// In verbose mode, it logs at debug level; otherwise at warn level.
func bootstrapLogger() *slog.Logger {
	level := slog.LevelWarn
	if globalConfig != nil && globalConfig.Verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

func init() {
	// Register subcommands under bootstrap
	bootstrapCmd.AddCommand(bootstrapAutoCmd)
	bootstrapCmd.AddCommand(noiseCmd)
	bootstrapCmd.AddCommand(daneCmd)
	bootstrapCmd.AddCommand(spkiCmd)

	// Noise subcommands and flags
	noiseCmd.AddCommand(noiseGenerateKeyCmd)
	noiseCmd.AddCommand(noiseShowKeyCmd)
	noiseCmd.AddCommand(noiseShowSPKIPinCmd)

	// Flags for generate-key
	noiseGenerateKeyCmd.Flags().StringP("output", "o", "", "write private key to file (with 0600 permissions)")

	// Flags for show-key
	noiseShowKeyCmd.Flags().String("key-file", "", "path to hex-encoded private key file")
	noiseShowKeyCmd.Flags().String("key-hex", "", "hex-encoded private key")

	// Flags for show-spki-pin
	noiseShowSPKIPinCmd.Flags().String("cert-file", "", "path to PEM certificate file")

	// Flags for auto
	bootstrapAutoCmd.Flags().String("server-url", "", "xkms server URL (e.g., https://kms.example.com:8443)")
	bootstrapAutoCmd.Flags().String("config", "", "path to bootstrap config file")
	bootstrapAutoCmd.Flags().String("dane-hostname", "", "hostname for DANE/TLSA verification")
	bootstrapAutoCmd.Flags().String("dane-dns-server", "", "DNS server for DANE lookups (e.g., 8.8.8.8:53)")
	bootstrapAutoCmd.Flags().String("noise-key", "", "hex-encoded Noise static public key of the server")
	bootstrapAutoCmd.Flags().String("noise-addr", "", "Noise bootstrap server address (host:port)")
	bootstrapAutoCmd.Flags().String("spki-pin", "", "hex-encoded SHA-256 SPKI pin of server certificate")
	bootstrapAutoCmd.Flags().Bool("direct", false, "enable direct HTTPS fallback using the system trust store")
	bootstrapAutoCmd.Flags().String("bundle-path", "", "REST API path for CA bundle endpoint (default: /api/v1/ca/bundle)")
	bootstrapAutoCmd.Flags().String("bundle-output", "", "path to write CA bundle file (default: stdout)")
}
