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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
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

When --config points to an xkmsd config file with a trust: section, the
default scope's settings are used as base values; CLI flags override them.

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
		configFile, _ := cmd.Flags().GetString("config")

		// Resolve the config file path: local --config flag takes
		// precedence, then the global --config flag from root.
		if configFile == "" && globalConfig != nil {
			configFile = globalConfig.ConfigFile
		}

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

		// Apply config-file-derived values as defaults (flags override).
		if configFile != "" {
			trustCfg, err := trustConfigFromFile(configFile)
			if err != nil {
				return err
			}
			if trustCfg != nil {
				autoParamsFromResolverScope(params, trustCfg.Scope("default"))
			}
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

// runAutoBootstrap dispatches via the canonical
// xkms/pkg/trust/bootstrap library, which wraps go-truststrap's
// AutoBootstrapper and tries each configured method in
// DefaultMethodOrder (DANE, Noise, SPKI, Direct) until one succeeds.
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
	bundle, err := bootstrap.Fetch(ctx, *cfg)
	if err != nil {
		return &WrappedError{Sentinel: ErrAllBootstrapMethodsFailed, Err: err}
	}

	printVerbose("Bootstrap succeeded (%d bytes)", len(bundle.PEM))
	return writeCABundle(bundle.PEM, params.bundleOutput)
}

// buildAutoConfig maps CLI flags to a bootstrap.Config. Returns nil if
// no methods are configured.
func buildAutoConfig(params *autoBootstrapParams) *bootstrap.Config {
	logger := bootstrapLogger()
	cfg := &bootstrap.Config{
		Mode:       bootstrap.ModeAuto,
		ServerURL:  params.serverURL,
		BundlePath: params.bundlePath,
		Logger:     logger,
	}

	hasMethod := false

	if params.daneHostname != "" {
		cfg.DANE = &bootstrap.DANEConfig{
			Hostname:  params.daneHostname,
			DNSServer: params.daneDNSServer,
		}
		hasMethod = true
	}

	if params.noiseKey != "" {
		cfg.Noise = &bootstrap.NoiseConfig{
			ServerAddr:      params.noiseAddr,
			ServerStaticKey: params.noiseKey,
		}
		hasMethod = true
	}

	if params.spkiPin != "" {
		cfg.SPKI = &bootstrap.SPKIConfig{
			Pin: params.spkiPin,
		}
		hasMethod = true
	}

	if params.directEnabled {
		cfg.Direct = &bootstrap.DirectConfig{}
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
			return &WrappedError{Sentinel: ErrBootstrapBundleWrite, Err: err}
		}
		return nil
	}

	if err := os.WriteFile(outputPath, bundlePEM, 0600); err != nil {
		return &WrappedDetailError{Sentinel: ErrBootstrapBundleWrite, Detail: outputPath, Err: err}
	}

	fmt.Printf("CA bundle written to %s\n", outputPath)
	return nil
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
	noiseCmd.AddCommand(p256GenerateKeyCmd)
	noiseCmd.AddCommand(p256ShowKeyCmd)

	// Flags for generate-key
	noiseGenerateKeyCmd.Flags().StringP("output", "o", "", "file to create the private key in, mode 0600 (required; must not exist; the key is never printed)")

	// Flags for show-key
	noiseShowKeyCmd.Flags().String("key-file", "", "path to hex-encoded private key file")
	noiseShowKeyCmd.Flags().String("key-hex", "", "hex-encoded private key")

	// Flags for generate-p256-key / show-p256-key (the FIPS-approved suite)
	p256GenerateKeyCmd.Flags().StringP("output", "o", "", "file to create the private key in, mode 0600 (required; must not exist; the key is never printed)")
	p256ShowKeyCmd.Flags().String("key-file", "", "path to hex-encoded P-256 private key file")
	p256ShowKeyCmd.Flags().String("key-hex", "", "hex-encoded P-256 private key")

	// Flags for show-spki-pin
	noiseShowSPKIPinCmd.Flags().String("cert-file", "", "path to PEM certificate file")

	// Flags for auto
	bootstrapAutoCmd.Flags().String("server-url", "", "xkms server URL (e.g., https://kms.example.com:8443)")
	bootstrapAutoCmd.Flags().String("config", "", "path to xkmsd config file (trust: section used as defaults)")
	bootstrapAutoCmd.Flags().String("dane-hostname", "", "hostname for DANE/TLSA verification")
	bootstrapAutoCmd.Flags().String("dane-dns-server", "", "DNS server for DANE lookups (e.g., 8.8.8.8:53)")
	bootstrapAutoCmd.Flags().String("noise-key", "", "hex-encoded Noise static public key of the server")
	bootstrapAutoCmd.Flags().String("noise-addr", "", "Noise bootstrap server address (host:port)")
	bootstrapAutoCmd.Flags().String("spki-pin", "", "hex-encoded SHA-256 SPKI pin of server certificate")
	bootstrapAutoCmd.Flags().Bool("direct", false, "enable direct HTTPS fallback using the system trust store")
	bootstrapAutoCmd.Flags().String("bundle-path", "", "REST API path for CA bundle endpoint (default: /api/v1/ca/bundle)")
	bootstrapAutoCmd.Flags().String("bundle-output", "", "path to write CA bundle file (default: stdout)")
}
