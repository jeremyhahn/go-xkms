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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Init subcommand error types.
var (
	// ErrMissingSOPin is returned when the --so-pin flag is not provided.
	ErrMissingSOPin = errors.New("init: --so-pin is required")

	// ErrMissingUserPin is returned when the --user-pin flag is not provided.
	ErrMissingUserPin = errors.New("init: --user-pin is required")

	// ErrInvalidOfficerFormat is returned when an --so flag value does not
	// match the expected "username:/path/to/csr.pem" format.
	ErrInvalidOfficerFormat = errors.New("init: --so value must be username:/path/to/csr.pem")

	// ErrEmptyOfficerUsername is returned when the username portion of an
	// --so flag value is empty.
	ErrEmptyOfficerUsername = errors.New("init: officer username must not be empty")

	// ErrEmptyCSRPath is returned when the CSR path portion of an --so flag
	// value is empty.
	ErrEmptyCSRPath = errors.New("init: officer CSR path must not be empty")

	// ErrCSRFileNotFound is returned when a CSR file specified by --so does
	// not exist on disk.
	ErrCSRFileNotFound = errors.New("init: CSR file not found")

	// ErrCSRReadFailed is returned when a CSR file cannot be read.
	ErrCSRReadFailed = errors.New("init: failed to read CSR file")

	// ErrCSRDecodeFailed is returned when a CSR file does not contain valid
	// PEM data.
	ErrCSRDecodeFailed = errors.New("init: CSR file does not contain valid PEM data")

	// ErrCSRParseFailed is returned when a CSR file contains invalid
	// certificate request data.
	ErrCSRParseFailed = errors.New("init: failed to parse certificate request")

	// ErrCSRSignatureInvalid is returned when a CSR's self-signature does
	// not verify.
	ErrCSRSignatureInvalid = errors.New("init: CSR signature verification failed")

	// ErrThresholdRequiresOfficers is returned when --threshold >= 2 but no
	// --so flags are provided.
	ErrThresholdRequiresOfficers = errors.New("init: --threshold >= 2 requires at least one --so officer")

	// ErrThresholdExceedsOfficers is returned when --threshold exceeds the
	// number of --so officers.
	ErrThresholdExceedsOfficers = errors.New("init: --threshold cannot exceed the number of --so officers")

	// ErrConfigLoadFailed is returned when configuration loading fails.
	ErrConfigLoadFailed = errors.New("init: failed to load configuration")

	// ErrBarrierCreateFailed is returned when barrier creation fails.
	ErrBarrierCreateFailed = errors.New("init: failed to create barrier")

	// ErrPlatformStoreCreateFailed is returned when platform store creation fails.
	ErrPlatformStoreCreateFailed = errors.New("init: failed to create platform store")

	// ErrCredentialServiceCreateFailed is returned when credential service creation fails.
	ErrCredentialServiceCreateFailed = errors.New("init: failed to create credential service")

	// ErrCeremonyServiceCreateFailed is returned when ceremony service creation fails.
	ErrCeremonyServiceCreateFailed = errors.New("init: failed to create ceremony service")
)

// stringSlice implements flag.Value for repeatable string flags.
type stringSlice []string

// String returns the comma-separated representation of the slice.
func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

// Set appends a value to the slice.
func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// initFlags holds the parsed init subcommand flags.
type initFlags struct {
	configPath         string
	soPin              string
	userPin            string
	threshold          int
	officers           stringSlice
	credentialStrategy string
	dataDir            string
	hostname           string
}

// parseOfficerFlag parses a single "--so" flag value in the format
// "username:/path/to/csr.pem" and returns the username and CSR path.
func parseOfficerFlag(value string) (string, string, error) {
	// Find the first colon separator. Colons in paths (e.g., Windows
	// drive letters) are not expected in this Unix-oriented tool.
	idx := strings.Index(value, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("%w: %q", ErrInvalidOfficerFormat, value)
	}

	username := strings.TrimSpace(value[:idx])
	csrPath := strings.TrimSpace(value[idx+1:])

	if username == "" {
		return "", "", fmt.Errorf("%w: %q", ErrEmptyOfficerUsername, value)
	}
	if csrPath == "" {
		return "", "", fmt.Errorf("%w: %q", ErrEmptyCSRPath, value)
	}

	return username, csrPath, nil
}

// readAndValidateCSR reads a PEM-encoded CSR file from disk, decodes it,
// parses the certificate request, and verifies its self-signature.
// Returns the raw PEM bytes on success.
func readAndValidateCSR(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrCSRFileNotFound, path)
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrCSRReadFailed, path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%w: %s is a directory", ErrCSRReadFailed, path)
	}

	// #nosec G304 - CSR path is provided by admin during init ceremony
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCSRReadFailed, path, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: %s", ErrCSRDecodeFailed, path)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCSRParseFailed, path, err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCSRSignatureInvalid, path, err)
	}

	return pemData, nil
}

// buildOfficerConfigs parses the --so flag values, reads and validates
// each CSR file, and returns the resulting officer configurations.
func buildOfficerConfigs(officerFlags []string) ([]initialize.OfficerConfig, error) {
	officers := make([]initialize.OfficerConfig, 0, len(officerFlags))
	for _, raw := range officerFlags {
		username, csrPath, err := parseOfficerFlag(raw)
		if err != nil {
			return nil, err
		}

		csrPEM, err := readAndValidateCSR(csrPath)
		if err != nil {
			return nil, err
		}

		officers = append(officers, initialize.OfficerConfig{
			Username: username,
			CSRPEM:   csrPEM,
		})
	}
	return officers, nil
}

// runInit implements the "xkmsd init" subcommand. It parses init-specific
// flags, loads configuration, creates the barrier and credential service,
// builds and validates the ceremony configuration, and prints a summary.
//
// The actual Initialize() call (which requires a CA) is deferred until
// CA integration is complete. This function validates all inputs and
// creates all dependencies that can be constructed without a CA.
func runInit(args []string) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	flags, err := parseInitFlags(args)
	if err != nil {
		logger.Error("flag parsing failed", slog.Any("error", err))
		os.Exit(1)
	}

	if err := validateInitFlags(flags); err != nil {
		logger.Error("validation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Load configuration if a config file is specified and exists.
	var cfg *config.Config
	if flags.configPath != "" {
		cfg, err = config.Load(flags.configPath)
		if err != nil {
			logger.Error("configuration load failed",
				slog.String("config", flags.configPath),
				slog.Any("error", err))
			os.Exit(1)
		}
		logger.Info("configuration loaded",
			slog.String("config", flags.configPath),
			slog.Any("backends", cfg.GetEnabledBackends()))
	}

	// Resolve credential strategy: flag overrides config, defaults to "barrier".
	credStrategy := resolveCredentialStrategy(flags, cfg)

	// Resolve data directory: flag overrides config, defaults to "/var/lib/xkms".
	dataDir := resolveDataDir(flags, cfg)

	// Resolve hostname: flag overrides config server host.
	hostname := resolveHostname(flags, cfg)

	// Create in-memory storage backend for the barrier and platform store.
	memBackend := storage.NewMemory()

	// Create barrier with software strategy.
	barrier, err := seal.NewBarrier(
		logger,
		memBackend,
		seal.BarrierConfig{
			RootKeyPath: "barrier/root-key",
		},
		seal.NewSoftwareStrategy(),
	)
	if err != nil {
		logger.Error("barrier creation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Create platform store backed by in-memory storage.
	platformStore, err := seal.NewPlatformStore(memBackend, logger)
	if err != nil {
		logger.Error("platform store creation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Create credential service.
	credService, err := credentials.New(
		&credentials.Config{Strategy: credStrategy},
		platformStore,
		barrier,
		logger,
	)
	if err != nil {
		logger.Error("credential service creation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Parse and validate officer CSR files for M-of-N mode.
	var officers []initialize.OfficerConfig
	if len(flags.officers) > 0 {
		officers, err = buildOfficerConfigs(flags.officers)
		if err != nil {
			logger.Error("officer CSR validation failed", slog.Any("error", err))
			os.Exit(1)
		}
	}

	// Build ceremony configuration.
	ceremonyCfg := &initialize.CeremonyConfig{
		SOPin:                  flags.soPin,
		UserPin:                flags.userPin,
		CredentialSealStrategy: credStrategy,
		Threshold:              flags.threshold,
		Officers:               officers,
		Hostname:               hostname,
		DataDir:                dataDir,
	}

	// Create the ceremony service to validate the full configuration.
	// The ceremony service now delegates to go-qrdb's CeremonyService
	// which accepts (config, barrier, credService, logger).
	_, err = initialize.NewCeremonyService(
		ceremonyCfg,
		barrier,
		credService,
		logger,
	)
	if err != nil {
		logger.Error("ceremony service creation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Print validated configuration summary.
	printInitSummary(ceremonyCfg, credStrategy, officers)

	logger.Info("initialization configuration validated successfully",
		slog.String("hostname", hostname),
		slog.String("data_dir", dataDir),
		slog.String("credential_strategy", credStrategy),
		slog.Int("threshold", flags.threshold),
		slog.Int("officers", len(officers)))

	// TODO(phase-3b): Wire CA integration and call ceremony.Initialize(ctx, ca).
	// The CA depends on backend initialization which is handled by the server
	// startup sequence. Once CA integration is ready, this command will perform
	// the full initialization ceremony.
	fmt.Fprintln(os.Stderr, "\nNote: CA integration pending (Phase 3b). Configuration validated; initialization ceremony will be executed when CA is wired.")
}

// parseInitFlags creates and parses the init subcommand FlagSet.
func parseInitFlags(args []string) (*initFlags, error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	flags := &initFlags{}

	fs.StringVar(&flags.configPath, "config", "/etc/xkms/xkmsd.yaml", "Path to configuration file")
	fs.StringVar(&flags.soPin, "so-pin", "", "SO PIN for C_InitToken and admin operations (required)")
	fs.StringVar(&flags.userPin, "user-pin", "", "User PIN for C_InitPIN and crypto operations (required)")
	fs.IntVar(&flags.threshold, "threshold", 0, "M-of-N unseal threshold (0 or 1 = single admin)")
	fs.Var(&flags.officers, "so", "SO officer in format username:/path/to/csr.pem (repeatable)")
	fs.StringVar(&flags.credentialStrategy, "credential-strategy", "", "Credential seal strategy (barrier, manual, tpm2, pkcs11, etc.)")
	fs.StringVar(&flags.dataDir, "data-dir", "", "Data directory for public artifacts")
	fs.StringVar(&flags.hostname, "hostname", "", "Server hostname for TLS certificate CN")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return flags, nil
}

// validateInitFlags checks that all required flags are present and
// threshold/officer constraints are satisfied.
func validateInitFlags(flags *initFlags) error {
	if flags.soPin == "" {
		return ErrMissingSOPin
	}
	if flags.userPin == "" {
		return ErrMissingUserPin
	}

	if flags.threshold >= 2 {
		if len(flags.officers) == 0 {
			return ErrThresholdRequiresOfficers
		}
		if flags.threshold > len(flags.officers) {
			return ErrThresholdExceedsOfficers
		}
	}

	return nil
}

// resolveCredentialStrategy determines the credential seal strategy from
// flags and config, defaulting to "barrier".
func resolveCredentialStrategy(flags *initFlags, cfg *config.Config) string {
	if flags.credentialStrategy != "" {
		return flags.credentialStrategy
	}
	if cfg != nil && cfg.Credentials.SealStrategy != "" {
		return cfg.Credentials.SealStrategy
	}
	return "barrier"
}

// resolveDataDir determines the data directory from flags and config,
// defaulting to "/var/lib/xkms".
func resolveDataDir(flags *initFlags, cfg *config.Config) string {
	if flags.dataDir != "" {
		return flags.dataDir
	}
	if cfg != nil && cfg.Storage.Path != "" {
		return cfg.Storage.Path
	}
	return "/var/lib/xkms"
}

// resolveHostname determines the hostname from flags and config,
// defaulting to "localhost".
func resolveHostname(flags *initFlags, cfg *config.Config) string {
	if flags.hostname != "" {
		return flags.hostname
	}
	if cfg != nil && cfg.Server.Host != "" {
		return cfg.Server.Host
	}
	return "localhost"
}

// printInitSummary outputs a human-readable summary of the validated
// initialization configuration to stdout.
func printInitSummary(cfg *initialize.CeremonyConfig, credStrategy string, officers []initialize.OfficerConfig) {
	fmt.Println("=== xkmsd init: Configuration Summary ===")
	fmt.Println()
	fmt.Printf("  Hostname:             %s\n", cfg.Hostname)
	fmt.Printf("  Data Directory:       %s\n", cfg.DataDir)
	fmt.Printf("  Credential Strategy:  %s\n", credStrategy)
	fmt.Printf("  SO PIN:               [provided]\n")
	fmt.Printf("  User PIN:             [provided]\n")
	fmt.Println()

	if cfg.Threshold >= 2 {
		fmt.Printf("  Mode:                 M-of-N (%d-of-%d)\n", cfg.Threshold, len(officers))
		fmt.Printf("  Officers:\n")
		for _, o := range officers {
			fmt.Printf("    - %s (CSR validated)\n", o.Username)
		}
	} else {
		fmt.Printf("  Mode:                 Single Admin\n")
	}

	fmt.Println()
	fmt.Println("=== Validation Passed ===")
}
