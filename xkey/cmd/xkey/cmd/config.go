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

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// Configuration command errors.
var (
	// ErrConfigFileExists indicates the config file already exists and --force was not specified.
	ErrConfigFileExists = errors.New("config: file already exists, use --force to overwrite")

	// ErrConfigFileWrite indicates the config file could not be written.
	ErrConfigFileWrite = errors.New("config: failed to write configuration file")

	// ErrConfigHomeDirResolve indicates the home directory could not be resolved.
	ErrConfigHomeDirResolve = errors.New("config: failed to resolve home directory")
)

// defaultConfigContent is the reference template for the default configuration
// file. It is retained as documentation; the init command uses the config
// package to generate the actual file so the output matches the struct layout.
const defaultConfigContent = `# xKey Configuration
# ==================
# This is the default configuration file for xKey.
# Configuration values can be overridden via environment variables
# with the XKEY_ prefix (e.g., XKEY_LOG_LEVEL=debug).

# Backend Configuration
# ---------------------
# The backend setting determines where cryptographic keys are stored
# and where operations like signing and decryption are performed.
backend:
  # Default backend for all operations: software, tpm2, or phone
  default: software

  # TPM 2.0 configuration (when backend=tpm2)
  tpm2:
    # TPM device path
    device: /dev/tpmrm0

    # Use TPM simulator instead of hardware TPM
    simulator: false

    # Hash algorithm for TPM operations
    hash: SHA-256

  # Per-operation backend overrides
  # Allows specific operations to use different backends
  # overrides:
  #   sign: tpm2      # Use TPM2 for signing operations
  #   decrypt: software  # Use software for decryption

# FIDO2/WebAuthn Configuration
# ----------------------------
fido2:
  # Storage type for credentials: memory or file
  # storage: file

  # Path for file-based storage (required when storage=file)
  # storage_path: /var/lib/xkey/fido2

  # Attestation format: none, packed, or tpm
  # attestation: none

  # Device name shown to clients
  # device_name: xKey

  # Enable PIN protection
  # pin_enabled: false

  # User presence timeout in seconds
  # user_presence_timeout: 30

  # Enable interactive mode (prompt for touch/PIN)
  # interactive: false

# OATH TOTP/HOTP Configuration
# ----------------------------
oath:
  # Path to the OATH credential store
  # store_path: /var/lib/xkey/oath.json

# Phone Backend Configuration
# ---------------------------
# Configuration for connecting to Android/iOS devices as key storage
phone:
  # Bluetooth device address of paired phone (auto-discover if empty)
  # device_address: ""

  # Connection timeout for BLE operations
  # connect_timeout: 30s

  # Enable auto-connect on startup
  # auto_connect: false

# xkmsd Bridge Configuration
# ------------------------------
# When enabled, connects to xkmsd server for centralized key management.
xkmsd:
  # Enable the xkmsd bridge
  # enabled: false

  # Transport protocol: unix (gRPC over Unix socket) or grpc
  # protocol: unix

  # xkmsd server address (Unix socket path or host:port)
  # address: xkms-data/xkms.sock

  # Connection timeout for xkmsd
  # connect_timeout: 10s

  # Per-request timeout for xkmsd operations
  # request_timeout: 30s

# TPM Configuration
# -----------------
# Global TPM settings used by TPM-based backends and attestation.
# These values map to go-xkms tpm2.Config fields during initialization.
tpm:
  # TPM device path (maps to Config.Device)
  device: /dev/tpmrm0

  # Use TPM simulator for testing (maps to Config.UseSimulator)
  simulator: false

  # Hash algorithm for TPM operations (maps to Config.Hash)
  hash: SHA-256

  # Encrypt TPM command sessions (maps to Config.EncryptSession)
  encrypt-sessions: true

  # PCR bank for quotes and policies (maps to Config.PlatformPCRBank)
  platform-pcr-bank: sha256

  # Golden PCRs for platform integrity measurement.
  # Leave empty to use defaults: [0, 7, 9, 10]
  #   PCR 0:  BIOS/UEFI firmware
  #   PCR 7:  Secure Boot state
  #   PCR 9:  Kernel command line
  #   PCR 10: Linux IMA (file integrity)
  # golden_pcrs: [0, 7, 9, 10]

  # Platform SRK configuration (maps to Config.PlatformSRK)
  platform-srk:
    # Enable the TPM-backed platform SRK
    enabled: true

    # SRK authorization mode: "platform" (platform policy) or "none"
    srk-auth: platform

    # Persistent handle for the platform SRK (maps to PlatformSRKConfig.SRKHandle)
    srk-handle: 0x81000002

    # Bind platform SRK operations to platform policy
    platform-policy: true

  # Endorsement Key configuration (maps to Config.EK)
  ek:
    # Hash algorithm for EK operations
    hash: SHA-256

    # RSA key size for EK
    rsa:
      keysize: 2048

  # PCRs to include in attestation quotes
  # pcrs: [0, 1, 2, 3, 7]

# Password Protection
# -------------------
# Configures how the static password store is protected.
# Modes: none, aes_software, tpm_sealed
password_protection:
  mode: none

# Trust Store Configuration
# -------------------------
# Settings for the trusted CA certificate store
trust:
  # Path to the trust store directory (defaults to ~/.xkey/trust/)
  # store_path: ""

  # Bootstrap configuration for automatic trust store population
  bootstrap:
    # Method priority order (available: dane, noise, spki, direct)
    # method_order: [dane, noise, spki, direct]

    # Timeout per bootstrap method attempt
    # per_method_timeout: "15s"

    # DANE/TLSA bootstrap method
    # dane:
    #   server_url: ""
    #   hostname: ""
    #   dns_server: ""

    # Noise_NK bootstrap method
    # noise:
    #   server_addr: ""
    #   server_key: ""

    # SPKI-pinned TLS bootstrap method
    # spki:
    #   server_url: ""
    #   pin_sha256: ""

    # Direct HTTPS bootstrap method (uses system CA store)
    # direct:
    #   server_url: ""

# Attestation Configuration
# -------------------------
# Settings for device attestation and trust establishment
attestation:
  # Attestation mode: auto, tpm2, or software
  # auto: Use TPM2 if available, fall back to software
  mode: auto

  # Store for trusted device certificates
  # trust_store: /var/lib/xkey/trust

# Logging Configuration
# ---------------------
log:
  # Log level: debug, info, warn, error
  level: info

  # Log file path (empty for stderr)
  # file: /var/log/xkey/xkey.log
`

var (
	// configInitForce forces overwriting existing config file.
	configInitForce bool
)

// configCmd is the parent command for configuration management.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage xKey configuration",
	Long: `Manage the xKey configuration.

xKey reads configuration from the following sources (in order of precedence):
  1. Command-line flags
  2. Environment variables (prefixed with XKEY_)
  3. Configuration file (~/.config/xkey/xkey.yaml or /etc/xkey/xkey.yaml)

Subcommands:
  show    Display the current effective configuration
  init    Create a default configuration file
  path    Show configuration file search paths`,
}

// configShowCmd displays the current configuration.
var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current configuration",
	Long: `Display the current effective configuration from all sources.

Shows the unified configuration struct as loaded by the config package,
which merges the configuration file, environment variables, and defaults.
The output is formatted as YAML for readability.`,
	RunE: runConfigShow,
}

// configInitCmd creates a default configuration file.
var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create default configuration file",
	Long: `Create a default configuration file at ~/.config/xkey/xkey.yaml.

The generated file contains the default configuration matching the
unified config struct layout. Existing files will not be overwritten
unless the --force flag is specified.

Example:
  xkey config init
  xkey config init --force`,
	RunE: runConfigInit,
}

// configPathCmd shows configuration file locations.
var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show configuration file locations",
	Long: `Show all paths where configuration files are searched.

xKey searches for configuration files in the following order:
  1. Path specified via --config flag
  2. ~/.config/xkey/xkey.yaml
  3. /etc/xkey/xkey.yaml

The currently loaded configuration file (if any) is indicated.`,
	RunE: runConfigPath,
}

func init() {
	// Add config subcommands
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configPathCmd)

	// Add flags to init command
	configInitCmd.Flags().BoolVar(&configInitForce, "force", false,
		"overwrite existing configuration file")

	// Add config command to root
	RootCmd.AddCommand(configCmd)
}

// runConfigShow executes the config show command.
func runConfigShow(cmd *cobra.Command, args []string) error {
	cfg := loadedConfig
	if cfg == nil {
		cfg = xkeyconfig.DefaultConfig()
	}

	// Show config file path
	configPath := xkeyconfig.ConfigPath()
	if cfgFile != "" {
		configPath = cfgFile
	}

	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("# Configuration loaded from: %s\n", configPath)
	} else {
		fmt.Println("# No configuration file loaded (using defaults and environment)")
	}
	fmt.Println()

	yamlData, err := yaml.Marshal(cfg)
	if err != nil {
		return &ConfigShowError{Err: err}
	}

	fmt.Print(string(yamlData))
	return nil
}

// runConfigInit executes the config init command.
func runConfigInit(cmd *cobra.Command, args []string) error {
	configPath := xkeyconfig.ConfigPath()

	// Check if file exists
	if _, err := os.Stat(configPath); err == nil {
		if !configInitForce {
			fmt.Printf("Configuration file already exists: %s\n", configPath)
			fmt.Println("Use --force to overwrite.")
			return ErrConfigFileExists
		}
		fmt.Printf("Overwriting existing configuration file: %s\n", configPath)
	}

	// Write the default config using the config package for consistency
	// with the struct layout.
	cfg := xkeyconfig.DefaultConfig()
	if err := xkeyconfig.SaveToPath(cfg, configPath); err != nil {
		return &ConfigInitError{
			Path: configPath,
			Err:  err,
		}
	}

	fmt.Printf("Created configuration file: %s\n", configPath)
	return nil
}

// runConfigPath executes the config path command.
func runConfigPath(cmd *cobra.Command, args []string) error {
	// Define search paths using the config package
	paths := []string{
		xkeyconfig.ConfigPath(),
		xkeyconfig.SystemConfigPath(),
	}

	// If a config file was specified via flag, show it first
	if cfgFile != "" {
		fmt.Println("Configuration search paths:")
		fmt.Println()
		fmt.Printf("  %s (from --config flag)\n", cfgFile)
	} else {
		fmt.Println("Configuration search paths:")
		fmt.Println()
	}

	// Show standard search paths
	for _, path := range paths {
		// Check if file exists
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("  %s (exists)\n", path)
		} else {
			fmt.Printf("  %s\n", path)
		}
	}

	fmt.Println()
	if cfgFile != "" {
		fmt.Printf("Currently using: %s\n", cfgFile)
	} else if _, err := os.Stat(xkeyconfig.ConfigPath()); err == nil {
		fmt.Printf("Currently using: %s\n", xkeyconfig.ConfigPath())
	} else if _, err := os.Stat(xkeyconfig.SystemConfigPath()); err == nil {
		fmt.Printf("Currently using: %s\n", xkeyconfig.SystemConfigPath())
	} else {
		fmt.Println("No configuration file currently loaded.")
	}

	return nil
}

// ConfigShowError represents an error displaying configuration.
type ConfigShowError struct {
	Err error
}

// Error returns the error message.
func (e *ConfigShowError) Error() string {
	return fmt.Sprintf("config show failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ConfigShowError) Unwrap() error {
	return e.Err
}

// ConfigInitError represents an error initializing configuration.
type ConfigInitError struct {
	Path string
	Err  error
}

// Error returns the error message.
func (e *ConfigInitError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("config init failed for %s: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("config init failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ConfigInitError) Unwrap() error {
	return e.Err
}

// ConfigPathError represents an error showing configuration paths.
type ConfigPathError struct {
	Err error
}

// Error returns the error message.
func (e *ConfigPathError) Error() string {
	return fmt.Sprintf("config path failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ConfigPathError) Unwrap() error {
	return e.Err
}
