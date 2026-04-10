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
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

const (
	// envPrefix is the environment variable prefix for xKey configuration.
	envPrefix = "XKEY"
)

// LUKS-related errors.
var (
	// ErrLUKSPassphraseRead indicates failure to read the passphrase.
	ErrLUKSPassphraseRead = errors.New("luks: failed to read passphrase")

	// ErrLUKSUnlockFailed indicates failure to unlock the LUKS volume.
	ErrLUKSUnlockFailed = errors.New("luks: failed to unlock volume")
)

var (
	// cfgFile holds the path to the configuration file specified via flag.
	cfgFile string

	// logLevel holds the logging level specified via flag.
	logLevel string

	// logFile holds the path to the log file specified via flag.
	logFile string

	// xkmsdURL holds the xkmsd server URL for server mode.
	xkmsdURL string

	// xkmsBackend holds the xkmsd backend name.
	xkmsBackend string

	// loadedConfig holds the unified config loaded during initialization.
	loadedConfig *xkeyconfig.Config

	// resolvedHome holds the resolved xKey home directory.
	resolvedHome *xhome.Home
)

// luksExemptCommands is the set of command names that bypass the LUKS
// volume check. These commands manage LUKS volumes themselves, or run
// before the barrier is unsealed.
var luksExemptCommands = map[string]bool{
	// LUKS management commands
	"seal":        true,
	"unseal":      true,
	"lock":        true,
	"migrate":     true,
	"wipe":        true,
	"import-data": true,
	"luks2":       true,
	// Barrier commands (run before barrier is unsealed)
	"barrier": true,
	"init":    true,
	"status":  true,
	// PIN commands (run before barrier is unsealed)
	"pin":           true,
	"set-so":        true,
	"set-user":      true,
	"change-so":     true,
	"change-user":   true,
	"verify":        true,
	"reset-lockout": true,
	// Native messaging host (invoked by Chrome, must not prompt or read stdin)
	"host": true,
}

// RootCmd is the base command for the xKey CLI application.
// It provides multi-protocol authentication capabilities including
// FIDO2/WebAuthn, OATH TOTP/HOTP, and PIV smart card operations.
var RootCmd = &cobra.Command{
	Use:   "xkey",
	Short: "xKey - Multi-protocol authentication",
	Long: `xKey is a flexible security key application that provides
multi-protocol authentication capabilities.

Supported Protocols:
  FIDO2/WebAuthn  - Passwordless authentication using public key cryptography
                    with support for resident keys, user verification, and
                    discoverable credentials per the WebAuthn specification.

  OATH TOTP/HOTP  - Time-based and HMAC-based One-Time Password generation
                    compatible with RFC 6238 (TOTP) and RFC 4226 (HOTP).
                    Works with authenticator apps and services like Google
                    Authenticator, Authy, and enterprise SSO systems.

  PIV             - Personal Identity Verification smart card functionality
                    following the FIPS 201 standard for digital certificates,
                    key management, and cryptographic operations.

xKey can operate as a virtual authenticator for development and testing,
or interface with hardware security devices for production deployments.

Configuration:
  xKey reads configuration from the following locations (in order):
    1. Command-line flags
    2. Environment variables (prefixed with XKEY_)
    3. Configuration file (~/.config/xkey/xkey.yaml or /etc/xkey/xkey.yaml)

Examples:
  # Start the FIDO2 authenticator
  xkey fido2 start

  # Generate a TOTP code
  xkey oath totp generate --account myservice

  # List PIV certificates
  xkey piv cert list`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Resolve the xKey home directory first. All path-dependent
		// operations (config loading, LUKS check) use this.
		home, err := xhome.Resolve()
		if err != nil {
			return &ConfigError{Operation: "resolve_home", Err: err}
		}
		resolvedHome = home

		// Skip LUKS check for exempt commands (they manage LUKS, barrier,
		// or PIN state themselves and must run before the barrier is unsealed).
		if luksExemptCommands[cmd.Name()] {
			return initConfig()
		}

		// Check for LUKS volume and prompt for unlock if needed
		if err := checkLUKSVolume(); err != nil {
			return err
		}

		return initConfig()
	},
}

// Execute runs the root command and returns any error encountered.
// This is the main entry point for the CLI application.
func Execute() error {
	return RootCmd.Execute()
}

// GetConfig returns the loaded configuration. Subcommands use this to
// access the unified config after initialization.
func GetConfig() *xkeyconfig.Config {
	return loadedConfig
}

// GetHome returns the resolved xKey home directory. Subcommands use
// this to obtain unified paths for data, config, LUKS, etc.
func GetHome() *xhome.Home {
	return resolvedHome
}

func init() {
	// Configuration file flag
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file path (default: ~/.config/xkey/xkey.yaml)")

	// Logging flags
	RootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info",
		"log level (debug, info, warn, error)")
	RootCmd.PersistentFlags().StringVar(&logFile, "log-file", "",
		"log output file path (default: stderr)")

	// Global xkmsd flags - apply to ALL subcommands
	RootCmd.PersistentFlags().StringVar(&xkmsdURL, "xkmsd-url", "",
		"xkmsd server URL (unix:// or grpc://) - enables server mode for all commands")
	RootCmd.PersistentFlags().StringVar(&xkmsBackend, "backend", "",
		"xkmsd backend to use (software, tpm2, pkcs11)")

	// Bind flags to viper for backward compatibility with code that still
	// reads from the global viper instance. This will be phased out as
	// subcommands migrate to GetConfig().
	_ = viper.BindPFlag("log.level", RootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log.file", RootCmd.PersistentFlags().Lookup("log-file"))
	_ = viper.BindPFlag("xkmsd_url", RootCmd.PersistentFlags().Lookup("xkmsd-url"))
	_ = viper.BindPFlag("backend", RootCmd.PersistentFlags().Lookup("backend"))

	// Set defaults
	viper.SetDefault("backend", "software")
}

// initConfig loads the unified configuration from the config package.
// When a --config flag is provided it takes precedence; otherwise the
// resolved xhome.Home directory is used. Falls back to the legacy
// XDG-based search (~/.config/xkey/) when no home is available.
func initConfig() error {
	var cfg *xkeyconfig.Config
	var err error

	switch {
	case cfgFile != "":
		cfg, err = xkeyconfig.LoadFromPath(cfgFile)
	case resolvedHome != nil:
		cfg, err = xkeyconfig.LoadFromHome(resolvedHome)
	default:
		cfg, err = xkeyconfig.Load()
	}
	if err != nil {
		return &ConfigError{Operation: "load_config", Err: err}
	}

	loadedConfig = cfg

	if err := initLogging(); err != nil {
		return err
	}
	return nil
}

// initLogging configures the slog logger based on the loaded configuration.
// CLI flags override config file values when explicitly set.
func initLogging() error {
	// Start with the config file value
	levelStr := loadedConfig.Log.Level

	// CLI flag overrides config file value when explicitly set
	if logLevel != "" && logLevel != "info" {
		levelStr = logLevel
	}

	level := parseLogLevel(levelStr)

	// Determine log output
	var output io.Writer = os.Stderr
	logFilePath := loadedConfig.Log.File

	// CLI flag overrides config file value
	if logFile != "" {
		logFilePath = logFile
	}

	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return &ConfigError{
				Operation: "open_log_file",
				Path:      logFilePath,
				Err:       err,
			}
		}
		output = file
	}

	// Create handler options
	opts := &slog.HandlerOptions{
		Level: level,
	}

	// Create and set the default logger
	handler := slog.NewJSONHandler(output, opts)
	slog.SetDefault(slog.New(handler))

	return nil
}

// parseLogLevel converts a string log level to slog.Level.
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ConfigError represents a configuration-related error.
type ConfigError struct {
	Operation string
	Path      string
	Err       error
}

// Error returns the error message.
func (e *ConfigError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("config %s failed for %s: %v", e.Operation, e.Path, e.Err)
	}
	return fmt.Sprintf("config %s failed: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ConfigError) Unwrap() error {
	return e.Err
}

// checkLUKSVolume checks for an encrypted LUKS volume and prompts for
// passphrase if the volume exists but is not mounted.
func checkLUKSVolume() error {
	// Create volume from resolved home, falling back to default paths.
	var vol *luks.Volume
	if resolvedHome != nil {
		vol = luks.NewVolumeFromHome(resolvedHome)
	} else {
		var err error
		vol, err = luks.NewVolume()
		if err != nil {
			// If we can't determine paths, continue without LUKS
			return nil
		}
	}

	// Check if LUKS file exists
	if !vol.Exists() {
		// No LUKS volume, use regular directory
		return nil
	}

	// Check if already mounted
	if vol.IsMounted() {
		// Already unlocked, nothing to do
		return nil
	}

	// LUKS file exists but not mounted - need root privileges
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Encrypted storage detected at %s\n", vol.LUKSPath)
		fmt.Fprintf(os.Stderr, "Run with sudo to unlock: sudo xkey luks2 unseal\n")
		return luks.ErrPermissionDenied
	}

	// Prompt for passphrase
	fmt.Fprintf(os.Stderr, "Encrypted storage detected. Enter passphrase to unlock: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return &ConfigError{
			Operation: "read_passphrase",
			Err:       fmt.Errorf("%w: %v", ErrLUKSPassphraseRead, err),
		}
	}

	// Unlock the volume
	if err := vol.Unlock(string(passphrase)); err != nil {
		return &ConfigError{
			Operation: "unlock_volume",
			Path:      vol.LUKSPath,
			Err:       fmt.Errorf("%w: %v", ErrLUKSUnlockFailed, err),
		}
	}

	fmt.Fprintf(os.Stderr, "Encrypted storage unlocked.\n")
	return nil
}
