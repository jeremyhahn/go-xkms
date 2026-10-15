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

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
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
	// logLevelExplicit records whether --log-level was actually passed, as
	// opposed to sitting at its default. Set in PersistentPreRunE.
	logLevelExplicit bool

	// logFile holds the path to the log file specified via flag.
	logFile string

	// xkmsdURL holds the xkmsd server URL for server mode.
	xkmsdURL string

	// xkmsBackend holds the xkmsd backend name.
	xkmsBackend string

	// ipcSocketPath holds the IPC socket path specified via --socket. It is
	// the one place any command declares this flag; see resolvedSocketPath
	// in socket.go for the fallback chain every command shares.
	ipcSocketPath string

	// loadedConfig holds the unified config loaded during initialization.
	loadedConfig *xkeyconfig.Config

	// resolvedHome holds the resolved xKey home directory.
	resolvedHome *xhome.Home
)

// socketFlagName is the name of the shared --socket persistent flag declared
// below. resolvedSocketPath (state_source.go) is the only place that reads
// it back; no other file may declare a flag by this name.
const socketFlagName = "socket"

// luksExemptCommands is the set of command names that bypass the LUKS
// volume check. These commands manage LUKS volumes themselves, or run
// before the barrier is unsealed.
// luksExemptGroups are the top-level command groups whose subcommands must
// run BEFORE the encrypted home is unlocked: they manage LUKS, barrier or
// PIN state themselves, or (the extension host) are invoked by Chrome and
// must never prompt or read stdin.
//
// Matching is by command GROUP, walking the parent chain — not by leaf
// name. Leaf names are not unique: 13 commands are named "status" alone
// (piv, agent, password, device, auth, extension, …), and "init", "lock",
// "unseal" and "verify" are each claimed by unrelated groups. Keying on
// cmd.Name() therefore exempted ~14 unrelated commands, letting e.g.
// `xkey piv status` and `xkey config init` skip the unlock gate entirely
// and run against an unmounted home.
var luksExemptGroups = map[string]bool{
	"luks2":   true, // seal/unseal/lock/migrate/wipe/import-data
	"barrier": true, // init/status/unseal — run before the barrier is unsealed
	"pin":     true, // set-so/set-user/change-*/verify/reset-lockout/status
	// usb provisions and runs the portable image / virtual CCID device, so
	// it must work without an unlocked home. Registering the group covers
	// `usb create|update` and `usb device start|stop`; the previous
	// per-leaf registration added the bare names "create", "update",
	// "start", "stop" and "device" — the last of which exempted the entire
	// top-level `device` command group.
	"usb": true,
	// provision drives barrier init, PIN set-so/set-user and FIDO2 token
	// initialization against a home that has not been unsealed yet — often
	// one that does not exist yet — exactly like the "barrier" and "pin"
	// groups it calls into.
	"provision": true,
}

// isLUKSExempt reports whether cmd (or any ancestor) belongs to a group
// that must bypass the LUKS unlock gate.
func isLUKSExempt(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if luksExemptGroups[c.Name()] {
			return true
		}
		// The Chrome native-messaging host is a leaf under `extension`;
		// match it by full path so `extension status` is NOT exempt.
		if c.Name() == "host" && c.Parent() != nil && c.Parent().Name() == "extension" {
			return true
		}
	}
	return false
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
		// Record whether --log-level was explicitly passed. This must be
		// captured here (cmd is in scope) rather than read from RootCmd
		// inside initLogging, which would create an initialization cycle.
		logLevelExplicit = cmd.Flags().Changed("log-level")

		// Resolve the xKey home directory first. All path-dependent
		// operations (config loading, LUKS check) use this.
		home, err := xhome.Resolve()
		if err != nil {
			return &ConfigError{Operation: "resolve_home", Err: err}
		}
		resolvedHome = home

		// Skip LUKS check for exempt commands (they manage LUKS, barrier,
		// or PIN state themselves and must run before the barrier is unsealed).
		if isLUKSExempt(cmd) {
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

	// IPC socket flag - the single declaration every command shares. It used
	// to be redeclared per-command (fido2, extension serve, extension host,
	// touch, unlock, password type, and every live-state command), which let
	// a client and the daemon it meant to reach drift onto different
	// defaults. resolvedSocketPath (state_source.go) is the one place that
	// reads it back.
	RootCmd.PersistentFlags().StringVar(&ipcSocketPath, socketFlagName, "",
		"IPC socket path of the xkey instance to talk to (default: derived from XKEY_HOME, or $XDG_RUNTIME_DIR/xkey/xkey.sock, or a per-user fallback: $TMPDIR or ~/Library/Caches on macOS, ~/.xkey/run elsewhere; the directory must be mode 0700 and owned by you)")

	// Bind flags to viper for backward compatibility with code that still
	// reads from the global viper instance. This will be phased out as
	// subcommands migrate to GetConfig().
	_ = viper.BindPFlag("log.level", RootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log.file", RootCmd.PersistentFlags().Lookup("log-file"))
	_ = viper.BindPFlag("xkmsd_url", RootCmd.PersistentFlags().Lookup("xkmsd-url"))
	_ = viper.BindPFlag("backend", RootCmd.PersistentFlags().Lookup("backend"))
	_ = viper.BindPFlag("ipc.socket", RootCmd.PersistentFlags().Lookup(socketFlagName))
	// XKEY_IPC_SOCKET is bound explicitly, rather than through the global
	// AutomaticEnv+SetEnvPrefix convention pkg/config uses for its own viper
	// instance: that convention maps every "ipc.socket"-shaped key to
	// XKEY_IPC_SOCKET automatically, but turning it on for this package's
	// shared viper instance would also start reading XKEY_LOG_LEVEL,
	// XKEY_XKMSD_URL and XKEY_BACKEND, which those flags do not opt into
	// today. BindEnv extends the existing BindPFlag convention to exactly
	// one key without changing behavior for the others.
	_ = viper.BindEnv("ipc.socket", "XKEY_IPC_SOCKET")

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

	// CLI flag overrides the config file value when EXPLICITLY set (see
	// logLevelExplicit, captured in PersistentPreRunE). The previous check
	// compared against the flag's default ("info"), which made
	// `--log-level info` indistinguishable from "not passed" — so a config
	// file setting log.level: debug could never be turned back down from
	// the command line.
	if logLevelExplicit && logLevel != "" {
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

// geteuid reports the effective user ID the root-only commands check
// before they touch a LUKS container or the TPM's physical presence
// interface. Tests replace it to reach the code behind the check.
var geteuid = os.Geteuid

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
	mounted, err := vol.IsMounted()
	if err != nil {
		return &ConfigError{Operation: "check_mounted", Path: vol.MountPoint, Err: err}
	}
	if mounted {
		// Already unlocked, nothing to do
		return nil
	}

	// LUKS file exists but not mounted - need root privileges. Report the
	// canonical xkms.ErrLUKSVolumeLocked sentinel (the same one the GUI
	// surfaces from StorageService.RequireUnlocked) so callers checking
	// errors.Is(err, xkmssdk.ErrLUKSVolumeLocked) recognize a locked volume
	// the same way regardless of which front end hit it; ErrPermissionDenied
	// remains reachable as the cause for the specific reason it's locked.
	if geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Encrypted storage detected at %s\n", vol.LUKSPath)
		fmt.Fprintf(os.Stderr, "Run with sudo to unlock: sudo xkey luks2 unseal\n")
		return &SentinelCauseError{Sentinel: xkmssdk.ErrLUKSVolumeLocked, Cause: luks.ErrPermissionDenied}
	}

	// Prompt for passphrase
	fmt.Fprintf(os.Stderr, "Encrypted storage detected. Enter passphrase to unlock: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return &ConfigError{
			Operation: "read_passphrase",
			Err:       &SentinelCauseError{Sentinel: ErrLUKSPassphraseRead, Cause: err},
		}
	}

	// Unlock the volume
	if err := vol.Unlock(string(passphrase)); err != nil {
		return &ConfigError{
			Operation: "unlock_volume",
			Path:      vol.LUKSPath,
			Err:       &SentinelCauseError{Sentinel: ErrLUKSUnlockFailed, Cause: err},
		}
	}

	fmt.Fprintf(os.Stderr, "Encrypted storage unlocked.\n")
	return nil
}
