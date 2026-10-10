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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-enclave"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/cdp"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/keyboard"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// FIDO2 configuration errors.
var (
	// ErrFIDO2InvalidStorageType indicates an unsupported storage type was specified.
	ErrFIDO2InvalidStorageType = errors.New("fido2: invalid storage type (must be 'memory', 'file', or 'barrier')")

	// ErrFIDO2StoragePathRequired indicates storage path is required for file storage.
	ErrFIDO2StoragePathRequired = errors.New("fido2: storage path required for file storage type")

	// ErrFIDO2InvalidBackend indicates an unsupported key backend was specified.
	ErrFIDO2InvalidBackend = errors.New("fido2: invalid backend type (must be 'software', 'tpm2', or 'phone')")
	// ErrFIDO2InvalidNotifyCommand is returned when notify_command cannot be
	// used; startup stops rather than running without touch notifications.
	ErrFIDO2InvalidNotifyCommand = errors.New("fido2: invalid notify command")

	// ErrFIDO2InvalidAttestationFormat indicates an unsupported attestation format.
	ErrFIDO2InvalidAttestationFormat = errors.New("fido2: invalid attestation format (must be 'none', 'packed', or 'tpm')")

	// ErrFIDO2TPMAttestationRequiresTPMBackend indicates TPM attestation requires tpm2 backend.
	ErrFIDO2TPMAttestationRequiresTPMBackend = errors.New("fido2: TPM attestation requires tpm2 backend")

	// ErrFIDO2SetPINRequiresPINEnabled indicates --set-pin requires --pin to be enabled.
	ErrFIDO2SetPINRequiresPINEnabled = errors.New("fido2: --set-pin-stdin requires --pin to be enabled")

	// ErrFIDO2StorageCreationFailed indicates the storage backend could not be created.
	ErrFIDO2StorageCreationFailed = errors.New("fido2: storage creation failed")

	// ErrFIDO2AuthenticatorCreationFailed indicates the authenticator could not be created.
	ErrFIDO2AuthenticatorCreationFailed = errors.New("fido2: authenticator creation failed")

	// ErrFIDO2UHIDOpenFailed indicates the UHID device could not be opened.
	ErrFIDO2UHIDOpenFailed = errors.New("fido2: UHID open failed")

	// ErrFIDO2UHIDCreateFailed indicates the virtual HID device could not be created.
	ErrFIDO2UHIDCreateFailed = errors.New("fido2: UHID create failed")

	// ErrFIDO2PINSetFailed indicates the initial PIN could not be set.
	ErrFIDO2PINSetFailed = errors.New("fido2: PIN set failed")

	// ErrFIDO2PINAlreadySet indicates --set-pin-stdin was given for a store that
	// already holds a PIN. --set-pin-stdin establishes the first PIN only; an
	// existing PIN is changed through the CTAP changePIN ceremony.
	ErrFIDO2PINAlreadySet = errors.New("fido2: --set-pin-stdin refused: a PIN is already configured in this store; drop --set-pin-stdin or change the PIN through the FIDO2 client")

	// ErrFIDO2BackendCreationFailed indicates the key backend could not be created.
	ErrFIDO2BackendCreationFailed = errors.New("fido2: backend creation failed")

	// ErrFIDO2TPMOpenFailed indicates the TPM device could not be opened.
	ErrFIDO2TPMOpenFailed = errors.New("fido2: TPM open failed")

	// ErrFIDO2TPMBackendCreationFailed indicates the TPM2 key backend could not be created.
	ErrFIDO2TPMBackendCreationFailed = errors.New("fido2: TPM2 backend creation failed")

	// ErrFIDO2DeviceAlreadyRunning indicates the device is already running.
	ErrFIDO2DeviceAlreadyRunning = errors.New("fido2: device already running")

	// ErrFIDO2NotifierCreationFailed indicates the notifier could not be created.
	ErrFIDO2NotifierCreationFailed = errors.New("fido2: notifier creation failed")

	// ErrFIDO2IPCServerCreationFailed indicates the IPC server could not be created.
	ErrFIDO2IPCServerCreationFailed = errors.New("fido2: IPC server creation failed")

	// ErrFIDO2PasswordStoreOpenFailed indicates the password store could not be opened.
	ErrFIDO2PasswordStoreOpenFailed = errors.New("fido2: password store open failed")

	// ErrFIDO2KeyboardCreationFailed indicates the virtual keyboard could not be created.
	ErrFIDO2KeyboardCreationFailed = errors.New("fido2: keyboard creation failed")

	// ErrFIDO2KeyboardUnavailable indicates the keyboard is not available for password typing.
	ErrFIDO2KeyboardUnavailable = errors.New("fido2: virtual keyboard unavailable")

	// ErrFIDO2PasswordStoreUnavailable indicates the password store is not available.
	ErrFIDO2PasswordStoreUnavailable = errors.New("fido2: password store unavailable")

	// ErrFIDO2DeviceBackendCreationFailed indicates the device key backend could not be created.
	ErrFIDO2DeviceBackendCreationFailed = errors.New("fido2: device backend creation failed")

	// ErrFIDO2DeviceConfigRequired indicates device configuration is required.
	ErrFIDO2DeviceConfigRequired = errors.New("fido2: device backend requires pairing; run 'xkey device pair' first")

	// ErrFIDO2BarrierPasswordRequired indicates barrier password or password file is required.
	ErrFIDO2BarrierPasswordRequired = errors.New("fido2: barrier password or password file required for barrier storage")

	// ErrFIDO2BarrierUnsealFailed indicates the barrier could not be unsealed.
	ErrFIDO2BarrierUnsealFailed = errors.New("fido2: barrier unseal failed")

	// ErrFIDO2CDPCaptureNoStorage indicates a CDP-captured credential could not
	// be persisted because no storage backend is configured.
	ErrFIDO2CDPCaptureNoStorage = errors.New("fido2: cdp credential capture requires a storage backend")

	// ErrFIDO2CDPCaptureDecodeFailed indicates a CDP-captured credential field
	// could not be base64-decoded. CDP carries these fields as standard base64
	// (RFC 4648 section 4) with padding.
	ErrFIDO2CDPCaptureDecodeFailed = errors.New("fido2: cdp credential capture decode failed")

	// ErrFIDO2CDPCaptureKeyParseFailed indicates the captured PKCS#8 private key
	// could not be parsed.
	ErrFIDO2CDPCaptureKeyParseFailed = errors.New("fido2: cdp credential key parse failed")

	// ErrFIDO2CDPCaptureUnsupportedKey indicates the captured key uses an
	// algorithm/curve not supported by FIDO2.
	ErrFIDO2CDPCaptureUnsupportedKey = errors.New("fido2: cdp credential key algorithm unsupported")

	// ErrFIDO2CDPCapturePersistFailed indicates the captured credential could
	// not be written to the storage backend.
	ErrFIDO2CDPCapturePersistFailed = errors.New("fido2: cdp credential persist failed")
)

// FIDO2StorageType represents the credential storage backend type.
type FIDO2StorageType string

const (
	// FIDO2StorageTypeMemory stores credentials in memory (volatile).
	FIDO2StorageTypeMemory FIDO2StorageType = "memory"

	// FIDO2StorageTypeFile stores credentials on the filesystem (persistent).
	FIDO2StorageTypeFile FIDO2StorageType = "file"

	// FIDO2StorageTypeBarrier uses barrier-encrypted storage matching the GUI.
	FIDO2StorageTypeBarrier FIDO2StorageType = "barrier"
)

// Credential-store key prefixes.
//
// These are NOT interchangeable and must not be unified without moving data.
// Each compensates for the root its backend is created with: the barrier
// backend is rooted at the data directory, the file backend at <dataDir>/fido2,
// so both compose to <dataDir>/fido2/xkey/... on disk. What differs between the
// two layouts is whether the stored value is encrypted, not where it lives.
const (
	// fido2BarrierKeyPrefix namespaces credentials inside the barrier backend.
	fido2BarrierKeyPrefix = "fido2/xkey/"

	// fido2FileKeyPrefix namespaces credentials inside a plain file backend
	// already rooted at the fido2 directory.
	fido2FileKeyPrefix = "xkey/"
)

// Default FIDO2 configuration values.
const (
	defaultFIDO2DeviceName  = "xKey (go-xkms)"
	defaultFIDO2Backend     = "software"
	defaultFIDO2TPMDevice   = "/dev/tpmrm0"
	defaultFIDO2Attestation = "none"
	defaultFIDO2Timeout     = 30 * time.Second
	defaultFIDO2StorageType = "memory"
)

// FIDO2Config holds the configuration for the virtual FIDO2 device.
type FIDO2Config struct {
	// Storage configuration
	StorageType         FIDO2StorageType
	StoragePath         string
	BarrierPassword     string
	BarrierPasswordFile string

	// Device configuration
	DeviceName   string
	SerialNumber string

	// PIN configuration. PIN is nil when --set-pin-stdin was not provided.
	EnablePIN bool
	PIN       *secure.Secret

	// User presence mode
	Interactive         bool
	RequireTouch        bool
	UserPresenceTimeout time.Duration

	// Key backend configuration
	Backend           string
	TPMDevice         string
	AttestationFormat string

	// Phone backend configuration
	PhoneDevice string // Specific phone name or address to use

	// Cmd is the "xkey fido2" command invocation. It is used only by the
	// phone backend (createFIDO2PhoneKeyBackend, fido2_device.go) to hand
	// buildListenBridgeConfig the same --barrier-password/
	// --barrier-password-file flags "xkey device listen" reads, so the
	// xkmsd bridge's OATH/PIV/sync collaborators open the same stores
	// (go-xkms#1041). Set by runFIDO2; nil for every other backend and for
	// callers that only use FIDO2Config for validation or storage setup.
	Cmd *cobra.Command

	// Password and IPC configuration
	PasswordStorePath string
	SocketPath        string
	DefaultPassword   string
	NotifyCommand     string
	NotifyType        string // "dialog", "passive", "log", or "none"

	// Unified PIN configuration
	UnifiedPIN bool

	// CDPEnabled enables Chrome DevTools Protocol virtual authenticator bridge.
	CDPEnabled bool
	// CDPHost is the Chrome DevTools host (default "localhost").
	CDPHost string
	// CDPPort is the Chrome DevTools debugging port (default 9222).
	CDPPort int
}

// Validate checks the FIDO2 configuration for errors.
func (c *FIDO2Config) Validate() error {
	// Validate storage type
	switch c.StorageType {
	case FIDO2StorageTypeMemory, FIDO2StorageTypeFile, FIDO2StorageTypeBarrier:
		// Valid
	default:
		return ErrFIDO2InvalidStorageType
	}

	// File storage requires a path
	if c.StorageType == FIDO2StorageTypeFile && c.StoragePath == "" {
		return ErrFIDO2StoragePathRequired
	}

	// Barrier storage requires a password or password file
	if c.StorageType == FIDO2StorageTypeBarrier {
		if c.BarrierPassword == "" && c.BarrierPasswordFile == "" {
			return ErrFIDO2BarrierPasswordRequired
		}
	}

	// Validate backend
	switch c.Backend {
	case "software", "tpm2", "phone":
		// Valid
	default:
		return ErrFIDO2InvalidBackend
	}

	// Validate attestation format
	switch c.AttestationFormat {
	case "none", "packed", "tpm":
		// Valid
	default:
		return ErrFIDO2InvalidAttestationFormat
	}

	// TPM attestation requires TPM2 backend
	if c.AttestationFormat == "tpm" && c.Backend != "tpm2" {
		return ErrFIDO2TPMAttestationRequiresTPMBackend
	}

	// Validate PIN configuration
	if c.PIN != nil && !c.EnablePIN {
		return ErrFIDO2SetPINRequiresPINEnabled
	}

	return nil
}

// fido2Cmd represents the fido2 command for running the virtual FIDO2 device.
var fido2Cmd = &cobra.Command{
	Use:     "fido2",
	Aliases: []string{"fido"},
	Short:   "Run as FIDO2/WebAuthn virtual USB device",
	Long: `Run xKey as a virtual FIDO2/WebAuthn security key.

This command creates a virtual USB HID device via Linux UHID (User-space HID)
that presents itself to the operating system as a FIDO2/WebAuthn security key.
Applications and browsers can then use this virtual device for passwordless
authentication, two-factor authentication, and discoverable credential flows.

The virtual device supports:
  - CTAP2 (Client to Authenticator Protocol 2)
  - WebAuthn credential creation and assertion
  - Resident/discoverable credentials
  - User verification via PIN
  - Multiple attestation formats (none, packed, tpm)
  - Software, TPM2, or phone-backed key storage
  - Phone backend with BLE communication and biometric auth
  - IPC-based user presence approval (xkey touch)
  - Static password typing via virtual keyboard
  - Desktop notifications for touch requests

Requirements:
  - Linux kernel with UHID support (CONFIG_UHID)
  - Access to /dev/uhid (typically requires root or uinput group membership)
  - For TPM2 backend: access to /dev/tpmrm0 or specified TPM device

Examples:
  # Run with default settings (memory storage, socket-based user presence)
  sudo xkey fido2

  # Run with file-based persistent storage
  sudo xkey fido2 --storage file --storage-path /var/lib/xkey

  # Run with PIN protection in interactive mode
  echo 123456 | sudo xkey fido2 --pin --set-pin-stdin --interactive

  # Run with TPM2 hardware-backed keys
  sudo xkey fido2 --backend tpm2 --tpm-device /dev/tpmrm0

  # Run with TPM attestation (requires TPM2 backend)
  sudo xkey fido2 --backend tpm2 --attestation tpm

  # Run with phone backend (requires BLE and prior pairing)
  sudo xkey fido2 --backend phone

  # Run with phone backend using specific device
  sudo xkey fido2 --backend phone --phone-device "John's Pixel"

  # Run with a default password for bare touch
  sudo xkey fido2 --default-password "DatabaseProd"

  # Run with custom notification command (request data via XKEY_* env vars)
  sudo xkey fido2 --notify-command 'sh -c "notify-send xKey \"$XKEY_RP_ID\""'

Only --storage, --storage-path, --name and --attestation can also be set via
the xkey config file's fido2: section or the environment variables
XKEY_FIDO2_STORAGE, XKEY_FIDO2_STORAGE_PATH, XKEY_FIDO2_DEVICE_NAME and
XKEY_FIDO2_ATTESTATION -- the settings pkg/config.FIDO2Config declares.
Command-line flags take precedence, then the environment, then the config
file. Every other flag on this command (backend, tpm-device, pin, PKCS#11
and phone settings, notifications, CDP, ...) is CLI-only: it has no
environment variable or config file source.`,
	RunE: runFIDO2,
}

func init() {
	// Register command with root
	RootCmd.AddCommand(fido2Cmd)

	// Storage configuration flags
	fido2Cmd.Flags().String("storage", defaultFIDO2StorageType,
		"Storage type: memory, file, or barrier")
	fido2Cmd.Flags().String("storage-path", "",
		"Path for file storage and the authenticator profile (default: ~/.xkey/data/fido2, see --data-dir/XKEY_DATA_DIR)")
	barrierPasswordSource.addFlags(fido2Cmd)
	fido2Cmd.Flags().String("barrier-password-file", "",
		"Read barrier password from file (first line)")

	// Device configuration flags
	fido2Cmd.Flags().String("name", defaultFIDO2DeviceName,
		"Device name visible to OS")
	fido2Cmd.Flags().String("serial", "",
		"Device serial number (auto-generated if empty)")

	// PIN configuration flags
	fido2Cmd.Flags().Bool("pin", true,
		"Enable PIN support (required for FIDO 2.1 credential management)")
	fido2SetPINSource.addFlags(fido2Cmd)

	// User presence configuration flags
	fido2Cmd.Flags().Bool("interactive", false,
		"Enable interactive mode (prompt for touch/PIN)")
	fido2Cmd.Flags().Bool("require-touch", true,
		"Require touch even after PIN verification (like hardware YubiKey)")
	fido2Cmd.Flags().Duration("timeout", defaultFIDO2Timeout,
		"Timeout for user presence requests")

	// Key backend configuration flags
	fido2Cmd.Flags().String("backend", defaultFIDO2Backend,
		"Key backend: software, tpm2, or phone")
	fido2Cmd.Flags().String("tpm-device", defaultFIDO2TPMDevice,
		"TPM device path")
	fido2Cmd.Flags().String("attestation", defaultFIDO2Attestation,
		"Attestation format: none, packed, or tpm")
	fido2Cmd.Flags().String("phone-device", "",
		"Specific phone name or address to use (default: use default paired phone)")

	// Password and IPC configuration flags
	fido2Cmd.Flags().String("password-store", "",
		"Path to static password store (default: ~/.xkey/data/staticpw, the same store `xkey password` uses)")
	fido2Cmd.Flags().String("default-password", "",
		"Password name to type on bare touch")
	fido2Cmd.Flags().String("notify-command", "",
		"Custom notification command (overrides built-in notifications). Split into argv on whitespace "+
			"(quote with ' or \" to include a space in one argument); run exactly as given, never through a "+
			"shell, and never modified. Request data (operation, RP ID, RP name, user name) reaches the "+
			"command only via the XKEY_OPERATION/XKEY_RP_ID/XKEY_RP_NAME/XKEY_USER_NAME environment "+
			"variables, for example: sh -c 'notify-send \"Touch required\" \"$XKEY_RP_ID\"'")
	fido2Cmd.Flags().String("notify", "dialog",
		"Notification type: dialog (interactive), passive (desktop notification), log (log-only), or none")

	// Unified PIN flag
	fido2Cmd.Flags().Bool("unified-pin", true,
		"Propagate the host PIN service's user PIN to the virtual FIDO2 authenticator's CTAP2 PIN hash on every set/change/verify "+
			"(it does not sync a separate PKCS#11 or file PIN store: there is exactly one governing PIN backend, see 'xkey pin status')")

	// CDP bridge flags
	fido2Cmd.Flags().Bool("cdp", false, "Enable Chrome DevTools virtual authenticator bridge")
	fido2Cmd.Flags().String("cdp-host", "localhost", "Chrome DevTools host")
	fido2Cmd.Flags().Int("cdp-port", 9222, "Chrome DevTools debugging port")

	// Bind flags to viper for unified configuration access
	_ = viper.BindPFlag("fido2.storage", fido2Cmd.Flags().Lookup("storage"))
	_ = viper.BindPFlag("fido2.storage_path", fido2Cmd.Flags().Lookup("storage-path"))
	_ = viper.BindPFlag("fido2.barrier_password_stdin", fido2Cmd.Flags().Lookup("barrier-password-stdin"))
	_ = viper.BindPFlag("fido2.barrier_password_file", fido2Cmd.Flags().Lookup("barrier-password-file"))
	_ = viper.BindPFlag("fido2.name", fido2Cmd.Flags().Lookup("name"))
	_ = viper.BindPFlag("fido2.serial", fido2Cmd.Flags().Lookup("serial"))
	_ = viper.BindPFlag("fido2.pin", fido2Cmd.Flags().Lookup("pin"))
	_ = viper.BindPFlag("fido2.set_pin_stdin", fido2Cmd.Flags().Lookup("set-pin-stdin"))
	_ = viper.BindPFlag("fido2.interactive", fido2Cmd.Flags().Lookup("interactive"))
	_ = viper.BindPFlag("fido2.require_touch", fido2Cmd.Flags().Lookup("require-touch"))
	_ = viper.BindPFlag("fido2.timeout", fido2Cmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("fido2.backend", fido2Cmd.Flags().Lookup("backend"))
	_ = viper.BindPFlag("fido2.tpm_device", fido2Cmd.Flags().Lookup("tpm-device"))
	_ = viper.BindPFlag("fido2.attestation", fido2Cmd.Flags().Lookup("attestation"))
	_ = viper.BindPFlag("fido2.phone_device", fido2Cmd.Flags().Lookup("phone-device"))
	_ = viper.BindPFlag("fido2.password_store", fido2Cmd.Flags().Lookup("password-store"))
	_ = viper.BindPFlag("fido2.default_password", fido2Cmd.Flags().Lookup("default-password"))
	_ = viper.BindPFlag("fido2.notify_command", fido2Cmd.Flags().Lookup("notify-command"))
	_ = viper.BindPFlag("fido2.notify", fido2Cmd.Flags().Lookup("notify"))
	_ = viper.BindPFlag("fido2.unified_pin", fido2Cmd.Flags().Lookup("unified-pin"))
	_ = viper.BindPFlag("fido2.cdp", fido2Cmd.Flags().Lookup("cdp"))
	_ = viper.BindPFlag("fido2.cdp_host", fido2Cmd.Flags().Lookup("cdp-host"))
	_ = viper.BindPFlag("fido2.cdp_port", fido2Cmd.Flags().Lookup("cdp-port"))
}

// runFIDO2 executes the FIDO2 virtual device command.
func runFIDO2(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// Build configuration from Viper (merges flags, env vars, config file)
	cfg := buildFIDO2Config()
	// Only the phone backend reads this (createFIDO2PhoneKeyBackend), to wire
	// the xkmsd bridge's OATH/PIV/sync collaborators from this command's own
	// barrier flags (go-xkms#1041); every other backend ignores it.
	cfg.Cmd = cmd

	// Resolve the file-storage default (issue #929) before validating: an
	// unset --storage-path must resolve through the shared xkey data
	// directory, not fail closed as "required".
	if cfg.StorageType == FIDO2StorageTypeFile {
		if _, err := resolveFIDO2StoragePath(cfg); err != nil {
			return err
		}
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Generate serial number if not provided
	if cfg.SerialNumber == "" {
		cfg.SerialNumber = generateFIDO2SerialNumber()
	}

	// Log startup information
	logger.Info("starting FIDO2 authenticator",
		slog.String("name", cfg.DeviceName),
		slog.String("serial", cfg.SerialNumber),
		slog.String("storage", string(cfg.StorageType)),
		slog.Bool("pin_enabled", cfg.EnablePIN),
		slog.Bool("interactive", cfg.Interactive),
		slog.Bool("require_touch", cfg.RequireTouch),
		slog.String("backend", cfg.Backend),
		slog.String("attestation", cfg.AttestationFormat),
	)

	// Setup signal handler for graceful shutdown
	ctx, cancel := setupFIDO2SignalHandler(logger)
	defer cancel()

	// Create and run the virtual FIDO2 device
	device, err := newFIDO2Device(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to create virtual FIDO2 device",
			slog.Any("error", err),
		)
		return err
	}

	// Run the device event loop (blocking)
	if err := device.Run(ctx); err != nil {
		// Context cancellation is expected on shutdown
		if ctx.Err() != nil {
			logger.Info("device stopped due to shutdown signal")
		} else {
			logger.Error("device error",
				slog.Any("error", err),
			)
			if closeErr := device.Close(); closeErr != nil {
				logger.Error("error during device cleanup", slog.Any("error", closeErr))
			}
			return err
		}
	}

	// Clean shutdown
	if err := device.Close(); err != nil {
		logger.Error("error during device cleanup",
			slog.Any("error", err),
		)
		return err
	}

	logger.Info("FIDO2 authenticator stopped")
	return nil
}

// buildFIDO2Config creates a FIDO2Config from Viper configuration.
//
// Every key pkg/config's FIDO2Config declares (storage, storage_path,
// device_name, attestation) is honoured here, not only attestation: the
// unified xkey config file is read by its own viper instance, so a value set
// there -- or an XKEY_FIDO2_* environment variable, which that instance also
// merges (pkg/config/load.go registers every leaf for both) -- never reached
// this command's viper on its own. Installing each as this viper's default
// gives the config/environment source its intended precedence: an explicit
// flag still wins, because viper only falls back to a default for a flag the
// user did not set (go-xkms#871).
func buildFIDO2Config() *FIDO2Config {
	if xcfg, err := xkeyconfig.Load(); err == nil {
		if xcfg.FIDO2.Storage != "" {
			viper.SetDefault("fido2.storage", xcfg.FIDO2.Storage)
		}
		if xcfg.FIDO2.StoragePath != "" {
			viper.SetDefault("fido2.storage_path", xcfg.FIDO2.StoragePath)
		}
		if xcfg.FIDO2.DeviceName != "" {
			viper.SetDefault("fido2.name", xcfg.FIDO2.DeviceName)
		}
		if xcfg.FIDO2.Attestation != "" {
			viper.SetDefault("fido2.attestation", xcfg.FIDO2.Attestation)
		}
	}

	cfg := &FIDO2Config{
		StorageType:         FIDO2StorageType(viper.GetString("fido2.storage")),
		StoragePath:         viper.GetString("fido2.storage_path"),
		BarrierPassword:     resolveFIDO2BarrierPassword(),
		BarrierPasswordFile: viper.GetString("fido2.barrier_password_file"),
		DeviceName:          viper.GetString("fido2.name"),
		SerialNumber:        viper.GetString("fido2.serial"),
		EnablePIN:           viper.GetBool("fido2.pin"),
		PIN:                 resolveFIDO2SetPINSecret(),
		Interactive:         viper.GetBool("fido2.interactive"),
		RequireTouch:        viper.GetBool("fido2.require_touch"),
		UserPresenceTimeout: viper.GetDuration("fido2.timeout"),
		Backend:             viper.GetString("fido2.backend"),
		TPMDevice:           viper.GetString("fido2.tpm_device"),
		AttestationFormat:   viper.GetString("fido2.attestation"),
		PhoneDevice:         viper.GetString("fido2.phone_device"),
		PasswordStorePath:   viper.GetString("fido2.password_store"),
		// buildFIDO2Config takes no *cobra.Command (dozens of call sites,
		// including every fido2 policy/attestation test, predate one), so
		// this reads back through viper rather than a specific command's
		// flags. That is still correct: root.go's --socket is bound to the
		// same viper key, and cobra parses it into that flag object on every
		// invocation regardless of which subcommand runs.
		SocketPath:      resolvedSocketPath(nil),
		DefaultPassword: viper.GetString("fido2.default_password"),
		NotifyCommand:   viper.GetString("fido2.notify_command"),
		NotifyType:      viper.GetString("fido2.notify"),
		UnifiedPIN:      viper.GetBool("fido2.unified_pin"),
		CDPEnabled:      viper.GetBool("fido2.cdp"),
		CDPHost:         viper.GetString("fido2.cdp_host"),
		CDPPort:         viper.GetInt("fido2.cdp_port"),
	}

	return cfg
}

// fido2SetPINSource is the one way the initial FIDO2 PIN to establish enters
// the CLI. It follows the PIN convention (pin_input.go): standard input,
// never a "--set-pin" value flag -- a value on the command line is visible to
// every other process on the host via 'ps' (go-xkms#1209). Unlike the other
// pinSources in this package it has no environment variable: --set-pin was
// CLI-only before this change (see fido2Cmd's doc comment), and establishing
// a brand-new PIN is rare enough, and consequential enough, that it does not
// need a headless/env path the way an existing PIN's authentication does.
var fido2SetPINSource = pinSource{
	label:      "PIN to establish",
	stdinFlag:  "set-pin-stdin",
	stdinEmpty: ErrPINInputStdinEmpty,
	stdinRead:  ErrPINInputStdinRead,
}

// resolveFIDO2BarrierPassword resolves the barrier password
// buildFIDO2Config populates FIDO2Config.BarrierPassword with: read from
// standard input when --barrier-password-stdin was given, otherwise
// XKEY_BARRIER_PASSWORD. buildFIDO2Config has no *cobra.Command (see its doc
// comment) and no error return, so a resolution failure is logged and
// treated as "no password provided" rather than propagated -- the same
// non-fallible contract fido2PINSecret already follows.
func resolveFIDO2BarrierPassword() string {
	secret, err := barrierPasswordSource.resolveBytesFrom(viper.GetBool("fido2.barrier_password_stdin"))
	if err != nil {
		slog.Default().Error("fido2: failed to resolve --barrier-password-stdin", "error", err)
		return ""
	}
	defer enclave.Wipe(secret)
	return string(secret)
}

// resolveFIDO2SetPINSecret resolves the initial PIN to establish
// (--set-pin-stdin) and seals it into a *secure.Secret for FIDO2Config.PIN.
// A PIN that was never supplied returns nil, matching fido2PINSecret's
// historical "no --set-pin" contract.
func resolveFIDO2SetPINSecret() *secure.Secret {
	secret, err := fido2SetPINSource.resolveBytesFrom(viper.GetBool("fido2.set_pin_stdin"))
	if err != nil {
		slog.Default().Error("fido2: failed to resolve --set-pin-stdin", "error", err)
		return nil
	}
	if len(secret) == 0 {
		return nil
	}
	defer enclave.Wipe(secret)
	return fido2PINSecret(string(secret))
}

// fido2PINSecret seals s into a *secure.Secret for FIDO2Config.PIN. An
// empty s returns nil: no --set-pin-stdin was provided.
//
// buildFIDO2Config has no error return -- it is called from more than a
// dozen commands that are not themselves fallible at this point -- so a
// sealing failure is logged and treated as "no PIN provided" rather than
// propagated. In practice this path is unreachable: the underlying
// memguard allocator panics the whole process on allocation failure before
// NewSecret could return an error here. For the same reason (no
// *cobra.Command) the PIN is sealed under a background context.
func fido2PINSecret(s string) *secure.Secret {
	if s == "" {
		return nil
	}
	secret, err := secure.NewSecret(context.Background(), []byte(s))
	if err != nil {
		slog.Default().Error("fido2: failed to seal --set-pin-stdin into protected memory", "error", err)
		return nil
	}
	return secret
}

// setupFIDO2SignalHandler creates a context that is cancelled on SIGTERM/SIGINT.
func setupFIDO2SignalHandler(logger *slog.Logger) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("received shutdown signal",
				slog.String("signal", sig.String()))
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	return ctx, cancel
}

// generateFIDO2SerialNumber creates a random 16-character hexadecimal serial number.
func generateFIDO2SerialNumber() string {
	b := make([]byte, 8)
	_, err := cryptoRandRead(b)
	if err != nil {
		// Fallback to a deterministic serial if crypto/rand fails
		return "XKEY-00000000"
	}
	return fmt.Sprintf("%X", b)
}

// cryptoRandRead is a variable to allow testing without crypto/rand.
var cryptoRandRead = cryptoRandReadImpl

// cryptoRandReadImpl reads random bytes from crypto/rand.
func cryptoRandReadImpl(b []byte) (int, error) {
	// Import inline to avoid circular dependencies in tests
	return len(b), nil // Will be replaced with actual implementation
}

// readCryptoRandomFrom reads exactly len(b) bytes from r into b using
// io.ReadFull, so a source that returns fewer bytes than requested on a
// single Read (a short read) is retried until b is fully populated,
// instead of silently returning fewer random bytes than the caller asked
// for. Extracted from the /dev/urandom closure below so this behavior is
// unit-testable against a fake short-reading io.Reader.
func readCryptoRandomFrom(r io.Reader, b []byte) (int, error) {
	return io.ReadFull(r, b)
}

func init() {
	// Set up the actual crypto/rand implementation
	cryptoRandRead = func(b []byte) (int, error) {
		// Use crypto/rand for secure random generation
		f, err := os.Open("/dev/urandom")
		if err != nil {
			return 0, err
		}
		defer func() { _ = f.Close() }()
		return readCryptoRandomFrom(f, b)
	}
}

// fido2Device manages the virtual FIDO2 USB device and integrates the IPC
// server, virtual keyboard, password store, and notification subsystem.
type fido2Device struct {
	cfg             *FIDO2Config
	logger          *slog.Logger
	uhidDevice      *uhid.Device
	auth            *authenticator.Authenticator
	hidHandler      *authenticator.CTAPHIDHandler
	storage         authenticator.StatefulCredentialStorage
	keyBackend      keybackend.FIDO2KeyBackend
	running         bool
	keyboard        *keyboard.Keyboard
	ipcServer       *ipc.Server
	pwStore         *xkms.StaticPasswordDAOStore
	socketHandler   *authenticator.SocketHandler
	notifier        notify.Notifier
	defaultPassword string
	cdpBridge       *cdp.Bridge
}

// newFIDO2Device creates a new virtual FIDO2 device with the given configuration.
func newFIDO2Device(ctx context.Context, cfg *FIDO2Config, logger *slog.Logger) (*fido2Device, error) {
	if cfg == nil {
		cfg = &FIDO2Config{
			StorageType:         FIDO2StorageTypeMemory,
			DeviceName:          defaultFIDO2DeviceName,
			SerialNumber:        generateFIDO2SerialNumber(),
			EnablePIN:           false,
			Interactive:         false,
			UserPresenceTimeout: defaultFIDO2Timeout,
			Backend:             defaultFIDO2Backend,
			TPMDevice:           defaultFIDO2TPMDevice,
			AttestationFormat:   defaultFIDO2Attestation,
		}
	}

	if logger == nil {
		logger = slog.Default()
	}

	// Resolve the file-storage default (issue #929) before validating, same
	// as runFIDO2: callers that build a *FIDO2Config directly (tests,
	// future callers) get the same resolution rather than a bare "required".
	if cfg.StorageType == FIDO2StorageTypeFile {
		if _, err := resolveFIDO2StoragePath(cfg); err != nil {
			return nil, err
		}
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create the appropriate storage backend
	storage, err := createFIDO2Storage(cfg, logger)
	if err != nil {
		return nil, errors.Join(ErrFIDO2StorageCreationFailed, err)
	}

	// Create user presence handler (may return a SocketHandler for daemon mode)
	upHandler, socketHandler, notifier, err := createFIDO2UserPresenceHandler(cfg, logger)
	if err != nil {
		return nil, errors.Join(ErrFIDO2AuthenticatorCreationFailed, err, storage.Close())
	}

	// Create key backend
	keyBackend, err := createFIDO2KeyBackend(cfg, logger)
	if err != nil {
		return nil, errors.Join(ErrFIDO2AuthenticatorCreationFailed, err, storage.Close())
	}

	// Create authenticator configuration
	// RequireUserPresence defaults to true to match hardware authenticator behavior
	// (YubiKey requires touch even after PIN verification). This ensures the
	// SocketHandler is invoked for every operation, triggering D-Bus notifications
	// and allowing approval via `xkey touch`. Can be disabled with --require-touch=false.
	authConfig := &authenticator.Config{
		// One product, one AAGUID: authenticator.DefaultAAGUID is the single
		// definition every xkey entry point reports.
		AAGUID:                     authenticator.DefaultAAGUID,
		EnablePIN:                  cfg.EnablePIN,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		EnableUserIntentCheck:      false,
		Storage:                    storage,
		UserPresenceHandler:        upHandler,
		UserPresenceTimeout:        cfg.UserPresenceTimeout,
		RequireUserPresence:        cfg.RequireTouch,
		KeyBackend:                 keyBackend,
		AttestationFormat:          cfg.AttestationFormat,
		Logger:                     logger,
	}

	// Apply the persisted authenticator profile (`xkey fido2 profile set`).
	// Without this the saved settings would never reach GetInfo, which is
	// what made `profile set` a no-op. A missing profile is not an error —
	// it simply leaves the authenticator's built-in defaults in place.
	if profile, perr := loadFIDO2Profile(context.Background(), cfg); perr != nil {
		logger.Warn("fido2: could not load authenticator profile; using defaults", "error", perr)
	} else if profile != nil {
		if len(profile.Transports) > 0 {
			authConfig.Transports = profile.Transports
		}
		authConfig.EnableEnterpriseAttestation = profile.EnterpriseAttestation
	}

	// Create the authenticator
	auth, err := authenticator.NewAuthenticator(authConfig)
	if err != nil {
		return nil, errors.Join(ErrFIDO2AuthenticatorCreationFailed, err, keyBackend.Close(), storage.Close())
	}

	// Wire audit logging before any PIN or credential operation can reach
	// the authenticator (SetInitialPIN below is the first one). This daemon
	// has no durable audit store of its own, so it uses the same
	// slog-backed audit.Logger the headless `xkey extension serve` daemon
	// uses for its own security events (#688): SeveritySecurity events
	// (OpPINSeeded, OpFIDO2CredentialCreated) are recorded in the structured
	// log stream this daemon already writes, and SlogLogger has no
	// persistent store to fail, so it never refuses an operation.
	auth.SetAuditLogger(audit.NewSlogLogger(logger))

	// Establish the initial PIN if configured. --set-pin-stdin is the operator
	// seeding a first PIN, so it goes through the authenticator's
	// SetInitialPIN: the same policy, retry-reset and pinUvAuthToken
	// invalidation as the CTAP setPIN ceremony, minus the wire-level proof
	// that only exists to authenticate a remote platform. It refuses to
	// overwrite a PIN a persistent store already holds; the old testing
	// helper silently replaced it and reset the retry counter (#377).
	if cfg.EnablePIN && cfg.PIN != nil {
		pinBuf, openErr := cfg.PIN.Open(ctx)
		if openErr != nil {
			return nil, errors.Join(ErrFIDO2PINSetFailed, openErr, auth.Close())
		}
		// SetInitialPIN seals the PIN into protected memory of its own, so the
		// PIN is copied out and wiped rather than lent across that call.
		pin, err := secure.CopyOut(pinBuf)
		pinBuf.Destroy()
		if err == nil {
			err = auth.SetInitialPIN(pin)
			secure.Wipe(pin)
		}
		if err != nil {
			closeErr := auth.Close()
			if errors.Is(err, authenticator.ErrPINAlreadySet) {
				return nil, errors.Join(ErrFIDO2PINAlreadySet, err, closeErr)
			}
			return nil, errors.Join(ErrFIDO2PINSetFailed, err, closeErr)
		}
		logger.Info("initial PIN configured")
	}

	// Create CTAP-HID handler
	hidHandler := authenticator.NewCTAPHIDHandler(auth)

	device := &fido2Device{
		cfg:             cfg,
		logger:          logger,
		auth:            auth,
		hidHandler:      hidHandler,
		storage:         storage,
		keyBackend:      keyBackend,
		socketHandler:   socketHandler,
		notifier:        notifier,
		defaultPassword: cfg.DefaultPassword,
	}

	return device, nil
}

// Run starts the virtual FIDO2 device event loop and initializes supplementary
// subsystems: virtual keyboard, password store, and IPC server.
func (d *fido2Device) Run(ctx context.Context) error {
	if d.running {
		return ErrFIDO2DeviceAlreadyRunning
	}
	d.running = true
	defer func() { d.running = false }()

	// In CDP bridge mode the Chrome-internal virtual authenticator is the sole
	// authenticator that answers browser WebAuthn ceremonies; xkey syncs its
	// stored credentials into it and captures new ones back out. Creating the
	// UHID device as well would expose TWO authenticators to the same browser,
	// and Chrome routes ceremonies between them nondeterministically. --cdp and
	// the UHID virtual USB device are therefore mutually exclusive.
	if d.cfg.CDPEnabled {
		d.logger.Info("CDP mode active: UHID virtual device suppressed (CDP authenticator is authoritative)")

		// Initialize supplementary subsystems (keyboard, password store, IPC).
		d.initSupplementarySubsystems(ctx)

		// Run the CDP bridge until the context is cancelled. The bridge
		// captures credentials created in Chrome via credentialAdded events.
		return d.cdpLoop(ctx)
	}

	// Open UHID device
	uhidDev, err := uhid.Open()
	if err != nil {
		return errors.Join(ErrFIDO2UHIDOpenFailed, err)
	}
	d.uhidDevice = uhidDev

	// Create the virtual HID device with FIDO2 descriptor
	createCfg := &uhid.CreateConfig{
		Name:             d.cfg.DeviceName,
		Uniq:             d.cfg.SerialNumber,
		VendorID:         uhid.VendorIDVirtualFIDO,
		ProductID:        uhid.ProductIDVirtualFIDO,
		ReportDescriptor: uhid.FIDO2HIDReportDescriptor,
	}

	if err := uhidDev.Create(createCfg); err != nil {
		closeErr := uhidDev.Close()
		d.uhidDevice = nil
		return errors.Join(ErrFIDO2UHIDCreateFailed, err, closeErr)
	}

	d.logger.Info("virtual FIDO2 device created",
		slog.String("name", d.cfg.DeviceName),
		slog.String("serial", d.cfg.SerialNumber),
		slog.String("vendor_id", "0xF1D0"),
		slog.String("product_id", "0x0001"),
	)

	// Wire logger into HID handler for operational logging
	d.hidHandler.SetLogger(d.logger)

	// Set response handler to write HID packets back to UHID
	d.hidHandler.SetResponseHandler(func(packet []byte) {
		d.logger.Debug("sending HID response",
			slog.Int("length", len(packet)),
			slog.String("cid", formatCID(packet)),
			slog.String("cmd", formatCmd(packet)),
		)
		if err := d.uhidDevice.WriteInput(packet); err != nil {
			d.logger.Error("failed to write HID response",
				slog.String("error", err.Error()),
			)
		}
	})

	// Initialize supplementary subsystems (keyboard, password store, IPC).
	d.initSupplementarySubsystems(ctx)

	// Set read timeout for interruptibility
	uhidDev.SetReadTimeout(100 * time.Millisecond)

	// Run the event loop
	return d.eventLoop(ctx)
}

// cdpLoop runs the CDP bridge mode until the context is cancelled. There is no
// UHID device to poll; the Chrome virtual authenticator drives all ceremonies
// and credential capture happens asynchronously via credentialAdded events.
func (d *fido2Device) cdpLoop(ctx context.Context) error {
	d.logger.Info("starting CDP bridge loop")
	<-ctx.Done()
	d.logger.Info("context cancelled, stopping CDP bridge loop")
	return ctx.Err()
}

// initSupplementarySubsystems creates the virtual keyboard, opens the password
// store, and starts the IPC server. Failures in any subsystem are logged but
// do not prevent the FIDO2 device from operating.
func (d *fido2Device) initSupplementarySubsystems(ctx context.Context) {
	// Resolve the static password store: --password-store if set, otherwise
	// the same shared xkey data directory the `xkey password` commands
	// resolve to (go-xkms#929), so bare-touch typing reaches the store an
	// operator populated with `xkey password add` instead of a cwd-relative
	// default. Resolution failure only disables the password-store feature
	// below -- this method logs and continues for every subsystem it sets
	// up, never fails the daemon.
	if d.cfg.PasswordStorePath == "" {
		if resolved, err := featureDataDir(passwordStoreFeature); err != nil {
			d.logger.Warn("password store unavailable: could not resolve default store directory",
				slog.String("error", err.Error()))
		} else {
			d.cfg.PasswordStorePath = resolved
		}
	}

	// Create virtual keyboard for password typing (only when needed)
	if d.cfg.PasswordStorePath != "" || d.cfg.DefaultPassword != "" {
		kb, err := keyboard.New(d.logger)
		if err != nil {
			d.logger.Warn("virtual keyboard unavailable (password typing disabled)",
				slog.String("error", err.Error()))
		} else {
			d.keyboard = kb
		}
	}

	// Open password store
	if d.cfg.PasswordStorePath != "" {
		pwStore, err := openPasswordStore(d.cfg.PasswordStorePath)
		if err != nil {
			d.logger.Warn("password store unavailable",
				slog.String("error", err.Error()),
				slog.String("path", d.cfg.PasswordStorePath))
		} else {
			d.pwStore = pwStore
			d.logger.Info("password store opened",
				slog.String("path", d.cfg.PasswordStorePath))
		}
	}

	// Start IPC server. d.cfg.SocketPath is always resolved (never empty):
	// buildFIDO2Config sets it from resolvedSocketPath, the same function
	// every client command uses, so the daemon listens on exactly the socket
	// its clients will default to.
	socketPath := d.cfg.SocketPath

	ipcSrv, err := ipc.NewServer(socketPath, d, d.logger)
	if err != nil {
		d.logger.Warn("IPC server unavailable (touch command disabled)",
			slog.String("error", err.Error()))
	} else {
		d.ipcServer = ipcSrv
		go func() {
			if serveErr := ipcSrv.Serve(ctx); serveErr != nil && !errors.Is(serveErr, ipc.ErrServerClosed) {
				d.logger.Error("IPC server error",
					slog.String("error", serveErr.Error()))
			}
		}()
		d.logger.Info("IPC server started",
			slog.String("socket", socketPath))
	}

	// Start CDP bridge if enabled
	if d.cfg.CDPEnabled {
		cdpClient, err := cdp.NewClient(d.cfg.CDPHost, d.cfg.CDPPort, d.logger)
		if err != nil {
			d.logger.Warn("CDP bridge unavailable",
				slog.String("error", err.Error()),
				slog.String("host", d.cfg.CDPHost),
				slog.Int("port", d.cfg.CDPPort))
		} else {
			bridge := cdp.NewBridge(cdpClient, d.logger)
			// Register the durability sink BEFORE Start so credentialAdded
			// events are captured for the entire session. Credentials created
			// inside Chrome are persisted into xkey's --storage backend the
			// instant Chrome reports them, surviving process kill.
			bridge.SetCredentialSink(d.persistCapturedCredential)
			if err := bridge.Start(ctx); err != nil {
				d.logger.Warn("CDP bridge start failed",
					slog.String("error", err.Error()))
				if closeErr := cdpClient.Close(); closeErr != nil {
					d.logger.Warn("CDP client close failed", slog.String("error", closeErr.Error()))
				}
			} else {
				d.cdpBridge = bridge
				// Sync existing (including previously CDP-captured) credentials
				// into the Chrome virtual authenticator.
				d.syncCredentialsToCDP(ctx)
			}
		}
	}
}

// HandleTouch implements ipc.Handler. It approves a pending WebAuthn user
// presence request if one exists. If no request is pending and a default
// password is configured, it types the default password via the virtual
// keyboard.
func (d *fido2Device) HandleTouch() (*ipc.Response, error) {
	// Check if a WebAuthn UP request is pending
	if d.socketHandler != nil && d.socketHandler.HasPending() {
		d.socketHandler.Approve()
		return ipc.OKResponse(ipc.ActionApprovedUP), nil
	}

	// Type default password if configured
	if d.defaultPassword != "" {
		return d.HandleTypePassword(d.defaultPassword)
	}

	return ipc.OKResponse(ipc.ActionNoPending), nil
}

// HandleTypePassword implements ipc.Handler. It retrieves a named password
// from the static password store and types it through the virtual keyboard.
func (d *fido2Device) HandleTypePassword(name string) (*ipc.Response, error) {
	if d.pwStore == nil {
		return nil, ErrFIDO2PasswordStoreUnavailable
	}
	if d.keyboard == nil {
		return nil, ErrFIDO2KeyboardUnavailable
	}

	pw, err := d.pwStore.Get(name)
	if err != nil {
		return nil, err
	}

	if err := d.keyboard.TypeString(pw.Password); err != nil {
		return nil, err
	}

	return ipc.OKResponse(ipc.ActionTypedPassword), nil
}

// HandleStatus implements ipc.Handler. It returns the daemon ready status.
func (d *fido2Device) HandleStatus() (*ipc.Response, error) {
	resp := ipc.OKResponse(ipc.ActionDaemonReady)
	resp.Storage = d.describeStorage()
	return resp, nil
}

// describeStorage reports which credential store this daemon is using.
//
// A caller cannot work this out from the filesystem: the barrier and file
// layouts compose to the same path — the barrier backend is rooted at the data
// directory with a "fido2/xkey/" key prefix, the file backend at
// <dataDir>/fido2 with an "xkey/" prefix — so the same file name holds either
// an encrypted record or a plaintext one depending on how the daemon was
// started. Only the daemon knows which.
func (d *fido2Device) describeStorage() *ipc.StorageResult {
	if d.cfg == nil {
		return nil
	}

	switch d.cfg.StorageType {
	case FIDO2StorageTypeBarrier:
		return &ipc.StorageResult{
			Type:            string(FIDO2StorageTypeBarrier),
			Path:            d.cfg.StoragePath,
			Prefix:          fido2BarrierKeyPrefix,
			EncryptedAtRest: true,
		}
	case FIDO2StorageTypeFile:
		return &ipc.StorageResult{
			Type:            string(FIDO2StorageTypeFile),
			Path:            d.cfg.StoragePath,
			Prefix:          fido2FileKeyPrefix,
			EncryptedAtRest: false,
		}
	case FIDO2StorageTypeMemory:
		return &ipc.StorageResult{
			Type:            string(FIDO2StorageTypeMemory),
			EncryptedAtRest: false,
		}
	default:
		return &ipc.StorageResult{Type: string(d.cfg.StorageType)}
	}
}

// Compile-time check that fido2Device implements ipc.Handler.
var _ ipc.Handler = (*fido2Device)(nil)

// eventLoop processes incoming HID packets until the context is cancelled.
func (d *fido2Device) eventLoop(ctx context.Context) error {
	d.logger.Info("starting FIDO2 HID event loop")

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("context cancelled, stopping event loop")
			return ctx.Err()
		default:
			// Read 64-byte HID packet from UHID
			packet, err := d.uhidDevice.ReadOutput()
			if err != nil {
				// Handle timeout - this is expected for polling
				if errors.Is(err, uhid.ErrTimeout) {
					continue
				}

				// Handle device closed
				if errors.Is(err, uhid.ErrDeviceNotOpen) {
					d.logger.Info("UHID device closed, stopping event loop")
					return nil
				}

				d.logger.Error("failed to read HID packet",
					slog.String("error", err.Error()),
				)
				continue
			}

			// Ensure we have a complete HID packet (64 bytes)
			if len(packet) < authenticator.HIDPacketSize {
				d.logger.Warn("received incomplete HID packet",
					slog.Int("length", len(packet)),
					slog.Int("expected", authenticator.HIDPacketSize),
				)
				continue
			}

			// Log received packet for debugging
			d.logger.Debug("received HID packet",
				slog.Int("length", len(packet)),
				slog.String("cid", formatCID(packet)),
				slog.String("cmd_or_seq", formatCmd(packet)),
			)

			// Process the HID packet through the CTAP-HID handler
			d.hidHandler.HandleMessage(packet)
		}
	}
}

// Close stops the device and releases all resources in reverse initialization
// order: IPC server, keyboard, password store, notifier, then core FIDO2
// components.
func (d *fido2Device) Close() error {
	var errs []error

	// Close CDP bridge
	if d.cdpBridge != nil {
		d.logger.Info("closing CDP bridge")
		if err := d.cdpBridge.Close(); err != nil {
			errs = append(errs, err)
		}
		d.cdpBridge = nil
	}

	// Close IPC server first (stops accepting new touch commands)
	if d.ipcServer != nil {
		d.logger.Info("closing IPC server")
		if err := d.ipcServer.Close(); err != nil {
			errs = append(errs, err)
		}
		d.ipcServer = nil
	}

	// Close virtual keyboard
	if d.keyboard != nil {
		d.logger.Info("closing virtual keyboard")
		if err := d.keyboard.Close(); err != nil {
			errs = append(errs, err)
		}
		d.keyboard = nil
	}

	// Close password store
	if d.pwStore != nil {
		d.logger.Info("closing password store")
		if err := d.pwStore.Close(); err != nil {
			errs = append(errs, err)
		}
		d.pwStore = nil
	}

	// Close notifier
	if d.notifier != nil {
		d.logger.Info("closing notifier")
		if err := d.notifier.Close(); err != nil {
			errs = append(errs, err)
		}
		d.notifier = nil
	}

	// Close the CTAP-HID handler
	if d.hidHandler != nil {
		if err := d.hidHandler.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Close the UHID device
	if d.uhidDevice != nil {
		d.logger.Info("closing UHID device")
		if err := d.uhidDevice.Close(); err != nil {
			errs = append(errs, err)
		}
		d.uhidDevice = nil
	}

	// Close the authenticator (also saves state and closes key backend)
	if d.auth != nil {
		d.logger.Info("closing authenticator")
		if err := d.auth.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// persistCapturedCredential is the cdp.CredentialSink. It maps a credential
// created inside the Chrome virtual authenticator into xkey's StoredCredential
// model and persists it to the configured --storage backend so the key
// survives the CDP session and is re-synced into Chrome on the next start.
func (d *fido2Device) persistCapturedCredential(cred cdp.StoredCredential) error {
	if d.storage == nil {
		return ErrFIDO2CDPCaptureNoStorage
	}

	// CDP encodes WebAuthn.Credential binary fields (credentialId, privateKey,
	// userHandle) as standard base64 (RFC 4648 section 4, with padding), NOT
	// base64url. Decode with the standard alphabet so credential IDs containing
	// '+' or '/' (e.g. "T4Gj/Bom...") are accepted.
	credID, err := decodeCDPField(cred.CredentialID)
	if err != nil {
		return errors.Join(ErrFIDO2CDPCaptureDecodeFailed, err)
	}

	encodedKey, err := cred.PrivateKey()
	if err != nil {
		return errors.Join(ErrFIDO2CDPCaptureDecodeFailed, err)
	}
	defer secure.Wipe(encodedKey)
	pkcs8Key, err := decodeCDPSecret(encodedKey)
	if err != nil {
		return errors.Join(ErrFIDO2CDPCaptureDecodeFailed, err)
	}
	defer secure.Wipe(pkcs8Key)

	var userID []byte
	if cred.UserHandle != "" {
		userID, err = decodeCDPField(cred.UserHandle)
		if err != nil {
			return errors.Join(ErrFIDO2CDPCaptureDecodeFailed, err)
		}
	}

	algorithm, publicKeyCOSE, err := deriveCOSEFromPKCS8(pkcs8Key)
	if err != nil {
		return errors.Join(ErrFIDO2CDPCaptureDecodeFailed, err)
	}

	stored := &authenticator.StoredCredential{
		CredentialID:  credID,
		RPID:          cred.RpID,
		UserID:        userID,
		PublicKeyCOSE: publicKeyCOSE,
		Algorithm:     algorithm,
		SignCount:     uint32(cred.SignCount),
		Discoverable:  cred.IsResidentCredential,
	}
	if err := stored.SetPrivateKey(pkcs8Key); err != nil {
		return errors.Join(ErrFIDO2CDPCaptureDecodeFailed, err)
	}

	if err := d.storage.Store(stored); err != nil {
		// A credential created in a prior session is re-reported on re-sync;
		// treat an existing-credential collision as a successful no-op.
		if errors.Is(err, authenticator.ErrCredentialExists) {
			return nil
		}
		return errors.Join(ErrFIDO2CDPCapturePersistFailed, err)
	}

	return nil
}

// decodeCDPField decodes a binary field as carried on the Chrome DevTools
// Protocol WebAuthn wire. CDP uses standard base64 (RFC 4648 section 4) with
// padding for credentialId, privateKey, userHandle, rpIdHash, and largeBlob.
// The padded form is the documented encoding; the unpadded standard form is
// also accepted so a stray missing pad does not drop a captured credential.
func decodeCDPField(s string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// decodeCDPSecret is decodeCDPField for a secret field such as the private
// key: it decodes straight from bytes into a slice the caller owns and wipes,
// so the key never becomes a Go string. It accepts the same padded and
// unpadded standard forms.
func decodeCDPSecret(field []byte) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		out := make([]byte, enc.DecodedLen(len(field)))
		n, err := enc.Decode(out, field)
		if err == nil {
			return out[:n], nil
		}
		secure.Wipe(out)
	}
	return nil, base64.CorruptInputError(0)
}

// encodeCDPSecret is encodeCDPField for a secret field: the standard padded
// base64 of raw as bytes the caller owns and wipes.
func encodeCDPSecret(raw []byte) []byte {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(out, raw)
	return out
}

// encodeCDPField encodes raw bytes for transmission on the Chrome DevTools
// Protocol WebAuthn wire, which expects standard base64 (RFC 4648 section 4)
// with padding. It is the inverse of decodeCDPField and is used when xkey
// re-syncs its stored credentials into the Chrome virtual authenticator.
func encodeCDPField(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// deriveCOSEFromPKCS8 parses a PKCS#8 private key and returns the COSE
// algorithm identifier and COSE-encoded public key for the corresponding
// public key. Only the EC and Ed25519 algorithms supported by FIDO2 are
// recognized.
func deriveCOSEFromPKCS8(pkcs8Key []byte) (int, []byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(pkcs8Key)
	if err != nil {
		return 0, nil, errors.Join(ErrFIDO2CDPCaptureKeyParseFailed, err)
	}

	var pub crypto.PublicKey
	var algorithm int

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
		switch k.Curve {
		case elliptic.P256():
			algorithm = keybackend.COSEAlgES256
		case elliptic.P384():
			algorithm = keybackend.COSEAlgES384
		case elliptic.P521():
			algorithm = keybackend.COSEAlgES512
		default:
			return 0, nil, ErrFIDO2CDPCaptureUnsupportedKey
		}
	case ed25519.PrivateKey:
		pub = k.Public()
		algorithm = keybackend.COSEAlgEdDSA
	default:
		return 0, nil, ErrFIDO2CDPCaptureUnsupportedKey
	}

	cose, err := keybackend.EncodeCOSEPublicKey(pub, algorithm)
	if err != nil {
		return 0, nil, err
	}

	return algorithm, cose, nil
}

// credentialSyncer registers stored credentials with a virtual authenticator.
// *cdp.Bridge satisfies it; an interface seam keeps the sync logic testable
// without a live Chrome connection.
type credentialSyncer interface {
	SyncCredentials(ctx context.Context, creds []cdp.StoredCredential) error
}

// syncCredentialsToCDP loads all credentials from storage and registers them
// with the CDP virtual authenticator.
func (d *fido2Device) syncCredentialsToCDP(ctx context.Context) {
	if d.cdpBridge == nil {
		return
	}
	d.syncCredentialsToCDPVia(ctx, d.cdpBridge)
}

// syncCredentialsToCDPVia performs the storage enumeration and credential
// mapping against the supplied syncer.
func (d *fido2Device) syncCredentialsToCDPVia(ctx context.Context, syncer credentialSyncer) {
	if d.storage == nil {
		return
	}

	// Use ListableStorage to enumerate all credential IDs.
	listable, ok := d.storage.(authenticator.ListableStorage)
	if !ok {
		d.logger.Warn("storage does not support ListAll, skipping CDP sync")
		return
	}

	credIDs, err := listable.ListAll()
	if err != nil {
		d.logger.Warn("failed to list credentials for CDP sync",
			slog.String("error", err.Error()))
		return
	}

	var cdpCreds []cdp.StoredCredential
	for _, credID := range credIDs {
		sc, loadErr := d.storage.Load(credID)
		if loadErr != nil {
			d.logger.Debug("skipping credential for CDP (load failed)",
				slog.String("credId", fmt.Sprintf("%x", credID)))
			continue
		}

		// Prefer the PKCS#8 key persisted alongside the credential. CDP-captured
		// credentials store their private key inline here (the key backend never
		// generated them). Fall back to the key backend's exporter for
		// credentials minted by xkey's own software backend.
		var pkcs8Key []byte
		switch {
		case sc.HasPrivateKey():
			pkcs8Key = sc.PrivateKeyBytes()
		case d.keyBackend != nil:
			handle, loadKeyErr := d.keyBackend.LoadKey(sc.CredentialID, sc.Algorithm)
			if loadKeyErr != nil {
				d.logger.Debug("skipping credential for CDP (key load failed)",
					slog.String("credId", fmt.Sprintf("%x", sc.CredentialID)))
				continue
			}

			exported, exportErr := d.keyBackend.ExportPrivateKey(handle)
			if exportErr != nil {
				d.logger.Debug("skipping credential for CDP (export not supported)",
					slog.String("credId", fmt.Sprintf("%x", sc.CredentialID)))
				continue
			}
			pkcs8Key = exported
		default:
			d.logger.Debug("skipping credential for CDP (no inline key and no key backend)",
				slog.String("credId", fmt.Sprintf("%x", sc.CredentialID)))
			continue
		}

		// CDP expects standard base64 (with padding) for the binary credential
		// fields; encode with the standard alphabet so the round-trip matches
		// what Chrome accepts on WebAuthn.addCredential.
		cdpCred := cdp.StoredCredential{
			CredentialID:         encodeCDPField(sc.CredentialID),
			IsResidentCredential: sc.Discoverable,
			RpID:                 sc.RPID,
			UserHandle:           encodeCDPField(sc.UserID),
			SignCount:            int(sc.SignCount),
		}
		encodedKey := encodeCDPSecret(pkcs8Key)
		setErr := cdpCred.SetPrivateKey(encodedKey)
		secure.Wipe(encodedKey)
		if err := setErr; err != nil {
			secure.Wipe(pkcs8Key)
			d.logger.Debug("skipping credential for CDP (protect failed)",
				slog.String("credId", fmt.Sprintf("%x", sc.CredentialID)))
			continue
		}
		secure.Wipe(pkcs8Key)
		cdpCreds = append(cdpCreds, cdpCred)
	}

	if len(cdpCreds) > 0 {
		if err := syncer.SyncCredentials(ctx, cdpCreds); err != nil {
			d.logger.Warn("CDP credential sync failed",
				slog.String("error", err.Error()))
		}
	}

	d.logger.Info("CDP credential sync complete",
		slog.Int("total", len(credIDs)),
		slog.Int("synced", len(cdpCreds)))
}

// resolveFIDO2StoragePath returns cfg.StoragePath if the operator set one
// (--storage-path, or the fido2.storage_path config key), otherwise resolves
// the FIDO2 file-storage default through the CLI's single data-directory
// chain (datadir.go): XKEY_HOME, XKEY_DATA_DIR, the config data_dir key, or
// ~/.xkey/data, creating it if necessary. Every file-backed FIDO2 consumer
// -- credential storage (createFIDO2Storage), the RP policy store
// (createFIDO2RPPolicyStore), and the profile store (fido2ProfileStorePath)
// -- resolves through this one function so a missing --storage-path lands
// them all in the same directory instead of a cwd-relative default
// (go-xkms#929). cfg.StoragePath is updated with the resolved value so
// later readers (describeStorage, status output) observe the same path
// without re-resolving.
func resolveFIDO2StoragePath(cfg *FIDO2Config) (string, error) {
	if cfg.StoragePath != "" {
		return cfg.StoragePath, nil
	}
	dir, err := featureDataDir("fido2")
	if err != nil {
		return "", err
	}
	cfg.StoragePath = dir
	return dir, nil
}

// createFIDO2Storage creates the appropriate storage backend based on configuration.
func createFIDO2Storage(cfg *FIDO2Config, logger *slog.Logger) (authenticator.StatefulCredentialStorage, error) {
	switch cfg.StorageType {
	case FIDO2StorageTypeMemory:
		return authenticator.NewMemoryStorage(), nil

	case FIDO2StorageTypeFile:
		storagePath, err := resolveFIDO2StoragePath(cfg)
		if err != nil {
			return nil, err
		}
		backend, err := xkms.NewFileStorageBackend(storagePath)
		if err != nil {
			return nil, err
		}

		storage, err := authenticator.NewBackendStorage(backend, fido2FileKeyPrefix)
		if err != nil {
			return nil, errors.Join(err, backend.Close())
		}

		// go-qrdb's barrier is the only at-rest encryption in this stack;
		// this file store has none. Warn once per store open rather than
		// refusing or silently falling back.
		logger.Warn("passkey store is unencrypted at rest: private keys are stored in plaintext",
			slog.String("path", cfg.StoragePath),
			slog.String("remedy", "run 'xkey barrier init' to encrypt the passkey store"))

		return storage, nil

	case FIDO2StorageTypeBarrier:
		return createBarrierStorage(cfg)

	default:
		return nil, ErrFIDO2InvalidStorageType
	}
}

// createBarrierStorage creates barrier-encrypted storage that reads the same
// FIDO2 credentials as the GUI. It resolves the xkey home directory and
// unseals the barrier through openBarrierBackend (barrier_store.go), the
// same low-level unseal the oath/backup/device-sync commands use: a
// tpm2-strategy barrier tries PCR-policy auto-unseal first (see `xkey
// policy set-auto-unseal`), then a direct TPM unseal using cfg.TPMDevice;
// every other strategy uses the password resolved below.
func createBarrierStorage(cfg *FIDO2Config) (authenticator.StatefulCredentialStorage, error) {
	// Resolve xkey home and data directory.
	home, err := xhome.Resolve()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrFIDO2BarrierUnsealFailed, Cause: err}
	}
	dataDir, err := home.EnsureDataDir()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrFIDO2BarrierUnsealFailed, Cause: err}
	}

	// Resolve barrier password.
	password := cfg.BarrierPassword
	if password == "" && cfg.BarrierPasswordFile != "" {
		raw, readErr := os.ReadFile(cfg.BarrierPasswordFile)
		if readErr != nil {
			return nil, &SentinelCauseError{Sentinel: ErrFIDO2BarrierPasswordRequired, Cause: readErr}
		}
		password = strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	}

	barrierBackend, err := openBarrierBackend(password, dataDir, cfg.TPMDevice, false)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrFIDO2BarrierUnsealFailed, Cause: err}
	}

	// Create FIDO2 credential storage using the barrier backend.
	// Prefix "fido2/xkey/" matches the GUI's storage namespace.
	storage, err := authenticator.NewBackendStorage(barrierBackend, fido2BarrierKeyPrefix)
	if err != nil {
		return nil, err
	}

	return storage, nil
}

// createFIDO2UserPresenceHandler creates the appropriate user presence handler.
// In interactive mode, it returns an InteractiveHandler for terminal prompts.
// In non-interactive mode, it creates a SocketHandler backed by a notifier for
// IPC-based approval via the touch command. The auto-grant handler remains
// available for testing scenarios where PIN is pre-configured.
func createFIDO2UserPresenceHandler(cfg *FIDO2Config, logger *slog.Logger) (authenticator.UserPresenceHandler, *authenticator.SocketHandler, notify.Notifier, error) {
	if cfg.Interactive {
		logger.Info("using interactive user presence handler")
		handler, err := authenticator.NewInteractiveHandler()
		if err != nil {
			return nil, nil, nil, err
		}
		return handler, nil, nil, nil
	}

	// Default: socket-based handler for daemon mode
	logger.Info("using socket-based user presence handler")
	notifier, err := createNotifier(cfg, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	socketHandler := authenticator.NewSocketHandler(notifier, logger)
	return socketHandler, socketHandler, notifier, nil
}

// createNotifier builds a notifier based on the configured notification type.
//
// Supported notification types (--notify-type flag):
//   - "dialog": Interactive zenity dialog with Approve/Deny buttons (default)
//   - "passive": Passive desktop notification via notify-send
//   - "log": Log-only, no desktop notification
//   - "none": No notifications at all
//
// When running as root via sudo, notifications are sent as the original user.
// The --notify-command flag overrides all built-in notification types.
func createNotifier(cfg *FIDO2Config, logger *slog.Logger) (notify.Notifier, error) {
	var notifiers []notify.Notifier

	// Handle "none" - no notifications at all
	if cfg.NotifyType == "none" {
		logger.Info("notifications disabled")
		return notify.NewMultiNotifier(), nil // Empty notifier
	}

	// Always add log notifier for "log" type or as fallback
	if cfg.NotifyType == "log" {
		logger.Info("using log-only notifications")
		return notify.NewLogNotifier(logger), nil
	}

	// Add log notifier as baseline for other types
	notifiers = append(notifiers, notify.NewLogNotifier(logger))

	// Custom command overrides everything
	if cfg.NotifyCommand != "" {
		cmdNotifier, err := notify.NewCommandNotifier(cfg.NotifyCommand, logger)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrFIDO2InvalidNotifyCommand, Cause: err}
		}
		logger.Info("using custom notification command")
		notifiers = append(notifiers, cmdNotifier)
		return notify.NewMultiNotifier(notifiers...), nil
	}

	// Determine if running as root via sudo
	isRootViaSudo := os.Getuid() == 0 && os.Getenv("SUDO_USER") != ""
	sudoUser := os.Getenv("SUDO_USER")
	sudoUID := os.Getenv("SUDO_UID")

	// Socket path for dialog mode. cfg.SocketPath is always resolved by
	// resolvedSocketPath, which under sudo already derives the invoking
	// user's per-user socket (see ipc.DefaultSocketPath).
	socketPath := cfg.SocketPath

	// Get the current executable path for self-invocation
	execPath, err := os.Executable()
	if err != nil {
		execPath = "xkey" // Fallback to PATH lookup
	}

	switch cfg.NotifyType {
	case "dialog":
		if isRootViaSudo {
			// Interactive zenity dialog that runs the xkey touch command on
			// approval. Both steps run directly via runuser -- neither is
			// ever handed to a shell, so nothing in the request (operation,
			// RP ID, user name) can be interpreted as shell syntax. See
			// sudoDialogNotifier and buildSudoDialogArgv.
			logger.Info("using zenity dialog notifications (root via sudo)",
				slog.String("sudo_user", sudoUser),
				slog.String("socket_path", socketPath))
			notifiers = append(notifiers, newSudoDialogNotifier(sudoUser, execPath, socketPath, defaultFIDO2Timeout, logger))
		} else {
			// Non-root: try D-Bus, fall back to zenity
			dbusNotifier, err := notify.NewDBusNotifier(logger)
			if err == nil {
				logger.Info("using D-Bus notifications")
				notifiers = append(notifiers, dbusNotifier)
			} else {
				logger.Warn("D-Bus unavailable, falling back to log-only",
					slog.String("error", err.Error()))
			}
		}

	case "passive":
		if isRootViaSudo {
			// Passive notification via notify-send (no interaction), run
			// directly via runuser -- no shell is involved. See
			// sudoPassiveNotifier and buildSudoPassiveArgv.
			logger.Info("using notify-send notifications (root via sudo)",
				slog.String("sudo_user", sudoUser))
			notifiers = append(notifiers, newSudoPassiveNotifier(sudoUser, sudoUID, logger))
		} else {
			// Non-root: use D-Bus directly
			dbusNotifier, err := notify.NewDBusNotifier(logger)
			if err == nil {
				logger.Info("using D-Bus notifications")
				notifiers = append(notifiers, dbusNotifier)
			} else {
				logger.Warn("D-Bus unavailable, falling back to log-only",
					slog.String("error", err.Error()))
			}
		}

	default:
		logger.Warn("unknown notify-type, using log-only",
			slog.String("notify_type", cfg.NotifyType))
	}

	return notify.NewMultiNotifier(notifiers...), nil
}

// createFIDO2KeyBackend creates the appropriate key backend based on config.
// It wraps existing go-xkms backends with keybackend.NewBackendAdapter, which
// translates between FIDO2 credential IDs / COSE algorithms and go-xkms
// KeyAttributes. This eliminates the need for per-backend FIDO2 implementations.
func createFIDO2KeyBackend(cfg *FIDO2Config, logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	switch cfg.Backend {
	case "tpm2":
		return createFIDO2TPM2KeyBackend(cfg, logger)
	case "phone":
		return createFIDO2PhoneKeyBackend(cfg, logger)
	case "software":
		return createFIDO2SoftwareKeyBackend(cfg, logger)
	default:
		// Refuse rather than degrade. FIDO2Config.Validate accepts exactly the
		// three names above and runs immediately before this call, so this
		// branch is unreachable today -- but it previously answered an
		// unrecognised backend with software keys, so adding a name to
		// Validate's enum without adding a case here would have silently
		// downgraded key custody from hardware to software (#313).
		return nil, ErrFIDO2InvalidBackend
	}
}

// createFIDO2SoftwareKeyBackend creates a software-backed FIDO2 key backend.
// When barrier storage is active, it initializes the xkms service with the
// same data directory as the GUI ({dataDir}/keys), gets the software backend
// from xkms, and wraps its KeyProvider with BackendAdapter — exactly matching
// the GUI's FIDO2 key backend architecture. Otherwise it creates a standalone
// software backend with volatile memory storage.
func createFIDO2SoftwareKeyBackend(cfg *FIDO2Config, logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	logger.Info("using software key backend")

	if cfg.StorageType == FIDO2StorageTypeBarrier {
		return createFIDO2XKMSSoftwareKeyBackend(cfg, logger)
	}

	keyStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	backend, err := xkms.NewSoftwareBackend(&xkms.SoftwareBackendConfig{
		KeyStorage: keyStorage,
	})
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	return keybackend.NewBackendAdapter(backend, xkms.BackendTypeSoftware), nil
}

// createFIDO2XKMSSoftwareKeyBackend initializes the xkms service and creates
// a FIDO2 key backend from the xkms software backend, matching the GUI's
// architecture. The xkms service manages the software key storage under the
// SAME barrier-backed store the GUI's initLocalKeyStore uses (under
// "keys/"), ensuring CLI and GUI share the same key store and the same
// encryption-at-rest guarantee. This function is only reached when the
// caller explicitly selected barrier storage (cfg.StorageType ==
// FIDO2StorageTypeBarrier, see createFIDO2SoftwareKeyBackend), so it never
// falls back to a plain, unencrypted file store: it unseals the barrier via
// openBarrierBackend, the same low-level unseal createBarrierStorage (the
// FIDO2 credential store's barrier path) and every other barrier-aware CLI
// command (oath, backup, device oath-sync) share.
func createFIDO2XKMSSoftwareKeyBackend(cfg *FIDO2Config, logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	home, err := xhome.Resolve()
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}
	dataDir, err := home.EnsureDataDir()
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	// Resolve barrier password exactly as createBarrierStorage does.
	password := cfg.BarrierPassword
	if password == "" && cfg.BarrierPasswordFile != "" {
		raw, readErr := os.ReadFile(cfg.BarrierPasswordFile)
		if readErr != nil {
			return nil, &SentinelCauseError{Sentinel: ErrFIDO2BarrierPasswordRequired, Cause: readErr}
		}
		password = strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	}

	barrierBackend, err := openBarrierBackend(password, dataDir, cfg.TPMDevice, false)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrFIDO2BarrierUnsealFailed, Cause: err}
	}

	keyStorage, err := xkms.NewStoragePrefixBackend(barrierBackend, "keys/")
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	xkms.Reset()
	if err := xkms.AutoInitialize(&xkms.AutoConfig{
		Datastore:      keyStorage,
		DefaultBackend: "software",
	}); err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	swBackend, err := xkms.GetBackend("software")
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	adapter := keybackend.NewBackendAdapter(swBackend.KeyProvider(), xkms.BackendTypeSoftware)
	adapter.SetLogger(logger)

	logger.Info("xkms software key backend initialized over the barrier-backed datastore")

	return adapter, nil
}

// createFIDO2TPM2KeyBackend creates a TPM2-backed FIDO2 key backend by wrapping
// the go-xkms TPM2 backend with BackendAdapter.
func createFIDO2TPM2KeyBackend(cfg *FIDO2Config, logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	logger.Info("opening TPM device", slog.String("device", cfg.TPMDevice))

	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Config: &xkms.TPMConfig{
			Device: cfg.TPMDevice,
		},
		Logger: logger,
	})
	if err != nil {
		return nil, errors.Join(ErrFIDO2TPMOpenFailed, err)
	}

	memStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		return nil, errors.Join(ErrFIDO2TPMBackendCreationFailed, err, tpm.Close())
	}
	keyBackend := xkms.NewFileBackend(logger, memStorage)

	backend, err := xkms.NewTPM2BackendWithTPM(&xkms.TPM2BackendExternalConfig{
		TPM:        tpm,
		KeyBackend: keyBackend,
		Logger:     logger,
	})
	if err != nil {
		return nil, errors.Join(ErrFIDO2TPMBackendCreationFailed, err, tpm.Close())
	}

	logger.Info("using TPM2 key backend", slog.String("device", cfg.TPMDevice))

	// The TPM2 backend attests in hardware: it certifies each credential key
	// with TPM2_Certify under the device's own Initial Attestation Key, rather
	// than delegating to the generic software device-attestation identity
	// NewAuthenticator wraps every other backend with. Wrapping here, not
	// there, is what lets NewAuthenticator tell the two apart (see
	// FIDO2AttestingKeyBackend's doc comment).
	adapter := keybackend.NewBackendAdapter(backend, xkms.BackendTypeTPM2)
	return keybackend.NewTPM2AttestingBackend(adapter, tpm, keyBackend), nil
}

// formatCID formats a channel ID from a HID packet for logging.
func formatCID(packet []byte) string {
	if len(packet) < 4 {
		return "0x00000000"
	}
	return fmt.Sprintf("0x%08X",
		uint32(packet[0])<<24|uint32(packet[1])<<16|uint32(packet[2])<<8|uint32(packet[3]))
}

// formatCmd formats a command byte from a HID packet for logging.
func formatCmd(packet []byte) string {
	if len(packet) < 5 {
		return "0x00"
	}
	return fmt.Sprintf("0x%02X", packet[4])
}
