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
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	softwarebackend "github.com/jeremyhahn/go-xkms/pkg/backend/software"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
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

	// ErrFIDO2InvalidAttestationFormat indicates an unsupported attestation format.
	ErrFIDO2InvalidAttestationFormat = errors.New("fido2: invalid attestation format (must be 'none', 'packed', or 'tpm')")

	// ErrFIDO2TPMAttestationRequiresTPMBackend indicates TPM attestation requires tpm2 backend.
	ErrFIDO2TPMAttestationRequiresTPMBackend = errors.New("fido2: TPM attestation requires tpm2 backend")

	// ErrFIDO2SetPINRequiresPINEnabled indicates --set-pin requires --pin to be enabled.
	ErrFIDO2SetPINRequiresPINEnabled = errors.New("fido2: --set-pin requires --pin to be enabled")

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

// Default FIDO2 configuration values.
const (
	defaultFIDO2DeviceName  = "xKey (go-xkms)"
	defaultFIDO2StoragePath = "./data"
	defaultFIDO2Backend     = "software"
	defaultFIDO2TPMDevice   = "/dev/tpmrm0"
	defaultFIDO2Attestation = "none"
	defaultFIDO2Timeout     = 30 * time.Second
	defaultFIDO2StorageType = "memory"
)

// FIDO2Config holds the configuration for the virtual FIDO2 device.
type FIDO2Config struct {
	// Storage configuration
	StorageType     FIDO2StorageType
	StoragePath     string
	BarrierPassword     string
	BarrierPasswordFile string

	// Device configuration
	DeviceName   string
	SerialNumber string

	// PIN configuration
	EnablePIN bool
	PIN       string

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

	// Password and IPC configuration
	PasswordStorePath string
	SocketPath        string
	DefaultPassword   string
	NotifyCommand     string
	NotifyType        string // "dialog", "passive", "log", or "none"

	// Unified PIN configuration
	UnifiedPIN bool

	// AutoUV enables built-in user verification so Chrome skips its PIN dialog.
	// Activated by either: (a) global auto-unseal config, or (b) --auto-uv CLI flag.
	AutoUV bool

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
	if c.PIN != "" && !c.EnablePIN {
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
  sudo xkey fido2 --pin --set-pin 123456 --interactive

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

  # Run with custom notification command
  sudo xkey fido2 --notify-command "notify-send xKey '%o for %r'"

Configuration can also be set via environment variables (XKEY_FIDO2_*) or
config file. Command-line flags take precedence over environment variables,
which take precedence over config file values.`,
	RunE: runFIDO2,
}

func init() {
	// Register command with root
	RootCmd.AddCommand(fido2Cmd)

	// Storage configuration flags
	fido2Cmd.Flags().String("storage", defaultFIDO2StorageType,
		"Storage type: memory, file, or barrier")
	fido2Cmd.Flags().String("storage-path", defaultFIDO2StoragePath,
		"Path for file storage")
	fido2Cmd.Flags().String("barrier-password", "",
		"Barrier password for encrypted storage")
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
	fido2Cmd.Flags().String("set-pin", "",
		"Set initial PIN (requires --pin)")

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
	fido2Cmd.Flags().String("password-store", defaultPasswordStorePath,
		"Path to static password store")
	fido2Cmd.Flags().String("socket", "",
		"IPC socket path (default: $XDG_RUNTIME_DIR/xkey/xkey.sock)")
	fido2Cmd.Flags().String("default-password", "",
		"Password name to type on bare touch")
	fido2Cmd.Flags().String("notify-command", "",
		"Custom notification command (overrides built-in notifications)")
	fido2Cmd.Flags().String("notify", "dialog",
		"Notification type: dialog (interactive), passive (desktop notification), log (log-only), or none")

	// Unified PIN flag
	fido2Cmd.Flags().Bool("unified-pin", true,
		"Enable unified PIN synchronization across FIDO2, PKCS#11, and file PIN systems")

	// CDP bridge flags
	fido2Cmd.Flags().Bool("auto-uv", false,
		"Report built-in user verification so Chrome skips its PIN dialog")
	fido2Cmd.Flags().Bool("cdp", false, "Enable Chrome DevTools virtual authenticator bridge")
	fido2Cmd.Flags().String("cdp-host", "localhost", "Chrome DevTools host")
	fido2Cmd.Flags().Int("cdp-port", 9222, "Chrome DevTools debugging port")

	// Bind flags to viper for unified configuration access
	_ = viper.BindPFlag("fido2.storage", fido2Cmd.Flags().Lookup("storage"))
	_ = viper.BindPFlag("fido2.storage_path", fido2Cmd.Flags().Lookup("storage-path"))
	_ = viper.BindPFlag("fido2.barrier_password", fido2Cmd.Flags().Lookup("barrier-password"))
	_ = viper.BindPFlag("fido2.barrier_password_file", fido2Cmd.Flags().Lookup("barrier-password-file"))
	_ = viper.BindPFlag("fido2.name", fido2Cmd.Flags().Lookup("name"))
	_ = viper.BindPFlag("fido2.serial", fido2Cmd.Flags().Lookup("serial"))
	_ = viper.BindPFlag("fido2.pin", fido2Cmd.Flags().Lookup("pin"))
	_ = viper.BindPFlag("fido2.set_pin", fido2Cmd.Flags().Lookup("set-pin"))
	_ = viper.BindPFlag("fido2.interactive", fido2Cmd.Flags().Lookup("interactive"))
	_ = viper.BindPFlag("fido2.require_touch", fido2Cmd.Flags().Lookup("require-touch"))
	_ = viper.BindPFlag("fido2.timeout", fido2Cmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("fido2.backend", fido2Cmd.Flags().Lookup("backend"))
	_ = viper.BindPFlag("fido2.tpm_device", fido2Cmd.Flags().Lookup("tpm-device"))
	_ = viper.BindPFlag("fido2.attestation", fido2Cmd.Flags().Lookup("attestation"))
	_ = viper.BindPFlag("fido2.phone_device", fido2Cmd.Flags().Lookup("phone-device"))
	_ = viper.BindPFlag("fido2.password_store", fido2Cmd.Flags().Lookup("password-store"))
	_ = viper.BindPFlag("fido2.socket", fido2Cmd.Flags().Lookup("socket"))
	_ = viper.BindPFlag("fido2.default_password", fido2Cmd.Flags().Lookup("default-password"))
	_ = viper.BindPFlag("fido2.notify_command", fido2Cmd.Flags().Lookup("notify-command"))
	_ = viper.BindPFlag("fido2.notify", fido2Cmd.Flags().Lookup("notify"))
	_ = viper.BindPFlag("fido2.unified_pin", fido2Cmd.Flags().Lookup("unified-pin"))
	_ = viper.BindPFlag("fido2.auto_uv", fido2Cmd.Flags().Lookup("auto-uv"))
	_ = viper.BindPFlag("fido2.cdp", fido2Cmd.Flags().Lookup("cdp"))
	_ = viper.BindPFlag("fido2.cdp_host", fido2Cmd.Flags().Lookup("cdp-host"))
	_ = viper.BindPFlag("fido2.cdp_port", fido2Cmd.Flags().Lookup("cdp-port"))
}

// runFIDO2 executes the FIDO2 virtual device command.
func runFIDO2(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// Build configuration from Viper (merges flags, env vars, config file)
	cfg := buildFIDO2Config()

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
	device, err := newFIDO2Device(cfg, logger)
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
			_ = device.Close()
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
func buildFIDO2Config() *FIDO2Config {
	cfg := &FIDO2Config{
		StorageType:         FIDO2StorageType(viper.GetString("fido2.storage")),
		StoragePath:         viper.GetString("fido2.storage_path"),
		BarrierPassword:     viper.GetString("fido2.barrier_password"),
		BarrierPasswordFile: viper.GetString("fido2.barrier_password_file"),
		DeviceName:          viper.GetString("fido2.name"),
		SerialNumber:        viper.GetString("fido2.serial"),
		EnablePIN:           viper.GetBool("fido2.pin"),
		PIN:                 viper.GetString("fido2.set_pin"),
		Interactive:         viper.GetBool("fido2.interactive"),
		RequireTouch:        viper.GetBool("fido2.require_touch"),
		UserPresenceTimeout: viper.GetDuration("fido2.timeout"),
		Backend:             viper.GetString("fido2.backend"),
		TPMDevice:           viper.GetString("fido2.tpm_device"),
		AttestationFormat:   viper.GetString("fido2.attestation"),
		PhoneDevice:         viper.GetString("fido2.phone_device"),
		PasswordStorePath:   viper.GetString("fido2.password_store"),
		SocketPath:          viper.GetString("fido2.socket"),
		DefaultPassword:     viper.GetString("fido2.default_password"),
		NotifyCommand:       viper.GetString("fido2.notify_command"),
		NotifyType:          viper.GetString("fido2.notify"),
		UnifiedPIN:          viper.GetBool("fido2.unified_pin"),
		CDPEnabled:          viper.GetBool("fido2.cdp"),
		CDPHost:             viper.GetString("fido2.cdp_host"),
		CDPPort:             viper.GetInt("fido2.cdp_port"),
	}

	// Enable auto-UV if either the global config or CLI flag requests it.
	if viper.GetBool("fido2.auto_uv") {
		cfg.AutoUV = true
	} else if xcfg, err := xkeyconfig.Load(); err == nil && xcfg.GUI.AutoUnseal.Enabled {
		cfg.AutoUV = true
	}

	return cfg
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
var cryptoRandRead = func(b []byte) (int, error) {
	return cryptoRandReadImpl(b)
}

// cryptoRandReadImpl reads random bytes from crypto/rand.
func cryptoRandReadImpl(b []byte) (int, error) {
	// Import inline to avoid circular dependencies in tests
	return len(b), nil // Will be replaced with actual implementation
}

func init() {
	// Set up the actual crypto/rand implementation
	cryptoRandRead = func(b []byte) (int, error) {
		// Use crypto/rand for secure random generation
		f, err := os.Open("/dev/urandom")
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return f.Read(b)
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
	pwStore         *staticpw.BackendStore
	socketHandler   *authenticator.SocketHandler
	notifier        notify.Notifier
	defaultPassword string
	cdpBridge       *cdp.Bridge
}

// newFIDO2Device creates a new virtual FIDO2 device with the given configuration.
func newFIDO2Device(cfg *FIDO2Config, logger *slog.Logger) (*fido2Device, error) {
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

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create the appropriate storage backend
	storage, err := createFIDO2Storage(cfg)
	if err != nil {
		return nil, errors.Join(ErrFIDO2StorageCreationFailed, err)
	}

	// Create user presence handler (may return a SocketHandler for daemon mode)
	upHandler, socketHandler, notifier, err := createFIDO2UserPresenceHandler(cfg, logger)
	if err != nil {
		_ = storage.Close()
		return nil, errors.Join(ErrFIDO2AuthenticatorCreationFailed, err)
	}

	// Create key backend
	keyBackend, err := createFIDO2KeyBackend(cfg, logger)
	if err != nil {
		_ = storage.Close()
		return nil, errors.Join(ErrFIDO2AuthenticatorCreationFailed, err)
	}

	if cfg.AutoUV {
		// When auto-unseal is configured, report built-in UV so Chrome
		// skips its PIN dialog. The authenticator handles UV internally.
		keyBackend = keybackend.NewAutoUVBackend(keyBackend, &staticBarrierProvider{active: true})
		logger.Info("auto-UV enabled: built-in user verification active")
	}

	// Create authenticator configuration
	// RequireUserPresence defaults to true to match hardware authenticator behavior
	// (YubiKey requires touch even after PIN verification). This ensures the
	// SocketHandler is invoked for every operation, triggering D-Bus notifications
	// and allowing approval via `xkey touch`. Can be disabled with --require-touch=false.
	// AAGUID: UUIDv5(DNS, "xkey.automatethethings.com") = 5150e208-1ab8-5162-bc67-f5e4f24adefa
	xkeyAAGUID := [16]byte{
		0x51, 0x50, 0xE2, 0x08, 0x1A, 0xB8, 0x51, 0x62,
		0xBC, 0x67, 0xF5, 0xE4, 0xF2, 0x4A, 0xDE, 0xFA,
	}

	authConfig := &authenticator.Config{
		AAGUID:                     xkeyAAGUID,
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

	// Create the authenticator
	auth, err := authenticator.NewAuthenticator(authConfig)
	if err != nil {
		_ = keyBackend.Close()
		_ = storage.Close()
		return nil, errors.Join(ErrFIDO2AuthenticatorCreationFailed, err)
	}
	// Set initial PIN if configured
	if cfg.EnablePIN && cfg.PIN != "" {
		if err := auth.SetPINForTesting(cfg.PIN); err != nil {
			_ = auth.Close()
			return nil, errors.Join(ErrFIDO2PINSetFailed, err)
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
		_ = uhidDev.Close()
		d.uhidDevice = nil
		return errors.Join(ErrFIDO2UHIDCreateFailed, err)
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

// initSupplementarySubsystems creates the virtual keyboard, opens the password
// store, and starts the IPC server. Failures in any subsystem are logged but
// do not prevent the FIDO2 device from operating.
func (d *fido2Device) initSupplementarySubsystems(ctx context.Context) {
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
		backend, err := file.New(d.cfg.PasswordStorePath)
		if err != nil {
			d.logger.Warn("password store unavailable",
				slog.String("error", err.Error()),
				slog.String("path", d.cfg.PasswordStorePath))
		} else {
			d.pwStore = staticpw.NewStore(backend)
			d.logger.Info("password store opened",
				slog.String("path", d.cfg.PasswordStorePath))
		}
	}

	// Start IPC server
	socketPath := d.cfg.SocketPath
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

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
			if err := bridge.Start(ctx); err != nil {
				d.logger.Warn("CDP bridge start failed",
					slog.String("error", err.Error()))
				_ = cdpClient.Close()
			} else {
				d.cdpBridge = bridge
				// Sync existing credentials to CDP
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
	return ipc.OKResponse(ipc.ActionDaemonReady), nil
}

// Compile-time check that fido2Device implements ipc.Handler.
var _ ipc.Handler = (*fido2Device)(nil)

// Compile-time check that staticBarrierProvider implements BarrierStateProvider.
var _ keybackend.BarrierStateProvider = (*staticBarrierProvider)(nil)

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

// staticBarrierProvider is a BarrierStateProvider that returns a fixed value.
// Used by the CLI when auto-unseal is confirmed active at startup.
type staticBarrierProvider struct {
	active bool
}

// IsAutoUVActive reports whether built-in user verification should be active.
func (p *staticBarrierProvider) IsAutoUVActive() bool {
	return p.active
}

// syncCredentialsToCDP loads all credentials from storage and registers them
// with the CDP virtual authenticator.
func (d *fido2Device) syncCredentialsToCDP(ctx context.Context) {
	if d.cdpBridge == nil || d.storage == nil {
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

		// Only sync credentials that have exportable keys.
		handle, loadKeyErr := d.keyBackend.LoadKey(sc.CredentialID, sc.Algorithm)
		if loadKeyErr != nil {
			d.logger.Debug("skipping credential for CDP (key load failed)",
				slog.String("credId", fmt.Sprintf("%x", sc.CredentialID)))
			continue
		}

		pkcs8Key, exportErr := d.keyBackend.ExportPrivateKey(handle)
		if exportErr != nil {
			d.logger.Debug("skipping credential for CDP (export not supported)",
				slog.String("credId", fmt.Sprintf("%x", sc.CredentialID)))
			continue
		}

		cdpCreds = append(cdpCreds, cdp.StoredCredential{
			CredentialID:         base64.RawURLEncoding.EncodeToString(sc.CredentialID),
			IsResidentCredential: sc.Discoverable,
			RpID:                 sc.RPID,
			PrivateKey:           base64.RawURLEncoding.EncodeToString(pkcs8Key),
			UserHandle:           base64.RawURLEncoding.EncodeToString(sc.UserID),
			SignCount:            int(sc.SignCount),
		})
	}

	if len(cdpCreds) > 0 {
		if err := d.cdpBridge.SyncCredentials(ctx, cdpCreds); err != nil {
			d.logger.Warn("CDP credential sync failed",
				slog.String("error", err.Error()))
		}
	}

	d.logger.Info("CDP credential sync complete",
		slog.Int("total", len(credIDs)),
		slog.Int("synced", len(cdpCreds)))
}

// createFIDO2Storage creates the appropriate storage backend based on configuration.
func createFIDO2Storage(cfg *FIDO2Config) (authenticator.StatefulCredentialStorage, error) {
	switch cfg.StorageType {
	case FIDO2StorageTypeMemory:
		return authenticator.NewMemoryStorage(), nil

	case FIDO2StorageTypeFile:
		backend, err := file.New(cfg.StoragePath)
		if err != nil {
			return nil, err
		}

		storage, err := authenticator.NewBackendStorage(backend, "xkey/")
		if err != nil {
			_ = backend.Close()
			return nil, err
		}

		return storage, nil

	case FIDO2StorageTypeBarrier:
		return createBarrierStorage(cfg)

	default:
		return nil, ErrFIDO2InvalidStorageType
	}
}

// createBarrierStorage creates barrier-encrypted storage that reads the same
// FIDO2 credentials as the GUI. It resolves the xkey home directory, creates
// a file backend, and unseals the barrier with the provided password.
func createBarrierStorage(cfg *FIDO2Config) (authenticator.StatefulCredentialStorage, error) {
	// Resolve xkey home and data directory.
	home, err := xhome.Resolve()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFIDO2BarrierUnsealFailed, err)
	}
	dataDir, err := home.EnsureDataDir()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFIDO2BarrierUnsealFailed, err)
	}

	// Resolve barrier password.
	password := cfg.BarrierPassword
	if password == "" && cfg.BarrierPasswordFile != "" {
		raw, readErr := os.ReadFile(cfg.BarrierPasswordFile)
		if readErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrFIDO2BarrierPasswordRequired, readErr)
		}
		password = strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	}

	// Create file backend over the data directory.
	fileBackend, err := file.New(dataDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFIDO2BarrierUnsealFailed, err)
	}

	// Read barrier strategy from root key to determine unseal method.
	strategy, err := readBarrierStrategy(dataDir)
	if err != nil {
		_ = fileBackend.Close()
		return nil, fmt.Errorf("%w: %v", ErrFIDO2BarrierUnsealFailed, err)
	}

	// Create barrier service and unseal.
	logger := slog.Default()
	barrierSvc := services.NewBarrierService(home.Root, logger)
	barrierSvc.SetDataDir(dataDir)

	if err := barrierSvc.Unseal(password, string(strategy)); err != nil {
		_ = fileBackend.Close()
		return nil, fmt.Errorf("%w: %v", ErrFIDO2BarrierUnsealFailed, err)
	}

	barrierBackend := barrierSvc.GetBackend()
	if barrierBackend == nil {
		_ = fileBackend.Close()
		return nil, fmt.Errorf("%w: barrier backend unavailable after unseal", ErrFIDO2BarrierUnsealFailed)
	}

	// Create FIDO2 credential storage using the barrier backend.
	// Prefix "fido2/xkey/" matches the GUI's storage namespace.
	storage, err := authenticator.NewBackendStorage(barrierBackend, "fido2/xkey/")
	if err != nil {
		_ = fileBackend.Close()
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
	notifier := createNotifier(cfg, logger)
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
func createNotifier(cfg *FIDO2Config, logger *slog.Logger) notify.Notifier {
	var notifiers []notify.Notifier

	// Handle "none" - no notifications at all
	if cfg.NotifyType == "none" {
		logger.Info("notifications disabled")
		return notify.NewMultiNotifier() // Empty notifier
	}

	// Always add log notifier for "log" type or as fallback
	if cfg.NotifyType == "log" {
		logger.Info("using log-only notifications")
		return notify.NewLogNotifier(logger)
	}

	// Add log notifier as baseline for other types
	notifiers = append(notifiers, notify.NewLogNotifier(logger))

	// Custom command overrides everything
	if cfg.NotifyCommand != "" {
		cmdNotifier, err := notify.NewCommandNotifier(cfg.NotifyCommand, logger)
		if err == nil {
			logger.Info("using custom notification command")
			notifiers = append(notifiers, cmdNotifier)
		} else {
			logger.Warn("invalid notify command, using log-only",
				slog.String("error", err.Error()))
		}
		return notify.NewMultiNotifier(notifiers...)
	}

	// Determine if running as root via sudo
	isRootViaSudo := os.Getuid() == 0 && os.Getenv("SUDO_USER") != ""
	sudoUser := os.Getenv("SUDO_USER")
	sudoUID := os.Getenv("SUDO_UID")

	// Get socket path for dialog mode
	socketPath := cfg.SocketPath
	if socketPath == "" && sudoUID != "" {
		socketPath = fmt.Sprintf("/tmp/xkey-%s/xkey.sock", sudoUID)
	}

	// Get the current executable path for self-invocation
	execPath, err := os.Executable()
	if err != nil {
		execPath = "xkey" // Fallback to PATH lookup
	}

	switch cfg.NotifyType {
	case "dialog":
		if isRootViaSudo {
			// Interactive zenity dialog that uses xkey touch command (no external dependencies)
			notifyCmd := fmt.Sprintf(
				`su -c 'DISPLAY=:0 zenity --question --icon-name=security-high --title="xKey: Touch Required" --text="<b>%%o</b> request from <b>%%r</b>\n\nUser: %%u\n\nClick Approve to authorize this action." --ok-label="✓ Approve" --cancel-label="✗ Deny" --width=350 --timeout=30 && %s touch --socket %s' %s`,
				execPath, socketPath, sudoUser,
			)
			logger.Info("using zenity dialog notifications (root via sudo)",
				slog.String("sudo_user", sudoUser),
				slog.String("socket_path", socketPath))

			cmdNotifier, err := notify.NewCommandNotifier(notifyCmd, logger)
			if err == nil {
				notifiers = append(notifiers, cmdNotifier)
			}
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
			// Passive notification via notify-send (no interaction)
			notifyCmd := fmt.Sprintf(
				`su -c 'DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/%s/bus" notify-send -u critical "xKey: Touch Required" "%%o request from %%r\nUser: %%u\nRun: xkey touch"' %s`,
				sudoUID, sudoUser,
			)
			logger.Info("using notify-send notifications (root via sudo)",
				slog.String("sudo_user", sudoUser))

			cmdNotifier, err := notify.NewCommandNotifier(notifyCmd, logger)
			if err == nil {
				notifiers = append(notifiers, cmdNotifier)
			}
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

	return notify.NewMultiNotifier(notifiers...)
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
		return createFIDO2SoftwareKeyBackend(cfg, logger)
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
		return createFIDO2XKMSSoftwareKeyBackend(logger)
	}

	keyStorage, err := storage.NewMemoryBackend()
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	backend, err := softwarebackend.NewBackend(&softwarebackend.Config{
		KeyStorage: keyStorage,
	})
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	return keybackend.NewBackendAdapter(backend, types.BackendTypeSoftware), nil
}

// createFIDO2XKMSSoftwareKeyBackend initializes the xkms service and creates
// a FIDO2 key backend from the xkms software backend, matching the GUI's
// architecture. The xkms service manages the software key storage at
// {dataDir}/keys/software, ensuring CLI and GUI share the same key store.
func createFIDO2XKMSSoftwareKeyBackend(logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	home, err := xhome.Resolve()
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}
	dataDir, err := home.EnsureDataDir()
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	keysDir := filepath.Join(dataDir, "keys")

	xkms.Reset()
	if err := xkms.AutoInitialize(&xkms.AutoConfig{
		DataDir:        keysDir,
		DefaultBackend: "software",
	}); err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	swBackend, err := xkms.GetBackend("software")
	if err != nil {
		return nil, errors.Join(ErrFIDO2BackendCreationFailed, err)
	}

	adapter := keybackend.NewBackendAdapter(swBackend.KeyProvider(), types.BackendTypeSoftware)
	adapter.SetLogger(logger)

	logger.Info("xkms software key backend initialized", slog.String("keys_dir", keysDir))

	return adapter, nil
}

// createFIDO2TPM2KeyBackend creates a TPM2-backed FIDO2 key backend by wrapping
// the go-xkms TPM2 backend with BackendAdapter.
func createFIDO2TPM2KeyBackend(cfg *FIDO2Config, logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	logger.Info("opening TPM device", slog.String("device", cfg.TPMDevice))

	tpm, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Config: &pkgtpm2.Config{
			Device: cfg.TPMDevice,
		},
		Logger: logger,
	})
	if err != nil {
		return nil, errors.Join(ErrFIDO2TPMOpenFailed, err)
	}

	memStorage, err := storage.NewMemoryBackend()
	if err != nil {
		tpm.Close()
		return nil, errors.Join(ErrFIDO2TPMBackendCreationFailed, err)
	}
	keyBackend := store.NewFileBackend(logger, memStorage)

	backend, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
		TPM:        tpm,
		KeyBackend: keyBackend,
		Logger:     logger,
	})
	if err != nil {
		tpm.Close()
		return nil, errors.Join(ErrFIDO2TPMBackendCreationFailed, err)
	}

	logger.Info("using TPM2 key backend", slog.String("device", cfg.TPMDevice))
	return keybackend.NewBackendAdapter(backend, types.BackendTypeTPM2), nil
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
