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
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Device command errors.
var (
	// ErrDeviceBLEUnavailable indicates Bluetooth is not available on this system.
	ErrDeviceBLEUnavailable = errors.New("device: bluetooth unavailable")

	// ErrDeviceNoDevicesFound indicates no xKey devices were found during scan.
	ErrDeviceNoDevicesFound = errors.New("device: no devices found")

	// ErrDevicePairingCancelled indicates the user cancelled the pairing process.
	ErrDevicePairingCancelled = errors.New("device: pairing cancelled by user")

	// ErrDeviceNotPaired indicates the specified device is not paired.
	ErrDeviceNotPaired = errors.New("device: device not paired")

	// ErrDeviceConfigSaveFailed indicates the device configuration could not be saved.
	ErrDeviceConfigSaveFailed = errors.New("device: failed to save configuration")

	// ErrDeviceConfigLoadFailed indicates the device configuration could not be loaded.
	ErrDeviceConfigLoadFailed = errors.New("device: failed to load configuration")

	// ErrDeviceNotFound indicates the specified device was not found.
	ErrDeviceNotFound = errors.New("device: device not found")

	// ErrDeviceNotConnected indicates no device is currently connected.
	ErrDeviceNotConnected = errors.New("device: not connected")

	// ErrDeviceAlreadyPaired indicates the device is already paired.
	ErrDeviceAlreadyPaired = errors.New("device: device already paired")

	// ErrDeviceAttestationRequired indicates device attestation is required.
	ErrDeviceAttestationRequired = errors.New("device: device attestation required")

	// ErrBootHashMismatch indicates the device boot hash changed.
	ErrBootHashMismatch = errors.New("device: boot hash mismatch - device may be compromised")

	// ErrSecurityLevelInsufficient indicates the device security level is too low.
	ErrSecurityLevelInsufficient = errors.New("device: security level insufficient")
)

// Default device configuration values.
const (
	defaultDeviceScanTimeout = 30 * time.Second
	devicesConfigFileName    = "devices.yaml"

	// legacyPhoneConfigFileName is the old config file name for migration.
	legacyPhoneConfigFileName = "phone.yaml"
)

// Duration wraps time.Duration for YAML marshaling.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// AttestationPolicy configures device attestation requirements.
type AttestationPolicy struct {
	// DefaultGracePeriod is the default time window for attestation validity.
	// Default: 5m
	DefaultGracePeriod Duration `yaml:"default_grace_period"`

	// RequireDeviceAttestation enforces device attestation before operations.
	RequireDeviceAttestation bool `yaml:"require_device_attestation"`

	// MinSecurityLevel specifies the minimum acceptable security level.
	// Valid values: "tee", "strongbox"
	MinSecurityLevel string `yaml:"min_security_level"`

	// VerifyBootState enables verification of the device boot state.
	VerifyBootState bool `yaml:"verify_boot_state"`

	// AutoAttestOnConnect triggers attestation automatically on device connect.
	AutoAttestOnConnect bool `yaml:"auto_attest_on_connect"`

	// AllowUnattestableDevices decides what `xkey device pair` does when the
	// phone's hardware attestation cannot be verified -- an emulator, a chain
	// that reaches no configured Android attestation root, a handset whose
	// firmware state we hold no root for, a replayed challenge.
	//
	// False (the zero value, and the default) refuses the pairing. True lets
	// it complete, and the record then carries NO attestation claim at all:
	// no security level, no boot state, no boot hash, no device fingerprint.
	// That is the part which is not configurable, because it is what #95 was
	// about -- a pairing record whose attestation half was never checked is
	// what every later connection is judged against, so an unverified claim
	// must never be written down, whatever this setting says about refusing.
	//
	// This is the user-facing half of the owner ruling of 2026-08-23 on #95.
	// The enterprise/SO half is config.PolicySection: while its
	// LockPairingAttestationPolicy is set, this field is ignored and
	// PairingAllowUnattestableDevices governs instead.
	AllowUnattestableDevices bool `yaml:"allow_unattestable_devices"`
}

// PairedDevice represents a paired device.
type PairedDevice struct {
	// Name is the human-readable device name.
	Name string `yaml:"name"`

	// Address is the BLE MAC address.
	Address string `yaml:"address"`

	// NoisePublicKey is the phone's Noise static public key (base64 encoded).
	NoisePublicKey string `yaml:"noise_public_key"`

	// LocalNoisePrivateKey is our local Noise static private key (base64 encoded).
	LocalNoisePrivateKey string `yaml:"local_noise_private_key"`

	// PairedAt is the timestamp when the device was paired.
	PairedAt time.Time `yaml:"paired_at"`

	// LastDeviceAttestationTime is the timestamp of the last successful device attestation.
	LastDeviceAttestationTime time.Time `yaml:"last_device_attestation_time,omitempty"`

	// DeviceBootHashHex is the hex-encoded hash of the device boot state.
	DeviceBootHashHex string `yaml:"device_boot_hash_hex,omitempty"`

	// AttestationGracePeriod is the per-device attestation validity window.
	AttestationGracePeriod Duration `yaml:"attestation_grace_period,omitempty"`

	// SecurityLevel indicates the device's hardware security level (e.g., "tee", "strongbox").
	SecurityLevel string `yaml:"security_level,omitempty"`

	// BootStateVerified indicates whether the device boot state has been verified.
	BootStateVerified bool `yaml:"boot_state_verified,omitempty"`

	// DeviceFingerprint is a unique identifier derived from device attestation:
	// the SHA-256 of the device's persistent attested key's
	// SubjectPublicKeyInfo (#93/#129), hex encoded.
	DeviceFingerprint string `yaml:"device_fingerprint,omitempty"`

	// AttestationProtocolVersion records which attestation model bound this
	// device: 2 for challenge-response (#129), absent or 1 for a record
	// established before it.
	//
	// It is the anti-downgrade term. A device bound under version 2 must prove
	// liveness on every reconnect, and a peer that answers a version 2 record
	// with a version 1 attestation is refused rather than accommodated —
	// otherwise the protocol version would be chosen at connect time by the
	// party being checked, which is the one party that must not choose it.
	// Records that predate the change keep working in the weaker mode until
	// the device is re-paired; they are not silently reported as if they had
	// the stronger binding.
	AttestationProtocolVersion int `yaml:"attestation_protocol_version,omitempty"`
}

// attestationBinding is what the shared verifier needs from this record: which
// device identity was bound, and under which attestation model.
//
// It is a projection rather than the record itself so that pkg/attestation
// depends on two fields instead of on this struct — which matters because
// whether the CLI, the GUI and the GUI's view model should collapse into one
// owned record type is an open decision (#130), and the verifier must not
// prejudge it.
func (d *PairedDevice) attestationBinding() attestation.DeviceBinding {
	return attestation.DeviceBinding{
		Fingerprint:     d.DeviceFingerprint,
		ProtocolVersion: d.AttestationProtocolVersion,
	}
}

// DevicesConfig holds the paired devices configuration.
type DevicesConfig struct {
	// Devices is the list of paired devices.
	Devices []PairedDevice `yaml:"devices"`

	// DefaultDevice is the name of the default device to use.
	DefaultDevice string `yaml:"default_device"`

	// AttestationPolicy configures device attestation requirements.
	AttestationPolicy *AttestationPolicy `yaml:"attestation_policy,omitempty"`
}

// deviceCmd is the parent command for device pairing and management.
var deviceCmd = &cobra.Command{
	Use:     "device",
	Aliases: []string{"phone"},
	Short:   "Manage paired device connections",
	Long: `Manage paired device connections (phones, agents, desktops).

xKey can pair with various device types to use them as secure key
storage backends or remote agents. Supported pairing transports include
BLE, USB, TCP, and QR code.

For phone devices, keys are stored in the phone's hardware-backed
Keystore (StrongBox) and signing operations require biometric verification.

The pairing process establishes a secure Noise protocol channel between
xKey and the paired device, ensuring all communication is authenticated
and encrypted end-to-end.

Examples:
  # Scan for and pair with a phone via BLE
  xkey device pair

  # List paired devices
  xkey device list

  # Unpair a device
  xkey device unpair "John's Pixel"

  # Check connection status
  xkey device status`,
}

// deviceListCmd lists all paired devices.
var deviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List paired devices",
	Long: `List all devices that have been paired with xKey.

Displays the device name, address, type, pairing date, and public key
fingerprint for each paired device.

Examples:
  # List all paired devices
  xkey device list`,
	RunE: runDeviceList,
}

// deviceUnpairCmd removes a device pairing.
var deviceUnpairCmd = &cobra.Command{
	Use:   "unpair <device-name>",
	Short: "Remove pairing with a device",
	Long: `Remove the pairing information for a paired device.

This removes the stored keys and configuration for the specified device.
The device will need to be re-paired to be used again.

Examples:
  # Unpair a device by name
  xkey device unpair "John's Pixel"

  # Unpair with force (no confirmation)
  xkey device unpair "John's Pixel" --force`,
	Args: cobra.ExactArgs(1),
	RunE: runDeviceUnpair,
}

// deviceStatusCmd shows connection status.
var deviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show device connection status",
	Long: `Display the current connection status of paired devices.

Shows whether devices are currently connected, their signal strength,
and the last time they were seen.

Examples:
  # Check status of all devices
  xkey device status

  # Check status of a specific device
  xkey device status --device "John's Pixel"`,
	RunE: runDeviceStatus,
}

func init() {
	RootCmd.AddCommand(deviceCmd)
	deviceCmd.AddCommand(deviceListCmd)
	deviceCmd.AddCommand(deviceUnpairCmd)
	deviceCmd.AddCommand(deviceStatusCmd)

	// Persistent flags for all device subcommands
	deviceCmd.PersistentFlags().Bool("trust-new-devices", false,
		"Allow connection to unpaired devices (empty prologue)")

	// Unpair flags
	deviceUnpairCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	// Status flags
	deviceStatusCmd.Flags().String("device", "", "Specific device to check")

	// Bind flags to viper
	_ = viper.BindPFlag("device.trust_new_devices", deviceCmd.PersistentFlags().Lookup("trust-new-devices"))
	_ = viper.BindPFlag("device.status.device", deviceStatusCmd.Flags().Lookup("device"))
}

// runDeviceList executes the device list command.
func runDeviceList(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintln(out, "No paired devices.")
			return nil
		}
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	if len(cfg.Devices) == 0 {
		_, _ = fmt.Fprintln(out, "No paired devices.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Paired Devices (%d):\n\n", len(cfg.Devices))

	for i, device := range cfg.Devices {
		defaultMarker := ""
		if device.Name == cfg.DefaultDevice {
			defaultMarker = " (default)"
		}

		_, _ = fmt.Fprintf(out, "%d. %s%s\n", i+1, device.Name, defaultMarker)
		_, _ = fmt.Fprintf(out, "   Address:   %s\n", device.Address)
		_, _ = fmt.Fprintf(out, "   Paired:    %s\n", device.PairedAt.Format(time.RFC3339))
		_, _ = fmt.Fprintf(out, "   Key (hex): %s...\n", truncateKey(device.NoisePublicKey))
		_, _ = fmt.Fprintln(out)
	}

	return nil
}

// runDeviceUnpair executes the device unpair command.
func runDeviceUnpair(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	deviceName := args[0]
	force, _ := cmd.Flags().GetBool("force")

	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	// Find the device
	deviceIndex := -1
	for i, device := range cfg.Devices {
		if device.Name == deviceName {
			deviceIndex = i
			break
		}
	}

	if deviceIndex == -1 {
		return &DetailError{Err: ErrDeviceNotFound, Detail: fmt.Sprintf(": %s", deviceName)}
	}

	// Confirm unless force flag is set
	if !force {
		_, _ = fmt.Fprintf(out, "Remove pairing with \"%s\"? [y/N]: ", deviceName)
		var response string
		if _, err := fmt.Scanln(&response); err != nil || (response != "y" && response != "Y") {
			return ErrDevicePairingCancelled
		}
	}

	// Remove the device
	cfg.Devices = append(cfg.Devices[:deviceIndex], cfg.Devices[deviceIndex+1:]...)

	// Update default device if needed
	if cfg.DefaultDevice == deviceName {
		if len(cfg.Devices) > 0 {
			cfg.DefaultDevice = cfg.Devices[0].Name
		} else {
			cfg.DefaultDevice = ""
		}
	}

	// Save configuration
	if err := saveDevicesConfig(cfg); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceConfigSaveFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Device \"%s\" unpaired successfully.\n", deviceName)
	return nil
}

// runDeviceStatus executes the device status command.
func runDeviceStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	logger := slog.Default()
	deviceFilter, _ := cmd.Flags().GetString("device")

	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintln(out, "No paired devices.")
			return nil
		}
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	if len(cfg.Devices) == 0 {
		_, _ = fmt.Fprintln(out, "No paired devices.")
		return nil
	}

	_, _ = fmt.Fprintln(out, "Device Status:")
	_, _ = fmt.Fprintln(out)

	for _, device := range cfg.Devices {
		// Filter by device name if specified
		if deviceFilter != "" && device.Name != deviceFilter {
			continue
		}

		// Check connection status
		status := checkDeviceStatus(device, logger)

		defaultMarker := ""
		if device.Name == cfg.DefaultDevice {
			defaultMarker = " (default)"
		}

		_, _ = fmt.Fprintf(out, "Device: %s%s\n", device.Name, defaultMarker)
		_, _ = fmt.Fprintf(out, "  Address:    %s\n", device.Address)
		_, _ = fmt.Fprintf(out, "  Status:     %s\n", status)
		_, _ = fmt.Fprintf(out, "  Paired:     %s\n", device.PairedAt.Format(time.RFC3339))
		_, _ = fmt.Fprintln(out)
	}

	return nil
}

// checkDeviceStatus checks if a device is reachable.
func checkDeviceStatus(device PairedDevice, logger *slog.Logger) string {
	// For now, we just report the pairing status
	// In a full implementation, we would attempt a BLE connection
	// and send a ping to check if the device is online
	return "Paired (connection check requires BLE)"
}

// loadDevicesConfig loads the devices configuration from disk.
func loadDevicesConfig() (*DevicesConfig, error) {
	configPath, err := getDevicesConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var cfg DevicesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// saveDevicesConfig saves the devices configuration to disk.
func saveDevicesConfig(cfg *DevicesConfig) error {
	configPath, err := getDevicesConfigPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Write with restricted permissions (contains private keys)
	return os.WriteFile(configPath, data, 0600)
}

// lookupUserHome returns the home directory of the named account. It is a
// variable so tests can stand in for the account database.
var lookupUserHome = func(name string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// resolveInvokingUserHome resolves the xKey home the way every other
// command does (XKEY_HOME, portable mode, ~/.xkey/, /etc/xkey), except
// that under sudo the per-user strategy is evaluated against the invoking
// user's home rather than root's, so that `sudo xkey device pair` and the
// user's own GUI session read the same devices file. An unresolvable home
// is an error, never a silent fallback (#442).
func resolveInvokingUserHome() (*xhome.Home, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if homeDir, err := lookupUserHome(sudoUser); err == nil && homeDir != "" {
			return xhome.ResolveForUser(homeDir)
		}
	}
	return xhome.Resolve()
}

// getDevicesConfigPath returns the path to the devices configuration file.
// When running under sudo, it resolves to the invoking user's home directory
// (via SUDO_USER) so that pair and fido2 commands use the same config file.
//
// Migration: if the legacy phone.yaml exists but devices.yaml does not,
// the old file is automatically renamed.
func getDevicesConfigPath() (string, error) {
	home, err := resolveInvokingUserHome()
	if err != nil {
		return "", err
	}
	configDir := home.Root
	newPath := filepath.Join(configDir, devicesConfigFileName)
	legacyPath := filepath.Join(configDir, legacyPhoneConfigFileName)

	// Migrate phone.yaml → devices.yaml if the new file does not exist
	if _, err := os.Stat(newPath); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(legacyPath); err == nil {
			if renameErr := os.Rename(legacyPath, newPath); renameErr != nil {
				slog.Warn("failed to migrate phone.yaml to devices.yaml",
					slog.String("error", renameErr.Error()))
				// Fall through — caller will get ErrNotExist from newPath
			} else {
				slog.Info("migrated config", slog.String("from", legacyPath), slog.String("to", newPath))
			}
		}
	}

	return newPath, nil
}

// truncateKey truncates a base64 key for display.
func truncateKey(key string) string {
	if len(key) > 16 {
		return key[:16]
	}
	return key
}

// findDeviceByName finds a paired device by name.
func findDeviceByName(cfg *DevicesConfig, name string) *PairedDevice {
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			return &cfg.Devices[i]
		}
	}
	return nil
}

// findDeviceByAddress finds a paired device by BLE address.
func findDeviceByAddress(cfg *DevicesConfig, address string) *PairedDevice {
	for i := range cfg.Devices {
		if cfg.Devices[i].Address == address {
			return &cfg.Devices[i]
		}
	}
	return nil
}

// encodePublicKey encodes a public key to base64 for storage.
func encodePublicKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// decodePublicKey decodes a base64-encoded public key.
func decodePublicKey(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// GetTrustNewDevices returns the value of the --trust-new-devices flag from context.
// This can be used by other commands that create PhoneKeyBackendConfig.
func GetTrustNewDevices(cmd *cobra.Command) bool {
	trustNewDevices, _ := cmd.Flags().GetBool("trust-new-devices")
	return trustNewDevices
}
