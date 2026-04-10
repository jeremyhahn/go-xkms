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

	// DeviceFingerprint is a unique identifier derived from device attestation.
	DeviceFingerprint string `yaml:"device_fingerprint,omitempty"`
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
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No paired devices.")
			return nil
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		fmt.Println("No paired devices.")
		return nil
	}

	fmt.Printf("Paired Devices (%d):\n\n", len(cfg.Devices))

	for i, device := range cfg.Devices {
		defaultMarker := ""
		if device.Name == cfg.DefaultDevice {
			defaultMarker = " (default)"
		}

		fmt.Printf("%d. %s%s\n", i+1, device.Name, defaultMarker)
		fmt.Printf("   Address:   %s\n", device.Address)
		fmt.Printf("   Paired:    %s\n", device.PairedAt.Format(time.RFC3339))
		fmt.Printf("   Key (hex): %s...\n", truncateKey(device.NoisePublicKey))
		fmt.Println()
	}

	return nil
}

// runDeviceUnpair executes the device unpair command.
func runDeviceUnpair(cmd *cobra.Command, args []string) error {
	deviceName := args[0]
	force, _ := cmd.Flags().GetBool("force")

	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
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
		return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
	}

	// Confirm unless force flag is set
	if !force {
		fmt.Printf("Remove pairing with \"%s\"? [y/N]: ", deviceName)
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
		return fmt.Errorf("%w: %v", ErrDeviceConfigSaveFailed, err)
	}

	fmt.Printf("Device \"%s\" unpaired successfully.\n", deviceName)
	return nil
}

// runDeviceStatus executes the device status command.
func runDeviceStatus(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	deviceFilter, _ := cmd.Flags().GetString("device")

	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No paired devices.")
			return nil
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		fmt.Println("No paired devices.")
		return nil
	}

	fmt.Println("Device Status:")
	fmt.Println()

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

		fmt.Printf("Device: %s%s\n", device.Name, defaultMarker)
		fmt.Printf("  Address:    %s\n", device.Address)
		fmt.Printf("  Status:     %s\n", status)
		fmt.Printf("  Paired:     %s\n", device.PairedAt.Format(time.RFC3339))
		fmt.Println()
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

// getDevicesConfigPath returns the path to the devices configuration file.
// When running under sudo, it resolves to the invoking user's home directory
// (via SUDO_USER) so that pair and fido2 commands use the same config file.
//
// Migration: if the legacy phone.yaml exists but devices.yaml does not,
// the old file is automatically renamed.
func getDevicesConfigPath() (string, error) {
	homeDir := ""
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		// Running under sudo: use the invoking user's home directory
		// so config is shared between `xkey device pair` and `sudo xkey fido2`
		if u, err := user.Lookup(sudoUser); err == nil {
			homeDir = u.HomeDir
		}
	}
	if homeDir == "" {
		var err error
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}

	configDir := filepath.Join(homeDir, ".xkey")
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
