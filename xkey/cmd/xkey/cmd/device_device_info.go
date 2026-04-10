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

//go:build ble

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Attestation status constants.
const (
	attestationStatusCurrent = "CURRENT"
	attestationStatusExpired = "EXPIRED"
	attestationStatusNever   = "NEVER"
)

// deviceInfoCmd displays detailed information about a paired device.
var deviceInfoCmd = &cobra.Command{
	Use:   "device-info [device-name]",
	Short: "Show detailed device information",
	Long: `Display detailed information about a paired phone device.

Shows connection details, attestation status, and configuration settings
for the specified device. If no device is specified, shows the default device.

Examples:
  # Show info for default device
  xkey device device-info

  # Show info for specific device
  xkey device device-info "John's Pixel"`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDeviceInfo,
}

func init() {
	deviceCmd.AddCommand(deviceInfoCmd)
}

// runDeviceInfo executes the phone device-info command.
func runDeviceInfo(cmd *cobra.Command, args []string) error {
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Determine which device to display
	var deviceName string
	if len(args) > 0 {
		deviceName = args[0]
	} else if cfg.DefaultDevice != "" {
		deviceName = cfg.DefaultDevice
	} else {
		deviceName = cfg.Devices[0].Name
	}

	device := findDeviceByName(cfg, deviceName)
	if device == nil {
		return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
	}

	// Determine attestation grace period
	gracePeriod := getDeviceInfoGracePeriod(device, cfg)

	// Calculate attestation status
	status, timeRemaining := calculateAttestationStatus(device, gracePeriod)

	// Display device information
	printDeviceInfo(device, cfg, gracePeriod, status, timeRemaining)

	return nil
}

// getDeviceInfoGracePeriod returns the effective grace period for a device.
func getDeviceInfoGracePeriod(device *PairedDevice, cfg *DevicesConfig) time.Duration {
	// Per-device override takes precedence
	if device.AttestationGracePeriod > 0 {
		return time.Duration(device.AttestationGracePeriod)
	}

	// Fall back to policy default
	if cfg.AttestationPolicy != nil && cfg.AttestationPolicy.DefaultGracePeriod > 0 {
		return time.Duration(cfg.AttestationPolicy.DefaultGracePeriod)
	}

	// Use system default (defined in phone_attestation.go)
	return defaultAttestationGracePeriod
}

// calculateAttestationStatus determines the attestation status and time remaining.
func calculateAttestationStatus(device *PairedDevice, gracePeriod time.Duration) (string, time.Duration) {
	if device.LastDeviceAttestationTime.IsZero() {
		return attestationStatusNever, 0
	}

	expiresAt := device.LastDeviceAttestationTime.Add(gracePeriod)
	now := time.Now()

	if now.Before(expiresAt) {
		return attestationStatusCurrent, expiresAt.Sub(now)
	}

	return attestationStatusExpired, 0
}

// formatDeviceInfoDuration formats a duration as "Xm Ys" for device info display.
func formatDeviceInfoDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}

	d = d.Round(time.Second)

	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	var parts []string
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(parts, " ")
}

// printDeviceInfo displays the formatted device information.
func printDeviceInfo(device *PairedDevice, cfg *DevicesConfig, gracePeriod time.Duration, status string, timeRemaining time.Duration) {
	fmt.Printf("Device Information: %s\n", device.Name)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Connection section
	fmt.Println("Connection")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  BLE Address:      %s\n", device.Address)
	fmt.Printf("  Paired At:        %s\n", device.PairedAt.Format(time.RFC3339))
	fmt.Printf("  Noise Public Key: %s...\n", truncateKey(device.NoisePublicKey))
	fmt.Println()

	// Attestation Status section
	fmt.Println("Attestation Status")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Status:           %s\n", status)

	if status == attestationStatusNever {
		fmt.Printf("  Last Attested:    never\n")
	} else {
		fmt.Printf("  Last Attested:    %s\n", device.LastDeviceAttestationTime.Format(time.RFC3339))
	}

	fmt.Printf("  Grace Period:     %s\n", formatDeviceInfoDuration(gracePeriod))

	if status == attestationStatusCurrent {
		fmt.Printf("  Time Remaining:   %s\n", formatDeviceInfoDuration(timeRemaining))
	} else if status == attestationStatusExpired {
		fmt.Printf("  Time Remaining:   expired\n")
	} else {
		fmt.Printf("  Time Remaining:   n/a\n")
	}

	if device.SecurityLevel != "" {
		fmt.Printf("  Security Level:   %s\n", device.SecurityLevel)
	} else {
		fmt.Printf("  Security Level:   unknown\n")
	}

	if device.BootStateVerified {
		fmt.Printf("  Boot Verified:    true\n")
	} else {
		fmt.Printf("  Boot Verified:    false\n")
	}

	if device.DeviceBootHashHex != "" {
		fmt.Printf("  Boot Hash:        %s...\n", truncateDeviceInfoHash(device.DeviceBootHashHex))
	} else {
		fmt.Printf("  Boot Hash:        n/a\n")
	}

	if device.DeviceFingerprint != "" {
		fmt.Printf("  Device Fingerprint: %s...\n", truncateDeviceInfoHash(device.DeviceFingerprint))
	} else {
		fmt.Printf("  Device Fingerprint: n/a\n")
	}
	fmt.Println()

	// Configuration section
	fmt.Println("Configuration")
	fmt.Println(strings.Repeat("-", 40))
	if device.Name == cfg.DefaultDevice {
		fmt.Printf("  Default Device:   yes\n")
	} else {
		fmt.Printf("  Default Device:   no\n")
	}
}

// truncateDeviceInfoHash truncates a hex hash for display, showing first 8 characters.
func truncateDeviceInfoHash(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}
