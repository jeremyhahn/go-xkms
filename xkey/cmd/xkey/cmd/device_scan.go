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
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// deviceScanCmd scans for nearby xKey devices.
var deviceScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for nearby xKey devices",
	Long: `Scan for xKey-enabled phones advertising the xKey BLE service.

This command performs a full BLE scan for the specified timeout duration
and lists all discovered xKey devices. Use this to find device names
and addresses for manual pairing.

Examples:
  # Scan for devices (default 30s timeout)
  xkey device scan

  # Quick scan with shorter timeout
  xkey device scan --timeout 10s

  # Extended scan
  xkey device scan --timeout 60s`,
	RunE: runDeviceScan,
}

func init() {
	deviceCmd.AddCommand(deviceScanCmd)

	// Scan flags
	deviceScanCmd.Flags().Duration("timeout", defaultDeviceScanTimeout, "Scan timeout duration")

	// Bind flags to viper
	_ = viper.BindPFlag("device.scan.timeout", deviceScanCmd.Flags().Lookup("timeout"))
}

// runDeviceScan executes the phone scan command.
func runDeviceScan(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	scanTimeout, _ := cmd.Flags().GetDuration("timeout")

	// Create BLE transport for scanning
	transport, err := phone.NewBLETransport(&phone.BLETransportConfig{
		ScanTimeout: scanTimeout,
		Logger:      logger,
	})
	if err != nil {
		if errors.Is(err, phone.ErrBLEUnavailable) {
			return ErrDeviceBLEUnavailable
		}
		return fmt.Errorf("failed to initialize Bluetooth: %w", err)
	}
	defer transport.Close()

	fmt.Printf("Scanning for xKey devices (%s timeout)...\n", scanTimeout)
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Use ScanAll to find all devices during the timeout period
	devices, err := transport.ScanAll(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if len(devices) == 0 {
		fmt.Println("No xKey devices found.")
		fmt.Println()
		fmt.Println("Make sure:")
		fmt.Println("  1. The xKey app is running on your phone")
		fmt.Println("  2. You've tapped 'Start xKey' to begin advertising")
		fmt.Println("  3. Bluetooth is enabled on both devices")
		return nil
	}

	fmt.Printf("Found %d xKey device(s):\n\n", len(devices))

	for i, d := range devices {
		fmt.Printf("  %d. %s\n", i+1, d.DisplayName())
		fmt.Printf("     Address: %s\n", d.Address)
		fmt.Println()
	}

	fmt.Println("To pair with a specific device:")
	fmt.Println("  xkey device pair --device \"<device-name>\"")
	fmt.Println()
	fmt.Println("Or just run 'xkey device pair' to auto-pair with the first device found.")

	return nil
}
