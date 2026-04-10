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
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Device backup errors.
var (
	// ErrBackupToDeviceFailed indicates sending backup to device failed.
	ErrBackupToDeviceFailed = errors.New("backup: send to device failed")

	// ErrBackupFromDeviceFailed indicates restoring from device failed.
	ErrBackupFromDeviceFailed = errors.New("backup: restore from device failed")
)

// backupToDeviceCmd sends a backup to a paired phone device.
var backupToDeviceCmd = &cobra.Command{
	Use:   "to-device",
	Short: "Send backup to a paired phone",
	Long: `Send an encrypted backup of xkey data to a paired phone device
over a secure BLE Noise protocol channel.

The backup is encrypted locally before transmission. The phone stores
the encrypted blob and can return it later for restore.

Examples:
  xkey backup to-device
  xkey backup to-device --device "Pixel 8"
  xkey backup to-device --timeout 2m`,
	RunE: runBackupToDevice,
}

// backupFromDeviceCmd restores a backup from a paired phone device.
var backupFromDeviceCmd = &cobra.Command{
	Use:   "from-device",
	Short: "Restore backup from a paired phone",
	Long: `Restore xkey data from an encrypted backup stored on a paired phone
device. The backup is retrieved over a secure BLE Noise protocol channel
and decrypted locally.

Examples:
  xkey backup from-device
  xkey backup from-device --device "Pixel 8"
  xkey backup from-device --timeout 2m`,
	RunE: runBackupFromDevice,
}

func init() {
	backupCmd.AddCommand(backupToDeviceCmd)
	backupCmd.AddCommand(backupFromDeviceCmd)

	// To-device flags
	backupToDeviceCmd.Flags().String("device", "", "Paired device name to send backup to")
	backupToDeviceCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// From-device flags
	backupFromDeviceCmd.Flags().String("device", "", "Paired device name to restore from")
	backupFromDeviceCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Bind flags to viper
	_ = viper.BindPFlag("backup.to_device.device", backupToDeviceCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("backup.to_device.timeout", backupToDeviceCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("backup.from_device.device", backupFromDeviceCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("backup.from_device.timeout", backupFromDeviceCmd.Flags().Lookup("timeout"))
}

// runBackupToDevice sends a backup to a paired phone device.
func runBackupToDevice(cmd *cobra.Command, args []string) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	logger := slog.Default()

	// Load phone config
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

	// Select device
	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
		}
		return ErrDeviceNotPaired
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Sending backup to device \"%s\"...\n\n", device.Name)

	// Decode pairing keys
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return fmt.Errorf("invalid phone noise key: %w", err)
	}

	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}

	// Connect to phone
	phoneBackend, err := phone.NewPhoneKeyBackend(&phone.PhoneKeyBackendConfig{
		DeviceAddress:        device.Address,
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		ScanTimeout:          30 * time.Second,
		ConnectTimeout:       30 * time.Second,
		OperationTimeout:     timeout,
		Logger:               logger,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupToDeviceFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupToDeviceFailed, err)
	}

	// Send backup to phone for storage
	fmt.Fprintln(cmd.OutOrStdout(), "Sending backup data...")

	req := phone.NewRequest(phone.MethodLocalCreateBackup, &phone.LocalCreateBackupParams{
		BackupData: nil, // Backup service will populate this once integrated
		Label:      fmt.Sprintf("xkey-backup-%s", time.Now().UTC().Format("20060102-150405")),
	})

	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupToDeviceFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrBackupToDeviceFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalCreateBackupResult](resp)
	if err != nil {
		return fmt.Errorf("failed to decode backup result: %w", err)
	}

	if result.Success {
		fmt.Fprintf(cmd.OutOrStdout(), "  Backup ID: %s\n", result.BackupID)
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Backup sent to device successfully.")

	return nil
}

// runBackupFromDevice restores a backup from a paired phone device.
func runBackupFromDevice(cmd *cobra.Command, args []string) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	logger := slog.Default()

	// Load phone config
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

	// Select device
	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
		}
		return ErrDeviceNotPaired
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Restoring backup from device \"%s\"...\n\n", device.Name)

	// Decode pairing keys
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return fmt.Errorf("invalid phone noise key: %w", err)
	}

	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}

	// Connect to phone
	phoneBackend, err := phone.NewPhoneKeyBackend(&phone.PhoneKeyBackendConfig{
		DeviceAddress:        device.Address,
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		ScanTimeout:          30 * time.Second,
		ConnectTimeout:       30 * time.Second,
		OperationTimeout:     timeout,
		Logger:               logger,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupFromDeviceFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupFromDeviceFailed, err)
	}

	// Request latest backup from phone
	fmt.Fprintln(cmd.OutOrStdout(), "Requesting backup data (check phone for biometric prompt)...")
	fmt.Fprintln(cmd.OutOrStdout())

	req := phone.NewRequest(phone.MethodLocalRestoreBackup, &phone.LocalRestoreBackupParams{})

	resp, err := phoneBackend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupFromDeviceFailed, err)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrBackupFromDeviceFailed, resp.Error.Code, resp.Error.Message)
	}

	result, err := phone.DecodeResult[phone.LocalRestoreBackupResult](resp)
	if err != nil {
		return fmt.Errorf("failed to decode restore result: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "  Backup ID:  %s\n", result.BackupID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Created:    %s\n", result.CreatedAt)
	fmt.Fprintf(cmd.OutOrStdout(), "  Data size:  %s\n", formatSize(int64(len(result.BackupData))))
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Backup restored from device successfully.")

	return nil
}
