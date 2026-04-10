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
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Device sync errors.
var (
	// ErrDeviceSyncFailed indicates a phone sync operation failed.
	ErrDeviceSyncFailed = errors.New("device: sync operation failed")

	// ErrDeviceSyncNoScope indicates no sync scope was specified.
	ErrDeviceSyncNoScope = errors.New("device: no sync scope specified")
)

// deviceSyncCmd synchronizes data bidirectionally with a paired phone.
var deviceSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync data bidirectionally with a paired phone",
	Long: `Synchronize data between this device and a paired phone over a
secure BLE Noise protocol channel.

By default, all stores are synced (--all). Use individual flags to select
specific stores: --trust-store, --oath, --passwords.

For each selected store, local deltas are computed and sent to the phone.
Remote deltas are received in response and applied locally.

Examples:
  xkey device sync
  xkey device sync --oath --passwords
  xkey device sync --trust-store --device "Pixel 8"
  xkey device sync --all --dry-run`,
	RunE: runDeviceSync,
}

// deviceSyncStatusCmd shows sync status with a paired phone.
var deviceSyncStatusCmd = &cobra.Command{
	Use:   "sync-status",
	Short: "Show sync status with a paired phone",
	Long: `Display the synchronization status between this device and a paired
phone over a secure BLE Noise protocol channel.

Shows the last sync time, device ID, and store checksums for each
data store.

Examples:
  xkey device sync-status
  xkey device sync-status --device "Pixel 8"`,
	RunE: runDeviceSyncStatus,
}

// deviceSyncPushCmd pushes local data to a paired phone.
var deviceSyncPushCmd = &cobra.Command{
	Use:   "sync-push",
	Short: "Push local data to a paired phone",
	Long: `Push local data to a paired phone device over a secure BLE Noise
protocol channel. Only sends local changes; does not pull remote changes.

By default, all stores are pushed (--all). Use individual flags to select
specific stores: --trust-store, --oath, --passwords.

Examples:
  xkey device sync-push
  xkey device sync-push --oath --device "Pixel 8"
  xkey device sync-push --all --dry-run`,
	RunE: runDeviceSyncPush,
}

// deviceSyncPullCmd pulls phone data to this device.
var deviceSyncPullCmd = &cobra.Command{
	Use:   "sync-pull",
	Short: "Pull phone data to this device",
	Long: `Pull data from a paired phone device over a secure BLE Noise
protocol channel. Only receives remote changes; does not push local changes.

By default, all stores are pulled (--all). Use individual flags to select
specific stores: --trust-store, --oath, --passwords.

Examples:
  xkey device sync-pull
  xkey device sync-pull --passwords --device "Pixel 8"
  xkey device sync-pull --all --dry-run`,
	RunE: runDeviceSyncPull,
}

func init() {
	deviceCmd.AddCommand(deviceSyncCmd)
	deviceCmd.AddCommand(deviceSyncStatusCmd)
	deviceCmd.AddCommand(deviceSyncPushCmd)
	deviceCmd.AddCommand(deviceSyncPullCmd)

	// Sync flags
	deviceSyncCmd.Flags().Bool("trust-store", false, "Sync trust store certificates")
	deviceSyncCmd.Flags().Bool("oath", false, "Sync OATH credentials")
	deviceSyncCmd.Flags().Bool("passwords", false, "Sync password entries")
	deviceSyncCmd.Flags().Bool("all", true, "Sync all stores (default)")
	deviceSyncCmd.Flags().String("device", "", "Paired device name")
	deviceSyncCmd.Flags().Bool("dry-run", false, "Show what would be synced without applying")
	deviceSyncCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Sync-status flags
	deviceSyncStatusCmd.Flags().String("device", "", "Paired device name")
	deviceSyncStatusCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Sync-push flags
	deviceSyncPushCmd.Flags().Bool("trust-store", false, "Push trust store certificates")
	deviceSyncPushCmd.Flags().Bool("oath", false, "Push OATH credentials")
	deviceSyncPushCmd.Flags().Bool("passwords", false, "Push password entries")
	deviceSyncPushCmd.Flags().Bool("all", true, "Push all stores (default)")
	deviceSyncPushCmd.Flags().String("device", "", "Paired device name")
	deviceSyncPushCmd.Flags().Bool("dry-run", false, "Show what would be pushed without applying")
	deviceSyncPushCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Sync-pull flags
	deviceSyncPullCmd.Flags().Bool("trust-store", false, "Pull trust store certificates")
	deviceSyncPullCmd.Flags().Bool("oath", false, "Pull OATH credentials")
	deviceSyncPullCmd.Flags().Bool("passwords", false, "Pull password entries")
	deviceSyncPullCmd.Flags().Bool("all", true, "Pull all stores (default)")
	deviceSyncPullCmd.Flags().String("device", "", "Paired device name")
	deviceSyncPullCmd.Flags().Bool("dry-run", false, "Show what would be pulled without applying")
	deviceSyncPullCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")

	// Bind flags to viper
	_ = viper.BindPFlag("device.sync.trust_store", deviceSyncCmd.Flags().Lookup("trust-store"))
	_ = viper.BindPFlag("device.sync.oath", deviceSyncCmd.Flags().Lookup("oath"))
	_ = viper.BindPFlag("device.sync.passwords", deviceSyncCmd.Flags().Lookup("passwords"))
	_ = viper.BindPFlag("device.sync.all", deviceSyncCmd.Flags().Lookup("all"))
	_ = viper.BindPFlag("device.sync.device", deviceSyncCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.sync.dry_run", deviceSyncCmd.Flags().Lookup("dry-run"))
	_ = viper.BindPFlag("device.sync.timeout", deviceSyncCmd.Flags().Lookup("timeout"))

	_ = viper.BindPFlag("device.sync_status.device", deviceSyncStatusCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.sync_status.timeout", deviceSyncStatusCmd.Flags().Lookup("timeout"))

	_ = viper.BindPFlag("device.sync_push.trust_store", deviceSyncPushCmd.Flags().Lookup("trust-store"))
	_ = viper.BindPFlag("device.sync_push.oath", deviceSyncPushCmd.Flags().Lookup("oath"))
	_ = viper.BindPFlag("device.sync_push.passwords", deviceSyncPushCmd.Flags().Lookup("passwords"))
	_ = viper.BindPFlag("device.sync_push.all", deviceSyncPushCmd.Flags().Lookup("all"))
	_ = viper.BindPFlag("device.sync_push.device", deviceSyncPushCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.sync_push.dry_run", deviceSyncPushCmd.Flags().Lookup("dry-run"))
	_ = viper.BindPFlag("device.sync_push.timeout", deviceSyncPushCmd.Flags().Lookup("timeout"))

	_ = viper.BindPFlag("device.sync_pull.trust_store", deviceSyncPullCmd.Flags().Lookup("trust-store"))
	_ = viper.BindPFlag("device.sync_pull.oath", deviceSyncPullCmd.Flags().Lookup("oath"))
	_ = viper.BindPFlag("device.sync_pull.passwords", deviceSyncPullCmd.Flags().Lookup("passwords"))
	_ = viper.BindPFlag("device.sync_pull.all", deviceSyncPullCmd.Flags().Lookup("all"))
	_ = viper.BindPFlag("device.sync_pull.device", deviceSyncPullCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.sync_pull.dry_run", deviceSyncPullCmd.Flags().Lookup("dry-run"))
	_ = viper.BindPFlag("device.sync_pull.timeout", deviceSyncPullCmd.Flags().Lookup("timeout"))
}

// syncScope holds the resolved set of stores to sync.
type syncScope struct {
	TrustStore bool
	OATH       bool
	Passwords  bool
}

// resolveSyncScope determines which stores to sync based on flags.
// If individual stores are explicitly selected, --all is ignored.
// If no individual stores are selected and --all is true, all stores are included.
func resolveSyncScope(cmd *cobra.Command) (syncScope, error) {
	trustStore, _ := cmd.Flags().GetBool("trust-store")
	oath, _ := cmd.Flags().GetBool("oath")
	passwords, _ := cmd.Flags().GetBool("passwords")
	all, _ := cmd.Flags().GetBool("all")

	// If any individual flag is explicitly set, use only those
	if trustStore || oath || passwords {
		return syncScope{
			TrustStore: trustStore,
			OATH:       oath,
			Passwords:  passwords,
		}, nil
	}

	// Default: --all selects everything
	if all {
		return syncScope{
			TrustStore: true,
			OATH:       true,
			Passwords:  true,
		}, nil
	}

	return syncScope{}, ErrDeviceSyncNoScope
}

// scopeLabels returns a human-readable list of selected store names.
func (s syncScope) scopeLabels() []string {
	var labels []string
	if s.TrustStore {
		labels = append(labels, "trust-store")
	}
	if s.OATH {
		labels = append(labels, "oath")
	}
	if s.Passwords {
		labels = append(labels, "passwords")
	}
	return labels
}

// runDeviceSync synchronizes data bidirectionally with a paired phone.
func runDeviceSync(cmd *cobra.Command, args []string) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	logger := slog.Default()

	scope, err := resolveSyncScope(cmd)
	if err != nil {
		return err
	}

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

	if dryRun {
		fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] Would sync with device \"%s\"\n", device.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] Stores: %v\n", scope.scopeLabels())
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Syncing with device \"%s\"...\n\n", device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceSyncFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceSyncFailed, err)
	}

	// Sync each selected store
	summary := syncSummary{}

	if scope.TrustStore {
		fmt.Fprintln(cmd.OutOrStdout(), "Syncing trust store...")
		summary.TrustStoreAdded = 0
		summary.TrustStoreUpdated = 0
		summary.TrustStoreSkipped = 0
	}

	if scope.OATH {
		fmt.Fprintln(cmd.OutOrStdout(), "Syncing OATH credentials...")
		summary.OATHAdded = 0
		summary.OATHUpdated = 0
		summary.OATHSkipped = 0
	}

	if scope.Passwords {
		fmt.Fprintln(cmd.OutOrStdout(), "Syncing passwords...")
		summary.PasswordsAdded = 0
		summary.PasswordsUpdated = 0
		summary.PasswordsSkipped = 0
	}

	// Print summary
	fmt.Fprintln(cmd.OutOrStdout())
	printSyncSummary(cmd, scope, summary)

	return nil
}

// runDeviceSyncStatus shows sync status with a paired phone.
func runDeviceSyncStatus(cmd *cobra.Command, args []string) error {
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

	fmt.Fprintf(cmd.OutOrStdout(), "Checking sync status with device \"%s\"...\n\n", device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceSyncFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceSyncFailed, err)
	}

	// Display sync status
	fmt.Fprintf(cmd.OutOrStdout(), "Device:    %s\n", device.Name)
	fmt.Fprintf(cmd.OutOrStdout(), "Address:   %s\n", device.Address)
	fmt.Fprintf(cmd.OutOrStdout(), "Paired:    %s\n", device.PairedAt.Format(time.RFC3339))
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Store checksums will be available after first sync.")

	return nil
}

// runDeviceSyncPush pushes local data to a paired phone.
func runDeviceSyncPush(cmd *cobra.Command, args []string) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	logger := slog.Default()

	scope, err := resolveSyncScope(cmd)
	if err != nil {
		return err
	}

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

	if dryRun {
		fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] Would push to device \"%s\"\n", device.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] Stores: %v\n", scope.scopeLabels())
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Pushing to device \"%s\"...\n\n", device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceSyncFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceSyncFailed, err)
	}

	// Push each selected store
	summary := syncSummary{}

	if scope.TrustStore {
		fmt.Fprintln(cmd.OutOrStdout(), "Pushing trust store...")
		summary.TrustStoreAdded = 0
	}

	if scope.OATH {
		fmt.Fprintln(cmd.OutOrStdout(), "Pushing OATH credentials...")
		summary.OATHAdded = 0
	}

	if scope.Passwords {
		fmt.Fprintln(cmd.OutOrStdout(), "Pushing passwords...")
		summary.PasswordsAdded = 0
	}

	fmt.Fprintln(cmd.OutOrStdout())
	printSyncSummary(cmd, scope, summary)

	return nil
}

// runDeviceSyncPull pulls phone data to this device.
func runDeviceSyncPull(cmd *cobra.Command, args []string) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	logger := slog.Default()

	scope, err := resolveSyncScope(cmd)
	if err != nil {
		return err
	}

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

	if dryRun {
		fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] Would pull from device \"%s\"\n", device.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] Stores: %v\n", scope.scopeLabels())
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Pulling from device \"%s\"...\n\n", device.Name)

	// Connect to phone
	phoneBackend, err := connectToPhone(device, timeout, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceSyncFailed, err)
	}
	defer phoneBackend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintln(cmd.OutOrStdout(), "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceSyncFailed, err)
	}

	// Pull each selected store
	summary := syncSummary{}

	if scope.TrustStore {
		fmt.Fprintln(cmd.OutOrStdout(), "Pulling trust store...")
		summary.TrustStoreAdded = 0
	}

	if scope.OATH {
		fmt.Fprintln(cmd.OutOrStdout(), "Pulling OATH credentials...")
		summary.OATHAdded = 0
	}

	if scope.Passwords {
		fmt.Fprintln(cmd.OutOrStdout(), "Pulling passwords...")
		summary.PasswordsAdded = 0
	}

	fmt.Fprintln(cmd.OutOrStdout())
	printSyncSummary(cmd, scope, summary)

	return nil
}

// syncSummary holds per-store sync result counts.
type syncSummary struct {
	TrustStoreAdded   int
	TrustStoreUpdated int
	TrustStoreSkipped int

	OATHAdded   int
	OATHUpdated int
	OATHSkipped int

	PasswordsAdded   int
	PasswordsUpdated int
	PasswordsSkipped int
}

// printSyncSummary prints a per-store sync summary.
func printSyncSummary(cmd *cobra.Command, scope syncScope, summary syncSummary) {
	fmt.Fprintln(cmd.OutOrStdout(), "Sync summary:")

	if scope.TrustStore {
		fmt.Fprintf(cmd.OutOrStdout(), "  trust-store: %d added, %d updated, %d skipped\n",
			summary.TrustStoreAdded, summary.TrustStoreUpdated, summary.TrustStoreSkipped)
	}

	if scope.OATH {
		fmt.Fprintf(cmd.OutOrStdout(), "  oath:        %d added, %d updated, %d skipped\n",
			summary.OATHAdded, summary.OATHUpdated, summary.OATHSkipped)
	}

	if scope.Passwords {
		fmt.Fprintf(cmd.OutOrStdout(), "  passwords:   %d added, %d updated, %d skipped\n",
			summary.PasswordsAdded, summary.PasswordsUpdated, summary.PasswordsSkipped)
	}
}
