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
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
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
	addBarrierPasswordFlags(deviceSyncCmd)

	// Sync-status flags
	deviceSyncStatusCmd.Flags().String("device", "", "Paired device name")
	deviceSyncStatusCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	addBarrierPasswordFlags(deviceSyncStatusCmd)

	// Sync-push flags
	deviceSyncPushCmd.Flags().Bool("trust-store", false, "Push trust store certificates")
	deviceSyncPushCmd.Flags().Bool("oath", false, "Push OATH credentials")
	deviceSyncPushCmd.Flags().Bool("passwords", false, "Push password entries")
	deviceSyncPushCmd.Flags().Bool("all", true, "Push all stores (default)")
	deviceSyncPushCmd.Flags().String("device", "", "Paired device name")
	deviceSyncPushCmd.Flags().Bool("dry-run", false, "Show what would be pushed without applying")
	deviceSyncPushCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	addBarrierPasswordFlags(deviceSyncPushCmd)

	// Sync-pull flags
	deviceSyncPullCmd.Flags().Bool("trust-store", false, "Pull trust store certificates")
	deviceSyncPullCmd.Flags().Bool("oath", false, "Pull OATH credentials")
	deviceSyncPullCmd.Flags().Bool("passwords", false, "Pull password entries")
	deviceSyncPullCmd.Flags().Bool("all", true, "Pull all stores (default)")
	deviceSyncPullCmd.Flags().String("device", "", "Paired device name")
	deviceSyncPullCmd.Flags().Bool("dry-run", false, "Show what would be pulled without applying")
	deviceSyncPullCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	addBarrierPasswordFlags(deviceSyncPullCmd)

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

// syncMode selects which halves of an exchange are applied.
type syncMode int

const (
	// syncModeBoth sends local items and applies the phone's reply.
	syncModeBoth syncMode = iota

	// syncModePush sends local items and discards the phone's reply.
	syncModePush

	// syncModePull sends nothing and applies the phone's reply.
	syncModePull
)

// sends reports whether the mode transmits local items to the phone.
func (m syncMode) sends() bool { return m != syncModePull }

// applies reports whether the mode writes the phone's items to local stores.
func (m syncMode) applies() bool { return m != syncModePush }

// verb returns the operator-facing name of the mode.
func (m syncMode) verb() string {
	switch m {
	case syncModePush:
		return "Pushing"
	case syncModePull:
		return "Pulling"
	default:
		return "Syncing"
	}
}

// runDeviceSync synchronizes data bidirectionally with a paired phone.
func runDeviceSync(cmd *cobra.Command, args []string) error {
	return runDeviceSyncMode(cmd, syncModeBoth)
}

// runDeviceSyncPush pushes local data to a paired phone.
func runDeviceSyncPush(cmd *cobra.Command, args []string) error {
	return runDeviceSyncMode(cmd, syncModePush)
}

// runDeviceSyncPull pulls phone data to this device.
func runDeviceSyncPull(cmd *cobra.Command, args []string) error {
	return runDeviceSyncMode(cmd, syncModePull)
}

// runDeviceSyncMode drives every selected store through one exchange with the
// phone. All three sync commands funnel through here; the mode decides which
// half of each exchange is applied.
func runDeviceSyncMode(cmd *cobra.Command, mode syncMode) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	out := cmd.OutOrStdout()

	scope, err := resolveSyncScope(cmd)
	if err != nil {
		return err
	}

	device, err := resolvePairedDevice(deviceName)
	if err != nil {
		return err
	}

	// Open the local stores before any radio work so an unreachable store
	// fails here rather than after the phone has already been handed data.
	svc, sources, err := openSyncService(cmd)
	if err != nil {
		return err
	}
	defer sources.Close()

	if dryRun {
		return reportSyncDryRun(out, device.Name, mode, scope, svc)
	}

	_, _ = fmt.Fprintf(out, "%s with device \"%s\"...\n\n", mode.verb(), device.Name)

	phoneBackend, err := connectToPhone(device, timeout, slog.Default())
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}
	defer func() { _ = phoneBackend.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _ = fmt.Fprintln(out, "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}

	var summary syncSummary
	var failures []error

	for _, store := range selectedSyncStores(scope) {
		_, _ = fmt.Fprintf(out, "%s %s...\n", mode.verb(), store.label)
		result, err := store.exchange(ctx, phoneBackend, svc, mode)
		if err != nil {
			_, _ = fmt.Fprintf(out, "  %s\n", err)
			failures = append(failures, err)
			continue
		}
		summary.set(store.label, result)
	}

	_, _ = fmt.Fprintln(out)
	summary.write(out, scope, mode)

	if len(failures) > 0 {
		return errors.Join(failures...)
	}

	if err := recordSyncState(svc); err != nil {
		return err
	}

	return nil
}

// runDeviceSyncStatus shows sync status with a paired phone.
func runDeviceSyncStatus(cmd *cobra.Command, args []string) error {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	out := cmd.OutOrStdout()

	device, err := resolvePairedDevice(deviceName)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Checking sync status with device \"%s\"...\n\n", device.Name)

	phoneBackend, err := connectToPhone(device, timeout, slog.Default())
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}
	defer func() { _ = phoneBackend.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _ = fmt.Fprintln(out, "Connecting to phone...")
	if err := phoneBackend.Connect(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}

	status, err := sendSyncRequest[pairing.LocalSyncStatusResult](ctx, phoneBackend,
		pairing.MethodLocalSyncStatus, &pairing.LocalSyncStatusParams{})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Device:    %s\n", device.Name)
	_, _ = fmt.Fprintf(out, "Address:   %s\n", device.Address)
	_, _ = fmt.Fprintf(out, "Paired:    %s\n", device.PairedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Phone:")
	_, _ = fmt.Fprintf(out, "  Device ID:  %s\n", status.DeviceID)
	_, _ = fmt.Fprintf(out, "  Last sync:  %s\n", orNever(status.LastSync))
	if len(status.StoreChecksums) == 0 {
		_, _ = fmt.Fprintln(out, "  Checksums:  (none reported)")
	} else {
		_, _ = fmt.Fprintln(out, "  Checksums:")
		for _, name := range []string{"trust_store", "oath", "passwords"} {
			if sum, ok := status.StoreChecksums[name]; ok {
				_, _ = fmt.Fprintf(out, "    %-12s %s\n", name+":", sum)
			}
		}
	}

	// The local half comes from the sync state file this machine maintains.
	svc, sources, err := openSyncService(cmd)
	if err != nil {
		return err
	}
	defer sources.Close()

	state, err := svc.LoadState()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "This device:")
	if state.LastSync.IsZero() {
		_, _ = fmt.Fprintln(out, "  Last sync:  never")
	} else {
		_, _ = fmt.Fprintf(out, "  Last sync:  %s\n", state.LastSync.UTC().Format(time.RFC3339))
	}

	return nil
}

// orNever renders an empty RFC 3339 timestamp as "never".
func orNever(value string) string {
	if value == "" {
		return "never"
	}
	return value
}

// ---------------------------------------------------------------------------
// Store exchanges
// ---------------------------------------------------------------------------

// syncCounts holds the outcome of one half of a store exchange.
type syncCounts struct {
	Added   int
	Updated int
	Skipped int
}

// syncResult pairs the counts the phone reported for what it received with
// the counts this device applied from the phone's reply.
type syncResult struct {
	Pushed syncCounts
	Pulled syncCounts
}

// syncStore binds a store's operator-facing label to its exchange function.
type syncStore struct {
	label    string
	exchange func(ctx context.Context, backend *phone.PhoneKeyBackend, svc *xkeysync.Service, mode syncMode) (syncResult, error)
}

// selectedSyncStores returns the exchanges for the selected scope, in a
// stable order.
func selectedSyncStores(scope syncScope) []syncStore {
	stores := make([]syncStore, 0, 3)
	if scope.TrustStore {
		stores = append(stores, syncStore{label: "trust-store", exchange: exchangeTrustStore})
	}
	if scope.OATH {
		stores = append(stores, syncStore{label: "oath", exchange: exchangeOATH})
	}
	if scope.Passwords {
		stores = append(stores, syncStore{label: "passwords", exchange: exchangePasswords})
	}
	return stores
}

// exchangeTrustStore sends the local trust store to the phone and merges the
// certificates the phone returns.
func exchangeTrustStore(ctx context.Context, backend *phone.PhoneKeyBackend, svc *xkeysync.Service, mode syncMode) (syncResult, error) {
	var result syncResult

	params := &pairing.LocalSyncTrustStoreParams{Certificates: []pairing.SyncCertificate{}}
	if mode.sends() {
		delta, err := svc.ComputeLocalTrustStoreDelta()
		if err != nil {
			return result, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
		}
		params.Certificates = wireCertificates(delta)
	}

	remote, err := sendSyncRequest[pairing.LocalSyncTrustStoreResult](ctx, backend,
		pairing.MethodLocalSyncTrustStore, params)
	if err != nil {
		return result, err
	}
	result.Pushed = syncCounts{Added: remote.Added, Skipped: remote.Skipped}

	if !mode.applies() {
		return result, nil
	}

	applied, err := svc.ApplyTrustStoreDelta(&xkeysync.TrustStoreDelta{
		Certificates: localCertificates(remote.Remote),
	})
	if err != nil {
		return result, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}
	result.Pulled = itemCounts(applied)

	return result, nil
}

// exchangeOATH sends the local OATH credentials to the phone and merges the
// credentials the phone returns.
func exchangeOATH(ctx context.Context, backend *phone.PhoneKeyBackend, svc *xkeysync.Service, mode syncMode) (syncResult, error) {
	var result syncResult

	params := &pairing.LocalSyncOATHParams{Credentials: []pairing.SyncOATHCredential{}}
	if mode.sends() {
		delta, err := svc.ComputeLocalOATHDelta()
		if err != nil {
			return result, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
		}
		params.Credentials = wireOATH(delta)
	}

	remote, err := sendSyncRequest[pairing.LocalSyncOATHResult](ctx, backend,
		pairing.MethodLocalSyncOATH, params)
	if err != nil {
		return result, err
	}
	result.Pushed = syncCounts{Added: remote.Added, Updated: remote.Updated, Skipped: remote.Skipped}

	if !mode.applies() {
		return result, nil
	}

	applied, err := svc.ApplyOATHDelta(&xkeysync.OATHDelta{
		Credentials: localOATH(remote.Remote),
	})
	if err != nil {
		return result, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}
	result.Pulled = itemCounts(applied)

	return result, nil
}

// exchangePasswords sends the local password entries to the phone and merges
// the entries the phone returns.
func exchangePasswords(ctx context.Context, backend *phone.PhoneKeyBackend, svc *xkeysync.Service, mode syncMode) (syncResult, error) {
	var result syncResult

	params := &pairing.LocalSyncPasswordsParams{Passwords: []pairing.SyncPassword{}}
	if mode.sends() {
		delta, err := svc.ComputeLocalPasswordDelta()
		if err != nil {
			return result, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
		}
		params.Passwords = wirePasswords(delta)
	}

	remote, err := sendSyncRequest[pairing.LocalSyncPasswordsResult](ctx, backend,
		pairing.MethodLocalSyncPasswords, params)
	if err != nil {
		return result, err
	}
	result.Pushed = syncCounts{Added: remote.Added, Updated: remote.Updated, Skipped: remote.Skipped}

	if !mode.applies() {
		return result, nil
	}

	applied, err := svc.ApplyPasswordDelta(&xkeysync.PasswordDelta{
		Passwords: localPasswords(remote.Remote),
	})
	if err != nil {
		return result, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}
	result.Pulled = itemCounts(applied)

	return result, nil
}

// sendSyncRequest performs one request/response round trip and decodes the
// result, mapping both transport and protocol failures onto the sync sentinel.
func sendSyncRequest[T any](ctx context.Context, backend *phone.PhoneKeyBackend, method string, params interface{}) (*T, error) {
	resp, err := backend.SendRequest(ctx, pairing.NewRequest(method, params))
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}
	if resp.Error != nil {
		return nil, &DetailError{
			Err:    ErrDeviceSyncFailed,
			Detail: fmt.Sprintf(": %s: [%d] %s", method, resp.Error.Code, resp.Error.Message),
		}
	}
	result, err := pairing.DecodeResult[T](resp)
	if err != nil {
		return nil, &DetailError{
			Err:    ErrDeviceSyncFailed,
			Detail: fmt.Sprintf(": %s: failed to decode result: %v", method, err),
		}
	}
	return result, nil
}

// itemCounts projects a sync service result onto the reporting counts.
func itemCounts(result *xkeysync.SyncItemResult) syncCounts {
	if result == nil {
		return syncCounts{}
	}
	return syncCounts{Added: result.Added, Updated: result.Updated, Skipped: result.Skipped}
}

// ---------------------------------------------------------------------------
// Wire conversions
// ---------------------------------------------------------------------------

// wireCertificates converts a local trust store delta to the pairing wire form.
func wireCertificates(delta *xkeysync.TrustStoreDelta) []pairing.SyncCertificate {
	if delta == nil {
		return []pairing.SyncCertificate{}
	}
	out := make([]pairing.SyncCertificate, 0, len(delta.Certificates))
	for _, cert := range delta.Certificates {
		out = append(out, pairing.SyncCertificate{
			PEM:         cert.PEM,
			Fingerprint: cert.Fingerprint,
			Purpose:     cert.Purpose,
			Source:      cert.Source,
			Tags:        cert.Tags,
		})
	}
	return out
}

// localCertificates converts wire certificates to a local trust store delta.
func localCertificates(certs []pairing.SyncCertificate) []xkeysync.TrustStoreCertSync {
	out := make([]xkeysync.TrustStoreCertSync, 0, len(certs))
	for _, cert := range certs {
		out = append(out, xkeysync.TrustStoreCertSync{
			PEM:         cert.PEM,
			Fingerprint: cert.Fingerprint,
			Purpose:     cert.Purpose,
			Source:      cert.Source,
			Tags:        cert.Tags,
		})
	}
	return out
}

// wireOATH converts a local OATH delta to the pairing wire form.
func wireOATH(delta *xkeysync.OATHDelta) []pairing.SyncOATHCredential {
	if delta == nil {
		return []pairing.SyncOATHCredential{}
	}
	out := make([]pairing.SyncOATHCredential, 0, len(delta.Credentials))
	for _, cred := range delta.Credentials {
		out = append(out, pairing.SyncOATHCredential{
			ID:          cred.ID,
			Name:        cred.Name,
			Issuer:      cred.Issuer,
			AccountName: cred.AccountName,
			Secret:      cred.Secret,
			Type:        cred.Type,
			Algorithm:   cred.Algorithm,
			Digits:      cred.Digits,
			Period:      cred.Period,
			Counter:     cred.Counter,
			UpdatedAt:   formatSyncTime(cred.UpdatedAt),
		})
	}
	return out
}

// localOATH converts wire OATH credentials to a local delta.
func localOATH(creds []pairing.SyncOATHCredential) []xkeysync.OATHCredentialSync {
	out := make([]xkeysync.OATHCredentialSync, 0, len(creds))
	for _, cred := range creds {
		out = append(out, xkeysync.OATHCredentialSync{
			ID:          cred.ID,
			Name:        cred.Name,
			Issuer:      cred.Issuer,
			AccountName: cred.AccountName,
			Secret:      cred.Secret,
			Type:        cred.Type,
			Algorithm:   cred.Algorithm,
			Digits:      cred.Digits,
			Period:      cred.Period,
			Counter:     cred.Counter,
			UpdatedAt:   parseSyncTime(cred.UpdatedAt),
		})
	}
	return out
}

// wirePasswords converts a local password delta to the pairing wire form.
func wirePasswords(delta *xkeysync.PasswordDelta) []pairing.SyncPassword {
	if delta == nil {
		return []pairing.SyncPassword{}
	}
	out := make([]pairing.SyncPassword, 0, len(delta.Passwords))
	for _, pw := range delta.Passwords {
		out = append(out, pairing.SyncPassword{
			ID:         pw.ID,
			Name:       pw.Name,
			Title:      pw.Title,
			Username:   pw.Username,
			Password:   pw.Password,
			URL:        pw.URL,
			Notes:      pw.Notes,
			FolderPath: pw.FolderPath,
			UpdatedAt:  formatSyncTime(pw.UpdatedAt),
		})
	}
	return out
}

// localPasswords converts wire password entries to a local delta.
func localPasswords(passwords []pairing.SyncPassword) []xkeysync.PasswordSync {
	out := make([]xkeysync.PasswordSync, 0, len(passwords))
	for _, pw := range passwords {
		out = append(out, xkeysync.PasswordSync{
			ID:         pw.ID,
			Name:       pw.Name,
			Title:      pw.Title,
			Username:   pw.Username,
			Password:   pw.Password,
			URL:        pw.URL,
			Notes:      pw.Notes,
			FolderPath: pw.FolderPath,
			UpdatedAt:  parseSyncTime(pw.UpdatedAt),
		})
	}
	return out
}

// formatSyncTime renders a timestamp in the RFC 3339 form the wire uses.
// The zero time becomes the empty string, which the peer reads as "unknown".
func formatSyncTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// parseSyncTime parses a wire timestamp. An absent or malformed value yields
// the zero time, which the merge treats as "older than anything local".
func parseSyncTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// ---------------------------------------------------------------------------
// Service wiring and reporting
// ---------------------------------------------------------------------------

// syncStateFile is the name of the sync state file kept in the data directory.
const syncStateFile = "sync-state.json"

// openSyncService opens every local store and wires it into a sync service.
// The caller owns the returned sources and must close them.
func openSyncService(cmd *cobra.Command) (*xkeysync.Service, *backupSources, error) {
	dataDir, err := backupDataDir()
	if err != nil {
		return nil, nil, err
	}

	sources, err := resolveBackupSources(cmd, backupStorePaths{})
	if err != nil {
		return nil, nil, err
	}

	svc, err := xkeysync.NewService(&xkeysync.Config{
		DeviceName:    getHostname(),
		StateFilePath: filepath.Join(dataDir, syncStateFile),
	}, sources.syncOptions()...)
	if err != nil {
		sources.Close()
		return nil, nil, &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}

	return svc, sources, nil
}

// recordSyncState stamps the successful sync so sync-status can report it.
func recordSyncState(svc *xkeysync.Service) error {
	state, err := svc.LoadState()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}
	state.LastSync = time.Now().UTC()
	if state.DeviceID == "" {
		state.DeviceID = getHostname()
	}
	if err := svc.SaveState(state); err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
	}
	return nil
}

// reportSyncDryRun prints what a real run would send without connecting.
func reportSyncDryRun(out io.Writer, deviceName string, mode syncMode, scope syncScope, svc *xkeysync.Service) error {
	_, _ = fmt.Fprintf(out, "[dry-run] Would %s device \"%s\"\n", dryRunPreposition(mode), deviceName)
	_, _ = fmt.Fprintf(out, "[dry-run] Stores: %v\n", scope.scopeLabels())

	if !mode.sends() {
		return nil
	}

	if scope.TrustStore {
		delta, err := svc.ComputeLocalTrustStoreDelta()
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
		}
		_, _ = fmt.Fprintf(out, "[dry-run] trust-store: %d certificate(s) to send\n", len(wireCertificates(delta)))
	}
	if scope.OATH {
		delta, err := svc.ComputeLocalOATHDelta()
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
		}
		_, _ = fmt.Fprintf(out, "[dry-run] oath: %d credential(s) to send\n", len(wireOATH(delta)))
	}
	if scope.Passwords {
		delta, err := svc.ComputeLocalPasswordDelta()
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrDeviceSyncFailed, Cause: err}
		}
		_, _ = fmt.Fprintf(out, "[dry-run] passwords: %d entry(s) to send\n", len(wirePasswords(delta)))
	}

	return nil
}

// dryRunPreposition renders the mode as it reads in the dry-run banner.
func dryRunPreposition(mode syncMode) string {
	switch mode {
	case syncModePush:
		return "push to"
	case syncModePull:
		return "pull from"
	default:
		return "sync with"
	}
}

// syncSummary holds the per-store outcome of a sync run.
type syncSummary struct {
	TrustStore syncResult
	OATH       syncResult
	Passwords  syncResult
}

// set records the result for the store identified by its label.
func (s *syncSummary) set(label string, result syncResult) {
	switch label {
	case "trust-store":
		s.TrustStore = result
	case "oath":
		s.OATH = result
	case "passwords":
		s.Passwords = result
	}
}

// write prints a per-store summary covering only the halves the mode ran.
func (s *syncSummary) write(out io.Writer, scope syncScope, mode syncMode) {
	_, _ = fmt.Fprintln(out, "Sync summary:")

	results := map[string]syncResult{
		"trust-store": s.TrustStore,
		"oath":        s.OATH,
		"passwords":   s.Passwords,
	}

	for _, store := range selectedSyncStores(scope) {
		result := results[store.label]
		_, _ = fmt.Fprintf(out, "  %-12s %s\n", store.label+":", formatSyncResult(result, mode))
	}
}

// formatSyncResult renders one store's counts for the halves the mode ran.
func formatSyncResult(result syncResult, mode syncMode) string {
	switch mode {
	case syncModePush:
		return "phone applied " + formatSyncCounts(result.Pushed)
	case syncModePull:
		return "locally applied " + formatSyncCounts(result.Pulled)
	default:
		return "phone applied " + formatSyncCounts(result.Pushed) +
			"; locally applied " + formatSyncCounts(result.Pulled)
	}
}

// formatSyncCounts renders one half's counts.
func formatSyncCounts(counts syncCounts) string {
	return fmt.Sprintf("%d added, %d updated, %d skipped",
		counts.Added, counts.Updated, counts.Skipped)
}
