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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Device backup errors.
var (
	// ErrBackupToDeviceFailed indicates sending backup to device failed.
	ErrBackupToDeviceFailed = errors.New("backup: send to device failed")

	// ErrBackupFromDeviceFailed indicates restoring from device failed.
	ErrBackupFromDeviceFailed = errors.New("backup: restore from device failed")

	// ErrBackupDeviceEmptyPayload indicates the phone returned a backup record
	// with no sealed data, so there is nothing to restore.
	ErrBackupDeviceEmptyPayload = errors.New("backup: phone returned an empty backup")
)

// deviceBackupTransport is the request/response channel to a paired phone.
// The concrete implementation is the BLE Noise transport; the interface keeps
// the command testable without a radio.
type deviceBackupTransport interface {
	Connect(ctx context.Context) error
	SendRequest(ctx context.Context, req *pairing.Request) (*pairing.Response, error)
	Close() error
}

// dialPairedDevice opens a channel to a paired phone. It is a variable so
// tests can substitute an in-process transport.
var dialPairedDevice = func(cfg *phone.PhoneKeyBackendConfig) (deviceBackupTransport, error) {
	return phone.NewPhoneKeyBackend(cfg)
}

// backupToDeviceCmd sends a backup to a paired phone device.
var backupToDeviceCmd = &cobra.Command{
	Use:   "to-device",
	Short: "Send backup to a paired phone",
	Long: `Send an encrypted backup of xkey data to a paired phone device
over a secure BLE Noise protocol channel.

The backup holds the same data as "xkey backup create" -- trust store
certificates, OATH credentials, and static passwords read from the xkey data
directory -- sealed with XChaCha20-Poly1305 before it leaves this machine. The
phone stores the sealed envelope and can return it later for restore; it never
sees the plaintext.

If no password is supplied (--password-stdin or XKEY_BACKUP_PASSWORD) a
random 256-bit key is generated and printed. Store it securely: without it
the backup on the phone cannot be read. A password is stretched with
Argon2id under a random salt recorded in the envelope header.

The command fails rather than sending an empty backup when every data store is
empty or unreachable.

Examples:
  xkey backup to-device
  xkey backup to-device --password-stdin < password.txt
  xkey backup to-device --device "Pixel 8"
  xkey backup to-device --timeout 2m`,
	RunE: runBackupToDevice,
}

// backupFromDeviceCmd restores a backup from a paired phone device.
var backupFromDeviceCmd = &cobra.Command{
	Use:   "from-device",
	Short: "Restore backup from a paired phone",
	Long: `Restore xkey data from an encrypted backup stored on a paired phone
device. The sealed envelope is retrieved over a secure BLE Noise protocol
channel, opened locally with the password or key used when the backup was
sent, and merged into the stores under the xkey data directory.

Requires the same password or key used by "xkey backup to-device"; any other
credential fails with a decryption error and nothing is written.

Examples:
  xkey backup from-device --password-stdin < password.txt
  xkey backup from-device --key-stdin < key.hex
  xkey backup from-device --device "Pixel 8" --timeout 2m`,
	RunE: runBackupFromDevice,
}

func init() {
	backupCmd.AddCommand(backupToDeviceCmd)
	backupCmd.AddCommand(backupFromDeviceCmd)

	registerBackupToDeviceFlags(backupToDeviceCmd)
	registerBackupFromDeviceFlags(backupFromDeviceCmd)
}

// runBackupToDevice seals a backup of the local xkey data and stores it on a
// paired phone device.
func runBackupToDevice(cmd *cobra.Command, args []string) (err error) {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	out := cmd.OutOrStdout()

	device, err := resolvePairedDevice(deviceName)
	if err != nil {
		return err
	}

	// Seal the backup before any radio work: an unreachable data store or an
	// empty backup must fail here rather than after the phone has been asked
	// to store something.
	key, err := resolveSealingKey(cmd, ErrBackupToDeviceFailed)
	if err != nil {
		return err
	}
	defer key.Wipe()

	sources, err := resolveBackupSources(cmd, backupStorePathsFromFlags(cmd), true)
	if err != nil {
		return err
	}
	defer sources.Close()

	svc, err := backup.NewService(&backup.Config{DeviceName: getHostname()}, sources.readerOptions()...)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupToDeviceFailed, Cause: err}
	}

	encrypted, err := svc.CreateBackup(key)
	if err != nil {
		if errors.Is(err, backup.ErrEmptyBackup) {
			return &DetailError{Err: ErrBackupNoData, Detail: ": " + sources.summary()}
		}
		return &SentinelCauseError{Sentinel: ErrBackupToDeviceFailed, Cause: err}
	}

	// Open the freshly sealed envelope before sending it. This yields the
	// authoritative item counts for the report and proves the payload the
	// phone is about to hold can be opened with the credential the operator
	// was handed.
	manifest, err := svc.GetManifest(encrypted, key)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupToDeviceFailed, Cause: err}
	}

	payload, err := json.Marshal(encrypted)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupToDeviceFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Sending backup to device \"%s\"...\n\n", device.Name)

	transport, err := connectPairedDevice(device, timeout, ErrBackupToDeviceFailed)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := transport.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _ = fmt.Fprintln(out, "Connecting to phone...")
	if err := transport.Connect(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupToDeviceFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(out, "Sending backup data...")

	req := pairing.NewRequest(pairing.MethodLocalCreateBackup, &pairing.LocalCreateBackupParams{
		BackupData: payload,
		Label:      fmt.Sprintf("xkey-backup-%s", time.Now().UTC().Format("20060102-150405")),
	})

	resp, err := transport.SendRequest(ctx, req)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupToDeviceFailed, Cause: err}
	}
	if resp.Error != nil {
		return &DetailError{Err: ErrBackupToDeviceFailed, Detail: fmt.Sprintf(": [%d] %s", resp.Error.Code, resp.Error.Message)}
	}

	result, err := pairing.DecodeResult[pairing.LocalCreateBackupResult](resp)
	if err != nil {
		return &WrappedError{Msg: "failed to decode backup result", Err: err}
	}
	if !result.Success {
		return &DetailError{Err: ErrBackupToDeviceFailed, Detail: ": " + result.Message}
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "  Backup ID:    %s\n", result.BackupID)
	writeManifestSummary(out, newBackupManifest(manifest))
	_, _ = fmt.Fprintf(out, "  Format:       %s v%d (XChaCha20-Poly1305)\n", encrypted.Magic, encrypted.Version)
	_, _ = fmt.Fprintf(out, "  Size:         %s\n", formatSize(int64(len(payload))))
	writeSkippedSources(out, sources.skipped)

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Backup sent to device successfully.")

	return nil
}

// runBackupFromDevice retrieves the sealed backup held by a paired phone and
// merges it back into the local xkey data stores.
func runBackupFromDevice(cmd *cobra.Command, args []string) (err error) {
	deviceName, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	out := cmd.OutOrStdout()

	// The credential is required to open the envelope, so refuse before
	// connecting rather than after prompting the operator for biometrics.
	// A password's key is derived once the envelope's KDF record arrives.
	credential, err := resolveBackupCredential(cmd)
	if err != nil {
		return err
	}
	defer credential.wipe()

	device, err := resolvePairedDevice(deviceName)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Restoring backup from device \"%s\"...\n\n", device.Name)

	transport, err := connectPairedDevice(device, timeout, ErrBackupFromDeviceFailed)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := transport.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _ = fmt.Fprintln(out, "Connecting to phone...")
	if err := transport.Connect(ctx); err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupFromDeviceFailed, Cause: err}
	}

	_, _ = fmt.Fprintln(out, "Requesting backup data (check phone for biometric prompt)...")
	_, _ = fmt.Fprintln(out)

	req := pairing.NewRequest(pairing.MethodLocalRestoreBackup, &pairing.LocalRestoreBackupParams{})

	resp, err := transport.SendRequest(ctx, req)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupFromDeviceFailed, Cause: err}
	}
	if resp.Error != nil {
		return &DetailError{Err: ErrBackupFromDeviceFailed, Detail: fmt.Sprintf(": [%d] %s", resp.Error.Code, resp.Error.Message)}
	}

	result, err := pairing.DecodeResult[pairing.LocalRestoreBackupResult](resp)
	if err != nil {
		return &WrappedError{Msg: "failed to decode restore result", Err: err}
	}
	if len(result.BackupData) == 0 {
		return &DetailError{Err: ErrBackupDeviceEmptyPayload, Detail: fmt.Sprintf(": backup %s", result.BackupID)}
	}

	var encrypted backup.EncryptedBackup
	if err := json.Unmarshal(result.BackupData, &encrypted); err != nil {
		return &DetailError{
			Err:    ErrBackupDecryptFailed,
			Detail: ": phone returned data that is not an xkey backup envelope",
		}
	}

	key, err := credential.keyFor(&encrypted)
	if err != nil {
		return err
	}

	svc, err := backup.NewService(&backup.Config{DeviceName: getHostname()})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBackupFromDeviceFailed, Cause: err}
	}

	archive, err := svc.DecryptBackup(&encrypted, key)
	if err != nil {
		return classifyBackupDecryptError(err)
	}

	sources, err := resolveBackupSources(cmd, backupStorePathsFromFlags(cmd), false)
	if err != nil {
		return err
	}
	defer sources.Close()

	_, _ = fmt.Fprintf(out, "  Backup ID:    %s\n", result.BackupID)
	_, _ = fmt.Fprintf(out, "  Received:     %s\n", result.CreatedAt)
	_, _ = fmt.Fprintf(out, "  Size:         %s\n", formatSize(int64(len(result.BackupData))))
	writeManifestSummary(out, newBackupManifest(&archive.Manifest))
	_, _ = fmt.Fprintln(out)

	results, err := restoreArchive(svc, archive, sources)
	if err != nil {
		return err
	}

	skipped := 0
	for _, restored := range results {
		_, _ = fmt.Fprintf(out, "  %-18s restored %d, skipped %d\n",
			restored.ItemType+":", restored.Restored, restored.Skipped)
		for _, msg := range restored.Errors {
			_, _ = fmt.Fprintf(out, "      skipped: %s\n", msg)
		}
		skipped += restored.Skipped
	}

	// Categories the archive carries that the CLI has no writer for are
	// reported as an incomplete restore rather than silently dropped.
	if archive.CAData != nil {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintf(out, "  %s: not restored (%s)\n", backup.ItemCAData, backupCASkipReason)
		return &DetailError{
			Err:    ErrBackupRestoreIncomplete,
			Detail: fmt.Sprintf(": %s could not be restored: %s", backup.ItemCAData, backupCASkipReason),
		}
	}

	_, _ = fmt.Fprintln(out)
	if skipped > 0 {
		_, _ = fmt.Fprintf(out, "Restore from device completed with %d skipped item(s).\n", skipped)
		return nil
	}
	_, _ = fmt.Fprintln(out, "Backup restored from device successfully.")

	return nil
}

// resolvePairedDevice loads the paired device configuration and selects the
// device the operator asked for, or the default when none was named.
func resolvePairedDevice(deviceName string) (*PairedDevice, error) {
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrDeviceNotPaired
		}
		return nil, &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}

	if len(cfg.Devices) == 0 {
		return nil, ErrDeviceNotPaired
	}

	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return nil, &DetailError{Err: ErrDeviceNotFound, Detail: fmt.Sprintf(": %s", deviceName)}
		}
		return nil, ErrDeviceNotPaired
	}

	return device, nil
}

// connectPairedDevice builds the Noise-protected transport for a paired
// device. The sentinel names the operation the failure belongs to.
func connectPairedDevice(device *PairedDevice, timeout time.Duration, sentinel error) (deviceBackupTransport, error) {
	cfg, err := newPairedDeviceBackendConfig(device, timeout, slog.Default())
	if err != nil {
		return nil, err
	}

	transport, err := dialPairedDevice(cfg)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: sentinel, Cause: err}
	}

	return transport, nil
}
