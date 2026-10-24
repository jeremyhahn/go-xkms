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

package pairing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
)

// remote.createBackup and remote.restoreBackup seal and open archives with a
// key derived from the password the phone sends (go-xkms#1693), using the
// same derivation as "xkey backup create --password" and "xkey backup
// restore": backup.NewPasswordKey on create, and the KDF record stored in
// the envelope (backup.EncryptedBackup.PasswordKey, which calls
// backup.DerivePasswordKey) on restore. A backup made on either side opens
// on the other with the same password.
//
// A backup of the OATH or password store exports secrets to a phone that
// chose the password, so it is gated by BridgeConfig.SyncApproval exactly
// as remote.sync* is (approveSync). A restore reports each category's
// rejected entries, and Success is false when any entry was skipped.
//
// remote.listBackups is not served. Bridge-created backups are returned to
// the phone, not kept on this host, and the protocol has no method that
// fetches a laptop-side backup by ID, so a list of local files would name
// backups the phone cannot use.

// BackupTrustStore is the trust store the backup methods archive and
// restore.
type BackupTrustStore interface {
	backup.TrustStoreReader
	backup.TrustStoreWriter
}

// BackupOATHStore is the OATH credential store the backup methods archive
// and restore.
type BackupOATHStore interface {
	backup.OATHReader
	backup.OATHWriter
}

// BackupPasswordStore is the static password store the backup methods
// archive and restore.
type BackupPasswordStore interface {
	backup.PasswordReader
	backup.PasswordWriter
}

// backupIDTimeFormat names a backup created without a label.
const backupIDTimeFormat = "20060102-150405"

// xkmsCAReader reads the CA category of a bridge-created backup from xkmsd.
// xkey keeps no local CA store: the CA is served by xkmsd, through the same
// client every other bridge handler uses.
type xkmsCAReader struct {
	ctx    context.Context
	client transport.Client
}

var _ backup.CAReader = (*xkmsCAReader)(nil)

// GetCACertificatePEM returns the xkmsd CA certificate in PEM form.
func (r *xkmsCAReader) GetCACertificatePEM() ([]byte, error) {
	resp, err := r.client.GetCACertificate(r.ctx, &transport.GetCACertificateRequest{})
	if err != nil {
		return nil, err
	}
	return resp.CertificatePEM, nil
}

// GetCAChainPEM returns the xkmsd CA certificate chain in PEM form.
func (r *xkmsCAReader) GetCAChainPEM() ([]byte, error) {
	resp, err := r.client.GetCABundle(r.ctx, &transport.GetCABundleRequest{})
	if err != nil {
		return nil, err
	}
	return resp.BundlePEM, nil
}

// backupRestorer restores one archive category into a configured store.
type backupRestorer struct {
	item    string
	restore func(svc *backup.Service, archive *backup.Archive) (*backup.RestoreResult, error)

	// quarantines reports that what restore writes is filed under the sync
	// quarantine, so it is reported as quarantined, not restored.
	quarantines bool
}

// quarantinedTrustStore files every certificate a phone restores under the
// quarantine that sync uses for phone-supplied certificates, whatever purpose
// the archive recorded. A paired phone is a peer, not an authority over this
// host's roots: a restored certificate stays pending until the desktop
// operator reclassifies it.
type quarantinedTrustStore struct {
	store backup.TrustStoreWriter
}

// ImportPEM imports pemData under xkeysync.QuarantineImportOptions,
// discarding the recorded options.
func (q quarantinedTrustStore) ImportPEM(pemData []byte, _ *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	return q.store.ImportPEM(pemData, xkeysync.QuarantineImportOptions())
}

// errBackupPasswordRequired is the error an empty password is refused with.
var errBackupPasswordRequired = &pairingproto.SentinelCauseError{
	Sentinel: pairingproto.ErrBridgeInvalidParams,
	Cause:    pairingproto.ErrBackupPasswordRequired,
}

// handleCreateBackup handles remote.createBackup - the phone asks the laptop
// to create an encrypted backup and return it. A requested category is
// archived when this host has its store configured; the CA category is read
// from xkmsd. A request that asks for nothing is refused, and one whose
// requested categories are all unconfigured reports ErrBackupNotConfigured.
func (b *Bridge) handleCreateBackup(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p pairingproto.RemoteCreateBackupParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, pairingproto.ErrBridgeInvalidParams
	}
	if p.Password == "" {
		return nil, errBackupPasswordRequired
	}
	if !p.IncludeTrustStore && !p.IncludeOATH && !p.IncludePasswords && !p.IncludeCA {
		return nil, pairingproto.ErrBridgeInvalidParams
	}

	// The phone chooses the backup password, so encryption does not protect
	// the OATH and password stores from it: exporting them takes the same
	// desktop decision as remote.sync*, made before either store is read.
	exportsSecrets := (p.IncludeOATH && b.backupOATH != nil) || (p.IncludePasswords && b.backupPasswords != nil)
	if exportsSecrets {
		if err := b.approveSync(ctx, pairingproto.MethodRemoteCreateBackup); err != nil {
			return nil, err
		}
	}

	opts := make([]backup.Option, 0, 4)
	if p.IncludeTrustStore && b.backupTrustStore != nil {
		opts = append(opts, backup.WithTrustStore(b.backupTrustStore))
	}
	if p.IncludeOATH && b.backupOATH != nil {
		opts = append(opts, backup.WithOATH(b.backupOATH))
	}
	if p.IncludePasswords && b.backupPasswords != nil {
		opts = append(opts, backup.WithPasswords(b.backupPasswords))
	}
	if p.IncludeCA {
		opts = append(opts, backup.WithCA(&xkmsCAReader{ctx: ctx, client: b.client}))
	}
	if len(opts) == 0 {
		return nil, pairingproto.ErrBackupNotConfigured
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupFailed, Cause: err}
	}
	svc, err := backup.NewService(&backup.Config{DeviceName: hostname}, opts...)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupFailed, Cause: err}
	}

	password := []byte(p.Password)
	key, err := backup.NewPasswordKey(password)
	secure.Wipe(password)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupFailed, Cause: err}
	}
	defer key.Wipe()

	encrypted, err := svc.CreateBackup(key)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupFailed, Cause: err}
	}
	manifest, err := svc.GetManifest(encrypted, key)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupFailed, Cause: err}
	}
	payload, err := json.Marshal(encrypted)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupFailed, Cause: err}
	}

	backupID := p.Label
	if backupID == "" {
		backupID = "backup-" + manifest.Created.UTC().Format(backupIDTimeFormat)
	}
	itemCount := 0
	for _, item := range manifest.Contents {
		itemCount += item.Count
	}

	b.logger.Info("backup created", "backupID", backupID, "itemCount", itemCount)

	return &pairingproto.RemoteCreateBackupResult{
		BackupData: payload,
		BackupID:   backupID,
		ItemCount:  itemCount,
	}, nil
}

// handleRestoreBackup handles remote.restoreBackup - the phone sends an
// encrypted backup blob to the laptop for restoration. The blob is opened
// with the key re-derived from the password and the envelope's KDF record,
// and each category is merged into this host's configured store for it. A
// category with no configured store, and CA data (xkey keeps no local CA
// store), is left unrestored. With no store configured at all the request
// reports ErrBackupNotConfigured before any key is derived.
func (b *Bridge) handleRestoreBackup(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p pairingproto.RemoteRestoreBackupParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, pairingproto.ErrBridgeInvalidParams
	}
	if len(p.BackupData) == 0 {
		return nil, pairingproto.ErrBridgeInvalidParams
	}
	if p.Password == "" {
		return nil, errBackupPasswordRequired
	}

	restorers := b.backupRestorers()
	if len(restorers) == 0 {
		return nil, pairingproto.ErrBackupNotConfigured
	}

	var encrypted backup.EncryptedBackup
	if err := json.Unmarshal(p.BackupData, &encrypted); err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupRestoreFailed, Cause: err}
	}

	password := []byte(p.Password)
	key, err := encrypted.PasswordKey(password)
	secure.Wipe(password)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupRestoreFailed, Cause: err}
	}
	defer key.Wipe()

	hostname, err := os.Hostname()
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupRestoreFailed, Cause: err}
	}
	svc, err := backup.NewService(&backup.Config{DeviceName: hostname})
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupRestoreFailed, Cause: err}
	}
	archive, err := svc.DecryptBackup(&encrypted, key)
	if err != nil {
		return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupRestoreFailed, Cause: err}
	}
	defer archive.Destroy()

	restored := make([]string, 0, len(restorers))
	messages := make([]string, 0, len(restorers))
	items := make([]pairingproto.RemoteRestoreBackupItem, 0, len(restorers))
	complete := true
	for _, r := range restorers {
		result, err := r.restore(svc, archive)
		if err != nil {
			return nil, &pairingproto.SentinelCauseError{Sentinel: pairingproto.ErrBackupRestoreFailed, Cause: err}
		}
		if result.Skipped > 0 || len(result.Errors) > 0 {
			complete = false
		}
		item := pairingproto.RemoteRestoreBackupItem{
			Item:    r.item,
			Skipped: result.Skipped,
			Errors:  result.Errors,
		}
		if r.quarantines {
			item.Quarantined = result.Restored
			messages = append(messages, fmt.Sprintf("%s: %d quarantined, %d skipped", r.item, item.Quarantined, item.Skipped))
		} else {
			item.Restored = result.Restored
			messages = append(messages, fmt.Sprintf("%s: %d restored, %d skipped", r.item, item.Restored, item.Skipped))
		}
		if item.Restored > 0 {
			restored = append(restored, r.item)
		}
		items = append(items, item)
	}

	b.logger.Info("backup restored", "categories", restored, "complete", complete)

	return &pairingproto.RemoteRestoreBackupResult{
		Success:  complete,
		Restored: restored,
		Message:  strings.Join(messages, "; "),
		Items:    items,
	}, nil
}

// backupRestorers returns a restorer for each backup store this bridge has
// configured, in archive order.
func (b *Bridge) backupRestorers() []backupRestorer {
	restorers := make([]backupRestorer, 0, 3)
	if b.backupTrustStore != nil {
		restorers = append(restorers, backupRestorer{
			item: backup.ItemTrustStore,
			restore: func(svc *backup.Service, archive *backup.Archive) (*backup.RestoreResult, error) {
				return svc.RestoreTrustStore(archive, quarantinedTrustStore{store: b.backupTrustStore})
			},
			quarantines: true,
		})
	}
	if b.backupOATH != nil {
		restorers = append(restorers, backupRestorer{
			item: backup.ItemOATH,
			restore: func(svc *backup.Service, archive *backup.Archive) (*backup.RestoreResult, error) {
				return svc.RestoreOATH(archive, b.backupOATH)
			},
		})
	}
	if b.backupPasswords != nil {
		restorers = append(restorers, backupRestorer{
			item: backup.ItemPasswords,
			restore: func(svc *backup.Service, archive *backup.Archive) (*backup.RestoreResult, error) {
				return svc.RestorePasswords(archive, b.backupPasswords)
			},
		})
	}
	return restorers
}

// handleListBackupsForRestore handles remote.listBackups - the phone asks the
// laptop to enumerate available backups. See the package note above: this
// host keeps no bridge-created backups, so this reports
// ErrBackupNotConfigured.
func (b *Bridge) handleListBackupsForRestore(_ context.Context, _ json.RawMessage) (interface{}, error) {
	b.logger.Info("backup list requested")

	return nil, pairingproto.ErrBackupNotConfigured
}
