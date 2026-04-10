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
)

// handleCreateBackup handles remote.createBackup - the phone asks the laptop
// to create an encrypted backup and return it.
//
// This is a placeholder implementation. The bridge will be connected to the
// backup service in the CLI layer when the backup command is invoked. The
// actual backup creation logic (key enumeration, encryption, packaging) will
// be implemented in the backup service and wired in via functional options or
// a setter on the Bridge.
func (b *Bridge) handleCreateBackup(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteCreateBackupParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("backup creation requested",
		"includeTrustStore", p.IncludeTrustStore,
		"includeOATH", p.IncludeOATH,
		"includePasswords", p.IncludePasswords,
		"includeCA", p.IncludeCA,
		"label", p.Label)

	return &RemoteCreateBackupResult{
		BackupData: nil,
		BackupID:   "",
		ItemCount:  0,
	}, nil
}

// handleRestoreBackup handles remote.restoreBackup - the phone sends an
// encrypted backup blob to the laptop for restoration.
//
// This is a placeholder implementation. The actual restore logic (decryption,
// validation, item-by-item import) will be implemented in the backup service
// and wired in when the restore command is invoked.
func (b *Bridge) handleRestoreBackup(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteRestoreBackupParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	if len(p.BackupData) == 0 {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("backup restore requested",
		"backupDataLen", len(p.BackupData))

	return &RemoteRestoreBackupResult{
		Success:  true,
		Restored: []string{},
		Message:  "backup received",
	}, nil
}

// handleListBackupsForRestore handles remote.listBackups - the phone asks the
// laptop to enumerate available backups.
//
// This is a placeholder implementation. The actual listing logic (directory
// enumeration, metadata parsing) will be implemented in the backup service
// and wired in when the list command is invoked.
func (b *Bridge) handleListBackupsForRestore(_ context.Context, _ json.RawMessage) (interface{}, error) {
	b.logger.Info("backup list requested")

	return &RemoteListBackupsResult{
		Backups: []BackupInfo{},
	}, nil
}
