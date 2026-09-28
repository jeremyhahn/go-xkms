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

// The remote.*Backup* methods are unimplemented pending an architecture
// decision this package cannot make on its own (go-xkms#690): backup.Service
// encrypts every archive with a caller-supplied 32-byte key
// (backup.Service.CreateBackup/DecryptBackup), and neither
// RemoteCreateBackupParams/Result nor RemoteRestoreBackupParams carries one.
// The phone-bridge wire protocol must not change to add one (out of scope for
// this task), so the key has to come from somewhere the Bridge already
// trusts on this host -- a passphrase or key file the CLI supplies when it
// starts "xkey device listen", or a key derived from material the bridge
// does not currently have access to. Either choice is a security-relevant
// decision (what protects a backup blob a paired phone may retain
// indefinitely) that needs the owner's sign-off, not a guess baked into a
// handler.
//
// remote.listBackups has the same open question one level further out:
// enumerating "available backups" presumes a persistence location and an
// ID/label scheme for backups created through this bridge, and no such
// convention exists anywhere in this codebase today.
//
// Until that decision is made, all three handlers report the feature as
// unconfigured rather than fabricating success or silently discarding the
// phone's data.

// handleCreateBackup handles remote.createBackup - the phone asks the laptop
// to create an encrypted backup and return it. See the package-level note
// above: this always reports ErrBackupNotConfigured.
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

	return nil, ErrBackupNotConfigured
}

// handleRestoreBackup handles remote.restoreBackup - the phone sends an
// encrypted backup blob to the laptop for restoration. See the package-level
// note above: this always reports ErrBackupNotConfigured.
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

	return nil, ErrBackupNotConfigured
}

// handleListBackupsForRestore handles remote.listBackups - the phone asks the
// laptop to enumerate available backups. See the package-level note above:
// this always reports ErrBackupNotConfigured.
func (b *Bridge) handleListBackupsForRestore(_ context.Context, _ json.RawMessage) (interface{}, error) {
	b.logger.Info("backup list requested")

	return nil, ErrBackupNotConfigured
}
