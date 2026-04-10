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

// handleSyncTrustStore handles remote.syncTrustStore - the phone sends its
// trust store certificates to the laptop for synchronization.
//
// This is a placeholder implementation. The bridge will be connected to the
// trust store sync service in the CLI layer when the sync command is invoked.
// The actual sync logic (deduplication, conflict resolution, merging) will be
// implemented in the sync service and wired in via functional options or a
// setter on the Bridge.
func (b *Bridge) handleSyncTrustStore(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteSyncTrustStoreParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("trust store sync requested",
		"certificateCount", len(p.Certificates))

	return &RemoteSyncTrustStoreResult{
		Added:   0,
		Skipped: len(p.Certificates),
		Local:   []SyncCertificate{},
	}, nil
}

// handleSyncOATH handles remote.syncOATH - the phone sends its OATH
// credentials to the laptop for synchronization.
//
// This is a placeholder implementation. The actual OATH sync logic
// (credential matching, update detection, conflict resolution) will be
// implemented in the sync service and wired in when the feature is enabled.
func (b *Bridge) handleSyncOATH(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteSyncOATHParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("OATH sync requested",
		"credentialCount", len(p.Credentials))

	return &RemoteSyncOATHResult{
		Added:   0,
		Updated: 0,
		Skipped: len(p.Credentials),
		Local:   []SyncOATHCredential{},
	}, nil
}

// handleSyncPasswords handles remote.syncPasswords - the phone sends its
// passwords to the laptop for synchronization.
//
// This is a placeholder implementation. The actual password sync logic
// (deduplication, timestamp-based conflict resolution, folder merging) will
// be implemented in the sync service and wired in when the feature is enabled.
func (b *Bridge) handleSyncPasswords(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteSyncPasswordsParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("password sync requested",
		"passwordCount", len(p.Passwords))

	return &RemoteSyncPasswordsResult{
		Added:   0,
		Updated: 0,
		Skipped: len(p.Passwords),
		Local:   []SyncPassword{},
	}, nil
}

// handleSyncAll handles remote.syncAll - the phone requests a full
// bidirectional sync of selected data types.
//
// This is a placeholder implementation. The actual full sync logic
// (orchestrating individual sync operations, transaction semantics) will be
// implemented in the sync service and wired in when the feature is enabled.
func (b *Bridge) handleSyncAll(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteSyncAllParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("full sync requested",
		"includeTrustStore", p.IncludeTrustStore,
		"includeOATH", p.IncludeOATH,
		"includePasswords", p.IncludePasswords)

	result := &RemoteSyncAllResult{}

	if p.IncludeTrustStore {
		result.TrustStore = &RemoteSyncTrustStoreResult{
			Added:   0,
			Skipped: 0,
			Local:   []SyncCertificate{},
		}
	}

	if p.IncludeOATH {
		result.OATH = &RemoteSyncOATHResult{
			Added:   0,
			Updated: 0,
			Skipped: 0,
			Local:   []SyncOATHCredential{},
		}
	}

	if p.IncludePasswords {
		result.Passwords = &RemoteSyncPasswordsResult{
			Added:   0,
			Updated: 0,
			Skipped: 0,
			Local:   []SyncPassword{},
		}
	}

	return result, nil
}

// handleSyncStatus handles remote.syncStatus - the phone requests the
// current sync status from the laptop.
//
// This is a placeholder implementation. The actual status reporting logic
// (last sync timestamp, data store checksums, device ID resolution) will be
// implemented in the sync service and wired in when the feature is enabled.
func (b *Bridge) handleSyncStatus(_ context.Context, _ json.RawMessage) (interface{}, error) {
	b.logger.Info("sync status requested")

	return &RemoteSyncStatusResult{
		DeviceID:       b.config.DeviceID,
		StoreChecksums: map[string]string{},
	}, nil
}
