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
	"time"

	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
)

// Sync status checksum map keys, matching the convention local.syncStatus
// already reports from the phone side (cmd/xkey/cmd/device_sync.go).
const (
	syncChecksumTrustStore = "trust_store"
	syncChecksumOATH       = "oath"
	syncChecksumPasswords  = "passwords"
)

// handleSyncTrustStore handles remote.syncTrustStore - the phone sends its
// trust store certificates to the laptop for synchronization.
//
// Certificates are merged through the Bridge's configured sync.Service (see
// BridgeConfig.SyncService), the same service "xkey device sync" drives from
// the laptop-initiated side. Trust store sync is a union merge: every
// certificate not already present (by fingerprint) is added, duplicates are
// skipped, and the laptop's own certificates are returned so the phone can
// merge them too. When no sync service is configured, ErrSyncNotConfigured
// is returned.
func (b *Bridge) handleSyncTrustStore(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteSyncTrustStoreParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("trust store sync requested",
		"certificateCount", len(p.Certificates))

	if b.syncService == nil {
		return nil, ErrSyncNotConfigured
	}

	applied, err := b.syncService.ApplyTrustStoreDelta(wireToTrustStoreDelta(p.Certificates))
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
	}

	local, err := b.syncService.ComputeLocalTrustStoreDelta()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
	}

	return &RemoteSyncTrustStoreResult{
		Added:   applied.Added,
		Skipped: applied.Skipped,
		Local:   trustStoreDeltaToWire(local),
	}, nil
}

// handleSyncOATH handles remote.syncOATH - the phone sends its OATH
// credentials to the laptop for synchronization.
//
// Credentials are merged through the Bridge's configured sync.Service using
// last-modified-wins conflict resolution on UpdatedAt. When no sync service
// is configured, ErrSyncNotConfigured is returned.
func (b *Bridge) handleSyncOATH(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteSyncOATHParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("OATH sync requested",
		"credentialCount", len(p.Credentials))

	if b.syncService == nil {
		return nil, ErrSyncNotConfigured
	}

	applied, err := b.syncService.ApplyOATHDelta(wireToOATHDelta(p.Credentials))
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
	}

	local, err := b.syncService.ComputeLocalOATHDelta()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
	}

	return &RemoteSyncOATHResult{
		Added:   applied.Added,
		Updated: applied.Updated,
		Skipped: applied.Skipped,
		Local:   oathDeltaToWire(local),
	}, nil
}

// handleSyncPasswords handles remote.syncPasswords - the phone sends its
// passwords to the laptop for synchronization.
//
// Passwords are merged through the Bridge's configured sync.Service using
// last-modified-wins conflict resolution on UpdatedAt. When no sync service
// is configured, ErrSyncNotConfigured is returned.
func (b *Bridge) handleSyncPasswords(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteSyncPasswordsParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("password sync requested",
		"passwordCount", len(p.Passwords))

	if b.syncService == nil {
		return nil, ErrSyncNotConfigured
	}

	applied, err := b.syncService.ApplyPasswordDelta(wireToPasswordDelta(p.Passwords))
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
	}

	local, err := b.syncService.ComputeLocalPasswordDelta()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
	}

	return &RemoteSyncPasswordsResult{
		Added:   applied.Added,
		Updated: applied.Updated,
		Skipped: applied.Skipped,
		Local:   passwordDeltaToWire(local),
	}, nil
}

// handleSyncAll handles remote.syncAll - the phone requests a full
// bidirectional sync of selected data types.
//
// remote.syncAll carries no phone-side data (see RemoteSyncAllParams), so it
// answers with the laptop's current data for each requested category rather
// than applying anything; a phone that wants to push data uses the
// per-store remote.sync* methods instead. When no sync service is
// configured, ErrSyncNotConfigured is returned.
func (b *Bridge) handleSyncAll(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteSyncAllParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	b.logger.Info("full sync requested",
		"includeTrustStore", p.IncludeTrustStore,
		"includeOATH", p.IncludeOATH,
		"includePasswords", p.IncludePasswords)

	if b.syncService == nil {
		return nil, ErrSyncNotConfigured
	}

	result := &RemoteSyncAllResult{}

	if p.IncludeTrustStore {
		local, err := b.syncService.ComputeLocalTrustStoreDelta()
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
		}
		result.TrustStore = &RemoteSyncTrustStoreResult{
			Local: trustStoreDeltaToWire(local),
		}
	}

	if p.IncludeOATH {
		local, err := b.syncService.ComputeLocalOATHDelta()
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
		}
		result.OATH = &RemoteSyncOATHResult{
			Local: oathDeltaToWire(local),
		}
	}

	if p.IncludePasswords {
		local, err := b.syncService.ComputeLocalPasswordDelta()
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
		}
		result.Passwords = &RemoteSyncPasswordsResult{
			Local: passwordDeltaToWire(local),
		}
	}

	return result, nil
}

// handleSyncStatus handles remote.syncStatus - the phone requests the
// current sync status from the laptop.
//
// Without a configured sync service there is nothing to report but the
// device ID, which is a valid status ("nothing has been synced yet") rather
// than an error. With one configured, the last sync timestamp comes from the
// persisted sync.State and the checksums are computed live over each store's
// current data, mirroring what local.syncStatus reports from the phone side.
func (b *Bridge) handleSyncStatus(_ context.Context, _ json.RawMessage) (interface{}, error) {
	b.logger.Info("sync status requested")

	if b.syncService == nil {
		return &RemoteSyncStatusResult{
			DeviceID:       b.config.DeviceID,
			StoreChecksums: map[string]string{},
		}, nil
	}

	state, err := b.syncService.LoadState()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSyncFailed, Cause: err}
	}

	deviceID := state.DeviceID
	if deviceID == "" {
		deviceID = b.config.DeviceID
	}

	var lastSync string
	if !state.LastSync.IsZero() {
		lastSync = state.LastSync.UTC().Format(time.RFC3339)
	}

	// Keys match the "trust_store"/"oath"/"passwords" convention
	// local.syncStatus already reports from the phone side (see
	// cmd/xkey/cmd/device_sync.go's status display), not the hyphenated
	// backup-package DataType* constants: the two directions of the same
	// status method must agree on what a checksum is keyed by.
	checksums := make(map[string]string, 3)
	if delta, dErr := b.syncService.ComputeLocalTrustStoreDelta(); dErr == nil && delta != nil {
		if data, mErr := json.Marshal(delta); mErr == nil {
			checksums[syncChecksumTrustStore] = xkeysync.Checksum(data)
		}
	}
	if delta, dErr := b.syncService.ComputeLocalOATHDelta(); dErr == nil && delta != nil {
		if data, mErr := json.Marshal(delta); mErr == nil {
			checksums[syncChecksumOATH] = xkeysync.Checksum(data)
		}
	}
	if delta, dErr := b.syncService.ComputeLocalPasswordDelta(); dErr == nil && delta != nil {
		if data, mErr := json.Marshal(delta); mErr == nil {
			checksums[syncChecksumPasswords] = xkeysync.Checksum(data)
		}
	}

	return &RemoteSyncStatusResult{
		LastSync:       lastSync,
		DeviceID:       deviceID,
		StoreChecksums: checksums,
	}, nil
}

// ---------------------------------------------------------------------------
// Wire conversions
// ---------------------------------------------------------------------------

// wireToTrustStoreDelta converts wire certificates to a sync.TrustStoreDelta.
func wireToTrustStoreDelta(certs []SyncCertificate) *xkeysync.TrustStoreDelta {
	delta := &xkeysync.TrustStoreDelta{
		Certificates: make([]xkeysync.TrustStoreCertSync, 0, len(certs)),
	}
	for _, c := range certs {
		delta.Certificates = append(delta.Certificates, xkeysync.TrustStoreCertSync{
			PEM:         c.PEM,
			Fingerprint: c.Fingerprint,
			Purpose:     c.Purpose,
			Source:      c.Source,
			Tags:        c.Tags,
		})
	}
	return delta
}

// trustStoreDeltaToWire converts a sync.TrustStoreDelta to wire certificates.
func trustStoreDeltaToWire(delta *xkeysync.TrustStoreDelta) []SyncCertificate {
	if delta == nil {
		return []SyncCertificate{}
	}
	out := make([]SyncCertificate, 0, len(delta.Certificates))
	for _, c := range delta.Certificates {
		out = append(out, SyncCertificate{
			PEM:         c.PEM,
			Fingerprint: c.Fingerprint,
			Purpose:     c.Purpose,
			Source:      c.Source,
			Tags:        c.Tags,
		})
	}
	return out
}

// wireToOATHDelta converts wire OATH credentials to a sync.OATHDelta.
func wireToOATHDelta(creds []SyncOATHCredential) *xkeysync.OATHDelta {
	delta := &xkeysync.OATHDelta{
		Credentials: make([]xkeysync.OATHCredentialSync, 0, len(creds)),
	}
	for _, c := range creds {
		delta.Credentials = append(delta.Credentials, xkeysync.OATHCredentialSync{
			ID:          c.ID,
			Name:        c.Name,
			Issuer:      c.Issuer,
			AccountName: c.AccountName,
			Secret:      c.Secret,
			Type:        c.Type,
			Algorithm:   c.Algorithm,
			Digits:      c.Digits,
			Period:      c.Period,
			Counter:     c.Counter,
			UpdatedAt:   parseSyncTimestamp(c.UpdatedAt),
		})
	}
	return delta
}

// oathDeltaToWire converts a sync.OATHDelta to wire OATH credentials.
func oathDeltaToWire(delta *xkeysync.OATHDelta) []SyncOATHCredential {
	if delta == nil {
		return []SyncOATHCredential{}
	}
	out := make([]SyncOATHCredential, 0, len(delta.Credentials))
	for _, c := range delta.Credentials {
		out = append(out, SyncOATHCredential{
			ID:          c.ID,
			Name:        c.Name,
			Issuer:      c.Issuer,
			AccountName: c.AccountName,
			Secret:      c.Secret,
			Type:        c.Type,
			Algorithm:   c.Algorithm,
			Digits:      c.Digits,
			Period:      c.Period,
			Counter:     c.Counter,
			UpdatedAt:   formatSyncTimestamp(c.UpdatedAt),
		})
	}
	return out
}

// wireToPasswordDelta converts wire passwords to a sync.PasswordDelta.
func wireToPasswordDelta(passwords []SyncPassword) *xkeysync.PasswordDelta {
	delta := &xkeysync.PasswordDelta{
		Passwords: make([]xkeysync.PasswordSync, 0, len(passwords)),
	}
	for _, p := range passwords {
		delta.Passwords = append(delta.Passwords, xkeysync.PasswordSync{
			ID:         p.ID,
			Name:       p.Name,
			Title:      p.Title,
			Username:   p.Username,
			Password:   p.Password,
			URL:        p.URL,
			Notes:      p.Notes,
			FolderPath: p.FolderPath,
			UpdatedAt:  parseSyncTimestamp(p.UpdatedAt),
		})
	}
	return delta
}

// passwordDeltaToWire converts a sync.PasswordDelta to wire passwords.
func passwordDeltaToWire(delta *xkeysync.PasswordDelta) []SyncPassword {
	if delta == nil {
		return []SyncPassword{}
	}
	out := make([]SyncPassword, 0, len(delta.Passwords))
	for _, p := range delta.Passwords {
		out = append(out, SyncPassword{
			ID:         p.ID,
			Name:       p.Name,
			Title:      p.Title,
			Username:   p.Username,
			Password:   p.Password,
			URL:        p.URL,
			Notes:      p.Notes,
			FolderPath: p.FolderPath,
			UpdatedAt:  formatSyncTimestamp(p.UpdatedAt),
		})
	}
	return out
}

// formatSyncTimestamp renders a timestamp in the RFC 3339 form the wire
// uses. The zero time becomes the empty string, which the peer reads as
// "unknown".
func formatSyncTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// parseSyncTimestamp parses a wire timestamp. An absent or malformed value
// yields the zero time, which the merge treats as "older than anything
// local".
func parseSyncTimestamp(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
