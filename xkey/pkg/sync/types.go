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

package sync

import "time"

// SyncDirection indicates the direction of a sync operation.
type SyncDirection string

const (
	// SyncBidirectional synchronizes changes in both directions.
	SyncBidirectional SyncDirection = "bidirectional"

	// SyncPush sends local changes to the remote device.
	SyncPush SyncDirection = "push"

	// SyncPull receives remote changes from the remote device.
	SyncPull SyncDirection = "pull"
)

// SyncScope specifies which data stores to synchronize.
type SyncScope struct {
	TrustStore bool `json:"trust_store"`
	OATH       bool `json:"oath"`
	Passwords  bool `json:"passwords"`
	CA         bool `json:"ca"`
}

// SyncScopeAll returns a scope that includes all data stores.
func SyncScopeAll() SyncScope {
	return SyncScope{
		TrustStore: true,
		OATH:       true,
		Passwords:  true,
		CA:         true,
	}
}

// SyncResult summarizes the outcome of a sync operation.
type SyncResult struct {
	Direction  SyncDirection    `json:"direction"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt time.Time        `json:"finished_at"`
	Items      []SyncItemResult `json:"items"`
	Conflicts  []SyncConflict   `json:"conflicts,omitempty"`
}

// TotalAdded returns the total number of items added across all stores.
func (r *SyncResult) TotalAdded() int {
	total := 0
	for i := range r.Items {
		total += r.Items[i].Added
	}
	return total
}

// TotalUpdated returns the total number of items updated across all stores.
func (r *SyncResult) TotalUpdated() int {
	total := 0
	for i := range r.Items {
		total += r.Items[i].Updated
	}
	return total
}

// TotalSkipped returns the total number of items skipped across all stores.
func (r *SyncResult) TotalSkipped() int {
	total := 0
	for i := range r.Items {
		total += r.Items[i].Skipped
	}
	return total
}

// HasConflicts returns true if any unresolved conflicts exist.
func (r *SyncResult) HasConflicts() bool {
	return len(r.Conflicts) > 0
}

// SyncItemResult summarizes the sync outcome for a single data type.
type SyncItemResult struct {
	DataType string   `json:"data_type"`
	Added    int      `json:"added"`
	Updated  int      `json:"updated"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors,omitempty"`
}

// SyncConflict describes a conflict found during synchronization.
type SyncConflict struct {
	DataType   string    `json:"data_type"`
	ItemID     string    `json:"item_id"`
	LocalTime  time.Time `json:"local_time"`
	RemoteTime time.Time `json:"remote_time"`
	Resolution string    `json:"resolution"` // "local-wins", "remote-wins", "skipped"
}

// SyncState tracks the last sync for incremental operations.
type SyncState struct {
	LastSync       time.Time         `json:"last_sync"`
	DeviceID       string            `json:"device_id"`
	StoreChecksums map[string]string `json:"store_checksums"`
}

// ---------------------------------------------------------------------------
// Delta types
// ---------------------------------------------------------------------------

// TrustStoreDelta represents trust store changes for sync.
type TrustStoreDelta struct {
	Certificates []TrustStoreCertSync `json:"certificates"`
}

// TrustStoreCertSync holds certificate data and metadata for sync.
type TrustStoreCertSync struct {
	PEM         string   `json:"pem"`
	Fingerprint string   `json:"fingerprint"`
	Purpose     string   `json:"purpose"`
	Source      string   `json:"source"`
	Tags        []string `json:"tags,omitempty"`
}

// OATHDelta represents OATH credential changes for sync.
type OATHDelta struct {
	Credentials []OATHCredentialSync `json:"credentials"`
}

// OATHCredentialSync holds OATH credential data for sync.
type OATHCredentialSync struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Issuer      string    `json:"issuer"`
	AccountName string    `json:"account_name"`
	Secret      string    `json:"secret"`
	Type        string    `json:"type"`
	Algorithm   string    `json:"algorithm"`
	Digits      int       `json:"digits"`
	Period      int       `json:"period"`
	Counter     int64     `json:"counter"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PasswordDelta represents password changes for sync.
type PasswordDelta struct {
	Passwords []PasswordSync `json:"passwords"`
}

// PasswordSync holds password data for sync.
type PasswordSync struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Title      string    `json:"title,omitempty"`
	Username   string    `json:"username,omitempty"`
	Password   string    `json:"password"`
	URL        string    `json:"url,omitempty"`
	Notes      string    `json:"notes,omitempty"`
	FolderPath string    `json:"folder_path,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CADelta represents CA certificate changes for sync.
type CADelta struct {
	CACertPEM  string `json:"ca_cert_pem"`
	CAChainPEM string `json:"ca_chain_pem,omitempty"`
}
