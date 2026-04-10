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

// Sync method names for bidirectional synchronization between laptop and phone.
// These methods enable trust store, OATH credential, and password sync
// operations in both directions.
//
// Protocol Direction:
//   - local.*  methods: Laptop sends TO phone (syncs laptop data to phone)
//   - remote.* methods: Phone sends TO laptop (syncs phone data to laptop)
const (
	// MethodLocalSyncTrustStore sends local trust store certificates to the
	// phone for synchronization.
	MethodLocalSyncTrustStore = "local.syncTrustStore"

	// MethodLocalSyncOATH sends local OATH credentials to the phone for
	// synchronization.
	MethodLocalSyncOATH = "local.syncOATH"

	// MethodLocalSyncPasswords sends local passwords to the phone for
	// synchronization.
	MethodLocalSyncPasswords = "local.syncPasswords"

	// MethodLocalSyncStatus requests the sync status from the phone.
	MethodLocalSyncStatus = "local.syncStatus"

	// MethodRemoteSyncTrustStore is sent by the phone to sync its trust
	// store certificates to the laptop.
	MethodRemoteSyncTrustStore = "remote.syncTrustStore"

	// MethodRemoteSyncOATH is sent by the phone to sync its OATH credentials
	// to the laptop.
	MethodRemoteSyncOATH = "remote.syncOATH"

	// MethodRemoteSyncPasswords is sent by the phone to sync its passwords
	// to the laptop.
	MethodRemoteSyncPasswords = "remote.syncPasswords"

	// MethodRemoteSyncAll is sent by the phone to request a full bidirectional
	// sync of all supported data types.
	MethodRemoteSyncAll = "remote.syncAll"

	// MethodRemoteSyncStatus is sent by the phone to request the sync status
	// from the laptop.
	MethodRemoteSyncStatus = "remote.syncStatus"
)

// SyncCertificate represents a certificate for trust store synchronization.
type SyncCertificate struct {
	PEM         string   `json:"pem"`
	Fingerprint string   `json:"fingerprint"`
	Purpose     string   `json:"purpose,omitempty"`
	Source      string   `json:"source,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// SyncOATHCredential represents an OATH credential for synchronization.
type SyncOATHCredential struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Issuer      string `json:"issuer,omitempty"`
	AccountName string `json:"account_name,omitempty"`
	Secret      string `json:"secret"`
	Type        string `json:"type"`
	Algorithm   string `json:"algorithm,omitempty"`
	Digits      int    `json:"digits,omitempty"`
	Period      int    `json:"period,omitempty"`
	Counter     int64  `json:"counter,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"` // RFC3339
}

// SyncPassword represents a password entry for synchronization.
type SyncPassword struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"` // RFC3339
}

// --- local.syncTrustStore ---

// LocalSyncTrustStoreParams contains parameters for local.syncTrustStore.
// The laptop sends its trust store certificates to the phone.
type LocalSyncTrustStoreParams struct {
	Certificates []SyncCertificate `json:"certificates"`
}

// LocalSyncTrustStoreResult contains the result of local.syncTrustStore.
type LocalSyncTrustStoreResult struct {
	Added   int               `json:"added"`
	Skipped int               `json:"skipped"`
	Remote  []SyncCertificate `json:"remote,omitempty"` // phone's certs for laptop
}

// --- local.syncOATH ---

// LocalSyncOATHParams contains parameters for local.syncOATH.
// The laptop sends its OATH credentials to the phone.
type LocalSyncOATHParams struct {
	Credentials []SyncOATHCredential `json:"credentials"`
}

// LocalSyncOATHResult contains the result of local.syncOATH.
type LocalSyncOATHResult struct {
	Added   int                  `json:"added"`
	Updated int                  `json:"updated"`
	Skipped int                  `json:"skipped"`
	Remote  []SyncOATHCredential `json:"remote,omitempty"` // phone's creds for laptop
}

// --- local.syncPasswords ---

// LocalSyncPasswordsParams contains parameters for local.syncPasswords.
// The laptop sends its passwords to the phone.
type LocalSyncPasswordsParams struct {
	Passwords []SyncPassword `json:"passwords"`
}

// LocalSyncPasswordsResult contains the result of local.syncPasswords.
type LocalSyncPasswordsResult struct {
	Added   int            `json:"added"`
	Updated int            `json:"updated"`
	Skipped int            `json:"skipped"`
	Remote  []SyncPassword `json:"remote,omitempty"` // phone's passwords for laptop
}

// --- local.syncStatus ---

// LocalSyncStatusParams contains parameters for local.syncStatus.
// Currently empty; filters may be added in the future.
type LocalSyncStatusParams struct{}

// LocalSyncStatusResult contains the result of local.syncStatus.
type LocalSyncStatusResult struct {
	LastSync       string            `json:"last_sync,omitempty"` // RFC3339
	DeviceID       string            `json:"device_id"`
	StoreChecksums map[string]string `json:"store_checksums"`
}

// --- remote.syncTrustStore ---

// RemoteSyncTrustStoreParams contains parameters for remote.syncTrustStore.
// The phone sends its trust store certificates to the laptop.
type RemoteSyncTrustStoreParams struct {
	Certificates []SyncCertificate `json:"certificates"`
}

// RemoteSyncTrustStoreResult contains the result of remote.syncTrustStore.
type RemoteSyncTrustStoreResult struct {
	Added   int               `json:"added"`
	Skipped int               `json:"skipped"`
	Local   []SyncCertificate `json:"local,omitempty"` // laptop's certs for phone
}

// --- remote.syncOATH ---

// RemoteSyncOATHParams contains parameters for remote.syncOATH.
// The phone sends its OATH credentials to the laptop.
type RemoteSyncOATHParams struct {
	Credentials []SyncOATHCredential `json:"credentials"`
}

// RemoteSyncOATHResult contains the result of remote.syncOATH.
type RemoteSyncOATHResult struct {
	Added   int                  `json:"added"`
	Updated int                  `json:"updated"`
	Skipped int                  `json:"skipped"`
	Local   []SyncOATHCredential `json:"local,omitempty"` // laptop's creds for phone
}

// --- remote.syncPasswords ---

// RemoteSyncPasswordsParams contains parameters for remote.syncPasswords.
// The phone sends its passwords to the laptop.
type RemoteSyncPasswordsParams struct {
	Passwords []SyncPassword `json:"passwords"`
}

// RemoteSyncPasswordsResult contains the result of remote.syncPasswords.
type RemoteSyncPasswordsResult struct {
	Added   int            `json:"added"`
	Updated int            `json:"updated"`
	Skipped int            `json:"skipped"`
	Local   []SyncPassword `json:"local,omitempty"` // laptop's passwords for phone
}

// --- remote.syncAll ---

// RemoteSyncAllParams contains parameters for remote.syncAll.
// The phone requests a full bidirectional sync.
type RemoteSyncAllParams struct {
	IncludeTrustStore bool `json:"include_trust_store"`
	IncludeOATH       bool `json:"include_oath"`
	IncludePasswords  bool `json:"include_passwords"`
}

// RemoteSyncAllResult contains the result of remote.syncAll.
type RemoteSyncAllResult struct {
	TrustStore *RemoteSyncTrustStoreResult `json:"trust_store,omitempty"`
	OATH       *RemoteSyncOATHResult       `json:"oath,omitempty"`
	Passwords  *RemoteSyncPasswordsResult  `json:"passwords,omitempty"`
}

// --- remote.syncStatus ---

// RemoteSyncStatusParams contains parameters for remote.syncStatus.
// Currently empty; filters may be added in the future.
type RemoteSyncStatusParams struct{}

// RemoteSyncStatusResult contains the result of remote.syncStatus.
type RemoteSyncStatusResult struct {
	LastSync       string            `json:"last_sync,omitempty"` // RFC3339
	DeviceID       string            `json:"device_id"`
	StoreChecksums map[string]string `json:"store_checksums"`
}

// syncLocalMethodNames contains all valid local.* sync method names.
var syncLocalMethodNames = map[string]bool{
	MethodLocalSyncTrustStore: true,
	MethodLocalSyncOATH:       true,
	MethodLocalSyncPasswords:  true,
	MethodLocalSyncStatus:     true,
}

// syncRemoteMethodNames contains all valid remote.* sync method names.
var syncRemoteMethodNames = map[string]bool{
	MethodRemoteSyncTrustStore: true,
	MethodRemoteSyncOATH:       true,
	MethodRemoteSyncPasswords:  true,
	MethodRemoteSyncAll:        true,
	MethodRemoteSyncStatus:     true,
}

// IsSyncLocalMethod returns true if the method name is a valid
// local.* sync method.
func IsSyncLocalMethod(method string) bool {
	return syncLocalMethodNames[method]
}

// IsSyncRemoteMethod returns true if the method name is a valid
// remote.* sync method.
func IsSyncRemoteMethod(method string) bool {
	return syncRemoteMethodNames[method]
}

func init() {
	// Register sync methods with the global local and remote method maps.
	for method := range syncLocalMethodNames {
		localMethodNames[method] = true
	}
	for method := range syncRemoteMethodNames {
		remoteMethodNames[method] = true
	}
}
