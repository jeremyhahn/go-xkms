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

package pairingproto

// Backup/restore method names for bidirectional backup operations between
// laptop and phone. These methods enable encrypted backup creation, storage,
// restoration, and listing of available backups.
//
// Protocol Direction:
//   - local.*  methods: Laptop sends TO phone (operates on phone's storage)
//   - remote.* methods: Phone sends TO laptop (operates on laptop's xkms)
const (
	// MethodLocalCreateBackup sends an encrypted backup blob to the phone
	// for storage.
	MethodLocalCreateBackup = "local.createBackup"

	// MethodLocalRestoreBackup requests the phone to return a stored backup
	// by ID, or the latest backup if no ID is specified.
	MethodLocalRestoreBackup = "local.restoreBackup"

	// MethodRemoteCreateBackup is sent by the phone to ask the laptop to
	// create an encrypted backup and send it back.
	MethodRemoteCreateBackup = "remote.createBackup"

	// MethodRemoteRestoreBackup is sent by the phone to provide an encrypted
	// backup blob for the laptop to restore.
	MethodRemoteRestoreBackup = "remote.restoreBackup"

	// MethodRemoteListBackups is sent by the phone to ask the laptop to
	// enumerate available backups.
	MethodRemoteListBackups = "remote.listBackups"
)

// --- local.createBackup ---

// LocalCreateBackupParams contains parameters for local.createBackup.
// The laptop sends an encrypted backup blob to the phone for storage.
type LocalCreateBackupParams struct {
	BackupData []byte `json:"backup_data"`
	Label      string `json:"label,omitempty"`
}

// LocalCreateBackupResult contains the result of local.createBackup.
type LocalCreateBackupResult struct {
	Success  bool   `json:"success"`
	BackupID string `json:"backup_id"`
	Message  string `json:"message,omitempty"`
}

// --- local.restoreBackup ---

// LocalRestoreBackupParams contains parameters for local.restoreBackup.
// The laptop requests the phone to return a stored backup. If BackupID is
// empty, the phone returns the most recent backup.
type LocalRestoreBackupParams struct {
	BackupID string `json:"backup_id,omitempty"`
}

// LocalRestoreBackupResult contains the result of local.restoreBackup.
type LocalRestoreBackupResult struct {
	BackupData []byte `json:"backup_data"`
	BackupID   string `json:"backup_id"`
	CreatedAt  string `json:"created_at"`
}

// --- remote.createBackup ---

// RemoteCreateBackupParams contains parameters for remote.createBackup.
// The phone asks the laptop to create an encrypted backup and return it.
// Password seals the backup the way "xkey backup create --password" does
// (backup.NewPasswordKey). It is required: the bridge has no channel to hand
// the operator a generated key, so an empty password is refused.
type RemoteCreateBackupParams struct {
	IncludeTrustStore bool   `json:"include_trust_store"`
	IncludeOATH       bool   `json:"include_oath"`
	IncludePasswords  bool   `json:"include_passwords"`
	IncludeCA         bool   `json:"include_ca"`
	Label             string `json:"label,omitempty"`
	Password          string `json:"password"`
}

// RemoteCreateBackupResult contains the result of remote.createBackup.
// BackupData is the JSON encoding of a backup.EncryptedBackup envelope, the
// same format "xkey backup create" writes to disk.
type RemoteCreateBackupResult struct {
	BackupData []byte `json:"backup_data"`
	BackupID   string `json:"backup_id"`
	ItemCount  int    `json:"item_count"`
}

// --- remote.restoreBackup ---

// RemoteRestoreBackupParams contains parameters for remote.restoreBackup.
// The phone sends an encrypted backup blob to the laptop for restoration:
// the JSON encoding of a backup.EncryptedBackup envelope, as returned in
// RemoteCreateBackupResult.BackupData. Password must be the password the
// backup was created with; the key is re-derived from it and the KDF record
// in the envelope (backup.DerivePasswordKey). It is required.
type RemoteRestoreBackupParams struct {
	BackupData []byte `json:"backup_data"`
	Password   string `json:"password"`
}

// RemoteRestoreBackupResult contains the result of remote.restoreBackup.
// Restored lists the backup.Item* category names that had at least one entry
// restored into a store this host has configured.
type RemoteRestoreBackupResult struct {
	Success  bool     `json:"success"`
	Restored []string `json:"restored"`
	Message  string   `json:"message,omitempty"`

	// Items reports each category the laptop restored into one of its
	// stores, with the entries that store rejected. Success is true only
	// when no item has a skipped entry; a quarantined certificate is
	// pending, not a failure.
	Items []RemoteRestoreBackupItem `json:"items,omitempty"`
}

// RemoteRestoreBackupItem is the restore outcome of one backup category.
type RemoteRestoreBackupItem struct {
	// Item names the category, e.g. "trust_store", "oath" or "passwords".
	Item string `json:"item"`

	// Restored counts the entries written to the store.
	Restored int `json:"restored"`

	// Quarantined counts the certificates written to the trust store under
	// the sync quarantine purpose. A phone-supplied certificate is never
	// trusted as it arrives: it stays pending until the desktop operator
	// reclassifies it, so a phone shows it as pending, not restored.
	Quarantined int `json:"quarantined,omitempty"`

	// Skipped counts the entries the store rejected or could not decode.
	Skipped int `json:"skipped"`

	// Errors describes each skipped entry by its ID, never its secret.
	Errors []string `json:"errors,omitempty"`
}

// --- remote.listBackups ---

// RemoteListBackupsParams contains parameters for remote.listBackups.
// Currently empty; filters may be added in the future.
type RemoteListBackupsParams struct{}

// RemoteListBackupsResult contains the result of remote.listBackups.
type RemoteListBackupsResult struct {
	Backups []BackupInfo `json:"backups"`
}

// BackupInfo describes a single backup available on the laptop.
type BackupInfo struct {
	BackupID  string `json:"backup_id"`
	CreatedAt string `json:"created_at"`
	Label     string `json:"label,omitempty"`
	Size      int64  `json:"size"`
}

// backupLocalMethodNames contains all valid local.* backup method names.
var backupLocalMethodNames = map[string]bool{
	MethodLocalCreateBackup:  true,
	MethodLocalRestoreBackup: true,
}

// backupRemoteMethodNames contains all valid remote.* backup method names.
var backupRemoteMethodNames = map[string]bool{
	MethodRemoteCreateBackup:  true,
	MethodRemoteRestoreBackup: true,
	MethodRemoteListBackups:   true,
}

// IsBackupLocalMethod returns true if the method name is a valid
// local.* backup method.
func IsBackupLocalMethod(method string) bool {
	return backupLocalMethodNames[method]
}

// IsBackupRemoteMethod returns true if the method name is a valid
// remote.* backup method.
func IsBackupRemoteMethod(method string) bool {
	return backupRemoteMethodNames[method]
}

func init() {
	// Register backup methods with the global local and remote method maps.
	for method := range backupLocalMethodNames {
		localMethodNames[method] = true
	}
	for method := range backupRemoteMethodNames {
		remoteMethodNames[method] = true
	}
}
