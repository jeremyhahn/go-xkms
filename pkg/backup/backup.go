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

// Package backup provides an adapter interface for backup and restore operations,
// allowing calling applications to implement custom backup strategies.
//
// This follows the same pattern as other adapters - providing a clean interface
// that applications can implement while offering sensible defaults for common use cases.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Backup key errors.
var (
	// ErrProtectedMemory reports that a BackupKey's private key material
	// could not be placed in mlocked protected memory. The key is never
	// kept on the ordinary heap as a fallback (go-xkms#587).
	ErrProtectedMemory = errors.New("backup: protected memory allocation failed")

	// ErrNoPrivateKey reports that no private key material is set on a
	// BackupKey, or that the protected buffer holding it has been
	// destroyed.
	ErrNoPrivateKey = errors.New("backup: no private key material")
)

// BackupFormat specifies the serialization format for backup data
type BackupFormat string

const (
	// BackupFormatJSON uses JSON serialization (human-readable, good for debugging)
	BackupFormatJSON BackupFormat = "json"

	// BackupFormatEncrypted uses encrypted format (secure, requires key)
	BackupFormatEncrypted BackupFormat = "encrypted"
)

// BackupMetadata contains information about a backup
type BackupMetadata struct {
	// ID is the unique identifier for this backup
	ID string

	// Timestamp when the backup was created
	Timestamp time.Time

	// Format specifies the serialization format used
	Format BackupFormat

	// Size is the backup size in bytes
	Size int64

	// KeyCount is the number of keys included in the backup
	KeyCount int

	// Checksum is the SHA-256 checksum of the backup data
	Checksum string

	// Encrypted indicates whether the backup is encrypted
	Encrypted bool

	// EncryptionAlgorithm specifies the encryption algorithm if encrypted
	EncryptionAlgorithm string

	// BackendType identifies the backend that created this backup
	BackendType types.BackendType

	// Version is the backup format version for compatibility
	Version string

	// Metadata stores additional backup information
	Metadata map[string]interface{}

	// KeyIDs contains the list of key identifiers included in this backup
	KeyIDs []string

	// CompressedSize is the size after compression (if compression was applied)
	CompressedSize int64

	// Compressed indicates whether the backup data is compressed
	Compressed bool

	// CompressionAlgorithm specifies the compression algorithm if compressed
	CompressionAlgorithm string
}

// BackupData represents the actual backup payload
type BackupData struct {
	// Metadata contains backup information
	Metadata *BackupMetadata

	// Keys contains the backed up key data
	Keys []*BackupKey

	// Attributes contains the key attributes for restoration
	Attributes []*types.KeyAttributes
}

// BackupKey represents a single key in the backup
type BackupKey struct {
	// ID is the key identifier
	ID string

	// Attributes contains the key's attributes
	Attributes *types.KeyAttributes

	// privateKey holds the private key material (encrypted if the backup is
	// encrypted) in mlocked, guard-paged protected memory (go-xkms#587). It
	// is unexported so no consumer can hold the key material as an
	// unwipeable Go byte slice; use SetPrivateKey to store it and
	// PrivateKeyBytes to export a copy at a serialization boundary. nil
	// means no private key is set. The persisted JSON form keeps the
	// historical "PrivateKey" key via MarshalJSON/UnmarshalJSON.
	privateKey *secure.Buffer

	// PublicKey contains the public key material
	PublicKey []byte

	// Metadata stores additional key information
	Metadata map[string]interface{}

	// Created timestamp when the key was created
	Created time.Time

	// Modified timestamp when the key was last modified
	Modified time.Time

	// Version is the key version (if versioning is enabled)
	Version uint64
}

// SetPrivateKey stores the key's private key material in protected memory,
// replacing (and destroying) any previous value. key is ADOPTED:
// secure.NewBufferFromBytes wipes it as part of construction, so the caller
// must not reuse key afterwards — copy first if the original is still
// needed elsewhere. An empty key clears the stored value.
//
// Returns a wrapped ErrProtectedMemory if the protected allocation fails.
func (k *BackupKey) SetPrivateKey(key []byte) error {
	if len(key) == 0 {
		k.privateKey.Destroy()
		k.privateKey = nil
		return nil
	}
	buf, err := secure.NewBufferFromBytes(key)
	if err != nil {
		return &errs.Joined{Lead: ErrProtectedMemory, Cause: err}
	}
	k.privateKey.Destroy()
	k.privateKey = buf
	return nil
}

// HasPrivateKey reports whether the key holds private key material.
func (k *BackupKey) HasPrivateKey() bool {
	return k != nil && k.privateKey != nil
}

// privateKeyCopy returns a heap copy of the private key material. The
// caller owns the copy and MUST wipe it (secure.Wipe) when done. Returns
// ErrNoPrivateKey when no private key is set or the buffer has been
// destroyed.
func (k *BackupKey) privateKeyCopy() ([]byte, error) {
	if k == nil || k.privateKey == nil {
		return nil, ErrNoPrivateKey
	}
	var out []byte
	if err := k.privateKey.WithBytes(func(b []byte) error {
		out = make([]byte, len(b))
		copy(out, b)
		return nil
	}); err != nil {
		return nil, &errs.Joined{Lead: ErrNoPrivateKey, Cause: err}
	}
	return out, nil
}

// PrivateKeyBytes returns a heap copy of the private key material, or nil
// when no private key is set.
//
// A []byte copy cannot be wiped by this package once returned, so calling
// this re-mints exactly the exposure the protected field exists to remove —
// it is for serialization boundaries only (persisted backups, restore
// destinations, operator export), where the surrounding format is a []byte
// anyway. The caller owns the copy and SHOULD wipe it (secure.Wipe) when
// done.
func (k *BackupKey) PrivateKeyBytes() []byte {
	b, err := k.privateKeyCopy()
	if err != nil {
		return nil
	}
	return b
}

// backupKeyJSON is the persisted JSON form of BackupKey. It exists so the
// protected in-memory private key round-trips through the historical wire
// format unchanged: the "PrivateKey" key carries the key bytes exactly as
// it did when PrivateKey was an exported []byte field.
type backupKeyJSON struct {
	ID         string                 `json:"ID"`
	Attributes *types.KeyAttributes   `json:"Attributes"`
	PrivateKey []byte                 `json:"PrivateKey"`
	PublicKey  []byte                 `json:"PublicKey"`
	Metadata   map[string]interface{} `json:"Metadata"`
	Created    time.Time              `json:"Created"`
	Modified   time.Time              `json:"Modified"`
	Version    uint64                 `json:"Version"`
}

// MarshalJSON implements json.Marshaler, exporting the protected private key
// into the historical "PrivateKey" JSON key. Serialization necessarily
// materializes the key on the heap; that residue belongs to the persistence
// boundary (the same bytes are about to be written to a backup), not to
// this type.
func (k *BackupKey) MarshalJSON() ([]byte, error) {
	privateKey := k.PrivateKeyBytes()
	defer secure.Wipe(privateKey)
	return json.Marshal(backupKeyJSON{
		ID:         k.ID,
		Attributes: k.Attributes,
		PrivateKey: privateKey,
		PublicKey:  k.PublicKey,
		Metadata:   k.Metadata,
		Created:    k.Created,
		Modified:   k.Modified,
		Version:    k.Version,
	})
}

// UnmarshalJSON implements json.Unmarshaler, adopting the "PrivateKey" JSON
// key into protected memory.
func (k *BackupKey) UnmarshalJSON(data []byte) error {
	var aux backupKeyJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	k.ID = aux.ID
	k.Attributes = aux.Attributes
	k.PublicKey = aux.PublicKey
	k.Metadata = aux.Metadata
	k.Created = aux.Created
	k.Modified = aux.Modified
	k.Version = aux.Version
	return k.SetPrivateKey(aux.PrivateKey)
}

// BackupOptions provides options for creating backups
type BackupOptions struct {
	// Format specifies the serialization format
	Format BackupFormat

	// EncryptionKey is the key to use for encrypting the backup (required if Format is BackupFormatEncrypted)
	EncryptionKey []byte

	// Compress enables compression of the backup data
	Compress bool

	// CompressionAlgorithm specifies the compression algorithm (gzip, zstd, etc.)
	CompressionAlgorithm string

	// KeyIDs limits the backup to specific keys (if empty, backs up all keys)
	KeyIDs []string

	// IncludeMetadata determines whether to include key metadata
	IncludeMetadata bool

	// Metadata stores additional options
	Metadata map[string]interface{}
}

// RestoreOptions provides options for restoring from backups
type RestoreOptions struct {
	// DecryptionKey is the key to use for decrypting the backup (required if backup is encrypted)
	DecryptionKey []byte

	// KeyIDs limits the restore to specific keys (if empty, restores all keys)
	KeyIDs []string

	// Overwrite determines whether to overwrite existing keys
	Overwrite bool

	// DryRun performs validation without actually restoring keys
	DryRun bool

	// Metadata stores additional options
	Metadata map[string]interface{}
}

// ListOptions provides options for listing backups
type ListOptions struct {
	// StartTime filters backups created after this time
	StartTime *time.Time

	// EndTime filters backups created before this time
	EndTime *time.Time

	// Limit limits the number of results
	Limit int

	// Offset skips the first N results
	Offset int

	// SortBy specifies the field to sort by (timestamp, size, key_count)
	SortBy string

	// SortOrder specifies the sort order (asc, desc)
	SortOrder string
}

// VerifyResult contains the result of backup verification
type VerifyResult struct {
	// Valid indicates whether the backup is valid
	Valid bool

	// Errors contains any validation errors
	Errors []error

	// ChecksumValid indicates whether the checksum matches
	ChecksumValid bool

	// DecryptionValid indicates whether the backup can be decrypted (if encrypted)
	DecryptionValid bool

	// FormatValid indicates whether the backup format is valid
	FormatValid bool

	// KeyCount is the number of keys found in the backup
	KeyCount int

	// CorruptedKeys contains IDs of keys that failed validation
	CorruptedKeys []string
}

// BackupAdapter provides backup and restore capabilities.
//
// Applications can implement this interface to provide custom backup strategies
// (e.g., cloud storage, network shares, encrypted archives).
type BackupAdapter interface {
	// CreateBackup creates a new backup with the given options
	// Returns the backup metadata on success
	CreateBackup(ctx context.Context, data *BackupData, opts *BackupOptions) (*BackupMetadata, error)

	// RestoreBackup restores keys from a backup
	// Returns the number of keys restored
	RestoreBackup(ctx context.Context, backupID string, opts *RestoreOptions) (int, error)

	// ListBackups lists available backups with optional filtering
	ListBackups(ctx context.Context, opts *ListOptions) ([]*BackupMetadata, error)

	// GetBackup retrieves metadata for a specific backup
	GetBackup(ctx context.Context, backupID string) (*BackupMetadata, error)

	// DeleteBackup removes a backup
	DeleteBackup(ctx context.Context, backupID string) error

	// VerifyBackup verifies the integrity and validity of a backup
	// This includes checksum validation, format validation, and optional decryption test
	VerifyBackup(ctx context.Context, backupID string, opts *RestoreOptions) (*VerifyResult, error)

	// ExportBackup exports a backup to an external location
	// Returns the export path or URL
	ExportBackup(ctx context.Context, backupID string, destination string) (string, error)

	// ImportBackup imports a backup from an external location
	// Returns the imported backup metadata
	ImportBackup(ctx context.Context, source string) (*BackupMetadata, error)

	// GetStatistics returns backup statistics
	GetStatistics(ctx context.Context) (*BackupStatistics, error)
}

// KeyRestorer is the destination a restore writes recovered keys to.
//
// A backup adapter owns the archive: it reads, decrypts, validates, and
// filters it. Where the recovered key material belongs is the caller's
// decision, so the caller supplies the key store. An adapter without a
// restorer cannot restore anything and must say so rather than report a
// count for keys it never wrote.
type KeyRestorer interface {
	// HasKey reports whether the destination already holds the given key.
	// It is consulted before anything is written so a restore that would
	// overwrite existing material can be refused while the destination is
	// still untouched.
	HasKey(ctx context.Context, key *BackupKey) (bool, error)

	// RestoreKey writes one backed-up key to the destination.
	RestoreKey(ctx context.Context, key *BackupKey) error
}

// BackupStatistics contains statistical information about backups
type BackupStatistics struct {
	// TotalBackups is the total number of backups
	TotalBackups int

	// TotalSize is the total size of all backups in bytes
	TotalSize int64

	// TotalKeys is the total number of keys across all backups
	TotalKeys int

	// OldestBackup is the timestamp of the oldest backup
	OldestBackup *time.Time

	// NewestBackup is the timestamp of the newest backup
	NewestBackup *time.Time

	// AverageSize is the average backup size in bytes
	AverageSize int64

	// BackupsByFormat breaks down backups by format
	BackupsByFormat map[BackupFormat]int

	// EncryptedBackups is the number of encrypted backups
	EncryptedBackups int

	// CompressedBackups is the number of compressed backups
	CompressedBackups int
}
