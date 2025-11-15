// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// BackupFormat specifies the serialization format for backup data
type BackupFormat string

const (
	// BackupFormatJSON uses JSON serialization (human-readable, good for debugging)
	BackupFormatJSON BackupFormat = "json"

	// BackupFormatProtobuf uses Protocol Buffers (compact, efficient)
	BackupFormatProtobuf BackupFormat = "protobuf"

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

	// PrivateKey contains the private key material (encrypted if backup is encrypted)
	PrivateKey []byte

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
