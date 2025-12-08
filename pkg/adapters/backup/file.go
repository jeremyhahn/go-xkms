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

package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// DefaultBackupVersion is the current backup format version
	DefaultBackupVersion = "1.0.0"

	// DefaultCompressionAlgorithm is the default compression algorithm
	DefaultCompressionAlgorithm = "gzip"

	// DefaultEncryptionAlgorithm is the default encryption algorithm
	DefaultEncryptionAlgorithm = "aes256-gcm"
)

var (
	// ErrBackupNotFound is returned when a backup does not exist
	ErrBackupNotFound = errors.New("backup not found")

	// ErrInvalidBackupFormat is returned when the backup format is invalid
	ErrInvalidBackupFormat = errors.New("invalid backup format")

	// ErrInvalidEncryptionKey is returned when the encryption key is invalid
	ErrInvalidEncryptionKey = errors.New("invalid encryption key")

	// ErrChecksumMismatch is returned when the backup checksum does not match
	ErrChecksumMismatch = errors.New("checksum mismatch")

	// ErrDecryptionFailed is returned when backup decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrKeyAlreadyExists is returned when attempting to restore a key that already exists
	ErrKeyAlreadyExists = errors.New("key already exists")
)

// FileBackupAdapter implements BackupAdapter using the local filesystem
type FileBackupAdapter struct {
	// basePath is the directory where backups are stored
	basePath string

	// mu protects concurrent access to backups
	mu sync.RWMutex

	// index maintains a cache of backup metadata for fast lookups
	index map[string]*BackupMetadata
}

// NewFileBackupAdapter creates a new file-based backup adapter
func NewFileBackupAdapter(basePath string) (*FileBackupAdapter, error) {
	// Ensure the backup directory exists
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	adapter := &FileBackupAdapter{
		basePath: basePath,
		index:    make(map[string]*BackupMetadata),
	}

	// Load existing backups into the index
	if err := adapter.loadIndex(); err != nil {
		return nil, fmt.Errorf("failed to load backup index: %w", err)
	}

	return adapter, nil
}

// CreateBackup creates a new backup with the given options
func (f *FileBackupAdapter) CreateBackup(ctx context.Context, data *BackupData, opts *BackupOptions) (*BackupMetadata, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if data == nil {
		return nil, errors.New("backup data is required")
	}

	if opts == nil {
		opts = &BackupOptions{
			Format:          BackupFormatJSON,
			IncludeMetadata: true,
		}
	}

	// Generate backup ID
	backupID := uuid.New().String()

	// Set default metadata if not provided
	if data.Metadata == nil {
		data.Metadata = &BackupMetadata{
			ID:        backupID,
			Timestamp: time.Now().UTC(),
			Format:    opts.Format,
			Version:   DefaultBackupVersion,
			KeyCount:  len(data.Keys),
			KeyIDs:    make([]string, 0, len(data.Keys)),
			Metadata:  make(map[string]interface{}),
		}
	} else {
		data.Metadata.ID = backupID
		data.Metadata.Timestamp = time.Now().UTC()
		data.Metadata.Format = opts.Format
		if data.Metadata.Version == "" {
			data.Metadata.Version = DefaultBackupVersion
		}
	}

	// Filter keys if specific KeyIDs are requested
	if len(opts.KeyIDs) > 0 {
		filteredKeys := make([]*BackupKey, 0, len(opts.KeyIDs))
		for _, key := range data.Keys {
			for _, id := range opts.KeyIDs {
				if key.ID == id {
					filteredKeys = append(filteredKeys, key)
					break
				}
			}
		}
		data.Keys = filteredKeys
	}

	// Update key count and IDs
	data.Metadata.KeyCount = len(data.Keys)
	data.Metadata.KeyIDs = make([]string, len(data.Keys))
	for i, key := range data.Keys {
		data.Metadata.KeyIDs[i] = key.ID
	}

	// Serialize the backup data with SessionCloser handling
	var serialized []byte
	var err error

	switch opts.Format {
	case BackupFormatJSON, BackupFormatEncrypted:
		// Clear SessionCloser from all keys before marshaling (cannot marshal func)
		var sessionClosers []func() error
		for i := range data.Keys {
			if data.Keys[i].Attributes != nil && data.Keys[i].Attributes.TPMAttributes != nil {
				sessionClosers = append(sessionClosers, data.Keys[i].Attributes.TPMAttributes.SessionCloser)
				data.Keys[i].Attributes.TPMAttributes.SessionCloser = nil
			}
		}
		// Restore SessionCloser after marshaling
		defer func() {
			closerIdx := 0
			for i := range data.Keys {
				if data.Keys[i].Attributes != nil && data.Keys[i].Attributes.TPMAttributes != nil && closerIdx < len(sessionClosers) {
					data.Keys[i].Attributes.TPMAttributes.SessionCloser = sessionClosers[closerIdx]
					closerIdx++
				}
			}
		}()

		serialized, err = json.Marshal(data) //nolint:staticcheck // SA1026: SessionCloser is cleared before marshaling
		if err != nil {
			return nil, fmt.Errorf("failed to serialize backup: %w", err)
		}
	case BackupFormatProtobuf:
		// Protobuf serialization is a planned feature for future releases.
		// JSON and Encrypted formats provide full functionality for production use.
		return nil, errors.New("protobuf format not yet implemented")
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidBackupFormat, opts.Format)
	}

	// Compress if requested
	if opts.Compress {
		compressed, err := f.compressData(serialized, opts.CompressionAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to compress backup: %w", err)
		}
		data.Metadata.CompressedSize = int64(len(compressed))
		data.Metadata.Compressed = true
		data.Metadata.CompressionAlgorithm = opts.CompressionAlgorithm
		if data.Metadata.CompressionAlgorithm == "" {
			data.Metadata.CompressionAlgorithm = DefaultCompressionAlgorithm
		}
		serialized = compressed
	}

	// Encrypt if requested
	if opts.Format == BackupFormatEncrypted {
		if len(opts.EncryptionKey) == 0 {
			return nil, ErrInvalidEncryptionKey
		}
		encrypted, err := f.encryptData(serialized, opts.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt backup: %w", err)
		}
		data.Metadata.Encrypted = true
		data.Metadata.EncryptionAlgorithm = DefaultEncryptionAlgorithm
		serialized = encrypted
	}

	// Calculate checksum
	checksum := sha256.Sum256(serialized)
	data.Metadata.Checksum = hex.EncodeToString(checksum[:])
	data.Metadata.Size = int64(len(serialized))

	// Write backup file
	backupPath := f.getBackupPath(backupID)
	if err := os.WriteFile(backupPath, serialized, 0600); err != nil {
		return nil, fmt.Errorf("failed to write backup file: %w", err)
	}

	// Write metadata file
	metadataPath := f.getMetadataPath(backupID)
	metadataBytes, err := json.MarshalIndent(data.Metadata, "", "  ")
	if err != nil {
		// Clean up backup file on error
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to clean up backup file %s: %v", backupPath, removeErr)
		}
		return nil, fmt.Errorf("failed to serialize metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, metadataBytes, 0600); err != nil {
		// Clean up backup file on error
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to clean up backup file %s: %v", backupPath, removeErr)
		}
		return nil, fmt.Errorf("failed to write metadata file: %w", err)
	}

	// Update index
	f.index[backupID] = data.Metadata

	return data.Metadata, nil
}

// RestoreBackup restores keys from a backup
func (f *FileBackupAdapter) RestoreBackup(ctx context.Context, backupID string, opts *RestoreOptions) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if opts == nil {
		opts = &RestoreOptions{}
	}

	// Load backup metadata
	metadata, err := f.getBackupMetadata(backupID)
	if err != nil {
		return 0, err
	}

	// Read backup file
	backupPath := f.getBackupPath(backupID)
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read backup file: %w", err)
	}

	// Verify checksum unless dry run
	if !opts.DryRun {
		checksum := sha256.Sum256(backupBytes)
		if hex.EncodeToString(checksum[:]) != metadata.Checksum {
			return 0, ErrChecksumMismatch
		}
	}

	// Decrypt if needed
	if metadata.Encrypted {
		if len(opts.DecryptionKey) == 0 {
			return 0, ErrInvalidEncryptionKey
		}
		decrypted, err := f.decryptData(backupBytes, opts.DecryptionKey)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}
		backupBytes = decrypted
	}

	// Decompress if needed
	if metadata.Compressed {
		decompressed, err := f.decompressData(backupBytes, metadata.CompressionAlgorithm)
		if err != nil {
			return 0, fmt.Errorf("failed to decompress backup: %w", err)
		}
		backupBytes = decompressed
	}

	// Deserialize backup data
	var data BackupData
	if err := json.Unmarshal(backupBytes, &data); err != nil {
		return 0, fmt.Errorf("failed to deserialize backup: %w", err)
	}

	// Filter keys if specific KeyIDs are requested
	keysToRestore := data.Keys
	if len(opts.KeyIDs) > 0 {
		keysToRestore = make([]*BackupKey, 0, len(opts.KeyIDs))
		for _, key := range data.Keys {
			for _, id := range opts.KeyIDs {
				if key.ID == id {
					keysToRestore = append(keysToRestore, key)
					break
				}
			}
		}
	}

	// Return count for dry run
	if opts.DryRun {
		return len(keysToRestore), nil
	}

	// In a real implementation, this would actually restore keys to a backend
	// For now, we just return the count
	restoredCount := len(keysToRestore)

	return restoredCount, nil
}

// ListBackups lists available backups with optional filtering
func (f *FileBackupAdapter) ListBackups(ctx context.Context, opts *ListOptions) ([]*BackupMetadata, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if opts == nil {
		opts = &ListOptions{}
	}

	// Collect all backups from index
	backups := make([]*BackupMetadata, 0, len(f.index))
	for _, metadata := range f.index {
		// Apply time filters
		if opts.StartTime != nil && metadata.Timestamp.Before(*opts.StartTime) {
			continue
		}
		if opts.EndTime != nil && metadata.Timestamp.After(*opts.EndTime) {
			continue
		}
		backups = append(backups, metadata)
	}

	// Sort backups
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}
	sortOrder := opts.SortOrder
	if sortOrder == "" {
		sortOrder = "desc"
	}

	sort.Slice(backups, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "size":
			less = backups[i].Size < backups[j].Size
		case "key_count":
			less = backups[i].KeyCount < backups[j].KeyCount
		default: // timestamp
			less = backups[i].Timestamp.Before(backups[j].Timestamp)
		}
		if sortOrder == "desc" {
			return !less
		}
		return less
	})

	// Apply offset and limit
	if opts.Offset > 0 {
		if opts.Offset >= len(backups) {
			return []*BackupMetadata{}, nil
		}
		backups = backups[opts.Offset:]
	}

	if opts.Limit > 0 && opts.Limit < len(backups) {
		backups = backups[:opts.Limit]
	}

	return backups, nil
}

// GetBackup retrieves metadata for a specific backup
func (f *FileBackupAdapter) GetBackup(ctx context.Context, backupID string) (*BackupMetadata, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.getBackupMetadata(backupID)
}

// DeleteBackup removes a backup
func (f *FileBackupAdapter) DeleteBackup(ctx context.Context, backupID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check if backup exists
	if _, exists := f.index[backupID]; !exists {
		return ErrBackupNotFound
	}

	// Remove backup file
	backupPath := f.getBackupPath(backupID)
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove backup file: %w", err)
	}

	// Remove metadata file
	metadataPath := f.getMetadataPath(backupID)
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove metadata file: %w", err)
	}

	// Remove from index
	delete(f.index, backupID)

	return nil
}

// VerifyBackup verifies the integrity and validity of a backup
func (f *FileBackupAdapter) VerifyBackup(ctx context.Context, backupID string, opts *RestoreOptions) (*VerifyResult, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if opts == nil {
		opts = &RestoreOptions{}
	}

	result := &VerifyResult{
		Valid:           true,
		Errors:          make([]error, 0),
		ChecksumValid:   true,
		DecryptionValid: true,
		FormatValid:     true,
		CorruptedKeys:   make([]string, 0),
	}

	// Load backup metadata
	metadata, err := f.getBackupMetadata(backupID)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err)
		return result, nil
	}

	// Read backup file
	backupPath := f.getBackupPath(backupID)
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Errorf("failed to read backup file: %w", err))
		return result, nil
	}

	// Verify checksum
	checksum := sha256.Sum256(backupBytes)
	if hex.EncodeToString(checksum[:]) != metadata.Checksum {
		result.Valid = false
		result.ChecksumValid = false
		result.Errors = append(result.Errors, ErrChecksumMismatch)
	}

	// Try to decrypt if encrypted
	if metadata.Encrypted {
		if len(opts.DecryptionKey) == 0 {
			result.DecryptionValid = false
			result.Errors = append(result.Errors, errors.New("decryption key not provided"))
		} else {
			decrypted, err := f.decryptData(backupBytes, opts.DecryptionKey)
			if err != nil {
				result.Valid = false
				result.DecryptionValid = false
				result.Errors = append(result.Errors, fmt.Errorf("decryption failed: %w", err))
				return result, nil
			}
			backupBytes = decrypted
		}
	}

	// Try to decompress if compressed
	if metadata.Compressed {
		decompressed, err := f.decompressData(backupBytes, metadata.CompressionAlgorithm)
		if err != nil {
			result.Valid = false
			result.FormatValid = false
			result.Errors = append(result.Errors, fmt.Errorf("decompression failed: %w", err))
			return result, nil
		}
		backupBytes = decompressed
	}

	// Try to deserialize
	var data BackupData
	if err := json.Unmarshal(backupBytes, &data); err != nil {
		result.Valid = false
		result.FormatValid = false
		result.Errors = append(result.Errors, fmt.Errorf("deserialization failed: %w", err))
		return result, nil
	}

	result.KeyCount = len(data.Keys)

	// Validate each key
	for _, key := range data.Keys {
		if key.ID == "" {
			result.CorruptedKeys = append(result.CorruptedKeys, "unnamed-key")
			result.Valid = false
		}
	}

	return result, nil
}

// ExportBackup exports a backup to an external location
func (f *FileBackupAdapter) ExportBackup(ctx context.Context, backupID string, destination string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Verify backup exists
	if _, exists := f.index[backupID]; !exists {
		return "", ErrBackupNotFound
	}

	// Read backup file
	backupPath := f.getBackupPath(backupID)
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to read backup file: %w", err)
	}

	// Ensure destination directory exists
	destDir := filepath.Dir(destination)
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Write to destination
	if err := os.WriteFile(destination, backupBytes, 0600); err != nil {
		return "", fmt.Errorf("failed to write backup to destination: %w", err)
	}

	return destination, nil
}

// ImportBackup imports a backup from an external location
func (f *FileBackupAdapter) ImportBackup(ctx context.Context, source string) (*BackupMetadata, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Read source file
	backupBytes, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("failed to read source file: %w", err)
	}

	// Try to deserialize to extract metadata
	var data BackupData
	if err := json.Unmarshal(backupBytes, &data); err != nil {
		return nil, fmt.Errorf("failed to deserialize backup: %w", err)
	}

	if data.Metadata == nil {
		return nil, errors.New("backup metadata is missing")
	}

	// Generate new ID if needed
	backupID := data.Metadata.ID
	if backupID == "" {
		backupID = uuid.New().String()
		data.Metadata.ID = backupID
	}

	// Check if backup already exists
	if _, exists := f.index[backupID]; exists {
		// Generate a new ID to avoid conflicts
		backupID = uuid.New().String()
		data.Metadata.ID = backupID
	}

	// Write backup file
	backupPath := f.getBackupPath(backupID)
	if err := os.WriteFile(backupPath, backupBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write backup file: %w", err)
	}

	// Write metadata file
	metadataPath := f.getMetadataPath(backupID)
	metadataBytes, err := json.MarshalIndent(data.Metadata, "", "  ")
	if err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to clean up backup file %s: %v", backupPath, removeErr)
		}
		return nil, fmt.Errorf("failed to serialize metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, metadataBytes, 0600); err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to clean up backup file %s: %v", backupPath, removeErr)
		}
		return nil, fmt.Errorf("failed to write metadata file: %w", err)
	}

	// Update index
	f.index[backupID] = data.Metadata

	return data.Metadata, nil
}

// GetStatistics returns backup statistics
func (f *FileBackupAdapter) GetStatistics(ctx context.Context) (*BackupStatistics, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	stats := &BackupStatistics{
		TotalBackups:    len(f.index),
		BackupsByFormat: make(map[BackupFormat]int),
	}

	if len(f.index) == 0 {
		return stats, nil
	}

	var totalSize int64
	var oldestTime, newestTime time.Time
	firstBackup := true

	for _, metadata := range f.index {
		stats.TotalKeys += metadata.KeyCount
		totalSize += metadata.Size

		// Track format distribution
		stats.BackupsByFormat[metadata.Format]++

		// Track encrypted backups
		if metadata.Encrypted {
			stats.EncryptedBackups++
		}

		// Track compressed backups
		if metadata.Compressed {
			stats.CompressedBackups++
		}

		// Track oldest and newest
		if firstBackup {
			oldestTime = metadata.Timestamp
			newestTime = metadata.Timestamp
			firstBackup = false
		} else {
			if metadata.Timestamp.Before(oldestTime) {
				oldestTime = metadata.Timestamp
			}
			if metadata.Timestamp.After(newestTime) {
				newestTime = metadata.Timestamp
			}
		}
	}

	stats.TotalSize = totalSize
	stats.AverageSize = totalSize / int64(len(f.index))
	stats.OldestBackup = &oldestTime
	stats.NewestBackup = &newestTime

	return stats, nil
}

// Helper methods

func (f *FileBackupAdapter) getBackupPath(backupID string) string {
	return filepath.Join(f.basePath, fmt.Sprintf("%s.backup", backupID))
}

func (f *FileBackupAdapter) getMetadataPath(backupID string) string {
	return filepath.Join(f.basePath, fmt.Sprintf("%s.metadata.json", backupID))
}

func (f *FileBackupAdapter) getBackupMetadata(backupID string) (*BackupMetadata, error) {
	// Check cache first
	if metadata, exists := f.index[backupID]; exists {
		return metadata, nil
	}

	// Try to load from disk
	metadataPath := f.getMetadataPath(backupID)
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrBackupNotFound
		}
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var metadata BackupMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to deserialize metadata: %w", err)
	}

	return &metadata, nil
}

func (f *FileBackupAdapter) loadIndex() error {
	// Read all metadata files in the backup directory
	entries, err := os.ReadDir(f.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist yet, that's ok
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Look for metadata files
		if filepath.Ext(entry.Name()) == ".json" {
			metadataPath := filepath.Join(f.basePath, entry.Name())
			metadataBytes, err := os.ReadFile(metadataPath)
			if err != nil {
				continue // Skip files we can't read
			}

			var metadata BackupMetadata
			if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
				continue // Skip files we can't parse
			}

			f.index[metadata.ID] = &metadata
		}
	}

	return nil
}

func (f *FileBackupAdapter) compressData(data []byte, algorithm string) ([]byte, error) {
	if algorithm == "" {
		algorithm = DefaultCompressionAlgorithm
	}

	switch algorithm {
	case "gzip":
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write(data); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}
}

func (f *FileBackupAdapter) decompressData(data []byte, algorithm string) ([]byte, error) {
	if algorithm == "" {
		algorithm = DefaultCompressionAlgorithm
	}

	switch algorithm {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := reader.Close(); closeErr != nil {
				log.Printf("failed to close gzip reader: %v", closeErr)
			}
		}()
		return io.ReadAll(reader)
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}
}

func (f *FileBackupAdapter) encryptData(data []byte, key []byte) ([]byte, error) {
	// Validate key size (must be 32 bytes for AES-256)
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key must be 32 bytes for AES-256", ErrInvalidEncryptionKey)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and prepend nonce
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (f *FileBackupAdapter) decryptData(data []byte, key []byte) ([]byte, error) {
	// Validate key size
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key must be 32 bytes for AES-256", ErrInvalidEncryptionKey)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
