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

package migration

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// defaultMigrator implements the Migrator interface.
type defaultMigrator struct {
	source types.Backend
	dest   types.Backend
	closed bool
	mu     sync.RWMutex
}

// NewMigrator creates a new Migrator for migrating keys between backends.
// Both source and destination backends must be non-nil.
// Returns an error if either backend is nil.
func NewMigrator(source, dest types.Backend) (Migrator, error) {
	if source == nil {
		return nil, fmt.Errorf("source backend cannot be nil")
	}
	if dest == nil {
		return nil, fmt.Errorf("destination backend cannot be nil")
	}

	return &defaultMigrator{
		source: source,
		dest:   dest,
	}, nil
}

// SourceBackend returns the source backend.
func (m *defaultMigrator) SourceBackend() types.Backend {
	return m.source
}

// DestBackend returns the destination backend.
func (m *defaultMigrator) DestBackend() types.Backend {
	return m.dest
}

// MigrateKey migrates a single key from source to destination backend.
func (m *defaultMigrator) MigrateKey(attrs *types.KeyAttributes, opts *MigrateOptions) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return fmt.Errorf("migrator is closed")
	}
	m.mu.RUnlock()

	if attrs == nil {
		return fmt.Errorf("key attributes cannot be nil")
	}

	if opts == nil {
		opts = &MigrateOptions{}
	}

	// Set reasonable defaults
	if opts.Parallel == 0 {
		opts.Parallel = 1
	}

	// Verify backends support import/export
	sourceExportBackend, ok := m.source.(backend.ImportExportBackend)
	if !ok {
		return ErrExportNotSupported
	}

	destImportBackend, ok := m.dest.(backend.ImportExportBackend)
	if !ok {
		return ErrImportNotSupported
	}

	// Step 1: Export the key from source backend
	wrapped, err := m.exportKey(sourceExportBackend, attrs, opts)
	if err != nil {
		return fmt.Errorf("failed to export key: %w", err)
	}

	// Step 2: Import the key into destination backend
	if err := m.importKey(destImportBackend, attrs, wrapped); err != nil {
		return fmt.Errorf("failed to import key: %w", err)
	}

	// Step 3: Validate migration if requested
	if !opts.SkipVerification {
		result, err := m.ValidateMigration(attrs)
		if err != nil {
			return fmt.Errorf("migration validation failed: %w", err)
		}
		if !result.IsValid {
			return fmt.Errorf("migration validation failed: %s", result.Message)
		}
	}

	// Step 4: Delete from source if requested
	if opts.DeleteSourceAfterVerification {
		if err := m.source.DeleteKey(attrs); err != nil {
			return fmt.Errorf("failed to delete source key after migration: %w", err)
		}
	}

	return nil
}

// MigrateAll migrates all keys matching the filter.
func (m *defaultMigrator) MigrateAll(filter *KeyFilter, opts *MigrateOptions) (*MigrationResult, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, fmt.Errorf("migrator is closed")
	}
	m.mu.RUnlock()

	if opts == nil {
		opts = &MigrateOptions{}
	}

	if opts.Parallel == 0 {
		opts.Parallel = 1
	}

	// Get all keys from source backend
	allKeys, err := m.source.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from source backend: %w", err)
	}

	// Filter keys based on criteria
	filteredKeys := m.filterKeys(allKeys, filter)

	result := &MigrationResult{
		StartTime:      time.Now(),
		FailedKeys:     make(map[*types.KeyAttributes]error),
		SuccessfulKeys: make([]*types.KeyAttributes, 0),
	}

	// Perform migrations
	if opts.Parallel > 1 {
		m.migrateKeysParallel(filteredKeys, opts, result)
	} else {
		m.migrateKeysSequential(filteredKeys, opts, result)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// MigrationPlan performs a dry-run analysis.
func (m *defaultMigrator) MigrationPlan(filter *KeyFilter) (*MigrationPlan, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, fmt.Errorf("migrator is closed")
	}
	m.mu.RUnlock()

	// Get all keys from source backend
	allKeys, err := m.source.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from source backend: %w", err)
	}

	// Filter keys based on criteria
	filteredKeys := m.filterKeys(allKeys, filter)

	plan := &MigrationPlan{
		Keys:              filteredKeys,
		SourceBackendType: m.source.Type(),
		DestBackendType:   m.dest.Type(),
		Timestamp:         time.Now(),
		Warnings:          make([]string, 0),
		Errors:            make([]string, 0),
	}

	// Check for compatibility issues
	m.checkCompatibility(plan)

	// Estimate duration (rough calculation: 100ms per key)
	plan.EstimatedDuration = time.Duration(len(filteredKeys)*100) * time.Millisecond

	return plan, nil
}

// ValidateMigration verifies the migrated key works in the destination backend.
func (m *defaultMigrator) ValidateMigration(attrs *types.KeyAttributes) (*ValidationResult, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, fmt.Errorf("migrator is closed")
	}
	m.mu.RUnlock()

	result := &ValidationResult{
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Try to get the key from destination backend
	_, err := m.dest.GetKey(attrs)
	if err != nil {
		result.IsValid = false
		result.Message = fmt.Sprintf("key not found in destination backend: %v", err)
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}

	// For asymmetric keys, try a sign operation
	if attrs.KeyAlgorithm != 0 {
		signer, err := m.dest.Signer(attrs)
		if err != nil {
			result.IsValid = false
			result.Message = fmt.Sprintf("failed to get signer for validation: %v", err)
			result.Errors = append(result.Errors, err.Error())
			return result, nil
		}

		// Try to sign test data
		testData := []byte("keychain-migration-validation")
		_, err = signer.Sign(nil, testData, attrs.Hash)
		if err != nil {
			result.IsValid = false
			result.Message = fmt.Sprintf("sign validation failed: %v", err)
			result.Errors = append(result.Errors, err.Error())
			return result, nil
		}
	}

	result.IsValid = true
	result.Message = "key validation successful"
	return result, nil
}

// Close closes the migrator and releases resources.
func (m *defaultMigrator) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	return nil
}

// Helper functions

// exportKey exports a key from the source backend using the specified algorithm.
func (m *defaultMigrator) exportKey(backend backend.ImportExportBackend, attrs *types.KeyAttributes, opts *MigrateOptions) (*backend.WrappedKeyMaterial, error) {
	// Determine wrapping algorithm
	algorithm := opts.WrappingAlgorithm
	if algorithm == "" {
		algorithm = m.selectWrappingAlgorithm(attrs)
	}

	// Export the key
	wrapped, err := backend.ExportKey(attrs, algorithm)
	if err != nil {
		return nil, err
	}

	return wrapped, nil
}

// importKey imports a wrapped key into the destination backend.
func (m *defaultMigrator) importKey(backend backend.ImportExportBackend, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	// Get import parameters with the same algorithm that was used for export
	params, err := backend.GetImportParameters(attrs, wrapped.Algorithm)
	if err != nil {
		return fmt.Errorf("failed to get import parameters: %w", err)
	}

	// Update wrapped key with import token from destination backend
	wrapped.ImportToken = params.ImportToken

	// Import the key
	if err := backend.ImportKey(attrs, wrapped); err != nil {
		return err
	}

	return nil
}

// filterKeys filters the list of keys based on the provided filter criteria.
func (m *defaultMigrator) filterKeys(keys []*types.KeyAttributes, filter *KeyFilter) []*types.KeyAttributes {
	if filter == nil {
		return keys
	}

	filtered := make([]*types.KeyAttributes, 0, len(keys))

	// Compile regex if pattern is provided
	var cnRegex *regexp.Regexp
	if filter.CNPattern != "" {
		re, err := regexp.Compile(filter.CNPattern)
		if err != nil {
			return filtered // Invalid regex, return empty list
		}
		cnRegex = re
	}

	for _, key := range keys {
		if !m.matchesFilter(key, filter, cnRegex) {
			continue
		}
		filtered = append(filtered, key)
	}

	return filtered
}

// matchesFilter checks if a key matches the filter criteria.
func (m *defaultMigrator) matchesFilter(key *types.KeyAttributes, filter *KeyFilter, cnRegex *regexp.Regexp) bool {
	// Check key types
	if len(filter.KeyTypes) > 0 {
		found := false
		for _, kt := range filter.KeyTypes {
			if key.KeyType == kt {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check store types
	if len(filter.StoreTypes) > 0 {
		found := false
		for _, st := range filter.StoreTypes {
			if key.StoreType == st {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check partitions
	if len(filter.Partitions) > 0 {
		found := false
		for _, p := range filter.Partitions {
			if key.Partition == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check key algorithms
	if len(filter.KeyAlgorithms) > 0 {
		found := false
		for _, alg := range filter.KeyAlgorithms {
			if key.KeyAlgorithm == alg {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check CN pattern
	if cnRegex != nil {
		if !cnRegex.MatchString(key.CN) {
			return false
		}
	}

	return true
}

// selectWrappingAlgorithm selects an appropriate wrapping algorithm for the key type.
func (m *defaultMigrator) selectWrappingAlgorithm(attrs *types.KeyAttributes) backend.WrappingAlgorithm {
	// For RSA keys, use hybrid wrapping to handle large keys
	if attrs.KeyAlgorithm == 1 { // x509.RSA
		return backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
	}

	// For other asymmetric keys, use standard OAEP
	if attrs.KeyAlgorithm != 0 {
		return backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	}

	// For symmetric keys, use OAEP (though they won't need wrapping)
	return backend.WrappingAlgorithmRSAES_OAEP_SHA_256
}

// checkCompatibility checks for known compatibility issues between backends.
func (m *defaultMigrator) checkCompatibility(plan *MigrationPlan) {
	sourceType := plan.SourceBackendType
	destType := plan.DestBackendType

	// Add warnings for known compatibility issues
	switch {
	case sourceType == types.BackendTypeAWSKMS && destType == types.BackendTypeAzureKV:
		plan.Warnings = append(plan.Warnings, "migrating between different cloud providers may have different key size limitations")
	case sourceType == types.BackendTypePKCS11 && destType == types.BackendTypeAWSKMS:
		plan.Warnings = append(plan.Warnings, "cloud backends may have different supported algorithms - verify compatibility")
	}

	// Check for unsupported key types in destination
	for _, keyAttrs := range plan.Keys {
		if !m.isKeyTypeSupported(keyAttrs) {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("key %s may not be fully supported in destination backend", keyAttrs.CN))
		}
	}
}

// isKeyTypeSupported checks if the destination backend supports the key type.
func (m *defaultMigrator) isKeyTypeSupported(attrs *types.KeyAttributes) bool {
	// Cloud KMS backends may not support all key types
	destType := m.dest.Type()
	keyAlg := attrs.KeyAlgorithm

	switch destType {
	case types.BackendTypeAWSKMS:
		// AWS KMS supports RSA and ECC
		return keyAlg == 1 || keyAlg == 3 // RSA=1, ECDSA=3
	case types.BackendTypeGCPKMS:
		// GCP KMS supports RSA and ECC
		return keyAlg == 1 || keyAlg == 3
	case types.BackendTypeAzureKV:
		// Azure supports RSA, ECC, oct (symmetric)
		return keyAlg == 1 || keyAlg == 3 || keyAlg == 0
	default:
		// Assume other backends support all types
		return true
	}
}

// migrateKeysSequential migrates keys one at a time.
func (m *defaultMigrator) migrateKeysSequential(keys []*types.KeyAttributes, opts *MigrateOptions, result *MigrationResult) {
	for _, key := range keys {
		err := m.MigrateKey(key, opts)
		if err != nil {
			result.FailureCount++
			result.FailedKeys[key] = err
			if opts.StopOnError {
				break
			}
		} else {
			result.SuccessCount++
			result.SuccessfulKeys = append(result.SuccessfulKeys, key)
		}
	}
}

// migrateKeysParallel migrates keys in parallel using goroutines.
func (m *defaultMigrator) migrateKeysParallel(keys []*types.KeyAttributes, opts *MigrateOptions, result *MigrationResult) {
	semaphore := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	mu := sync.Mutex{}

	for _, key := range keys {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(k *types.KeyAttributes) {
			defer wg.Done()
			defer func() { <-semaphore }()

			err := m.MigrateKey(k, opts)

			mu.Lock()
			if err != nil {
				result.FailureCount++
				result.FailedKeys[k] = err
			} else {
				result.SuccessCount++
				result.SuccessfulKeys = append(result.SuccessfulKeys, k)
			}
			mu.Unlock()
		}(key)

		if opts.StopOnError && result.FailureCount > 0 {
			break
		}
	}

	wg.Wait()
}
