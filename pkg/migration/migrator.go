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

package migration

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// defaultMigrator implements the Migrator interface.
type defaultMigrator struct {
	source types.KeyProvider
	dest   types.KeyProvider
	closed bool
	mu     sync.RWMutex
}

// NewMigrator creates a new Migrator for migrating keys between backends.
// Both source and destination backends must be non-nil.
// Returns an error if either backend is nil.
func NewMigrator(source, dest types.KeyProvider) (Migrator, error) {
	if source == nil {
		return nil, &errs.Detail{Err: ErrNilBackend, Detail: "source"}
	}
	if dest == nil {
		return nil, &errs.Detail{Err: ErrNilBackend, Detail: "destination"}
	}

	return &defaultMigrator{
		source: source,
		dest:   dest,
	}, nil
}

// SourceBackend returns the source backend.
func (m *defaultMigrator) SourceBackend() types.KeyProvider {
	return m.source
}

// DestBackend returns the destination backend.
func (m *defaultMigrator) DestBackend() types.KeyProvider {
	return m.dest
}

// MigrateKey migrates a single key from source to destination backend.
func (m *defaultMigrator) MigrateKey(ctx context.Context, attrs *types.KeyAttributes, opts *MigrateOptions) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return ErrMigratorClosed
	}
	m.mu.RUnlock()

	if attrs == nil {
		return ErrNilKeyAttributes
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
	wrapped, err := m.exportKey(ctx, sourceExportBackend, attrs, opts)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to export key", Err: err}
	}

	// Step 2: Import the key into destination backend
	if err := m.importKey(ctx, destImportBackend, attrs, wrapped); err != nil {
		return &errs.Wrapped{Msg: "failed to import key", Err: err}
	}

	// Step 3: Validate migration if requested
	if !opts.SkipVerification {
		result, err := m.ValidateMigration(ctx, attrs)
		if err != nil {
			return &errs.Wrapped{Msg: "migration validation failed", Err: err}
		}
		if !result.IsValid {
			return &errs.Detail{Err: ErrVerificationFailed, Detail: fmt.Sprintf("%s", result.Message)}
		}
	}

	// Step 4: Delete from source if requested
	if opts.DeleteSourceAfterVerification {
		if err := m.source.DeleteKey(ctx, attrs); err != nil {
			return &errs.Wrapped{Msg: "failed to delete source key after migration", Err: err}
		}
	}

	return nil
}

// MigrateAll migrates all keys matching the filter.
func (m *defaultMigrator) MigrateAll(ctx context.Context, filter *KeyFilter, opts *MigrateOptions) (*MigrationResult, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrMigratorClosed
	}
	m.mu.RUnlock()

	if opts == nil {
		opts = &MigrateOptions{}
	}

	if opts.Parallel == 0 {
		opts.Parallel = 1
	}

	// Get all keys from source backend
	allKeys, err := m.source.ListKeys(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys from source backend", Err: err}
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
		m.migrateKeysParallel(ctx, filteredKeys, opts, result)
	} else {
		m.migrateKeysSequential(ctx, filteredKeys, opts, result)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// MigrationPlan performs a dry-run analysis.
func (m *defaultMigrator) MigrationPlan(ctx context.Context, filter *KeyFilter) (*MigrationPlan, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrMigratorClosed
	}
	m.mu.RUnlock()

	// Get all keys from source backend
	allKeys, err := m.source.ListKeys(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys from source backend", Err: err}
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
func (m *defaultMigrator) ValidateMigration(ctx context.Context, attrs *types.KeyAttributes) (*ValidationResult, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrMigratorClosed
	}
	m.mu.RUnlock()

	result := &ValidationResult{
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Try to get the key from destination backend
	_, err := m.dest.GetKey(ctx, attrs)
	if err != nil {
		result.IsValid = false
		result.Message = fmt.Sprintf("key not found in destination backend: %v", err)
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}

	// For asymmetric keys, try a sign operation
	if attrs.KeyAlgorithm != 0 {
		signer, err := m.dest.Signer(ctx, attrs)
		if err != nil {
			result.IsValid = false
			result.Message = fmt.Sprintf("failed to get signer for validation: %v", err)
			result.Errors = append(result.Errors, err.Error())
			return result, nil
		}

		// Try to sign test data
		testData := []byte("xkms-migration-validation")
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
func (m *defaultMigrator) exportKey(ctx context.Context, backend backend.ImportExportBackend, attrs *types.KeyAttributes, opts *MigrateOptions) (*backend.WrappedKeyMaterial, error) {
	// Determine wrapping algorithm
	algorithm := opts.WrappingAlgorithm
	if algorithm == "" {
		algorithm = m.selectWrappingAlgorithm(attrs)
	}

	// Export the key
	wrapped, err := backend.ExportKey(ctx, attrs, algorithm)
	if err != nil {
		return nil, err
	}

	return wrapped, nil
}

// importKey imports a wrapped key into the destination backend.
func (m *defaultMigrator) importKey(ctx context.Context, backend backend.ImportExportBackend, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	// Get import parameters with the same algorithm that was used for export
	params, err := backend.GetImportParameters(ctx, attrs, wrapped.Algorithm)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get import parameters", Err: err}
	}

	// Update wrapped key with import token from destination backend
	wrapped.ImportToken = params.ImportToken

	// Import the key
	if err := backend.ImportKey(ctx, attrs, wrapped); err != nil {
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
func (m *defaultMigrator) migrateKeysSequential(ctx context.Context, keys []*types.KeyAttributes, opts *MigrateOptions, result *MigrationResult) {
	for _, key := range keys {
		err := m.MigrateKey(ctx, key, opts)
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

// migrateKeysParallel migrates keys in parallel using goroutines. The
// dispatch loop honors both context cancellation and StopOnError: workers
// record a failure under mu and flip the lock-free stop flag, which the
// dispatcher checks before launching each migration.
func (m *defaultMigrator) migrateKeysParallel(ctx context.Context, keys []*types.KeyAttributes, opts *MigrateOptions, result *MigrationResult) {
	semaphore := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	mu := sync.Mutex{}
	var stop atomic.Bool

	for _, key := range keys {
		if stop.Load() {
			break
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case semaphore <- struct{}{}:
		}
		wg.Add(1)

		go func(k *types.KeyAttributes) {
			defer wg.Done()
			defer func() { <-semaphore }()

			err := m.MigrateKey(ctx, k, opts)

			mu.Lock()
			if err != nil {
				result.FailureCount++
				result.FailedKeys[k] = err
				if opts.StopOnError {
					stop.Store(true)
				}
			} else {
				result.SuccessCount++
				result.SuccessfulKeys = append(result.SuccessfulKeys, k)
			}
			mu.Unlock()
		}(key)
	}

	wg.Wait()
}
