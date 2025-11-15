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

// Package migration provides tools to migrate cryptographic keys between different backends.
// This package enables users to move keys from one storage backend to another while
// maintaining security and verifying successful migration.
//
// Supported migrations include:
//   - PKCS#8 (software) to AES (symmetric encryption)
//   - PKCS#8 to PKCS#11 (hardware)
//   - PKCS#11 to TPM2 (different hardware)
//   - Cloud KMS (AWS, GCP, Azure) to local backends
//   - Any backend supporting ImportExportBackend interface
//
// Usage:
//
//	migrator := migration.NewMigrator(sourceBackend, destBackend)
//
//	// Perform a dry-run to see what would be migrated
//	plan, err := migrator.MigrationPlan(filter)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Will migrate %d keys\n", len(plan.Keys))
//
//	// Execute the migration
//	result, err := migrator.MigrateAll(filter, &MigrateOptions{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Successfully migrated %d keys\n", result.SuccessCount)
package migration

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyFilter defines criteria for filtering which keys to migrate.
type KeyFilter struct {
	// KeyTypes filters by key type (e.g., KeyTypeSigning, KeyTypeEncryption).
	// Empty means all key types.
	KeyTypes []types.KeyType

	// StoreTypes filters by source store type.
	// Empty means all store types.
	StoreTypes []types.StoreType

	// Partitions filters by partition (e.g., PartitionSigningKeys).
	// Empty means all partitions.
	Partitions []types.Partition

	// KeyAlgorithms filters by key algorithm (e.g., RSA, ECDSA).
	// Empty means all algorithms.
	KeyAlgorithms []x509.PublicKeyAlgorithm

	// CNPattern is an optional regex pattern to match common names.
	// If provided, only keys with CNs matching this pattern are migrated.
	// Empty means all CNs.
	CNPattern string

	// CreatedBefore filters to only keys created before this time.
	// If nil, no filter is applied.
	CreatedBefore *time.Time

	// CreatedAfter filters to only keys created after this time.
	// If nil, no filter is applied.
	CreatedAfter *time.Time
}

// MigrationPlan represents a dry-run analysis of what would be migrated.
type MigrationPlan struct {
	// Keys are the KeyAttributes that would be migrated
	Keys []*types.KeyAttributes

	// SourceBackendType is the type of the source backend
	SourceBackendType types.BackendType

	// DestBackendType is the type of the destination backend
	DestBackendType types.BackendType

	// EstimatedDuration is a rough estimate of how long the migration would take
	EstimatedDuration time.Duration

	// Warnings contains any warnings about the migration (e.g., unsupported key types)
	Warnings []string

	// Errors contains any errors encountered during planning
	Errors []string

	// Timestamp when the plan was created
	Timestamp time.Time
}

// MigrationResult represents the outcome of a migration operation.
type MigrationResult struct {
	// SuccessCount is the number of keys successfully migrated
	SuccessCount int

	// FailureCount is the number of keys that failed to migrate
	FailureCount int

	// SkippedCount is the number of keys skipped (e.g., due to unsupported types)
	SkippedCount int

	// SuccessfulKeys contains the attributes of successfully migrated keys
	SuccessfulKeys []*types.KeyAttributes

	// FailedKeys contains the attributes and error messages for failed migrations
	FailedKeys map[*types.KeyAttributes]error

	// StartTime when the migration began
	StartTime time.Time

	// EndTime when the migration completed
	EndTime time.Time

	// Duration is the total time taken for the migration
	Duration time.Duration
}

// MigrateOptions controls the behavior of migration operations.
type MigrateOptions struct {
	// DeleteSourceAfterVerification deletes the key from source backend after successful
	// migration and verification. Default is false to be conservative.
	DeleteSourceAfterVerification bool

	// SkipVerification skips the verification step that ensures the migrated key
	// works correctly in the destination backend. Default is false.
	// WARNING: Only disable verification if you understand the risks.
	SkipVerification bool

	// StopOnError stops the entire migration if any single key fails to migrate.
	// Default is false, which continues with remaining keys.
	StopOnError bool

	// Parallel sets the number of concurrent migration operations. Default is 1 (sequential).
	// Higher values improve throughput but may increase resource usage.
	// Only used if the destination backend is thread-safe.
	Parallel int

	// Timeout is the maximum time to wait for a single key migration.
	// If nil, no timeout is applied. Recommended for remote backends (cloud KMS).
	Timeout *time.Duration

	// RetryCount is the number of times to retry a failed migration. Default is 0.
	// Useful for handling transient errors in cloud backends.
	RetryCount int

	// WrappingAlgorithm specifies the algorithm to use for wrapping keys during export.
	// If not specified, the migrator will choose an appropriate algorithm.
	WrappingAlgorithm backend.WrappingAlgorithm
}

// ValidationResult contains the result of key validation after migration.
type ValidationResult struct {
	// IsValid indicates if the key validation succeeded
	IsValid bool

	// Message provides details about the validation result
	Message string

	// Errors contains any validation errors encountered
	Errors []string

	// Warnings contains any validation warnings
	Warnings []string
}

// Migrator defines the interface for migrating keys between backends.
//
// A Migrator is responsible for:
// 1. Analyzing which keys can be migrated
// 2. Executing the migration (export, import, verify)
// 3. Optionally cleaning up the source backend
// 4. Providing detailed reporting of success/failure
type Migrator interface {
	// MigrateKey migrates a single key from source to destination backend.
	// Returns an error if the migration fails.
	// The options parameter controls the migration behavior.
	// If opts is nil, default options are used.
	MigrateKey(attrs *types.KeyAttributes, opts *MigrateOptions) error

	// MigrateAll migrates all keys matching the filter from source to destination backend.
	// The filter parameter specifies which keys to migrate. If nil, all keys are migrated.
	// Returns a MigrationResult with detailed information about success/failure counts.
	// The options parameter controls the migration behavior.
	// If opts is nil, default options are used.
	MigrateAll(filter *KeyFilter, opts *MigrateOptions) (*MigrationResult, error)

	// MigrationPlan performs a dry-run analysis without actually migrating any keys.
	// Returns a MigrationPlan that shows what would be migrated, including any warnings.
	// The filter parameter specifies which keys would be migrated. If nil, all keys are analyzed.
	MigrationPlan(filter *KeyFilter) (*MigrationPlan, error)

	// ValidateMigration verifies that a key migrated to the destination backend
	// works correctly by performing a test operation (sign/verify or encrypt/decrypt).
	// Returns a ValidationResult with details about the validation.
	ValidateMigration(attrs *types.KeyAttributes) (*ValidationResult, error)

	// SourceBackend returns the source backend being migrated from
	SourceBackend() types.Backend

	// DestBackend returns the destination backend being migrated to
	DestBackend() types.Backend

	// Close releases any resources held by the migrator
	Close() error
}

// ErrMigrationNotSupported is returned when migration between backends is not supported
var ErrMigrationNotSupported = errors.New("migration not supported between these backends")

// ErrIncompatibleKeyType is returned when a key type cannot be migrated to the destination backend
var ErrIncompatibleKeyType = errors.New("key type incompatible with destination backend")

// ErrVerificationFailed is returned when post-migration verification fails
var ErrVerificationFailed = errors.New("key validation after migration failed")

// ErrExportNotSupported is returned when the source backend doesn't support key export
var ErrExportNotSupported = errors.New("source backend does not support key export")

// ErrImportNotSupported is returned when the destination backend doesn't support key import
var ErrImportNotSupported = errors.New("destination backend does not support key import")
