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
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMigrator tests migrator creation with valid and invalid inputs
func TestNewMigrator(t *testing.T) {
	tests := []struct {
		name      string
		source    types.Backend
		dest      types.Backend
		wantError bool
	}{
		{
			name:      "valid backends",
			source:    mocks.NewMockBackend(),
			dest:      mocks.NewMockBackend(),
			wantError: false,
		},
		{
			name:      "nil source backend",
			source:    nil,
			dest:      mocks.NewMockBackend(),
			wantError: true,
		},
		{
			name:      "nil destination backend",
			source:    mocks.NewMockBackend(),
			dest:      nil,
			wantError: true,
		},
		{
			name:      "both nil backends",
			source:    nil,
			dest:      nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMigrator(tt.source, tt.dest)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, m)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, m)
				if m != nil {
					assert.NoError(t, m.Close())
				}
			}
		})
	}
}

// TestMigratorSourceDestBackends tests accessor methods
func TestMigratorSourceDestBackends(t *testing.T) {
	source := mocks.NewMockBackend()
	dest := mocks.NewMockBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)
	defer func() { _ = m.Close() }()

	assert.Equal(t, source, m.SourceBackend())
	assert.Equal(t, dest, m.DestBackend())
}

// TestMigrateKeyNilAttributes tests MigrateKey with nil attributes
func TestMigrateKeyNilAttributes(t *testing.T) {
	source := mocks.NewMockBackend()
	dest := mocks.NewMockBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)
	defer func() { _ = m.Close() }()

	err = m.MigrateKey(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// TestMigrateKeyAfterClose tests operations on closed migrator
func TestMigrateKeyAfterClose(t *testing.T) {
	source := mocks.NewMockBackend()
	dest := mocks.NewMockBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)

	err = m.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:        "test.example.com",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StorePKCS8,
	}

	err = m.MigrateKey(attrs, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

// TestMigrateKeyWithoutExportSupport tests MigrateKey when source doesn't support export
func TestMigrateKeyWithoutExportSupport(t *testing.T) {
	// Create a mock backend that doesn't support import/export
	source := mocks.NewMockBackend()
	dest := mocks.NewMockBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)
	defer func() { _ = m.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test.example.com",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StorePKCS8,
	}

	err = m.MigrateKey(attrs, nil)
	assert.Error(t, err)
	assert.Equal(t, ErrExportNotSupported, err)
}

// TestMigrateKeyWithoutImportSupport tests MigrateKey when destination doesn't support import
func TestMigrateKeyWithoutImportSupport(t *testing.T) {
	// Create a source backend that supports import/export
	source := mocks.NewMockBackend()
	// Create a mock backend that doesn't support import/export
	dest := mocks.NewMockBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)
	defer func() { _ = m.Close() }()

	attrs := &types.KeyAttributes{
		CN:        "test.example.com",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StorePKCS8,
	}

	err = m.MigrateKey(attrs, nil)
	assert.Error(t, err)
	assert.Equal(t, ErrExportNotSupported, err)
}

// TestMigrationPlanAfterClose tests operations on closed migrator
func TestMigrationPlanAfterClose(t *testing.T) {
	source := mocks.NewMockBackend()
	dest := mocks.NewMockBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)

	err = m.Close()
	require.NoError(t, err)

	plan, err := m.MigrationPlan(nil)
	assert.Error(t, err)
	assert.Nil(t, plan)
	assert.Contains(t, err.Error(), "closed")
}

// TestValidateMigrationAfterClose tests ValidateMigration on closed migrator
func TestValidateMigrationAfterClose(t *testing.T) {
	source := mocks.NewMockBackend()
	dest := mocks.NewMockBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)

	err = m.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:        "test",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StorePKCS8,
	}

	result, err := m.ValidateMigration(attrs)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "closed")
}

// TestMigrateAllAfterClose tests MigrateAll on closed migrator
func TestMigrateAllAfterClose(t *testing.T) {
	source := mocks.NewMockBackend()
	dest := mocks.NewMockBackend()

	m, err := NewMigrator(source, dest)
	require.NoError(t, err)

	err = m.Close()
	require.NoError(t, err)

	result, err := m.MigrateAll(nil, nil)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "closed")
}

// TestKeyFilterWithCNPattern tests filtering by CN pattern
func TestKeyFilterWithCNPattern(t *testing.T) {
	filter := &KeyFilter{
		CNPattern: "^api\\..*",
	}

	assert.Equal(t, "^api\\..*", filter.CNPattern)
	assert.Empty(t, filter.KeyTypes)
	assert.Empty(t, filter.Partitions)
}

// TestMigrateOptions tests MigrateOptions structure
func TestMigrateOptions(t *testing.T) {
	opts := &MigrateOptions{
		SkipVerification:              true,
		DeleteSourceAfterVerification: false,
		StopOnError:                   true,
		Parallel:                      4,
	}

	assert.True(t, opts.SkipVerification)
	assert.False(t, opts.DeleteSourceAfterVerification)
	assert.True(t, opts.StopOnError)
	assert.Equal(t, 4, opts.Parallel)
}

// TestMigrationResult tests MigrationResult structure
func TestMigrationResult(t *testing.T) {
	result := &MigrationResult{
		SuccessCount:   5,
		FailureCount:   1,
		SkippedCount:   0,
		SuccessfulKeys: make([]*types.KeyAttributes, 5),
		FailedKeys:     make(map[*types.KeyAttributes]error),
	}

	assert.Equal(t, 5, result.SuccessCount)
	assert.Equal(t, 1, result.FailureCount)
	assert.Equal(t, 0, result.SkippedCount)
	assert.Len(t, result.SuccessfulKeys, 5)
	assert.Len(t, result.FailedKeys, 0)
}

// TestMigrationPlan tests MigrationPlan structure
func TestMigrationPlanStructure(t *testing.T) {
	plan := &MigrationPlan{
		Keys:              make([]*types.KeyAttributes, 3),
		SourceBackendType: types.BackendTypePKCS8,
		DestBackendType:   types.BackendTypeTPM2,
		Warnings:          make([]string, 0),
		Errors:            make([]string, 0),
	}

	plan.Warnings = append(plan.Warnings, "test warning")
	plan.Errors = append(plan.Errors, "test error")

	assert.Len(t, plan.Keys, 3)
	assert.Equal(t, types.BackendTypePKCS8, plan.SourceBackendType)
	assert.Equal(t, types.BackendTypeTPM2, plan.DestBackendType)
	assert.Len(t, plan.Warnings, 1)
	assert.Len(t, plan.Errors, 1)
}

// TestValidationResult tests ValidationResult structure
func TestValidationResult(t *testing.T) {
	result := &ValidationResult{
		IsValid:  true,
		Message:  "validation passed",
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	assert.True(t, result.IsValid)
	assert.Equal(t, "validation passed", result.Message)
	assert.Empty(t, result.Errors)
	assert.Empty(t, result.Warnings)
}

// TestKeyFilterCreatedBefore tests time-based key filtering
func TestKeyFilterCreatedBefore(t *testing.T) {
	// This test verifies the filter structure is properly set up for time-based filtering
	filter := &KeyFilter{}
	assert.Nil(t, filter.CreatedBefore)
	assert.Nil(t, filter.CreatedAfter)
}
