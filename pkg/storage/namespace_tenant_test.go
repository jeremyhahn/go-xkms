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

package storage

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantKeyPath tests TenantKeyPath with empty and non-empty tenant IDs.
func TestTenantKeyPath(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		id       string
		expect   string
	}{
		{
			name:     "empty tenant falls back to KeyPath",
			tenantID: "",
			id:       "key1",
			expect:   "keys/key1.key",
		},
		{
			name:     "tenant namespaces key path",
			tenantID: "tenant-abc",
			id:       "key1",
			expect:   "tenant-abc/keys/key1.key",
		},
		{
			name:     "UUID tenant ID",
			tenantID: "550e8400-e29b-41d4-a716-446655440000",
			id:       "my-key",
			expect:   "550e8400-e29b-41d4-a716-446655440000/keys/my-key.key",
		},
		{
			name:     "empty ID with tenant",
			tenantID: "tenant-x",
			id:       "",
			expect:   "tenant-x/keys/.key",
		},
		{
			name:     "empty ID without tenant",
			tenantID: "",
			id:       "",
			expect:   "keys/.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TenantKeyPath(tt.tenantID, tt.id)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestTenantKeyPath_BackwardCompatible verifies that TenantKeyPath with empty
// tenant produces the same result as KeyPath.
func TestTenantKeyPath_BackwardCompatible(t *testing.T) {
	ids := []string{"key1", "my-uuid-key", "test_key_123", ""}
	for _, id := range ids {
		assert.Equal(t, KeyPath(id), TenantKeyPath("", id),
			"TenantKeyPath with empty tenant must match KeyPath for id=%q", id)
	}
}

// TestTenantCertPath tests TenantCertPath with empty and non-empty tenant IDs.
func TestTenantCertPath(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		id       string
		expect   string
	}{
		{
			name:     "empty tenant falls back to CertPath",
			tenantID: "",
			id:       "cert1",
			expect:   "certs/cert1.pem",
		},
		{
			name:     "tenant namespaces cert path",
			tenantID: "org-42",
			id:       "cert1",
			expect:   "org-42/certs/cert1.pem",
		},
		{
			name:     "domain-like ID with tenant",
			tenantID: "team-x",
			id:       "example.com",
			expect:   "team-x/certs/example.com.pem",
		},
		{
			name:     "empty ID with tenant",
			tenantID: "tenant-y",
			id:       "",
			expect:   "tenant-y/certs/.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TenantCertPath(tt.tenantID, tt.id)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestTenantCertPath_BackwardCompatible verifies that TenantCertPath with empty
// tenant produces the same result as CertPath.
func TestTenantCertPath_BackwardCompatible(t *testing.T) {
	ids := []string{"cert1", "example.com", "550e8400-e29b-41d4-a716-446655440000", ""}
	for _, id := range ids {
		assert.Equal(t, CertPath(id), TenantCertPath("", id),
			"TenantCertPath with empty tenant must match CertPath for id=%q", id)
	}
}

// TestTenantCertChainPath tests TenantCertChainPath with empty and non-empty tenant IDs.
func TestTenantCertChainPath(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		id       string
		expect   string
	}{
		{
			name:     "empty tenant falls back to CertChainPath",
			tenantID: "",
			id:       "chain1",
			expect:   "certs/chain1-chain.pem",
		},
		{
			name:     "tenant namespaces cert chain path",
			tenantID: "tenant-abc",
			id:       "chain1",
			expect:   "tenant-abc/certs/chain1-chain.pem",
		},
		{
			name:     "UUID ID with tenant",
			tenantID: "org-99",
			id:       "550e8400-e29b-41d4-a716-446655440000",
			expect:   "org-99/certs/550e8400-e29b-41d4-a716-446655440000-chain.pem",
		},
		{
			name:     "empty ID with tenant",
			tenantID: "tenant-z",
			id:       "",
			expect:   "tenant-z/certs/-chain.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TenantCertChainPath(tt.tenantID, tt.id)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestTenantCertChainPath_BackwardCompatible verifies that TenantCertChainPath with
// empty tenant produces the same result as CertChainPath.
func TestTenantCertChainPath_BackwardCompatible(t *testing.T) {
	ids := []string{"chain1", "example.com", "my-uuid", ""}
	for _, id := range ids {
		assert.Equal(t, CertChainPath(id), TenantCertChainPath("", id),
			"TenantCertChainPath with empty tenant must match CertChainPath for id=%q", id)
	}
}

// TestTenantKeyPrefix tests TenantKeyPrefix with empty and non-empty tenant IDs.
func TestTenantKeyPrefix(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		expect   string
	}{
		{
			name:     "empty tenant returns default prefix",
			tenantID: "",
			expect:   "keys/",
		},
		{
			name:     "tenant namespaces key prefix",
			tenantID: "tenant-abc",
			expect:   "tenant-abc/keys/",
		},
		{
			name:     "UUID tenant ID",
			tenantID: "550e8400-e29b-41d4-a716-446655440000",
			expect:   "550e8400-e29b-41d4-a716-446655440000/keys/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TenantKeyPrefix(tt.tenantID)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestTenantCertPrefix tests TenantCertPrefix with empty and non-empty tenant IDs.
func TestTenantCertPrefix(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		expect   string
	}{
		{
			name:     "empty tenant returns default prefix",
			tenantID: "",
			expect:   "certs/",
		},
		{
			name:     "tenant namespaces cert prefix",
			tenantID: "org-42",
			expect:   "org-42/certs/",
		},
		{
			name:     "UUID tenant ID",
			tenantID: "550e8400-e29b-41d4-a716-446655440000",
			expect:   "550e8400-e29b-41d4-a716-446655440000/certs/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TenantCertPrefix(tt.tenantID)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestValidateTenantID tests ValidateTenantID with valid, empty, and invalid inputs.
func TestValidateTenantID(t *testing.T) {
	tests := []struct {
		name      string
		tenantID  string
		expectErr bool
	}{
		{
			name:      "empty is valid (single-tenant mode)",
			tenantID:  "",
			expectErr: false,
		},
		{
			name:      "simple alphanumeric",
			tenantID:  "tenant123",
			expectErr: false,
		},
		{
			name:      "hyphenated ID",
			tenantID:  "my-tenant-id",
			expectErr: false,
		},
		{
			name:      "underscored ID",
			tenantID:  "tenant_abc",
			expectErr: false,
		},
		{
			name:      "UUID format",
			tenantID:  "550e8400-e29b-41d4-a716-446655440000",
			expectErr: false,
		},
		{
			name:      "single character",
			tenantID:  "a",
			expectErr: false,
		},
		{
			name:      "path traversal with double dots",
			tenantID:  "..",
			expectErr: true,
		},
		{
			name:      "path traversal embedded",
			tenantID:  "tenant../escape",
			expectErr: true,
		},
		{
			name:      "forward slash",
			tenantID:  "tenant/escape",
			expectErr: true,
		},
		{
			name:      "backslash",
			tenantID:  "tenant\\escape",
			expectErr: true,
		},
		{
			name:      "double dots in middle",
			tenantID:  "abc..def",
			expectErr: true,
		},
		{
			name:      "leading forward slash",
			tenantID:  "/tenant",
			expectErr: true,
		},
		{
			name:      "trailing forward slash",
			tenantID:  "tenant/",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTenantID(tt.tenantID)
			if tt.expectErr {
				require.Error(t, err)
				var invalidErr *ErrInvalidTenantID
				assert.True(t, errors.As(err, &invalidErr),
					"error should be *ErrInvalidTenantID, got %T", err)
				assert.Equal(t, tt.tenantID, invalidErr.TenantID)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateTenantID_ErrorType verifies the typed error contains the right tenant ID
// and produces a readable error message.
func TestValidateTenantID_ErrorType(t *testing.T) {
	err := ValidateTenantID("bad/../id")
	require.Error(t, err)

	var invalidErr *ErrInvalidTenantID
	require.True(t, errors.As(err, &invalidErr))
	assert.Equal(t, "bad/../id", invalidErr.TenantID)
	assert.Contains(t, invalidErr.Error(), "bad/../id")
	assert.Contains(t, invalidErr.Error(), "must not contain path separators")
}

// TestTenantPathIsolation verifies that different tenants produce non-overlapping paths
// for the same key/cert ID.
func TestTenantPathIsolation(t *testing.T) {
	id := "shared-key"

	keyA := TenantKeyPath("tenant-a", id)
	keyB := TenantKeyPath("tenant-b", id)
	keyNone := TenantKeyPath("", id)

	// All paths must be distinct
	assert.NotEqual(t, keyA, keyB)
	assert.NotEqual(t, keyA, keyNone)
	assert.NotEqual(t, keyB, keyNone)

	certA := TenantCertPath("tenant-a", id)
	certB := TenantCertPath("tenant-b", id)
	certNone := TenantCertPath("", id)

	assert.NotEqual(t, certA, certB)
	assert.NotEqual(t, certA, certNone)
	assert.NotEqual(t, certB, certNone)

	chainA := TenantCertChainPath("tenant-a", id)
	chainB := TenantCertChainPath("tenant-b", id)
	chainNone := TenantCertChainPath("", id)

	assert.NotEqual(t, chainA, chainB)
	assert.NotEqual(t, chainA, chainNone)
	assert.NotEqual(t, chainB, chainNone)
}
