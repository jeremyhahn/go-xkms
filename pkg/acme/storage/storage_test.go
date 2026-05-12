// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStorageErrors verifies that all storage error variables are properly defined.
func TestStorageErrors(t *testing.T) {
	// External account binding errors
	assert.NotNil(t, ErrExternalAccountBindingExpired)
	assert.NotNil(t, ErrExternalAccountBindingUsed)
	assert.NotNil(t, ErrExternalAccountBindingRevoked)

	// Tenant errors
	assert.NotNil(t, ErrTenantAlreadyExists)
	assert.NotNil(t, ErrTenantSuspended)
	assert.NotNil(t, ErrTenantDeleted)
	assert.NotNil(t, ErrTenantCANotConfigured)
	assert.NotNil(t, ErrTenantQuotaExceeded)
}

// TestStorageErrorMessages verifies that error messages are descriptive.
func TestStorageErrorMessages(t *testing.T) {
	tests := []struct {
		err      error
		expected string
	}{
		{ErrExternalAccountBindingExpired, "external account binding has expired"},
		{ErrExternalAccountBindingUsed, "external account binding has already been used"},
		{ErrExternalAccountBindingRevoked, "external account binding has been revoked"},
		{ErrTenantAlreadyExists, "tenant already exists"},
		{ErrTenantSuspended, "tenant is suspended"},
		{ErrTenantDeleted, "tenant is deleted"},
		{ErrTenantCANotConfigured, "tenant CA not configured"},
		{ErrTenantQuotaExceeded, "tenant quota exceeded"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.Error())
		})
	}
}

// TestInterfaceTypes verifies that interface types are properly exported.
func TestInterfaceTypes(t *testing.T) {
	var _ Factory
	var _ TenantAwareFactory
}
