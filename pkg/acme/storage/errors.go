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

import "errors"

// Business logic errors for external account bindings.
var (
	// ErrExternalAccountBindingExpired is returned when an external account binding has expired.
	ErrExternalAccountBindingExpired = errors.New("external account binding has expired")

	// ErrExternalAccountBindingUsed is returned when an external account binding has already been used.
	ErrExternalAccountBindingUsed = errors.New("external account binding has already been used")

	// ErrExternalAccountBindingRevoked is returned when an external account binding has been revoked.
	ErrExternalAccountBindingRevoked = errors.New("external account binding has been revoked")
)

// Business logic errors for tenants.
var (
	// ErrTenantAlreadyExists is returned when trying to create a tenant that already exists.
	ErrTenantAlreadyExists = errors.New("tenant already exists")

	// ErrTenantSuspended is returned when an operation is attempted on a suspended tenant.
	ErrTenantSuspended = errors.New("tenant is suspended")

	// ErrTenantDeleted is returned when an operation is attempted on a deleted tenant.
	ErrTenantDeleted = errors.New("tenant is deleted")

	// ErrTenantCANotConfigured is returned when a tenant's CA is not configured.
	ErrTenantCANotConfigured = errors.New("tenant CA not configured")

	// ErrTenantQuotaExceeded is returned when a tenant exceeds their resource quota.
	ErrTenantQuotaExceeded = errors.New("tenant quota exceeded")
)
