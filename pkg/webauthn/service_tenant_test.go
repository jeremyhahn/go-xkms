// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package webauthn

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// tenantStore is a UserStore double whose tenant the test sets; the embedded
// interface is nil, so any other call panics.
type tenantStore struct {
	UserStore
	tenant string
}

func (s tenantStore) TenantID() string { return s.tenant }

// TestUserStoreTenant_NoTenantIsNotSystem is Tenant Agent ruling 1041 (1):
// a user store that names no tenant must not read as the system tenant,
// which reopened the cross-tenant invite hole; it is a typed error.
func TestUserStoreTenant_NoTenantIsNotSystem(t *testing.T) {
	_, err := userStoreTenant(tenantStore{})
	require.Error(t, err)
	var unset *UserStoreTenantUnsetError
	require.True(t, errors.As(err, &unset), "want *UserStoreTenantUnsetError, got %T", err)

	_, err = userStoreTenant(nil)
	require.Error(t, err)
	require.True(t, errors.As(err, &unset), "want *UserStoreTenantUnsetError, got %T", err)

	tenant, err := userStoreTenant(tenantStore{tenant: "tenant-a"})
	require.NoError(t, err)
	require.Equal(t, "tenant-a", tenant)
}
