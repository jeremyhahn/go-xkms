// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package offline builds OIDC credential services (pkg/oidc/credential) for
// tests of the API layers above them. It is apart from oidccredentialtest
// because the credential service reaches pkg/auth, which the transports
// below pkg/auth cannot import from their tests.
package offline

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
)

// NewService returns a credential service over an in-memory barrier
// registry with an initialized, unsealed barrier for each of tenants. It
// requests nothing of a provider until a credential needs one; credentials
// created with oidccredentialtest.Config never do.
func NewService(t *testing.T, tenants ...string) *credential.Service {
	t.Helper()
	registry := barriertest.NewRegistry(t)
	for _, tenant := range tenants {
		barriertest.RegisterTenant(t, registry, tenant)
	}
	svc, err := credential.New(credential.RegistryBarriers(registry))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc
}
