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

package admin

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateTenant_RefusesNonTrustDomainID pins that go-xkms tenant creation
// refuses an ID that can never name a SPIFFE trust domain, before go-qrdb is
// called: such a tenant could never hold an SVID.
func TestCreateTenant_RefusesNonTrustDomainID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want error
	}{
		{"uppercase", "Acme", spiffe.ErrTrustDomainCharacters},
		{"space", "a b", spiffe.ErrTrustDomainCharacters},
		{"slash", "a/b", spiffe.ErrTrustDomainCharacters},
		{"too long", strings.Repeat("a", 256), spiffe.ErrTrustDomainTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeTenantServicer()
			svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
			svc.SetTenantService(fake)

			_, err := svc.CreateTenant(context.Background(), CreateTenantRequest{ID: tc.id, Name: "Tenant"})
			require.Error(t, err)
			assert.True(t, errors.Is(err, caerrors.Malformed), "want an input error, got %v", err)
			assert.True(t, errors.Is(err, tc.want), "want %v reachable, got %v", tc.want, err)
			assert.Contains(t, err.Error(), "id")
			assert.Empty(t, fake.tenants, "go-qrdb CreateTenant must not be called on a refusal")
		})
	}
}

func TestCreateTenant_AcceptsTrustDomainID(t *testing.T) {
	for _, id := range []string{"acme", "acme-1.prod_eu"} {
		t.Run(id, func(t *testing.T) {
			fake := newFakeTenantServicer()
			svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
			svc.SetTenantService(fake)

			info, err := svc.CreateTenant(context.Background(), CreateTenantRequest{ID: id, Name: "Tenant"})
			require.NoError(t, err)
			assert.Equal(t, id, info.ID)
			assert.Contains(t, fake.tenants, id)
		})
	}
}

func TestCreateTenant_RefusesClusterTrustDomain(t *testing.T) {
	fake := newFakeTenantServicer()
	svc := mustTenantAwareAdminService(t, nil, nil, nil, slog.Default(), "1.0.0")
	svc.SetTenantService(fake)

	// Without a cluster trust domain the equality check is skipped.
	_, err := svc.CreateTenant(context.Background(), CreateTenantRequest{ID: "cluster.example", Name: "Tenant"})
	require.NoError(t, err)

	svc.SetClusterTrustDomain("cluster.example")
	fake = newFakeTenantServicer()
	svc.SetTenantService(fake)
	_, err = svc.CreateTenant(context.Background(), CreateTenantRequest{ID: "cluster.example", Name: "Tenant"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, caerrors.Malformed), "want an input error, got %v", err)
	assert.ErrorIs(t, err, spiffe.ErrTenantIsClusterTrustDomain)
	assert.Empty(t, fake.tenants, "go-qrdb CreateTenant must not be called on a refusal")

	_, err = svc.CreateTenant(context.Background(), CreateTenantRequest{ID: "acme", Name: "Tenant"})
	require.NoError(t, err)
}
