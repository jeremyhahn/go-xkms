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

package xkms

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

func TestCreateTenantDetail_RefusesNonTrustDomainID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want error
	}{
		{"uppercase", "Acme", spiffe.ErrTrustDomainCharacters},
		{"space", "a b", spiffe.ErrTrustDomainCharacters},
		{"slash", "a/b", spiffe.ErrTrustDomainCharacters},
		{"too long", strings.Repeat("a", 256), spiffe.ErrTrustDomainTooLong},
		{"cluster trust domain", "cluster.example", spiffe.ErrTenantIsClusterTrustDomain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeTenantServicer{}
			svc := &XKMSService{}
			svc.SetTenantService(fake)
			svc.SetSPIFFETrustDomain("cluster.example")

			_, err := svc.CreateTenantDetail(context.Background(), &transport.CreateTenantRequest{ID: tc.id, Name: "Tenant"}, nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.want)
			assert.Empty(t, fake.createID, "go-qrdb CreateTenant must not be called on a refusal")
		})
	}
}

func TestCreateTenantDetail_AcceptsTrustDomainID(t *testing.T) {
	for _, id := range []string{"acme", "acme-1.prod_eu"} {
		t.Run(id, func(t *testing.T) {
			fake := &fakeTenantServicer{}
			svc := &XKMSService{}
			svc.SetTenantService(fake)
			svc.SetSPIFFETrustDomain("cluster.example")

			detail, err := svc.CreateTenantDetail(context.Background(), &transport.CreateTenantRequest{ID: id, Name: "Tenant"}, nil)
			require.NoError(t, err)
			assert.Equal(t, id, detail.Tenant.ID)
			assert.Equal(t, id, fake.createID)
		})
	}
}

func TestCreateTenantDetail_NoTrustDomainSkipsEqualityCheck(t *testing.T) {
	fake := &fakeTenantServicer{}
	svc := &XKMSService{}
	svc.SetTenantService(fake)

	_, err := svc.CreateTenantDetail(context.Background(), &transport.CreateTenantRequest{ID: "cluster.example", Name: "Tenant"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "cluster.example", fake.createID)
}

func TestCreateTenantDetail_EmptyChecksKeepOrder(t *testing.T) {
	svc := &XKMSService{}
	svc.SetTenantService(&fakeTenantServicer{})

	_, err := svc.CreateTenantDetail(context.Background(), &transport.CreateTenantRequest{Name: "Tenant"}, nil)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
	_, err = svc.CreateTenantDetail(context.Background(), &transport.CreateTenantRequest{ID: "Acme"}, nil)
	assert.ErrorIs(t, err, ErrTenantNameRequired)
}
