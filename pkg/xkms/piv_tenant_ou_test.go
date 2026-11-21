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

package xkms

import (
	"context"
	"crypto/x509"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const pivTenantOUTenant = "acme"

func pivTenantContext() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: pivTenantOUTenant})
}

// A PIV self-signed certificate names the caller's tenant as OU[0], the
// only organizational unit it carries.
func TestGeneratePIVKey_SelfSigned_StampsCallerTenant(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"tenant caller", pivTenantContext(), pivTenantOUTenant},
		{"no identity", context.Background(), qrdbsdk.SystemTenantID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := setupPIVWithMockResolver(t)
			_, err := GeneratePIVKey(tc.ctx, &transport.GeneratePIVKeyRequest{
				Slot:         "9a",
				Algorithm:    "ecdsap256",
				Backend:      "software",
				Subject:      "PIV Tenant",
				Organization: "Example Org",
			})
			require.NoError(t, err)
			slot, err := pivcert.ParseSlot("9a")
			require.NoError(t, err)
			stored, ok := store.certs[slot]
			require.True(t, ok)
			require.Equal(t, []string{tc.want}, stored.Subject.OrganizationalUnit)
			require.Equal(t, "PIV Tenant", stored.Subject.CommonName)
		})
	}
}

// SelfSignExistingPIVKey stamps the caller's tenant the same way.
func TestSelfSignExistingPIVKey_StampsCallerTenant(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"tenant caller", pivTenantContext(), pivTenantOUTenant},
		{"no identity", context.Background(), qrdbsdk.SystemTenantID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, software := setupPIVAndServiceForSelfSign(t)
			slot, err := pivcert.ParseSlot("9a")
			require.NoError(t, err)
			_, err = software.GenerateECDSA(tc.ctx, &types.KeyAttributes{CN: PivSlotCN(slot), KeyAlgorithm: x509.ECDSA})
			require.NoError(t, err)

			_, err = SelfSignExistingPIVKey(tc.ctx, "software", "9a", "Existing", 30)
			require.NoError(t, err)
			stored, ok := store.certs[slot]
			require.True(t, ok)
			require.Equal(t, []string{tc.want}, stored.Subject.OrganizationalUnit)
		})
	}
}
