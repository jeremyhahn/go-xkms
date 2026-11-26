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

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// A tenant ID the core create path refuses (not a SPIFFE trust-domain name,
// or the cluster trust domain) is the caller's bad input: InvalidArgument,
// not Internal.
func TestMapTenantError_RefusedTenantIDIsInvalidArgument(t *testing.T) {
	for _, id := range []string{"Acme", "cluster.example"} {
		t.Run(id, func(t *testing.T) {
			svc := &xkms.XKMSService{}
			svc.SetSPIFFETrustDomain("cluster.example")
			_, err := svc.CreateTenantDetail(context.Background(), &transport.CreateTenantRequest{ID: id, Name: "Tenant"}, nil)
			require.Error(t, err)

			assert.Equal(t, codes.InvalidArgument, status.Code(mapTenantError(err, "create tenant")))
		})
	}
}
