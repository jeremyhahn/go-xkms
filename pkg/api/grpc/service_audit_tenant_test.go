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

package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestServiceQueryAudit_TenantCallerIsClampedToItsOwnTenant drives #1115 over
// gRPC: a tenant caller's empty or foreign tenant_id reaches the audit chain as
// its own tenant.
func TestServiceQueryAudit_TenantCallerIsClampedToItsOwnTenant(t *testing.T) {
	client := &grpcFakeAuditClient{}
	svc := newAuditGRPCService(t, client)
	ctx := auth.WithIdentity(t.Context(), &auth.Identity{Subject: "alice", TenantID: "tenant-a"})

	for _, requested := range []string{"", "tenant-b"} {
		_, err := svc.QueryAudit(ctx, &pb.QueryAuditRequest{TenantId: requested})
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", client.lastFilter.TenantID, "requested %q", requested)
	}
}
