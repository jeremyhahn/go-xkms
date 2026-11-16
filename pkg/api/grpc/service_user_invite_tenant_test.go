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
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// TestServiceCreateUser_NonSystemTenantInviteIsPermissionDenied: CreateUser's
// refusal of an invited account outside the system tenant, whether the tenant
// is named in the request or resolved from the caller context, is a policy
// refusal (PermissionDenied), not an Internal server fault, and nothing is
// persisted (#2183 narrowing part 13).
func TestServiceCreateUser_NonSystemTenantInviteIsPermissionDenied(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		req  *pb.CreateUserRequest
	}{
		{"explicit tenant", context.Background(),
			&pb.CreateUserRequest{Username: "acme-user", Email: "user@acme.example", TenantId: "acme"}},
		{"context tenant", qrdbsdk.ContextWithTenant(context.Background(), "acme"),
			&pb.CreateUserRequest{Username: "acme-user", Email: "user@acme.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, users := newUserGRPCService(t)
			_, err := svc.CreateUser(tc.ctx, tc.req)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.Empty(t, users.byID, "no account is persisted")
		})
	}
}
