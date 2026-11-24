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

package mcp

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestHandleCreateUser_NonSystemTenantInviteIsForbidden: CreateUser's refusal
// of an invited account outside the system tenant, whether the tenant is
// named in the params or resolved from the caller context, is a policy
// refusal (ErrCodeForbidden), not an internal error, and the store is never
// reached (#2183 narrowing part 13).
func TestHandleCreateUser_NonSystemTenantInviteIsForbidden(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		req  *transport.CreateUserRequest
	}{
		{"explicit tenant", context.Background(),
			&transport.CreateUserRequest{Username: "acme-user", Email: "user@acme.example", TenantID: "acme"}},
		{"context tenant", qrdbsdk.ContextWithTenant(context.Background(), "acme"),
			&transport.CreateUserRequest{Username: "acme-user", Email: "user@acme.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			users := &mcpMockUserClient{
				createUser: func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
					called = true
					return &qrdbtransport.User{ID: 1, Username: req.Username}, nil
				},
			}
			server := newUserTestServer(t, users)

			_, err := server.handleCreateUser(tc.ctx, rpcRequest("user.create", tc.req))
			var opErr *KeyOpError
			require.True(t, errors.As(err, &opErr), "got %v", err)
			assert.Equal(t, ErrCodeForbidden, opErr.Code)
			assert.False(t, called, "the store must not be reached")
		})
	}
}
