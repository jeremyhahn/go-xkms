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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
)

// TestHandleCreateUser_NonSystemTenantInviteIsForbidden: CreateUser's refusal
// of an invited account outside the system tenant, whether the tenant is
// named in the body or resolved from the caller context, is a policy refusal
// (403), not a 500, and the store is never reached (#2183 narrowing part 13).
func TestHandleCreateUser_NonSystemTenantInviteIsForbidden(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		body createUserBody
	}{
		{"explicit tenant", context.Background(),
			createUserBody{Username: "acme-user", Email: "user@acme.example", TenantID: "acme"}},
		{"context tenant", qrdbsdk.ContextWithTenant(context.Background(), "acme"),
			createUserBody{Username: "acme-user", Email: "user@acme.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			users := &restMockUserClient{
				createUser: func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
					called = true
					return &qrdbtransport.User{ID: 1, Username: req.Username}, nil
				},
			}
			r := setupUserHandlerTest(t, users, &restMockRoleClient{})

			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/users/", bytes.NewReader(body)).WithContext(tc.ctx)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusForbidden, rr.Code)
			assert.False(t, called, "the store must not be reached")
		})
	}
}
