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

// server_policy_authz_test.go proves POST /api/v1/policies/ is behind the
// policy:create RequirePermission decorator end to end, through the real
// chi router (go-xkms#691) — the route-table counterpart of
// server_bootstrap_authz_test.go for the bootstrap route.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// fakePCRReader is a minimal policy.PCRReader returning deterministic
// values, exactly enough to construct a policy.Manager for the route's
// Enabled guard (hasPolicies) to mount the handler.
type fakePCRReader struct{}

func (fakePCRReader) ReadPCRs(_ string, indices []int) (map[int][]byte, error) {
	values := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		values[idx] = []byte{byte(idx)} // #nosec G115 - PCR indices are 0-23
	}
	return values, nil
}

// policyCreateBody is the wire request body for POST /api/v1/policies/, in
// pkg/api/rest/policy_handlers.go's own shape (see pkg/api/rest/wire's PCR
// Policy types for why it diverges from transport.PolicyCreateRequest).
func policyCreateBody(t *testing.T) *bytes.Reader {
	t.Helper()
	body, err := json.Marshal(PolicyCreateRequest{Name: "boot", Bank: "sha256", PCRIndices: []int{0, 7}})
	require.NoError(t, err)
	return bytes.NewReader(body)
}

// TestPolicyCreateRoute_RBACDenied proves a caller whose policy:create check
// is refused is denied by the middleware before the handler runs.
func TestPolicyCreateRoute_RBACDenied(t *testing.T) {
	mgr, err := policy.NewManager(fakePCRReader{}, policy.NewMemoryPolicyStore())
	require.NoError(t, err)

	server, err := NewServer(&Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
		PolicyManager:  mgr,
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(denyingRBACClient{}),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/", policyCreateBody(t))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// policyRecordingRBACClient records the resource:action pair it was asked
// to authorize and allows exactly one configured pair.
type policyRecordingRBACClient struct {
	allowResource string
	allowAction   string

	gotResource string
	gotAction   string
}

func (c *policyRecordingRBACClient) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	c.gotResource = resource
	c.gotAction = action
	if resource == c.allowResource && action == c.allowAction {
		return nil
	}
	return errors.New("permission denied")
}

func (c *policyRecordingRBACClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errors.New("not implemented")
}

// TestPolicyCreateRoute_RequiresPolicyCreate proves the route demands
// exactly policy:create — the same pair pkg/api/mcp's methodPermissions and
// pkg/api/grpc's proto option declare for PolicyCreate — and that a caller
// holding that grant passes the gate and reaches the real handler.
func TestPolicyCreateRoute_RequiresPolicyCreate(t *testing.T) {
	mgr, err := policy.NewManager(fakePCRReader{}, policy.NewMemoryPolicyStore())
	require.NoError(t, err)
	rbac := &policyRecordingRBACClient{allowResource: "policy", allowAction: "create"}

	server, err := NewServer(&Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
		PolicyManager:  mgr,
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(rbac),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/", policyCreateBody(t))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, "policy", rbac.gotResource, "decorator asked for wrong resource")
	assert.Equal(t, "create", rbac.gotAction, "decorator asked for wrong action")

	// The right grant passes the gate and reaches the handler, which
	// actually creates the policy.
	assert.Equal(t, http.StatusCreated, w.Code)
}
