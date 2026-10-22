// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package xkms

import (
	"context"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// errGrantMissing is the fake RBAC client's denial.
var errGrantMissing = errors.New("fake rbac: permission denied")

// serviceWithRBAC is a service whose Authorizer is backed by rbac.
func serviceWithRBAC(t *testing.T, rbac qrdbtransport.RBACClient) *XKMSService {
	t.Helper()
	svc := &XKMSService{}
	svc.SetAuthorizer(auth.NewAuthorizer(rbac))
	return svc
}

// recordingRBAC grants exactly one permission and records what it was asked.
type recordingRBAC struct {
	grant    string
	resource string
	action   string
	identity *qrdbtransport.Identity
}

func (r *recordingRBAC) Authorize(_ context.Context, id *qrdbtransport.Identity, resource, action string) error {
	r.identity, r.resource, r.action = id, resource, action
	if resource+":"+action == r.grant {
		return nil
	}
	return errGrantMissing
}

func (r *recordingRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errGrantMissing
}

func (r *recordingRBAC) ListOwnPermissions(ctx context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return r.ListPermissions(ctx, nil)
}

// TestAuthorizeCaller_AsksTheAuthorizerForTheCaller proves the below-gate
// check resolves the identity on ctx and the named permission, and refuses
// what the authorizer refuses.
func TestAuthorizeCaller_AsksTheAuthorizerForTheCaller(t *testing.T) {
	rbac := &recordingRBAC{grant: "ssh:service"}
	svc := serviceWithRBAC(t, rbac)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "acme"})

	require.NoError(t, svc.AuthorizeCaller(ctx, auth.ResourceSSH, auth.ActionService))
	assert.Equal(t, "alice", rbac.identity.Subject)
	assert.Equal(t, "acme", rbac.identity.TenantID)
	assert.Equal(t, auth.ResourceSSH, rbac.resource)
	assert.Equal(t, auth.ActionService, rbac.action)

	require.ErrorIs(t, svc.AuthorizeCaller(ctx, auth.ResourceSSH, auth.ActionDelete), errGrantMissing)
}
