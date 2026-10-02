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
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	xkmsaudit "github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// countingRBAC admits everything and counts how often it is asked. QueryAudit
// must never ask: its confinement is fixed by the caller's tenant, not by a
// grant, so no grant can widen it.
type countingRBAC struct{ calls int }

func (c *countingRBAC) Authorize(context.Context, *qrdbtransport.Identity, string, string) error {
	c.calls++
	return nil
}

func (c *countingRBAC) ListPermissions(context.Context, *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func identityCtx(tenantID string, roles ...string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "caller", TenantID: tenantID, Roles: roles})
}

// TestQueryAudit_EveryCallerIsConfinedToItsOwnTenant is go-qrdb's audit
// contract: every caller reads only its own tenant's events, the system
// tenant included -- the #1115 exploit (a tenant Admin asking for every
// tenant with an empty filter) and the old system-tenant lift alike. A
// foreign or empty request is narrowed to the caller's tenant, never "" (the
// chain's match-everything filter), and no authorizer decision is consulted,
// so an admitting RBAC cannot widen it either.
func TestQueryAudit_EveryCallerIsConfinedToItsOwnTenant(t *testing.T) {
	callers := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"tenant admin", identityCtx("tenant-a", qrdbsdk.PermissionRoleAdmin), "tenant-a"},
		{"system admin", identityCtx(qrdbsdk.SystemTenantID, qrdbsdk.PermissionRoleAdmin), qrdbsdk.SystemTenantID},
		{"system auditor", identityCtx(qrdbsdk.SystemTenantID, qrdbsdk.PermissionRoleAuditor), qrdbsdk.SystemTenantID},
		{"identity with no tenant", identityCtx(""), qrdbsdk.SystemTenantID},
		{"no identity", context.Background(), qrdbsdk.SystemTenantID},
	}
	for _, caller := range callers {
		for _, requested := range []string{"", "tenant-a", "tenant-b", qrdbsdk.SystemTenantID} {
			t.Run(caller.name+"/requested="+requested, func(t *testing.T) {
				stub := &stubAuditClient{page: &qrdbtransport.AuditPage{}}
				svc := auditService(t, stub)
				rbac := &countingRBAC{}
				svc.SetAuthorizer(auth.NewAuthorizer(rbac))

				_, err := svc.QueryAudit(caller.ctx, &transport.AuditFilter{TenantID: requested})

				require.NoError(t, err)
				assert.Equal(t, caller.want, stub.gotFilter.TenantID)
				assert.Zero(t, rbac.calls, "no grant decides an audit query's tenant")
			})
		}
	}
}

// TestQueryAudit_RBACDisabledStillConfines proves the confinement does not
// depend on RBAC being on.
func TestQueryAudit_RBACDisabledStillConfines(t *testing.T) {
	stub := &stubAuditClient{page: &qrdbtransport.AuditPage{}}
	svc := auditService(t, stub)
	svc.SetAuthorizer(auth.NewAuthorizer(nil))

	_, err := svc.QueryAudit(identityCtx(qrdbsdk.SystemTenantID), &transport.AuditFilter{TenantID: "tenant-b"})
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.SystemTenantID, stub.gotFilter.TenantID)
}

// memoryNodeConfigForAudit returns an in-memory qrdb node config with all
// network protocols disabled, suitable for an in-process round-trip test.
// Mirrors pkg/audit's memoryNodeConfig; not shared across packages because
// that one lives in an external _test package.
func memoryNodeConfigForAudit(t *testing.T) *qrdbsdk.DaemonConfig {
	t.Helper()
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	return cfg
}

// TestQueryAudit_SystemAuditorSeesIdentityLessEvent is the #1134 round-trip
// proof: an event emitted with no identity on the context (a background job,
// an internal operation) is stored under qrdbsdk.SystemTenantID by
// audit.QRDBLogger, not "" (the audit chain's match-everything filter), so a
// system-tenant caller -- which auditTenantFilter confines to SystemTenantID
// -- can read it back through QueryAudit. Before the fix the event was stored
// under "" and no confined query could ever see it.
func TestQueryAudit_SystemAuditorSeesIdentityLessEvent(t *testing.T) {
	t.Chdir(t.TempDir())
	ctx := context.Background()

	sink := qrdbsdk.NewAuditRingBuffer(64)
	serverOpts := []qrdbsdk.ServerOption{qrdbsdk.WithAuditLogger(sink)}

	node, err := qrdbnode.NewStandaloneNode(ctx, memoryNodeConfigForAudit(t), serverOpts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })

	client := node.Client()
	require.NotNil(t, client)
	require.NotNil(t, client.Audit())

	logger := xkmsaudit.NewQRDBLogger(client.Audit())
	require.NoError(t, logger.Log(ctx, &xkmsaudit.Event{
		Timestamp: time.Now().UTC(),
		Subject:   "system",
		Action:    "seal_auto_unseal",
		Resource:  "barrier",
		Outcome:   xkmsaudit.OutcomeAllow,
	}))

	// An event of tenant-a, which no system-tenant query may return.
	tenantCtx := auth.WithIdentity(ctx, &auth.Identity{Subject: "alice", TenantID: "tenant-a"})
	require.NoError(t, logger.Log(tenantCtx, &xkmsaudit.Event{
		Timestamp: time.Now().UTC(),
		Subject:   "alice",
		Action:    "key_create",
		Resource:  "key",
		Outcome:   xkmsaudit.OutcomeAllow,
	}))

	svc := auditService(t, &stubAuditClient{page: &qrdbtransport.AuditPage{}})
	svc.SetAuditClient(client.Audit())

	page, err := svc.QueryAudit(
		identityCtx(qrdbsdk.SystemTenantID, qrdbsdk.PermissionRoleAuditor),
		&transport.AuditFilter{},
	)

	require.NoError(t, err)
	require.Len(t, page.Events, 1, "the system tenant reads its own event and none of tenant-a's")
	assert.Equal(t, qrdbsdk.SystemTenantID, page.Events[0].TenantID)
	assert.Equal(t, "seal_auto_unseal", page.Events[0].Action)

	// tenant-a reads its own event, and asking for the system tenant's is
	// narrowed to its own.
	page, err = svc.QueryAudit(tenantCtx, &transport.AuditFilter{TenantID: qrdbsdk.SystemTenantID})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	assert.Equal(t, "key_create", page.Events[0].Action)
}
