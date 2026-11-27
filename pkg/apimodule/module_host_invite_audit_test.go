package apimodule

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	qrdbaudit "github.com/jeremyhahn/go-qrdb/pkg/audit"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// TestModule_HostMount_InviteDenialIsAudited is SPEC row
// authz-device-onboarding with docs/audit-log/engineering.md ("Denials are
// logged, always") on the self-built ServiceModule path: the module wires
// the host node's audit plane into the service alongside the authorizer,
// so the users:invite refusal CreateUser makes below the transport gate
// lands in the node's audit trail.
func TestModule_HostMount_InviteDenialIsAudited(t *testing.T) {
	client := newHostNodeClient(t)
	ctx := context.Background()
	_, err := client.Roles().CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		ID:          "creator",
		Name:        "creator",
		TenantID:    qrdbsdk.SystemTenantID,
		Permissions: []string{string(qrdbsdk.PermissionUsersCreate)},
	})
	require.NoError(t, err)

	h := mountLikeHost(t, client)
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)

	creator := &auth.Identity{Subject: "creator", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"creator"}}
	_, err = h.svc.CreateUser(auth.WithIdentity(ctx, creator), &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)

	page, err := client.Audit().QueryAudit(ctx, qrdbtransport.AuditFilter{Resource: "users", Action: "invite"})
	require.NoError(t, err)
	require.NotEmpty(t, page.Events, "the refusal must reach the node's audit trail")
	require.Equal(t, "creator", page.Events[len(page.Events)-1].Actor)
}

// failingAuditClient is a node audit plane whose writes fail.
type failingAuditClient struct{ qrdbtransport.AuditClient }

func (failingAuditClient) EmitAudit(context.Context, qrdbtransport.AuditEvent) error {
	return errors.New("audit plane down")
}

// TestModule_HostAuditSink_WriteFailureFailsClosed: a decision the node's
// audit plane cannot record is not acted on; the module's sink returns the
// write failure, which the service's audit seam turns into go-qrdb's
// AuditGateError.
func TestModule_HostAuditSink_WriteFailureFailsClosed(t *testing.T) {
	sink := &clientAuditSink{audit: failingAuditClient{}}
	err := audit.Emit(context.Background(), sink, &audit.Event{
		Timestamp: time.Now(), Action: "invite", Resource: "users", Outcome: audit.OutcomeDeny,
	})
	var gate *qrdbsdk.AuditGateError
	require.True(t, errors.As(err, &gate), "want an AuditGateError, got %v", err)
}

// TestModule_HostMount_TenantDenialStaysInTheTenantTrail: with the host's
// service-context binder configured (WithServiceContext, which binds the
// system-tenant service principal for datastore calls), a tenant caller's
// users:invite refusal is recorded under the caller's own tenant. The node
// stamps an emitted event with the tenant of the context it is emitted
// under, so the audit write must keep the caller's context: a tenant's
// auditors read their own refusals and the system trail holds none of them.
func TestModule_HostMount_TenantDenialStaysInTheTenantTrail(t *testing.T) {
	const tenantID = "acme"
	client := newHostNodeClient(t)
	ctx := context.Background()
	tenantAdmin := qrdbsdk.ContextWithTenant(auth.WithIdentity(ctx, &auth.Identity{Subject: "acme-admin", TenantID: tenantID}), tenantID)
	_, err := client.Roles().CreateRole(tenantAdmin, &qrdbtransport.CreateRoleRequest{
		ID:          "acme-creator",
		Name:        "acme-creator",
		TenantID:    tenantID,
		Permissions: []string{string(qrdbsdk.PermissionUsersCreate)},
	})
	require.NoError(t, err)

	system := &auth.Identity{Subject: "xkms-service", TenantID: qrdbsdk.SystemTenantID}
	bindSystem := func(ctx context.Context) (context.Context, error) {
		return auth.WithIdentity(ctx, system), nil
	}
	h := mountLikeHost(t, client, WithServiceContext(bindSystem))
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)

	caller := &auth.Identity{Subject: "acme-creator", TenantID: tenantID, Roles: []string{"acme-creator"}}
	callerCtx := qrdbsdk.ContextWithTenant(auth.WithIdentity(ctx, caller), tenantID)
	_, err = h.svc.CreateUser(callerCtx, &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: tenantID,
	})
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)

	page, err := client.Audit().QueryAudit(tenantAdmin, qrdbtransport.AuditFilter{TenantID: tenantID, Resource: "users", Action: "invite"})
	require.NoError(t, err)
	require.NotEmpty(t, page.Events, "the tenant's refusal must reach the tenant's audit trail")
	last := page.Events[len(page.Events)-1]
	require.Equal(t, tenantID, last.TenantID)
	require.Equal(t, "acme-creator", last.Actor)

	sys, err := client.Audit().QueryAudit(ctx, qrdbtransport.AuditFilter{TenantID: qrdbsdk.SystemTenantID, Resource: "users", Action: "invite"})
	require.NoError(t, err)
	require.Empty(t, sys.Events, "a tenant's refusal must not land in the system trail")
}

// TestModule_HostMount_NoNodeAuditLoggerStillInvites: a host node built
// without an audit logger (no qrdbsdk.WithAuditLogger) exposes no audit
// client. The module then installs no sink, keeping the service's
// documented nil-sink posture (auditing off), so CreateUser answers with
// a typed decision instead of panicking on a nil audit client.
func TestModule_HostMount_NoNodeAuditLoggerStillInvites(t *testing.T) {
	// A node built without qrdbsdk.WithAuditLogger exposes no audit client;
	// composing the host over it must not panic.
	node, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	require.Nil(t, node.Client().Audit(), "the node is built without an audit logger")
	bare := mountLikeHost(t, node.Client())
	require.NotPanics(t, func() { bare.module.hostStores(bare.svc) })

	// The sink the module builds for a missing audit client is the nil
	// interface, the service's auditing-off posture, never an adapter
	// around a nil client.
	sink := hostAuditSink(nil)
	require.True(t, sink == nil, "want the nil sink, got %#v", sink)

	// With that sink installed, the users:invite decision is still made and
	// returned typed instead of panicking on the nil audit client.
	client := newHostNodeClient(t)
	ctx := context.Background()
	_, err = client.Roles().CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
		ID:          "creator",
		Name:        "creator",
		TenantID:    qrdbsdk.SystemTenantID,
		Permissions: []string{string(qrdbsdk.PermissionUsersCreate)},
	})
	require.NoError(t, err)
	h := mountLikeHost(t, client)
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)
	h.svc.SetAuditLogger(sink)

	creator := &auth.Identity{Subject: "creator", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"creator"}}
	require.NotPanics(t, func() {
		_, err = h.svc.CreateUser(auth.WithIdentity(ctx, creator), &transport.CreateUserRequest{
			Username: "invitee",
			Email:    "invitee@example.com",
			TenantID: qrdbsdk.SystemTenantID,
		})
	})
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)
}

// TestModule_HostMount_PreconfiguredAuthorizerIsAudited: a host that set its
// own authorizer (auth.NewNodeAuthorizer, the delegated-grant path) still
// gets the node's audit sink, so its invite decisions reach the trail.
func TestModule_HostMount_PreconfiguredAuthorizerIsAudited(t *testing.T) {
	client := newHostNodeClient(t)
	ctx := context.Background()
	h := mountLikeHost(t, client)
	preset := auth.NewAuthorizer(nodeScopeRBAC{client.RBAC()})
	h.svc.SetAuthorizer(preset)
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)
	require.Same(t, preset, h.svc.Authorizer(), "the host's authorizer is kept")
	require.NotNil(t, h.svc.AuditLogger(), "the node's sink is wired whoever set the authorizer")

	caller := &auth.Identity{Subject: "no-grant", TenantID: qrdbsdk.SystemTenantID}
	_, err := h.svc.CreateUser(auth.WithIdentity(ctx, caller), &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(err, &denied), "want PermissionDeniedError, got %v", err)

	page, err := client.Audit().QueryAudit(ctx, qrdbtransport.AuditFilter{Resource: "users", Action: "invite"})
	require.NoError(t, err)
	require.NotEmpty(t, page.Events, "the refusal must reach the node's audit trail")
	require.Equal(t, "no-grant", page.Events[len(page.Events)-1].Actor)
}

// TestModule_HostMount_PreconfiguredFailingSinkStopsInvite: an audit sink
// the host set is kept, and when its write fails an allowed invitation is
// refused with an AuditGateError and no account is created.
func TestModule_HostMount_PreconfiguredFailingSinkStopsInvite(t *testing.T) {
	client := newHostNodeClient(t)
	ctx := context.Background()
	h := mountLikeHost(t, client)
	h.svc.SetAuthorizer(auth.NewAuthorizer(nodeScopeRBAC{client.RBAC()}))
	failing := &clientAuditSink{audit: failingAuditClient{}}
	h.svc.SetAuditLogger(failing)
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)
	require.Same(t, failing, h.svc.AuditLogger(), "the host's sink is kept")

	delegated := &auth.Identity{
		Subject:          "qrdb-service:onboarder",
		TenantID:         qrdbsdk.SystemTenantID,
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	_, err := h.svc.CreateUser(auth.WithIdentity(ctx, delegated), &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	var gate *qrdbsdk.AuditGateError
	require.True(t, errors.As(err, &gate), "want an AuditGateError, got %v", err)
	_, err = client.Users().GetUserByUsername(ctx, qrdbsdk.SystemTenantID, "invitee")
	require.Error(t, err, "an unaudited invite creates nothing")
}

// switchableNodeAudit is a node audit sink whose writes fail once fail is set.
type switchableNodeAudit struct {
	qrdbsdk.NodeAuditLogger
	fail atomic.Bool
}

func (s *switchableNodeAudit) Emit(ctx context.Context, ev qrdbaudit.AuditEvent) error {
	if s.fail.Load() {
		return errors.New("node audit plane down")
	}
	return s.NodeAuditLogger.Emit(ctx, ev)
}

// TestModule_HostMount_PreconfiguredAuthorizerNodeSinkFailureStopsInvite: a
// host that set its own authorizer and no sink gets the node's audit sink
// from hostStores, and when the node's audit plane fails an allowed
// invitation is refused with an AuditGateError and no account is created.
func TestModule_HostMount_PreconfiguredAuthorizerNodeSinkFailureStopsInvite(t *testing.T) {
	sink := &switchableNodeAudit{NodeAuditLogger: qrdbsdk.NewAuditRingBuffer(64)}
	cfg := &config.Config{Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()}}
	node, _, err := embeddednode.OpenEmbeddedNode(context.Background(), embeddednode.EmbeddedNodeOptions{
		Config:    cfg,
		Logger:    slog.New(slog.DiscardHandler),
		AuditSink: sink,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	client := node.Client()
	require.NotNil(t, client.Audit(), "the node exposes its audit client")

	ctx := context.Background()
	h := mountLikeHost(t, client)
	preset := auth.NewAuthorizer(nodeScopeRBAC{client.RBAC()})
	h.svc.SetAuthorizer(preset)
	h.svc.SetUserClients(client.Users(), client.Roles())
	h.module.hostStores(h.svc)
	require.Same(t, preset, h.svc.Authorizer(), "the host's authorizer is kept")
	require.NotNil(t, h.svc.AuditLogger(), "hostStores wires the node's sink")
	require.IsType(t, &clientAuditSink{}, h.svc.AuditLogger(), "the sink is the node's, not one the test set")

	sink.fail.Store(true)
	delegated := &auth.Identity{
		Subject:          "qrdb-service:onboarder",
		TenantID:         qrdbsdk.SystemTenantID,
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	_, err = h.svc.CreateUser(auth.WithIdentity(ctx, delegated), &transport.CreateUserRequest{
		Username: "invitee",
		Email:    "invitee@example.com",
		TenantID: qrdbsdk.SystemTenantID,
	})
	var gate *qrdbsdk.AuditGateError
	require.True(t, errors.As(err, &gate), "want an AuditGateError, got %v", err)

	sink.fail.Store(false)
	_, err = client.Users().GetUserByUsername(ctx, qrdbsdk.SystemTenantID, "invitee")
	require.Error(t, err, "an unaudited invite creates nothing")
}
