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

package testutil

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// ErrFirstBootServicesUnavailable is returned by NewFirstBootNode when the
// constructed node exposes no tenant, user, or role service to seed through.
var ErrFirstBootServicesUnavailable = errors.New("testutil: qrdb node exposes no tenant, user or role service for first-boot")

// FirstBootNode is an in-memory go-qrdb standalone node on which qrdb's own
// canonical first-boot (qrdbsdk.FirstBootInitialize) has run: the system
// tenant exists and carries the built-in roles under the identifiers qrdb
// persisted for them, so an identity built from RoleID holds exactly what a
// real user record's RoleIDs would hold, and Client().RBAC() renders the same
// decision a production node renders for it.
//
// It exists for authorization tests: a fake that grants by role NAME cannot
// catch a check that compares role names against role identifiers, because
// in the fake the two are the same string.
type FirstBootNode struct {
	node   *qrdbnode.Node
	logger *slog.Logger
}

// NewFirstBootNode constructs the node with every network protocol and the
// seal disabled, runs first-boot, and registers the node's shutdown with
// t.Cleanup. It never touches the host outside t.TempDir.
func NewFirstBootNode(t testing.TB) (*FirstBootNode, error) {
	t.Helper()
	ctx := context.Background()

	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false

	node, err := qrdbnode.NewStandaloneNode(ctx, cfg, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		if closeErr := node.Close(); closeErr != nil {
			t.Errorf("testutil: close first-boot node: %v", closeErr)
		}
	})

	svcs := node.Services()
	if svcs == nil || svcs.Tenant == nil || svcs.User == nil || svcs.Role == nil {
		return nil, ErrFirstBootServicesUnavailable
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := qrdbsdk.FirstBootInitialize(ctx, qrdbsdk.FirstBootDependencies{
		Tenants: svcs.Tenant,
		Users:   svcs.User,
		Roles:   svcs.Role,
		Logger:  logger,
	}); err != nil {
		return nil, err
	}
	return &FirstBootNode{node: node, logger: logger}, nil
}

// ProvisionTenant runs qrdb's canonical control-plane tenant provisioning
// (qrdbsdk.ProvisionTenant) for tenantID: the tenant record, its own
// built-in roles, and its admin user, with prefix isolation. No certificate is
// enrolled and no tenant barrier is initialized. Afterwards RoleID resolves the tenant's
// roles, which carry identifiers distinct from the system tenant's.
func (n *FirstBootNode) ProvisionTenant(tenantID string) error {
	svcs := n.node.Services()
	if svcs == nil {
		return ErrFirstBootServicesUnavailable
	}
	_, err := qrdbsdk.ProvisionTenant(context.Background(), qrdbsdk.BootstrapTenantProvisionConfig{
		TenantID: tenantID,
		// The node runs with the seal disabled, so the tenant shares the
		// system store under a key prefix rather than owning a barrier.
		Isolation: qrdbsdk.TenantIsolationPrefix,
	}, qrdbsdk.BootstrapDependencies{
		Tenants: svcs.Tenant,
		Users:   svcs.User,
		Roles:   svcs.Role,
		Logger:  n.logger,
	})
	return err
}

// Client returns the node's in-process SDK client. Its RBAC() and Roles()
// clients are the ones production wires into auth.NewAuthorizer and
// XKMSService.SetUserClients.
func (n *FirstBootNode) Client() *qrdbsdk.Client {
	return n.node.Client()
}

// RoleID returns the identifier the named built-in role is persisted under in
// tenantID, read back from the node's role store rather than derived, so it
// is exactly the value a seeded user record carries in RoleIDs.
func (n *FirstBootNode) RoleID(tenantID, roleName string) (string, error) {
	ctx := qrdbsdk.ContextWithTenant(context.Background(), tenantID)
	r, err := n.node.Client().Roles().GetRoleByName(ctx, &qrdbtransport.GetRoleByNameRequest{
		TenantID: tenantID,
		Name:     roleName,
	})
	if err != nil {
		return "", err
	}
	return r.ID, nil
}
