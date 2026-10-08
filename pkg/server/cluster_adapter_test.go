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

package server

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"

	"github.com/stretchr/testify/require"
)

// newClusterAdapterForTest boots a real, first-booted standalone qrdb node and
// returns a clusterClientAdapter wired to its own in-process ClusterClient, so
// the adapter is exercised against the real qrdb SDK instead of a hand-rolled
// fake, plus a context carrying a system-tenant identity holding roleName: the
// client authorizes every call as the identity on its context, as
// production's request contexts do.
func newClusterAdapterForTest(t *testing.T, roleName string) (*clusterClientAdapter, context.Context) {
	t.Helper()
	node, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	roleID, err := node.RoleID(qrdbsdk.SystemTenantID, roleName)
	require.NoError(t, err)

	caller := &qrdbsdk.Identity{Subject: roleName, TenantID: qrdbsdk.SystemTenantID, Roles: []string{roleID}}
	ctx := qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(context.Background(), caller), qrdbsdk.SystemTenantID)
	return &clusterClientAdapter{cluster: node.Client().Cluster()}, ctx
}

// TestClusterClientAdapter_LeaderEndpoint_UnknownProtocol proves an unknown
// API protocol name is rejected by the underlying qrdb SDK rather than
// silently returning no endpoint, and that the adapter's plain-string
// protocol parameter reaches that validation.
func TestClusterClientAdapter_LeaderEndpoint_UnknownProtocol(t *testing.T) {
	adapter, ctx := newClusterAdapterForTest(t, qrdbsdk.RoleNameAdmin)

	_, err := adapter.LeaderEndpoint(ctx, 0, "carrier-pigeon")
	require.Error(t, err)
}
