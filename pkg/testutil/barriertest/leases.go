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

package barriertest

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

// NewStandaloneCoordinator boots a real in-memory standalone qrdb node --
// no network protocols, no seal, everything under t.TempDir -- configured
// with xkms's service principal, as embeddednode.NewNode configures every
// node. It returns the node's coordination client, the lease primitive a
// host hands the OIDC credential service, and the node's ServiceContext,
// which a lease call must run on: the node refuses a call that carries no
// identity.
func NewStandaloneCoordinator(t testing.TB) (*qrdbsdk.Coordinator, func(context.Context) (context.Context, error)) {
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

	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil, serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	coord, err := node.Client().Coordination()
	require.NoError(t, err)
	return coord, node.ServiceContext
}
