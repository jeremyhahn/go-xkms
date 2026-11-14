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

//go:build qrdb_vlog

package tlog

import (
	"context"
	"crypto"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

// newVlogClient starts an in-memory standalone node configured as
// production's (serviceprincipal.Option) with p as its head-signer
// provider, and returns its verifiable-log client and a context running as
// the xkms service principal. go-qrdb serves verifiable logs only when built
// with its qrdb_vlog tag, so every test that needs a node carries it.
func newVlogClient(t *testing.T, p *HeadSignerProvider) (transport.VlogClient, context.Context) {
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

	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil,
		serviceprincipal.Option(), qrdbnode.WithHeadSignerProvider(p))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	ctx, err := node.ServiceContext(t.Context())
	require.NoError(t, err)
	return node.Client().Vlog(), ctx
}

// newLog creates the "certs" log over a fresh node whose CA key is signer.
func newLog(t *testing.T, signer crypto.Signer) (*Log, transport.VlogClient, context.Context) {
	t.Helper()
	return newLogWith(t, signer, Config{Name: "certs", Origin: testOrigin})
}

// newLogWith creates a log from cfg over a fresh node whose CA key is signer.
func newLogWith(t *testing.T, signer crypto.Signer, cfg Config) (*Log, transport.VlogClient, context.Context) {
	t.Helper()
	p := newProvider(t, signer)
	client, ctx := newVlogClient(t, p)
	l, err := Create(ctx, client, cfg, p)
	require.NoError(t, err)
	return l, client, ctx
}
