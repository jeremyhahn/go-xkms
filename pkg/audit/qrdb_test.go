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

package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memoryNodeConfig returns an in-memory qrdb node config with all network
// protocols disabled, suitable for an in-process round-trip test. A temporary
// directory is provided as DataDir because the qrdb lifecycle now rejects an
// empty DataDir (EmptyVectorDataDirError) when the vector subsystem is enabled.
func memoryNodeConfig(t *testing.T) *qrdbsdk.DaemonConfig {
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

// TestQRDBLogger_EmitQueryRoundTrip is the end-to-end proof that an xkms audit
// Event logged through QRDBLogger lands in the qrdb node's HMAC-chained audit
// subsystem and is retrievable through the same node's QueryAudit. It mirrors
// the production wiring: the node receives its audit sink via
// sdk.WithAuditLogger(sdk.NewAuditRingBuffer(...)) — exactly what
// initEmbeddedQRDBNode does — and QRDBLogger emits through Client().Audit().
func TestQRDBLogger_EmitQueryRoundTrip(t *testing.T) {
	// memoryNodeConfig pins DataDir to a temp dir, so the vector store and other
	// on-disk subsystems are already contained there. chdir into a temp dir as
	// belt-and-suspenders for any subsystem that still materializes a relative
	// path, keeping artifacts out of the source tree.
	t.Chdir(t.TempDir())

	ctx := context.Background()

	sink := qrdbsdk.NewAuditRingBuffer(64)
	serverOpts := []qrdbsdk.ServerOption{qrdbsdk.WithAuditLogger(sink)}

	node, err := qrdbnode.NewStandaloneNode(ctx, memoryNodeConfig(t), serverOpts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })

	client := node.Client()
	require.NotNil(t, client)
	require.NotNil(t, client.Audit(), "node must expose an audit client when a sink is injected")

	logger := audit.NewQRDBLogger(client.Audit())

	// Carry a tenant-scoped identity so the logger lifts it into the chain.
	id := &auth.Identity{Subject: "alice", TenantID: "tenant-a", Roles: []string{"admin"}}
	emitCtx := auth.WithIdentity(ctx, id)

	ev := &audit.Event{
		Timestamp:  time.Now().UTC(),
		Subject:    "alice",
		Action:     "unseal",
		Resource:   "barrier",
		ResourceID: "system",
		Outcome:    audit.OutcomeAllow,
		Details: map[string]string{
			"transport":   "grpc",
			"remote_addr": "10.0.0.7:5555",
			"role":        "admin",
		},
	}
	require.NoError(t, logger.Log(emitCtx, ev))

	page, err := client.Audit().QueryAudit(ctx, qrdbtransport.AuditFilter{})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)

	got := page.Events[0]
	assert.Equal(t, "alice", got.Actor)
	assert.Equal(t, "unseal", got.Action)
	assert.Equal(t, "barrier", got.Resource)
	assert.Equal(t, audit.OutcomeAllow, got.Outcome)
	assert.Equal(t, "tenant-a", got.TenantID, "tenant lifted from identity")
	assert.Equal(t, "10.0.0.7:5555", got.ClientIP)
	assert.Equal(t, "admin", got.Role)
	require.NotNil(t, got.Attributes)
	assert.Equal(t, "system", got.Attributes["resource_id"])
	assert.Equal(t, "grpc", got.Attributes["transport"])
}

// TestQRDBLogger_NilEvent verifies the error path: a nil event is rejected with
// ErrNilEvent and never reaches the audit subsystem.
func TestQRDBLogger_NilEvent(t *testing.T) {
	logger := audit.NewQRDBLogger(stubAuditClient{})

	err := logger.Log(context.Background(), nil)
	assert.ErrorIs(t, err, audit.ErrNilEvent)
}

// TestQRDBLogger_Close verifies Close is a no-op: QRDBLogger does not own the
// AuditClient lifecycle.
func TestQRDBLogger_Close(t *testing.T) {
	logger := audit.NewQRDBLogger(stubAuditClient{})
	assert.NoError(t, logger.Close())
}

// stubAuditClient is a minimal AuditClient that records the last emitted event.
type stubAuditClient struct {
	emitted *qrdbtransport.AuditEvent
}

func (s stubAuditClient) EmitAudit(_ context.Context, ev qrdbtransport.AuditEvent) error {
	if s.emitted != nil {
		*s.emitted = ev
	}
	return nil
}

func (s stubAuditClient) QueryAudit(_ context.Context, _ qrdbtransport.AuditFilter) (*qrdbtransport.AuditPage, error) {
	return &qrdbtransport.AuditPage{Total: 0}, nil
}
