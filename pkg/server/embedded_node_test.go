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

package server

import (
	"context"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// embeddedNodeTestLogger returns a logger that discards output, matching the
// other package fixtures' silent-by-default convention.
func embeddedNodeTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestOpenEmbeddedNode_StandaloneNoBarrier proves the base case:
// storage.backend="qrdb" with no barrier configured opens a standalone node
// over a fresh temp dir, unsealed, with the node-seal flip disabled.
func TestOpenEmbeddedNode_StandaloneNoBarrier(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	}

	node, sealRes, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: embeddedNodeTestLogger(),
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	defer func() { _ = node.Close() }()

	assert.False(t, sealRes.Enabled)
	assert.False(t, node.IsSealed())
}

// TestOpenEmbeddedNode_BarrierNoneAutoUnseals proves the node-flip case:
// barrier.enabled with strategy "none" engages the flip and auto-unseals
// unattended, matching TestNodeSealFlip_NoneStrategyAutoUnseal's assertion
// at the (*Server) level.
func TestOpenEmbeddedNode_BarrierNoneAutoUnseals(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "none"},
	}

	node, sealRes, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: embeddedNodeTestLogger(),
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	defer func() { _ = node.Close() }()

	assert.True(t, sealRes.Enabled)
	assert.False(t, node.IsSealed(), `strategy "none" must auto-unseal unattended`)
}

// TestOpenEmbeddedNode_ResolveNodeSealErrorPropagates proves a resolution
// error (tpm2 selected for the node-seal flip with no backends.tpm2 section)
// short-circuits before any node is constructed, rather than attempting to
// open hardware with a nil config.
func TestOpenEmbeddedNode_ResolveNodeSealErrorPropagates(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "tpm2"},
	}

	node, sealRes, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: embeddedNodeTestLogger(),
	})
	require.Error(t, err)
	assert.Nil(t, node)
	assert.False(t, sealRes.Enabled)

	var nodeSealErr *NodeSealError
	require.ErrorAs(t, err, &nodeSealErr)
}

// TestOpenEmbeddedNode_OverridesFactorRegistryAndAuditSink proves that a
// caller-supplied FactorRegistry/AuditSink is used as-is rather than built
// from NewNodeFactorRegistry/NewEmbeddedAuditSink -- the seam xkmsd init and
// xkmsd run rely on to share one registry/sink across composition roots.
func TestOpenEmbeddedNode_OverridesFactorRegistryAndAuditSink(t *testing.T) {
	registry, err := NewNodeFactorRegistry()
	require.NoError(t, err)
	sink := qrdbsdk.NewAuditRingBuffer(16)

	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	}

	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config:         cfg,
		Logger:         embeddedNodeTestLogger(),
		FactorRegistry: registry,
		AuditSink:      sink,
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	defer func() { _ = node.Close() }()
}

// TestOpenEmbeddedNode_NetworkServingBuildsServerOptions proves that when
// the deployment serves the network (NetworkServing), OpenEmbeddedNode still
// constructs the node successfully with the caller's ExtraServerOptions
// appended -- exercised here with a benign audit-logger override standing in
// for a real caller option, since ExtraServerOptions is otherwise opaque to
// this package.
func TestOpenEmbeddedNode_ExtraNodeAndServerOptionsApplied(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	}

	sink := qrdbsdk.NewAuditRingBuffer(8)
	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config:             cfg,
		Logger:             embeddedNodeTestLogger(),
		ExtraServerOptions: []qrdbsdk.ServerOption{qrdbsdk.WithAuditLogger(sink)},
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	defer func() { _ = node.Close() }()
}
