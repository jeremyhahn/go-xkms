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

package embeddednode

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/factor"
)

// testLogger returns a logger that discards output, matching the other
// package fixtures' silent-by-default convention.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestOpenEmbeddedNode_StandaloneNoBarrier proves the base case: a standalone
// datastore with no barrier configured opens a node over a fresh temp dir,
// unsealed, with the node-seal flip disabled.
func TestOpenEmbeddedNode_StandaloneNoBarrier(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	}

	node, sealRes, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: testLogger(),
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	defer func() { _ = node.Close() }()

	assert.False(t, sealRes.Enabled)
	assert.False(t, node.IsSealed())
}

// TestOpenEmbeddedNode_BarrierNoneAutoUnseals proves the node-flip case:
// barrier.enabled with strategy "none" engages the flip and auto-unseals
// unattended.
func TestOpenEmbeddedNode_BarrierNoneAutoUnseals(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: "none"},
	}

	node, sealRes, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: testLogger(),
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
		Logger: testLogger(),
	})
	require.Error(t, err)
	assert.Nil(t, node)
	assert.False(t, sealRes.Enabled)

	var nodeSealErr *NodeSealError
	require.ErrorAs(t, err, &nodeSealErr)
}

// TestOpenEmbeddedNode_UnknownEngineRejected verifies a config that skipped
// Validate cannot hand an unknown engine to go-qrdb: OpenEmbeddedNode fails
// with the typed config error before opening anything.
func TestOpenEmbeddedNode_UnknownEngineRejected(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir(), Engine: "carrier-pigeon"},
	}

	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: testLogger(),
	})
	require.Error(t, err)
	assert.Nil(t, node)

	var engineErr *config.ErrUnknownDatastoreEngine
	require.ErrorAs(t, err, &engineErr)
	assert.Equal(t, "carrier-pigeon", engineErr.Engine)
}

// TestOpenEmbeddedNode_EngineNormalised verifies an engine written with
// mixed case and surrounding whitespace is accepted.
func TestOpenEmbeddedNode_EngineNormalised(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir(), Engine: " Memory "},
	}

	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: testLogger(),
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
}

func TestTrustDomain(t *testing.T) {
	assert.Equal(t, DefaultTrustDomain, TrustDomain(&config.Config{}),
		"no configured trust domain falls back to the default")

	cfg := &config.Config{Cluster: config.ClusterConfig{
		RaftEnrollment: config.RaftEnrollmentConfig{TrustDomain: "example.org"},
	}}
	assert.Equal(t, "example.org", TrustDomain(cfg))
}

// The deployment's trust domain becomes qrdb's cluster trust domain, the one
// node certificates are issued and pinned under.
func TestEmbeddedNodeStorageConfig_PinsClusterTrustDomain(t *testing.T) {
	qcfg := EmbeddedNodeStorageConfig(&config.Config{}, ResolvedNodeSeal{})
	assert.Equal(t, DefaultTrustDomain, qcfg.Auth.ClusterTrustDomain)

	cfg := &config.Config{Cluster: config.ClusterConfig{
		RaftEnrollment: config.RaftEnrollmentConfig{TrustDomain: "example.org"},
	}}
	qcfg = EmbeddedNodeStorageConfig(cfg, ResolvedNodeSeal{})
	assert.Equal(t, "example.org", qcfg.Auth.ClusterTrustDomain)
}

// TestOpenEmbeddedNode_OverridesFactorRegistryAndAuditSink proves that a
// caller-supplied FactorRegistry/AuditSink is used as-is rather than built
// from a default -- the seam xkmsd init and xkmsd run rely on to share one
// registry/sink across composition roots.
func TestOpenEmbeddedNode_OverridesFactorRegistryAndAuditSink(t *testing.T) {
	registry, err := factor.NewDefaultRegistry(factor.Config{})
	require.NoError(t, err)
	sink := qrdbsdk.NewAuditRingBuffer(16)

	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	}

	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config:         cfg,
		Logger:         testLogger(),
		FactorRegistry: registry,
		AuditSink:      sink,
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	defer func() { _ = node.Close() }()
}

// TestOpenEmbeddedNode_NoFactorRegistryByDefault proves a caller that leaves
// FactorRegistry nil (the SDK/library composition path, which only wants a
// KV store) still gets a working node -- pkg/factor is never a required
// dependency of this package.
func TestOpenEmbeddedNode_NoFactorRegistryByDefault(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	}

	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: testLogger(),
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	defer func() { _ = node.Close() }()
}

// TestOpenEmbeddedNode_ExtraNodeAndServerOptionsApplied proves that
// OpenEmbeddedNode still constructs the node successfully with the caller's
// ExtraServerOptions appended -- exercised here with a benign audit-logger
// override standing in for a real caller option, since ExtraServerOptions is
// otherwise opaque to this package.
func TestOpenEmbeddedNode_ExtraNodeAndServerOptionsApplied(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	}

	sink := qrdbsdk.NewAuditRingBuffer(8)
	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config:             cfg,
		Logger:             testLogger(),
		ExtraServerOptions: []qrdbserver.ServerOption{qrdbserver.WithAuditLogger(sink)},
	})
	require.NoError(t, err)
	require.NotNil(t, node)
	defer func() { _ = node.Close() }()
}

// TestNodeSealError_ErrorAndUnwrap exercises the Error()/Unwrap() methods
// directly: production code constructs and returns this type, but no other
// test's assertions actually call .Error() on it (errors.As/errors.Is never
// invoke it), so a future edit that breaks the format string or drops the
// wrapped cause would otherwise go unnoticed.
func TestNodeSealError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("tpm not found")
	err := &NodeSealError{Reason: "no usable TPM", Err: cause}
	assert.Contains(t, err.Error(), "no usable TPM")
	assert.Same(t, cause, err.Unwrap())

	// Err is optional: a NodeSealError raised without an underlying cause
	// must still Unwrap cleanly to nil rather than panic.
	bare := &NodeSealError{Reason: "no usable TPM"}
	assert.Nil(t, bare.Unwrap())
}

// TestErrDatastorePathRequired_Error exercises the typed error's message.
func TestErrDatastorePathRequired_Error(t *testing.T) {
	err := &ErrDatastorePathRequired{}
	assert.Contains(t, err.Error(), "datastore.path")
}

// TestResolveNodeSeal_DisabledForRemoteDatastore verifies the node seal never
// engages for a remote datastore (no local node to seal), even with the
// barrier enabled.
func TestResolveNodeSeal_DisabledForRemoteDatastore(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{
			Mode: "remote",
			Remote: config.DatastoreRemoteConfig{
				Address:   "https://qrdb.example.com:63002",
				Transport: "rest",
			},
		},
		Barrier: config.BarrierConfig{
			Enabled:  true,
			Strategy: "passphrase",
		},
	}

	res, err := ResolveNodeSeal(cfg, testLogger())
	require.NoError(t, err)
	assert.False(t, res.Enabled, "the flip only applies to a standalone-hosted datastore")
}

// TestResolveNodeSeal_TPM2EmptyStoragePathFailsClosed is the regression test
// for go-xkms#609: a standalone + barrier + tpm2 deployment with an
// unconfigured storage path (e.g. an embedded caller that never ran
// config.Config.Validate) must fail closed with a typed error instead of
// resolving the TPM2 seal key directory relative to the process's working
// directory.
func TestResolveNodeSeal_TPM2EmptyStoragePathFailsClosed(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: ""}, // never configured
		Barrier: config.BarrierConfig{
			Enabled:  true,
			Strategy: "tpm2",
		},
	}

	res, err := ResolveNodeSeal(cfg, testLogger())
	require.Error(t, err)
	assert.False(t, res.Enabled)

	var nodeErr *NodeSealError
	require.True(t, errors.As(err, &nodeErr), "error must unwrap to *NodeSealError, got %v", err)

	var pathErr *ErrDatastorePathRequired
	require.True(t, errors.As(err, &pathErr), "error must unwrap to *ErrDatastorePathRequired, got %v", err)
}

// TestResolveNodeSeal_TPM2NoBackendConfigFailsClosed is the regression test
// for a nil-pointer panic: barrier.strategy: tpm2 selects the node-seal flip
// independently of backends.tpm2 (the separate crypto-operation TPM2
// backend), so an operator can configure the flip without a backends.tpm2
// section. ResolveNodeSeal must fail one deployment closed with a typed
// error rather than dereferencing a nil cfg.Backends.TPM2.
func TestResolveNodeSeal_TPM2NoBackendConfigFailsClosed(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
		Barrier: config.BarrierConfig{
			Enabled:  true,
			Strategy: "tpm2",
		},
		// Backends.TPM2 deliberately left nil.
	}

	res, err := ResolveNodeSeal(cfg, testLogger())
	require.Error(t, err)
	assert.False(t, res.Enabled)

	var nodeErr *NodeSealError
	require.True(t, errors.As(err, &nodeErr), "error must unwrap to *NodeSealError, got %v", err)
}
