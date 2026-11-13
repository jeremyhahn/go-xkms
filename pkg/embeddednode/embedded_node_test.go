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
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

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

// The qrdb mTLS authenticator pins the SPIFFE trust domain the CA issues
// client certificates under, so a SAN under a foreign trust domain is rejected.
func TestEmbeddedNodeStorageConfig_PinsSPIFFETrustDomain(t *testing.T) {
	qcfg := EmbeddedNodeStorageConfig(&config.Config{}, ResolvedNodeSeal{})
	assert.Equal(t, DefaultTrustDomain, qcfg.Auth.SPIFFETrustDomain)

	cfg := &config.Config{Cluster: config.ClusterConfig{
		RaftEnrollment: config.RaftEnrollmentConfig{TrustDomain: "example.org"},
	}}
	qcfg = EmbeddedNodeStorageConfig(cfg, ResolvedNodeSeal{})
	assert.Equal(t, "example.org", qcfg.Auth.SPIFFETrustDomain)
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

// TestResolveNodeSeal_OperatorStrategiesAwaitTheOperator proves passphrase
// and shamir enable the barrier without an xkms-built strategy: go-qrdb
// builds the seal itself and waits for the operator to unseal it.
func TestResolveNodeSeal_OperatorStrategiesAwaitTheOperator(t *testing.T) {
	for _, strategy := range []string{"passphrase", "shamir"} {
		t.Run(strategy, func(t *testing.T) {
			cfg := &config.Config{
				Datastore: config.DatastoreConfig{Path: t.TempDir()},
				Barrier:   config.BarrierConfig{Enabled: true, Strategy: strategy},
			}

			res, err := ResolveNodeSeal(cfg, testLogger())
			require.NoError(t, err)
			assert.True(t, res.Enabled)
			assert.Nil(t, res.Strategy)
			assert.Nil(t, res.TPM)
			assert.Nil(t, res.Close)
		})
	}
}

// TestResolveTPM2KeyDir_UnderTheDatastorePath proves the TPM2 seal keys live
// under the datastore path.
func TestResolveTPM2KeyDir_UnderTheDatastorePath(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: dir}}

	keyDir, err := ResolveTPM2KeyDir(cfg)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, KeyDirSubdir), keyDir)
}

// TestResolveTPM2KeyDir_RequiresTheDatastorePath proves the key directory is
// never resolved relative to the working directory.
func TestResolveTPM2KeyDir_RequiresTheDatastorePath(t *testing.T) {
	keyDir, err := ResolveTPM2KeyDir(&config.Config{})
	var pathErr *ErrDatastorePathRequired
	require.ErrorAs(t, err, &pathErr)
	assert.Empty(t, keyDir)
}

// TestEmbeddedNodeStorageConfig_CarriesTheShamirQuorumAndRootKeyPath proves
// an enabled shamir seal reaches go-qrdb with its quorum, the operator's root
// key path and a tenant volume pool under the datastore path.
func TestEmbeddedNodeStorageConfig_CarriesTheShamirQuorumAndRootKeyPath(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: dir},
		Barrier: config.BarrierConfig{
			Enabled:         true,
			Strategy:        "shamir",
			ShamirThreshold: 2,
			ShamirTotal:     3,
			RootKeyPath:     "core/operator-root-key",
		},
	}

	qcfg := EmbeddedNodeStorageConfig(cfg, ResolvedNodeSeal{Enabled: true})
	assert.True(t, qcfg.Seal.Enabled)
	assert.Equal(t, "shamir", qcfg.Seal.Strategy)
	assert.EqualValues(t, 2, qcfg.Seal.ShamirThreshold)
	assert.EqualValues(t, 3, qcfg.Seal.ShamirTotal)
	assert.Equal(t, "core/operator-root-key", qcfg.Seal.RootKeyPath)
	require.Len(t, qcfg.Storage.VolumePools, 1)
	assert.Equal(t, filepath.Join(dir, "tenant-volumes"), qcfg.Storage.VolumePools[0].Path)
}

// TestNewEmbeddedAuditSink_ConfiguredPathIsAFileLogger proves an enabled
// audit path gets the persistent file logger, not the in-memory ring.
func TestNewEmbeddedAuditSink_ConfiguredPathIsAFileLogger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	cfg := &config.Config{}
	cfg.Auth.Audit = &config.AuditConfig{Enabled: true, Path: path}

	sink, err := NewEmbeddedAuditSink(cfg, testLogger())
	require.NoError(t, err)
	require.NoError(t, sink.Close())
	assert.FileExists(t, path)
}

// TestOpenEmbeddedNode_UnopenableAuditPathFailsBeforeTheNode proves an audit
// log that cannot be opened refuses the node instead of opening it without
// its audit trail.
func TestOpenEmbeddedNode_UnopenableAuditPathFailsBeforeTheNode(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: t.TempDir()}}
	cfg.Auth.Audit = &config.AuditConfig{Enabled: true, Path: filepath.Join(notADir, "audit.log")}

	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{Config: cfg, Logger: testLogger()})
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	assert.Nil(t, node)
}

// TestOpenEmbeddedNode_UnusableDatastorePathFails proves a datastore path
// go-qrdb cannot open is an error, never a node.
func TestOpenEmbeddedNode_UnusableDatastorePathFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: path}}

	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{Config: cfg, Logger: testLogger()})
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	assert.Nil(t, node)
}
