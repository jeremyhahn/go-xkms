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

//go:build raft

package daemon

import (
	"context"
	"errors"
	"testing"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errResolver is a sentinel returned by the failing resolver below.
var errResolver = errors.New("resolver exploded")

// TestNewNode_MultiNodeConsultsResolver verifies that a multi-node membership
// routes inter-node mTLS through the injected resolver. This is the seam that
// lets hardware-backed strategies (TPM-attested ACME, PKCS#11/TPM2 node keys)
// live in the daemon that owns the CA, instead of inside node construction.
//
// The resolver returns an error so the test asserts the wiring without
// standing up a Raft transport.
func TestNewNode_MultiNodeConsultsResolver(t *testing.T) {
	var (
		called      bool
		gotMembers  map[uint64]string
		expectPeers = "1=10.0.0.1:9001,2=10.0.0.2:9001"
	)

	opts := &Options{
		QRDB:   newTestQRDBConfig(),
		Logger: testLogger(),
		Cluster: ClusterOptions{
			Enabled: true,
			NodeID:  1,
			Peers:   expectPeers,
		},
		RaftMTLSResolver: func(_ context.Context, members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
			called = true
			gotMembers = members
			return nil, nil, errResolver
		},
	}

	res, err := NewNode(t.Context(), opts)

	require.Error(t, err)
	assert.Nil(t, res)
	assert.ErrorIs(t, err, errResolver, "resolver failure must abort node construction")
	assert.True(t, called, "multi-node cluster must consult the mTLS resolver")
	assert.Equal(t, map[uint64]string{
		1: "10.0.0.1:9001",
		2: "10.0.0.2:9001",
	}, gotMembers)
}

// TestNewNode_SingleNodeSkipsResolver verifies a single-node cluster does NOT
// provision peer certificates: it uses an in-process transport that needs
// none. Calling the resolver here would force operators of single-node
// deployments through a needless enrollment.
//
// Construction is expected to fail past this point (no real engine), so the
// assertion is on the resolver never being consulted.
func TestNewNode_SingleNodeSkipsResolver(t *testing.T) {
	called := false

	cfg := newTestQRDBConfig()
	// NewClusteredNode does not consult ctx until after it has opened its
	// Raft data directory, so a shared "./data" default (relative to the
	// test binary's working directory) would leave real WAL/snapshot files
	// behind in the package source tree. An isolated TempDir keeps this test
	// from writing to the host.
	cfg.Raft.DataDir = t.TempDir()

	opts := &Options{
		QRDB:   cfg,
		Logger: testLogger(),
		Cluster: ClusterOptions{
			Enabled: true,
			NodeID:  1,
			Peers:   "1=10.0.0.1:9001",
		},
		RaftMTLSResolver: func(context.Context, map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
			called = true
			return nil, nil, errResolver
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // abort engine startup; the resolver decision happens first
	_, _ = NewNode(ctx, opts)

	assert.False(t, called, "single-node cluster must not provision peer mTLS")
}

// TestNewNode_RejectsMalformedMembership verifies membership parsing failures
// abort before any engine work, surfacing the typed peer error.
func TestNewNode_RejectsMalformedMembership(t *testing.T) {
	opts := &Options{
		QRDB:   newTestQRDBConfig(),
		Logger: testLogger(),
		Cluster: ClusterOptions{
			Enabled: true,
			Peers:   "not-a-peer",
		},
	}

	res, err := NewNode(t.Context(), opts)

	require.Error(t, err)
	assert.Nil(t, res)
	var typed *MemberFormatError
	assert.True(t, errors.As(err, &typed), "expected MemberFormatError, got %T", err)
}

// TestNewNode_StandaloneStillServedByRaftBuild verifies the raft-tagged
// build's NewNode still serves an unclustered configuration (Cluster.Enabled
// false, the zero value) by delegating straight to go-qrdb's
// NewStandaloneNode, exactly like the non-raft build does. A raft binary
// must still boot single-node without a Raft membership.
//
// The config supplies no persistent data directory, so go-qrdb rejects it
// before opening any storage -- proving the standalone branch is reachable
// from this build without paying for a real engine boot.
func TestNewNode_StandaloneStillServedByRaftBuild(t *testing.T) {
	cfg := newTestQRDBConfig()
	cfg.Raft.DataDir = ""

	opts := &Options{
		QRDB:   cfg,
		Logger: testLogger(),
	}

	res, err := NewNode(t.Context(), opts)

	require.Error(t, err)
	assert.Nil(t, res)
	var configErr *qrdbnode.ConfigError
	require.True(t, errors.As(err, &configErr), "expected go-qrdb ConfigError, got %T", err)
	assert.Equal(t, "raft.data_dir", configErr.Field)
}

// TestNewNode_DefaultResolverAppliesWhenNil verifies a nil RaftMTLSResolver
// selects the built-in software auto-provisioning path
// (Options.resolveSoftwareRaftMTLS) instead of leaving a multi-node cluster
// without inter-node mTLS. AdvertiseNoiseHost is left empty so
// clusterenroll's own validation fails immediately, without starting a
// listener or touching disk.
func TestNewNode_DefaultResolverAppliesWhenNil(t *testing.T) {
	opts := &Options{
		QRDB:        newTestQRDBConfig(),
		Logger:      testLogger(),
		StoragePath: t.TempDir(),
		Cluster: ClusterOptions{
			Enabled: true,
			NodeID:  1,
			Peers:   "1=10.0.0.1:9001,2=10.0.0.2:9001",
		},
		// RaftMTLSResolver intentionally left nil.
	}

	res, err := NewNode(t.Context(), opts)

	require.Error(t, err)
	assert.Nil(t, res)
	var bindErr *clusterenroll.MissingBindHostError
	assert.True(t, errors.As(err, &bindErr), "expected MissingBindHostError from the default resolver, got %T", err)
}

// TestOptions_ResolveSoftwareRaftMTLS_SurfacesClusterenrollError verifies the
// default resolver method propagates a clusterenroll failure unwrapped, so
// NewNode's error-type assertions above hold for direct callers too.
func TestOptions_ResolveSoftwareRaftMTLS_SurfacesClusterenrollError(t *testing.T) {
	opts := &Options{
		QRDB:        newTestQRDBConfig(),
		Logger:      testLogger(),
		StoragePath: t.TempDir(),
		Cluster: ClusterOptions{
			RaftAddress: "127.0.0.1:63011",
			// AdvertiseNoiseHost intentionally left empty.
		},
	}
	members := map[uint64]string{1: "10.0.0.1:9001", 2: "10.0.0.2:9001"}

	mtls, adv, err := opts.resolveSoftwareRaftMTLS(t.Context(), members)

	require.Error(t, err)
	assert.Nil(t, mtls)
	assert.Nil(t, adv)
	var bindErr *clusterenroll.MissingBindHostError
	assert.True(t, errors.As(err, &bindErr), "expected MissingBindHostError, got %T", err)
}
