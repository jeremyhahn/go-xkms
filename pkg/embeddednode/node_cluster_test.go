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

package embeddednode

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/jeremyhahn/go-qrdb/sdk/go/testutil/qrdbdharness"
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

	opts := &NodeOptions{
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

	opts := &NodeOptions{
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
	opts := &NodeOptions{
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

	opts := &NodeOptions{
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
	opts := &NodeOptions{
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
	opts := &NodeOptions{
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

// clusterFormationBudget bounds how long the three-replica cluster below may
// take to elect a leader and replicate one write. It is a failure bound, not a
// pacing interval: the waits return as soon as their condition holds.
const clusterFormationBudget = 2 * time.Minute

// raftReplica is one member of the in-process test cluster: its replica ID,
// Raft address and transport certificate.
type raftReplica struct {
	id   uint64
	addr string
	cert *qrdbdharness.KeyPair
}

// newRaftReplicas issues one leaf certificate per replica from a shared test
// CA and reserves one loopback UDP port per replica for its Raft transport.
func newRaftReplicas(t *testing.T, n int) (*qrdbdharness.CA, []raftReplica) {
	t.Helper()
	pki := t.TempDir()
	ca, err := qrdbdharness.NewCA(pki)
	require.NoError(t, err)
	ports, err := qrdbdharness.ReserveUDPPorts(n)
	require.NoError(t, err)

	replicas := make([]raftReplica, n)
	for i := range replicas {
		id := uint64(i + 1)
		name := "node-" + strconv.FormatUint(id, 10)
		kp, err := ca.Issue(filepath.Join(pki, name),
			qrdbdharness.WithSubject(name, "raft"), qrdbdharness.WithServerAuth())
		require.NoError(t, err)
		replicas[i] = raftReplica{id: id, addr: "127.0.0.1:" + strconv.Itoa(ports[i]), cert: kp}
	}
	return ca, replicas
}

// raftReplicaConfig returns the go-qrdb config of one replica: the local
// engine config plus its Raft identity and the transport identities of every
// other member, derived from their certificates as an operator would.
func raftReplicaConfig(t *testing.T, self raftReplica, replicas []raftReplica) *qrdbsdk.DaemonConfig {
	t.Helper()
	var identities []string
	for _, r := range replicas {
		if r.id == self.id {
			continue
		}
		identity, err := qrdbnode.MemberIdentityFromPEM(r.cert.CertPEM)
		require.NoError(t, err)
		identities = append(identities, strconv.FormatUint(r.id, 10)+"="+identity)
	}

	cfg := newLocalQRDBConfig(t)
	cfg.Raft.ReplicaID = self.id
	cfg.Raft.RaftAddress = self.addr
	cfg.Raft.ListenAddress = self.addr
	cfg.Raft.MemberIdentities = strings.Join(identities, ",")
	return cfg
}

// TestNewNode_FormsClusterOverRaftMTLS proves the clustered path end to end:
// three replicas built through NewNode, each handed its own certificate from
// one CA by the injected resolver, form a cluster over the mutually
// authenticated Raft transport and replicate a write to every member.
func TestNewNode_FormsClusterOverRaftMTLS(t *testing.T) {
	ca, replicas := newRaftReplicas(t, 3)
	peers := make([]string, len(replicas))
	for i, r := range replicas {
		peers[i] = strconv.FormatUint(r.id, 10) + "=" + r.addr
	}

	// A founder's shard start does not wait for its peers, but building the
	// replicas concurrently is how a real cluster comes up. Options are built
	// on the test goroutine because the helpers may fail the test.
	opts := make([]*NodeOptions, len(replicas))
	for i, r := range replicas {
		cert := r.cert
		opts[i] = &NodeOptions{
			QRDB:   raftReplicaConfig(t, r, replicas),
			Logger: testLogger(),
			Cluster: ClusterOptions{
				Enabled:     true,
				NodeID:      r.id,
				RaftAddress: r.addr,
				Peers:       strings.Join(peers, ","),
			},
			RaftMTLSResolver: func(_ context.Context, members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
				if len(members) != len(replicas) {
					return nil, nil, errResolver
				}
				return &qrdbnode.RaftMTLSConfig{CACert: ca.CertPEM, Cert: cert.CertPEM, Key: cert.KeyPEM}, nil, nil
			},
		}
	}

	results := make([]*NodeResult, len(replicas))
	errs := make([]error, len(replicas))
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Go(func() {
			results[i], errs[i] = NewNode(context.Background(), opts[i])
		})
	}
	wg.Wait()
	for _, res := range results {
		if res == nil {
			continue
		}
		// Replicas close one after another, so the last ones lose quorum
		// and may report it; teardown is not under test here.
		t.Cleanup(func() {
			if err := res.Node.Close(); err != nil {
				t.Logf("close replica: %v", err)
			}
		})
	}
	require.NoError(t, errors.Join(errs...))

	ctx, cancel := context.WithTimeout(t.Context(), clusterFormationBudget)
	defer cancel()

	// Any member accepts the write once a leader is elected: a follower
	// forwards it to the leader.
	require.Eventually(t, func() bool {
		for _, res := range results {
			if res.Node.Client().KV().Put(ctx, "embeddednode/cluster-probe", []byte("formed")) == nil {
				return true
			}
		}
		return false
	}, clusterFormationBudget, 50*time.Millisecond, "the cluster never committed a write")

	for i, res := range results {
		got, err := res.Node.Client().KV().Get(ctx, "embeddednode/cluster-probe")
		require.NoError(t, err, "replica %d read", replicas[i].id)
		assert.Equal(t, "formed", string(got), "replica %d", replicas[i].id)
	}
}
