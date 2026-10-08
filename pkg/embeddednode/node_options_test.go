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

package embeddednode

import (
	"errors"
	"path/filepath"
	"testing"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClusterOptions_Members_ParsesValidPeers verifies the happy path: a
// well-formed comma-separated peer list becomes the replicaID→address map
// go-qrdb's clustered constructor expects, tolerating surrounding whitespace
// and empty entries.
func TestClusterOptions_Members_ParsesValidPeers(t *testing.T) {
	c := ClusterOptions{Peers: "1=10.0.0.1:9001, 2=10.0.0.2:9001 ,,3=10.0.0.3:9001"}

	members, err := c.Members()
	require.NoError(t, err)

	assert.Equal(t, map[uint64]string{
		1: "10.0.0.1:9001",
		2: "10.0.0.2:9001",
		3: "10.0.0.3:9001",
	}, members)
}

// TestClusterOptions_Members_EmptyPeersYieldsEmptyMap verifies that an unset
// peer list is not an error — a single-node cluster supplies no peers.
func TestClusterOptions_Members_EmptyPeersYieldsEmptyMap(t *testing.T) {
	members, err := ClusterOptions{}.Members()
	require.NoError(t, err)
	assert.Empty(t, members)
}

// TestClusterOptions_Members_RejectsMalformedEntries verifies each malformed
// shape surfaces its own typed error rather than being silently dropped. A
// silently-dropped peer would form a cluster with the wrong membership.
func TestClusterOptions_Members_RejectsMalformedEntries(t *testing.T) {
	tests := []struct {
		name   string
		peers  string
		target any
	}{
		{"no equals sign", "10.0.0.1:9001", new(*MemberFormatError)},
		{"non-numeric node ID", "abc=10.0.0.1:9001", new(*MemberNodeIDError)},
		{"zero node ID", "0=10.0.0.1:9001", new(*MemberNodeIDError)},
		{"empty address", "1=", new(*MemberAddressError)},
		{"whitespace address", "1=   ", new(*MemberAddressError)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members, err := ClusterOptions{Peers: tt.peers}.Members()
			require.Error(t, err)
			assert.Nil(t, members)
			assert.True(t, errors.As(err, tt.target),
				"expected typed error for %q, got %T: %v", tt.peers, err, err)
			assert.Contains(t, err.Error(), "embeddednode: peer")
		})
	}
}

// TestClusterOptions_PeerList verifies the slice form used to derive a
// bootstrap server URL, including the nil-for-empty contract.
func TestClusterOptions_PeerList(t *testing.T) {
	t.Run("splits and trims", func(t *testing.T) {
		got := ClusterOptions{Peers: " 1=a:1 , 2=b:2 ,, "}.PeerList()
		assert.Equal(t, []string{"1=a:1", "2=b:2"}, got)
	})

	t.Run("empty yields nil", func(t *testing.T) {
		assert.Nil(t, ClusterOptions{}.PeerList())
		assert.Nil(t, ClusterOptions{Peers: "   "}.PeerList())
	})
}

// TestOptions_ClusterEnrollOptions_AppliesDefaults verifies the pure mapping
// onto go-qrdb's clusterenroll options fills in the trust domain and Noise
// port defaults and roots the TLS cache under the storage path.
func TestOptions_ClusterEnrollOptions_AppliesDefaults(t *testing.T) {
	opts := &NodeOptions{
		StoragePath: "/var/lib/xkms",
		Cluster: ClusterOptions{
			RaftAddress: "10.0.0.1:9001",
			Peers:       "1=10.0.0.1:9001,2=10.0.0.2:9001",
		},
	}

	got := opts.ClusterEnrollOptions(map[uint64]string{1: "a", 2: "b"})

	assert.Equal(t, DefaultTrustDomain, got.TrustDomain)
	assert.Equal(t, clusterenroll.DefaultNoisePort, got.Advertise.NoisePort)
	assert.Equal(t, filepath.Join("/var/lib/xkms", RaftTLSCacheSubdir), got.DataDir)
	assert.Equal(t, "10.0.0.1:9001", got.RaftAddress)
	assert.False(t, got.SingleNode, "two members is not a single-node cluster")
	assert.Equal(t, "static", got.Bootstrap.DiscoveryMethod)
	assert.Equal(t, []string{"1=10.0.0.1:9001", "2=10.0.0.2:9001"}, got.Bootstrap.Peers)
}

// TestOptions_ClusterEnrollOptions_HonoursExplicitValues verifies operator
// values are not overwritten by the defaults, and that a lone member marks the
// enrollment single-node (which skips peer certificate provisioning).
func TestOptions_ClusterEnrollOptions_HonoursExplicitValues(t *testing.T) {
	opts := &NodeOptions{
		StoragePath: "/data",
		Cluster: ClusterOptions{
			TrustDomain:        "prod.example.test",
			AdvertiseNoisePort: 15000,
		},
	}

	got := opts.ClusterEnrollOptions(map[uint64]string{1: "a"})

	assert.Equal(t, "prod.example.test", got.TrustDomain)
	assert.Equal(t, 15000, got.Advertise.NoisePort)
	assert.True(t, got.SingleNode, "one member is a single-node cluster")
}

// TestOptions_Validate_RejectsIncompleteOptions verifies each required field
// is enforced with its own sentinel, so a misconfigured embedder gets a
// precise error instead of a nil dereference inside go-qrdb.
func TestOptions_Validate_RejectsIncompleteOptions(t *testing.T) {
	t.Run("nil options", func(t *testing.T) {
		var opts *NodeOptions
		assert.ErrorIs(t, opts.validate(), ErrNilNodeOptions)
	})

	t.Run("nil qrdb config", func(t *testing.T) {
		opts := &NodeOptions{Logger: testLogger()}
		assert.ErrorIs(t, opts.validate(), ErrNilQRDBConfig)
	})

	t.Run("nil logger", func(t *testing.T) {
		opts := &NodeOptions{QRDB: newTestQRDBConfig()}
		assert.ErrorIs(t, opts.validate(), ErrNilLogger)
	})
}

// TestNewNode_RejectsInvalidOptions verifies NewNode validates before doing
// any work, on both the standalone and clustered builds.
func TestNewNode_RejectsInvalidOptions(t *testing.T) {
	t.Run("nil options", func(t *testing.T) {
		res, err := NewNode(t.Context(), nil)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.ErrorIs(t, err, ErrNilNodeOptions)
	})

	t.Run("nil logger", func(t *testing.T) {
		res, err := NewNode(t.Context(), &NodeOptions{QRDB: newTestQRDBConfig()})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.ErrorIs(t, err, ErrNilLogger)
	})
}

// TestNewNode_StartsStandalone proves the standalone path end to end on both
// builds: a topology with clustering off yields a running node, configured
// with xkms's service principal, whose client round-trips a write as that
// principal, and no cluster-enrollment advertiser. That the principal is not
// ambient is proven with authentication on, in package serviceprincipal.
func TestNewNode_StartsStandalone(t *testing.T) {
	res, err := NewNode(t.Context(), &NodeOptions{
		QRDB:   newLocalQRDBConfig(t),
		Logger: testLogger(),
	})
	require.NoError(t, err)
	require.NotNil(t, res.Node)
	t.Cleanup(func() { assert.NoError(t, res.Node.Close()) })

	assert.Nil(t, res.Advertiser, "a standalone node advertises no cluster enrollment")

	ctx, err := res.Node.ServiceContext(t.Context())
	require.NoError(t, err, "NewNode configures the service principal")

	kv := res.Node.Client().KV()
	require.NoError(t, kv.Put(ctx, "embeddednode/probe", []byte("standalone")))
	got, err := kv.Get(ctx, "embeddednode/probe")
	require.NoError(t, err)
	assert.Equal(t, "standalone", string(got))
}
