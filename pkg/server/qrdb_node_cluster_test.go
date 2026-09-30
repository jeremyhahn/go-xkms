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

package server

import (
	"path/filepath"
	"reflect"
	"testing"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestBuildClusterEnrollOptions_Defaults verifies that an enrollment config with
// no overrides maps onto clusterenroll.Options with the documented defaults
// (xkms.cluster trust domain, the default Noise port) and that membership of
// more than one node yields SingleNode=false.
func TestBuildClusterEnrollOptions_Defaults(t *testing.T) {
	dir := t.TempDir()
	s := &Server{config: &config.Config{
		Datastore: config.DatastoreConfig{Path: dir},
		Cluster: config.ClusterConfig{
			RaftAddress: "10.0.0.1:63001",
			Peers:       "1=10.0.0.1:63001,2=10.0.0.2:63001",
		},
	}}
	members := map[uint64]string{1: "10.0.0.1:63001", 2: "10.0.0.2:63001"}

	opts := s.buildClusterEnrollOptions(members)

	if opts.TrustDomain != defaultRaftTrustDomain {
		t.Errorf("TrustDomain = %q, want %q", opts.TrustDomain, defaultRaftTrustDomain)
	}
	if opts.Advertise.NoisePort != clusterenroll.DefaultNoisePort {
		t.Errorf("Advertise.NoisePort = %d, want %d", opts.Advertise.NoisePort, clusterenroll.DefaultNoisePort)
	}
	if opts.RaftAddress != "10.0.0.1:63001" {
		t.Errorf("RaftAddress = %q, want 10.0.0.1:63001", opts.RaftAddress)
	}
	if want := filepath.Join(dir, raftTLSCacheSubdir); opts.DataDir != want {
		t.Errorf("DataDir = %q, want %q", opts.DataDir, want)
	}
	if opts.SingleNode {
		t.Error("SingleNode = true, want false for a 2-member cluster")
	}
	if opts.Bootstrap.DiscoveryMethod != "static" {
		t.Errorf("Bootstrap.DiscoveryMethod = %q, want static", opts.Bootstrap.DiscoveryMethod)
	}
	if len(opts.Bootstrap.Peers) != 2 {
		t.Errorf("Bootstrap.Peers = %v, want 2 entries", opts.Bootstrap.Peers)
	}
}

// TestBuildClusterEnrollOptions_ExplicitAndSingleNode verifies that explicit
// enrollment values (trust domain, advertise port, join bootstrap source) pass
// through unchanged, and that a single-member cluster yields SingleNode=true.
func TestBuildClusterEnrollOptions_ExplicitAndSingleNode(t *testing.T) {
	dir := t.TempDir()
	s := &Server{config: &config.Config{
		Datastore: config.DatastoreConfig{Path: dir},
		Cluster: config.ClusterConfig{
			RaftAddress: "10.0.0.1:63001",
			RaftEnrollment: config.RaftEnrollmentConfig{
				TrustDomain:        "corp.cluster",
				AdvertiseNoisePort: 7777,
				Bootstrap: config.RaftBootstrapConfig{
					NoiseKey:  "deadbeef",
					NoiseAddr: "10.0.0.2:63006",
				},
			},
		},
	}}
	members := map[uint64]string{1: "10.0.0.1:63001"}

	opts := s.buildClusterEnrollOptions(members)

	if opts.TrustDomain != "corp.cluster" {
		t.Errorf("TrustDomain = %q, want corp.cluster", opts.TrustDomain)
	}
	if opts.Advertise.NoisePort != 7777 {
		t.Errorf("Advertise.NoisePort = %d, want 7777", opts.Advertise.NoisePort)
	}
	if !opts.SingleNode {
		t.Error("SingleNode = false, want true for a 1-member cluster")
	}
	if opts.Bootstrap.NoiseKey != "deadbeef" {
		t.Errorf("Bootstrap.NoiseKey = %q, want deadbeef", opts.Bootstrap.NoiseKey)
	}
	if opts.Bootstrap.NoiseAddr != "10.0.0.2:63006" {
		t.Errorf("Bootstrap.NoiseAddr = %q, want 10.0.0.2:63006", opts.Bootstrap.NoiseAddr)
	}
}

// TestSplitClusterPeers checks the comma-separated "id=addr" peer parser,
// including empty, whitespace, and empty-element handling.
func TestSplitClusterPeers(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single", "1=a:1", []string{"1=a:1"}},
		{"two", "1=a:1,2=b:2", []string{"1=a:1", "2=b:2"}},
		{"trimmed", " 1=a:1 , 2=b:2 ", []string{"1=a:1", "2=b:2"}},
		{"empty element skipped", "1=a:1,,2=b:2", []string{"1=a:1", "2=b:2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := splitClusterPeers(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitClusterPeers(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
