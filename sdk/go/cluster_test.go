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

package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// clusterUnsupportedClient is a Client that does not implement ClusterReader.
type clusterUnsupportedClient struct {
	transport.Client
}

// clusterReaderClient is a Client that also implements ClusterReader.
type clusterReaderClient struct {
	transport.Client

	status  *ClusterStatusResponse
	members *ListClusterMembersResponse
}

func (c *clusterReaderClient) ClusterStatus(_ context.Context) (*ClusterStatusResponse, error) {
	return c.status, nil
}

func (c *clusterReaderClient) ClusterMembers(_ context.Context) (*ListClusterMembersResponse, error) {
	return c.members, nil
}

func TestCluster_Unsupported(t *testing.T) {
	_, err := Cluster(&clusterUnsupportedClient{})
	if !errors.Is(err, ErrClusterUnsupported) {
		t.Fatalf("Cluster() error = %v, want ErrClusterUnsupported", err)
	}
}

func TestCluster_StatusAndMembers(t *testing.T) {
	cl := &clusterReaderClient{
		status: &ClusterStatusResponse{
			Status: ClusterStatusInfo{ShardID: 1, NodeID: 1, LeaderID: 1, HasLeader: true, Clustered: true},
		},
		members: &ListClusterMembersResponse{
			Members: []ClusterMemberInfo{{NodeID: 1, Address: "10.0.0.1:63001", IsLeader: true}},
		},
	}

	cluster, err := Cluster(cl)
	if err != nil {
		t.Fatalf("Cluster() unexpected error: %v", err)
	}

	st, err := cluster.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if !st.Status.Clustered || st.Status.LeaderID != 1 {
		t.Errorf("unexpected status: %+v", st.Status)
	}

	mem, err := cluster.Members(context.Background())
	if err != nil {
		t.Fatalf("Members() error: %v", err)
	}
	if len(mem.Members) != 1 || mem.Members[0].Address != "10.0.0.1:63001" {
		t.Errorf("unexpected members: %+v", mem.Members)
	}
}
