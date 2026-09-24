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

//go:build integration

// cluster_rest_api_test.go exercises the xkms-authored REST cluster surface
// (go-xkms#847, GET /api/v1/cluster/*, pkg/api/rest/handlers_cluster.go)
// against both the 3-node cluster and the standalone harnesses. It is
// deliberately distinct from cluster_test.go's coverage of go-qrdb's own
// "GET /peers" admin-plane endpoint: the two surfaces answer independently
// (see docs/clustering/architecture.md, "Two distinct surfaces over the same
// Raft shard"), so a regression in one must not be masked by the other still
// passing.
//
// There is no POST/DELETE coverage here: the REST cluster surface is
// read-only by design (no mutation routes exist to test — see
// docs/clustering/api.md and docs/web/parity.md "Cluster mutations"); Raft
// membership mutation is exercised entirely through the qrdb control plane
// by cmd/xkmsctl/cluster_test.go instead.
package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// clusterStatusResponse fetches GET /api/v1/cluster/status from baseURL.
func clusterStatusResponse(ctx context.Context, baseURL string) (int, *transport.ClusterStatusResponse, error) {
	code, body, err := get(ctx, baseURL+"/api/v1/cluster/status")
	if err != nil {
		return code, nil, err
	}
	if code != http.StatusOK {
		return code, nil, nil
	}
	var resp transport.ClusterStatusResponse
	if uerr := json.Unmarshal(body, &resp); uerr != nil {
		return code, nil, uerr
	}
	return code, &resp, nil
}

// clusterMembersResponse fetches GET /api/v1/cluster/members from baseURL.
func clusterMembersResponse(ctx context.Context, baseURL string) (int, *transport.ListClusterMembersResponse, error) {
	code, body, err := get(ctx, baseURL+"/api/v1/cluster/members")
	if err != nil {
		return code, nil, err
	}
	if code != http.StatusOK {
		return code, nil, nil
	}
	var resp transport.ListClusterMembersResponse
	if uerr := json.Unmarshal(body, &resp); uerr != nil {
		return code, nil, uerr
	}
	return code, &resp, nil
}

// TestCluster_RESTStatusAndMembers proves the xkms REST cluster surface
// agrees with go-qrdb's own admin-plane view (fetchPeers/shardLeader,
// already exercised by TestCluster_LeaderElected/TestCluster_Membership) on
// every node of the 3-node cluster: clustered:true, a consistent leader
// across all three nodes, this node's own node_id matching its docker
// compose identity (node(i+1) => node_id i+1), and exactly 3 members with
// exactly one leader.
func TestCluster_RESTStatusAndMembers(t *testing.T) {
	nodes := nodeURLs(t)
	ctx := context.Background()

	waitAllReady(t, ctx, nodes)
	_ = waitLeader(t, ctx, nodes)

	poll(t, 60*time.Second, 2*time.Second, func() (bool, string) {
		wantLeaderID, err := shardLeader(ctx, nodes[0])
		if err != nil {
			return false, fmt.Sprintf("qrdb admin-plane leader query: %v", err)
		}
		if wantLeaderID == 0 {
			return false, "no leader reported yet by the qrdb admin plane"
		}

		for i, u := range nodes {
			nodeIdx := i + 1
			code, status, err := clusterStatusResponse(ctx, u)
			if err != nil {
				return false, fmt.Sprintf("node%d status: %v", nodeIdx, err)
			}
			if code != http.StatusOK {
				return false, fmt.Sprintf("node%d status: HTTP %d", nodeIdx, code)
			}
			if !status.Status.Clustered {
				return false, fmt.Sprintf("node%d status: clustered=false", nodeIdx)
			}
			if !status.Status.HasLeader {
				return false, fmt.Sprintf("node%d status: has_leader=false", nodeIdx)
			}
			if status.Status.NodeID != uint64(nodeIdx) {
				return false, fmt.Sprintf("node%d status: node_id=%d, want %d",
					nodeIdx, status.Status.NodeID, nodeIdx)
			}
			if status.Status.LeaderID != wantLeaderID {
				return false, fmt.Sprintf("node%d status: leader_id=%d, want %d (qrdb admin plane)",
					nodeIdx, status.Status.LeaderID, wantLeaderID)
			}

			mcode, members, err := clusterMembersResponse(ctx, u)
			if err != nil {
				return false, fmt.Sprintf("node%d members: %v", nodeIdx, err)
			}
			if mcode != http.StatusOK {
				return false, fmt.Sprintf("node%d members: HTTP %d", nodeIdx, mcode)
			}
			if len(members.Members) != 3 {
				return false, fmt.Sprintf("node%d members: got %d, want 3", nodeIdx, len(members.Members))
			}
			leaders := 0
			for _, m := range members.Members {
				if m.IsLeader {
					leaders++
				}
			}
			if leaders != 1 {
				return false, fmt.Sprintf("node%d members: %d marked leader, want 1", nodeIdx, leaders)
			}
		}
		return true, ""
	})
	t.Log("REST cluster status/members agree with the qrdb admin plane on every node")
}

// TestStandalone_RESTClusterStatusDegrades proves the standalone harness's
// REST cluster surface degrades gracefully rather than erroring: a
// non-clustered node reports clustered:false and an empty member list, never
// a 4xx/5xx, matching the exact contract the web console's Cluster page
// relies on (docs/clustering/architecture.md).
func TestStandalone_RESTClusterStatusDegrades(t *testing.T) {
	url := standaloneURL(t)
	ctx := context.Background()
	poll(t, 60*time.Second, 1*time.Second, func() (bool, string) {
		return isReady(ctx, url), "standalone server not ready yet"
	})

	code, status, err := clusterStatusResponse(ctx, url)
	if err != nil {
		t.Fatalf("standalone status: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("standalone status: HTTP %d, want 200 even though not clustered", code)
	}
	if status.Status.Clustered {
		t.Fatalf("standalone node reports clustered=true")
	}
	if status.Status.HasLeader {
		t.Fatalf("standalone node reports has_leader=true")
	}

	mcode, members, err := clusterMembersResponse(ctx, url)
	if err != nil {
		t.Fatalf("standalone members: %v", err)
	}
	if mcode != http.StatusOK {
		t.Fatalf("standalone members: HTTP %d, want 200 even though not clustered", mcode)
	}
	if len(members.Members) != 0 {
		t.Fatalf("standalone node reports %d members, want 0", len(members.Members))
	}
}
