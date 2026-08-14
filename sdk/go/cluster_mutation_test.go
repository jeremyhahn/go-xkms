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

// errMutation is the sentinel a fake transport returns so tests can assert the
// SDK propagates the transport's error unchanged rather than wrapping it.
var errMutation = errors.New("transport refused the mutation")

// addCall records the arguments a mutation reached the transport with.
type addCall struct {
	replicaID uint64
	raftAddr  string
}

// clusterMutatorClient is a Client implementing both the read and the mutation
// halves of the cluster surface.
type clusterMutatorClient struct {
	transport.Client

	members *ListClusterMembersResponse

	adds    []addCall
	removes []uint64

	addErr    error
	removeErr error
}

func (c *clusterMutatorClient) ClusterStatus(_ context.Context) (*ClusterStatusResponse, error) {
	return &ClusterStatusResponse{}, nil
}

func (c *clusterMutatorClient) ClusterMembers(_ context.Context) (*ListClusterMembersResponse, error) {
	return c.members, nil
}

func (c *clusterMutatorClient) AddClusterReplica(_ context.Context, replicaID uint64, raftAddr string) (*transport.ClusterReplicaResponse, error) {
	c.adds = append(c.adds, addCall{replicaID: replicaID, raftAddr: raftAddr})
	if c.addErr != nil {
		return nil, c.addErr
	}
	return &transport.ClusterReplicaResponse{ShardID: 1, ReplicaID: replicaID}, nil
}

func (c *clusterMutatorClient) RemoveClusterReplica(_ context.Context, replicaID uint64) (*transport.ClusterReplicaResponse, error) {
	c.removes = append(c.removes, replicaID)
	if c.removeErr != nil {
		return nil, c.removeErr
	}
	return &transport.ClusterReplicaResponse{ShardID: 1, ReplicaID: replicaID}, nil
}

func TestClusterClient_AddReplica_Success(t *testing.T) {
	cl := &clusterMutatorClient{}
	cluster, err := Cluster(cl)
	if err != nil {
		t.Fatalf("Cluster() unexpected error: %v", err)
	}

	resp, err := cluster.AddReplica(context.Background(), 2, "10.0.0.2:63001")
	if err != nil {
		t.Fatalf("AddReplica() unexpected error: %v", err)
	}
	if resp.ReplicaID != 2 || resp.ShardID != 1 {
		t.Fatalf("AddReplica() response = %+v, want shard 1 replica 2", resp)
	}

	if len(cl.adds) != 1 {
		t.Fatalf("transport add calls = %d, want 1", len(cl.adds))
	}
	if cl.adds[0].replicaID != 2 || cl.adds[0].raftAddr != "10.0.0.2:63001" {
		t.Fatalf("transport received %+v, want {2 10.0.0.2:63001}", cl.adds[0])
	}
}

func TestClusterClient_RemoveReplica_Success(t *testing.T) {
	cl := &clusterMutatorClient{}
	cluster, err := Cluster(cl)
	if err != nil {
		t.Fatalf("Cluster() unexpected error: %v", err)
	}

	resp, err := cluster.RemoveReplica(context.Background(), 3)
	if err != nil {
		t.Fatalf("RemoveReplica() unexpected error: %v", err)
	}
	if resp.ReplicaID != 3 {
		t.Fatalf("RemoveReplica() replica = %d, want 3", resp.ReplicaID)
	}
	if len(cl.removes) != 1 || cl.removes[0] != 3 {
		t.Fatalf("transport remove calls = %v, want [3]", cl.removes)
	}
}

// TestClusterClient_Mutation_Idempotent proves the SDK adds no bookkeeping of
// its own: repeating a mutation reaches the server every time and succeeds,
// because the underlying qrdb membership operations are idempotent.
func TestClusterClient_Mutation_Idempotent(t *testing.T) {
	cl := &clusterMutatorClient{}
	cluster, err := Cluster(cl)
	if err != nil {
		t.Fatalf("Cluster() unexpected error: %v", err)
	}
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := cluster.AddReplica(ctx, 2, "10.0.0.2:63001"); err != nil {
			t.Fatalf("AddReplica() attempt %d unexpected error: %v", i+1, err)
		}
		if _, err := cluster.RemoveReplica(ctx, 2); err != nil {
			t.Fatalf("RemoveReplica() attempt %d unexpected error: %v", i+1, err)
		}
	}

	if len(cl.adds) != 2 {
		t.Fatalf("transport add calls = %d, want 2", len(cl.adds))
	}
	if len(cl.removes) != 2 {
		t.Fatalf("transport remove calls = %d, want 2", len(cl.removes))
	}
}

func TestClusterClient_AddReplica_TransportError(t *testing.T) {
	cl := &clusterMutatorClient{addErr: errMutation}
	cluster, err := Cluster(cl)
	if err != nil {
		t.Fatalf("Cluster() unexpected error: %v", err)
	}

	if _, err := cluster.AddReplica(context.Background(), 2, "10.0.0.2:63001"); !errors.Is(err, errMutation) {
		t.Fatalf("AddReplica() error = %v, want errMutation", err)
	}
}

func TestClusterClient_RemoveReplica_TransportError(t *testing.T) {
	cl := &clusterMutatorClient{removeErr: errMutation}
	cluster, err := Cluster(cl)
	if err != nil {
		t.Fatalf("Cluster() unexpected error: %v", err)
	}

	if _, err := cluster.RemoveReplica(context.Background(), 2); !errors.Is(err, errMutation) {
		t.Fatalf("RemoveReplica() error = %v, want errMutation", err)
	}
}

// TestClusterClient_Mutation_UnsupportedTransport verifies that a transport
// which can read the cluster surface but cannot mutate it yields a distinct,
// typed refusal rather than a nil-pointer panic or a generic error.
func TestClusterClient_Mutation_UnsupportedTransport(t *testing.T) {
	cluster, err := Cluster(&clusterReaderClient{})
	if err != nil {
		t.Fatalf("Cluster() unexpected error: %v", err)
	}

	if _, err := cluster.AddReplica(context.Background(), 2, "10.0.0.2:63001"); !errors.Is(err, ErrClusterMutationUnsupported) {
		t.Fatalf("AddReplica() error = %v, want ErrClusterMutationUnsupported", err)
	}
	if _, err := cluster.RemoveReplica(context.Background(), 2); !errors.Is(err, ErrClusterMutationUnsupported) {
		t.Fatalf("RemoveReplica() error = %v, want ErrClusterMutationUnsupported", err)
	}
}

// TestClusterClient_Members_APIEndpoints covers the address-map contract from
// the SDK's side: an advertising replica exposes its endpoints, and one that
// advertises nothing degrades to a nil map without error.
func TestClusterClient_Members_APIEndpoints(t *testing.T) {
	cl := &clusterMutatorClient{
		members: &ListClusterMembersResponse{
			Members: []ClusterMemberInfo{
				{
					NodeID:  1,
					Address: "10.0.0.1:63001",
					APIEndpoints: map[string]string{
						"rest": "10.0.0.1:8443",
						"grpc": "10.0.0.1:9443",
					},
					IsLeader: true,
				},
				{NodeID: 2, Address: "10.0.0.2:63001"},
			},
		},
	}

	cluster, err := Cluster(cl)
	if err != nil {
		t.Fatalf("Cluster() unexpected error: %v", err)
	}

	resp, err := cluster.Members(context.Background())
	if err != nil {
		t.Fatalf("Members() unexpected error: %v", err)
	}
	if len(resp.Members) != 2 {
		t.Fatalf("Members() returned %d members, want 2", len(resp.Members))
	}

	if got := resp.Members[0].APIEndpoints["rest"]; got != "10.0.0.1:8443" {
		t.Fatalf("advertising replica rest endpoint = %q, want 10.0.0.1:8443", got)
	}

	// A replica that advertises nothing must be readable, not an error: the
	// consumer sees no endpoint and falls back to the Raft address.
	if resp.Members[1].APIEndpoints != nil {
		t.Fatalf("non-advertising replica endpoints = %v, want nil", resp.Members[1].APIEndpoints)
	}
}
