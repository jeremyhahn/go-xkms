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
	"context"
	"log/slog"
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
)

// DefaultTrustDomain is the SPIFFE trust domain stamped into Raft node
// certificates when the deployment configures none.
const DefaultTrustDomain = "xkms.cluster"

// RaftMTLSResolver resolves the inter-node mTLS material for a multi-node
// cluster. It is consulted once, at node construction, and only when the
// membership holds more than one node.
//
// The returned Advertiser is non-nil only on the node that bootstraps the
// cluster trust anchor; callers own its lifecycle. Implementations that
// cannot satisfy the request must return an error rather than nil material —
// the Raft QUIC transport mandates mTLS for multi-node clusters.
type RaftMTLSResolver func(ctx context.Context, members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error)

// ClusterOptions describes the clustered topology. The zero value is a valid
// standalone configuration.
type ClusterOptions struct {
	// Enabled turns on the clustered node path. When false every other field
	// is ignored and a standalone node is built.
	Enabled bool

	// NodeID is this node's Raft replica ID.
	NodeID uint64

	// RaftAddress is this node's advertised Raft transport address.
	RaftAddress string

	// Peers is the initial membership in comma-separated "nodeID=address"
	// form. Parsed by [ClusterOptions.Members].
	Peers string

	// Join marks this node as joining an existing cluster rather than
	// forming a new one.
	Join bool
}

// Members parses Peers into the replicaID→address map go-qrdb's clustered
// node constructor expects. It returns a typed error for malformed entries.
func (c ClusterOptions) Members() (map[uint64]string, error) {
	members := make(map[uint64]string)
	for _, entry := range strings.Split(c.Peers, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, addr, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, &MemberFormatError{Entry: entry}
		}
		replicaID, err := strconv.ParseUint(strings.TrimSpace(id), 10, 64)
		if err != nil || replicaID == 0 {
			return nil, &MemberNodeIDError{Entry: entry}
		}
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return nil, &MemberAddressError{Entry: entry}
		}
		members[replicaID] = addr
	}
	return members, nil
}

// PeerList splits the comma-separated "id=addr" peer list into the slice form
// clusterenroll uses to derive a bootstrap server URL. An empty list yields
// nil.
func (c ClusterOptions) PeerList() []string {
	peers := strings.TrimSpace(c.Peers)
	if peers == "" {
		return nil
	}
	parts := strings.Split(peers, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NodeOptions configures node construction.
type NodeOptions struct {
	// QRDB is the go-qrdb daemon configuration. Required.
	QRDB *qrdbsdk.DaemonConfig

	// Cluster describes the topology. The zero value builds a standalone node.
	Cluster ClusterOptions

	// Logger receives node construction events. Required.
	Logger *slog.Logger

	// ServerOptions and NodeOptions are forwarded verbatim to go-qrdb;
	// NewNode adds xkms's service principal ([serviceprincipal.Option]) to every node it builds.
	ServerOptions []qrdbserver.ServerOption
	NodeOptions   []qrdbnode.NodeOption

	// RaftMTLSResolver supplies inter-node mTLS material for multi-node
	// clusters. Required when the membership holds more than one node
	// ([ErrNilRaftMTLSResolver]); unused for a standalone node.
	RaftMTLSResolver RaftMTLSResolver
}

// NodeResult carries the constructed node and any cluster-enrollment advertiser
// that must be shut down with it.
type NodeResult struct {
	// Node is the running go-qrdb node.
	Node *qrdbnode.Node

	// Advertiser serves the Noise NK bootstrap endpoint for peers enrolling
	// into the cluster. It is non-nil only on the bootstrapping node; the
	// caller owns its lifecycle.
	Advertiser *clusterenroll.Advertiser
}

// validate reports the first structural problem with the options.
func (o *NodeOptions) validate() error {
	switch {
	case o == nil:
		return ErrNilNodeOptions
	case o.QRDB == nil:
		return ErrNilQRDBConfig
	case o.Logger == nil:
		return ErrNilLogger
	}
	return nil
}
