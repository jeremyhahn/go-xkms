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

// Package daemon builds the embedded go-qrdb node that every go-xkms-derived
// daemon runs on, in both standalone and clustered topologies.
//
// It is the single node-construction path for the stack: go-xkms itself, and
// every downstream project that embeds go-qrdb through go-xkms, calls
// [NewNode] rather than reaching for go-qrdb's node constructors directly.
// That keeps the standalone/clustered decision, the membership parsing, and
// the inter-node mTLS provisioning in one place.
//
// Clustering is compiled in only with the `raft` build tag. Without it,
// [NewNode] serves standalone topologies and fails loudly on a clustered
// configuration rather than silently degrading to a single node.
//
// Hardware-backed provisioning (TPM-attested ACME enrollment, PKCS#11 /
// TPM2-resident node keys) is supplied by the caller through
// [Options.RaftMTLSResolver]. Those strategies need a certificate authority
// and key-strategy dependencies that belong to the daemon, not to node
// construction, so they are injected instead of imported. A nil resolver
// selects the built-in software auto-provisioning path.
package daemon

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
)

// DefaultTrustDomain is the SPIFFE trust domain stamped into auto-provisioned
// Raft node certificates when [ClusterOptions.TrustDomain] is unset.
const DefaultTrustDomain = "xkms.cluster"

// RaftTLSCacheSubdir is the subdirectory of [Options.StoragePath] where
// auto-provisioned cluster TLS material (CA + node cert/key + Noise key) is
// cached so restarts reuse it.
const RaftTLSCacheSubdir = "raft-tls"

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

	// TrustDomain is the SPIFFE trust domain for auto-provisioned node
	// certificates. Empty selects [DefaultTrustDomain].
	TrustDomain string

	// AdvertiseNoisePort is the TCP port the Noise NK bootstrap advertiser
	// listens on. Zero selects clusterenroll.DefaultNoisePort.
	AdvertiseNoisePort int

	// Bootstrap carries the join-side discovery sources used to fetch the
	// cluster CA when this node is not the one generating it.
	Bootstrap clusterenroll.BootstrapOptions
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

// Options configures node construction.
type Options struct {
	// QRDB is the go-qrdb daemon configuration. Required.
	QRDB *qrdbsdk.DaemonConfig

	// Cluster describes the topology. The zero value builds a standalone node.
	Cluster ClusterOptions

	// StoragePath roots the node's on-disk state. Auto-provisioned cluster
	// TLS material is cached beneath it in [RaftTLSCacheSubdir].
	StoragePath string

	// Logger receives node construction events. Required.
	Logger *slog.Logger

	// ServerOptions and NodeOptions are forwarded verbatim to go-qrdb.
	ServerOptions []qrdbsdk.ServerOption
	NodeOptions   []qrdbnode.NodeOption

	// RaftMTLSResolver supplies inter-node mTLS material for multi-node
	// clusters. Nil selects the built-in software auto-provisioning path
	// ([ResolveSoftwareRaftMTLS]).
	RaftMTLSResolver RaftMTLSResolver
}

// Result carries the constructed node and any cluster-enrollment advertiser
// that must be shut down with it.
type Result struct {
	// Node is the running go-qrdb node.
	Node *qrdbnode.Node

	// Advertiser serves the Noise NK bootstrap endpoint for peers enrolling
	// into the cluster. It is non-nil only on the bootstrapping node; the
	// caller owns its lifecycle.
	Advertiser *clusterenroll.Advertiser
}

// validate reports the first structural problem with the options.
func (o *Options) validate() error {
	switch {
	case o == nil:
		return ErrNilOptions
	case o.QRDB == nil:
		return ErrNilQRDBConfig
	case o.Logger == nil:
		return ErrNilLogger
	}
	return nil
}

// ClusterEnrollOptions maps the cluster options onto go-qrdb's clusterenroll
// Options, applying defaults and computing SingleNode from the membership. It
// is pure, so the mapping is unit-testable without starting the advertiser.
func (o *Options) ClusterEnrollOptions(members map[uint64]string) *clusterenroll.Options {
	trustDomain := o.Cluster.TrustDomain
	if trustDomain == "" {
		trustDomain = DefaultTrustDomain
	}
	advPort := o.Cluster.AdvertiseNoisePort
	if advPort == 0 {
		advPort = clusterenroll.DefaultNoisePort
	}

	bootstrap := o.Cluster.Bootstrap
	bootstrap.DiscoveryMethod = "static"
	bootstrap.Peers = o.Cluster.PeerList()

	return &clusterenroll.Options{
		RaftAddress: o.Cluster.RaftAddress,
		TrustDomain: trustDomain,
		DataDir:     o.raftTLSCacheDir(),
		SingleNode:  len(members) <= 1,
		Bootstrap:   bootstrap,
		Advertise: clusterenroll.AdvertiseOptions{
			NoisePort: advPort,
		},
	}
}
