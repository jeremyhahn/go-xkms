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
	"path/filepath"
	"slices"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

// NewNode hosts a clustered go-qrdb engine when clustering is enabled,
// replicating all datastore state (keys, users, RBAC, custodian records,
// shares, CA serials/revocations, …) across the cluster via Raft. When
// clustering is not enabled it builds a standalone node, so a raft-built
// binary still runs single-node.
//
// Raft mTLS is consulted only for multi-node clusters: a single-node cluster
// uses an in-process transport that needs no peer certificates. For multi-node
// the material comes from [NodeOptions.RaftMTLSResolver], or — when that is nil —
// from the built-in software auto-provisioning path. It is never nothing; the
// Raft QUIC transport mandates mTLS between peers.
func NewNode(ctx context.Context, opts *NodeOptions) (*NodeResult, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	nodeOpts := append(slices.Clone(opts.NodeOptions), serviceprincipal.Option())

	if !opts.Cluster.Enabled {
		opts.Logger.Info("Hosting qrdb engine in-process via NewStandaloneNode")
		node, err := qrdbnode.NewStandaloneNode(ctx, opts.QRDB, opts.ServerOptions, nodeOpts...)
		if err != nil {
			return nil, err
		}
		return &NodeResult{Node: node}, nil
	}

	members, err := opts.Cluster.Members()
	if err != nil {
		return nil, err
	}

	result := &NodeResult{}

	if len(members) > 1 {
		resolve := opts.RaftMTLSResolver
		if resolve == nil {
			resolve = opts.resolveSoftwareRaftMTLS
		}
		mtls, adv, resolveErr := resolve(ctx, members)
		if resolveErr != nil {
			return nil, resolveErr
		}
		result.Advertiser = adv
		nodeOpts = append(nodeOpts, qrdbnode.WithRaftMTLS(mtls))
	}

	opts.Logger.Info("Hosting clustered qrdb engine via NewClusteredNode",
		"node_id", opts.Cluster.NodeID,
		"shard_id", opts.QRDB.Raft.ShardID,
		"raft_address", opts.Cluster.RaftAddress,
		"members", len(members),
		"join", opts.Cluster.Join)

	node, err := qrdbnode.NewClusteredNode(ctx, opts.QRDB, members, opts.ServerOptions, nodeOpts...)
	if err != nil {
		return nil, err
	}
	result.Node = node
	return result, nil
}

// resolveSoftwareRaftMTLS auto-provisions inter-node Raft mTLS material by
// delegating to go-qrdb's shared cluster-TLS enrollment. The first node
// generates a dedicated self-signed cluster CA and returns a running Noise
// advertiser for peer enrollment; joining nodes fetch that CA and issue their
// own leaf. Generated material is cached under {StoragePath}/raft-tls so
// restarts reuse it.
//
// This is the default when no [RaftMTLSResolver] is supplied. Hardware-backed
// strategies (TPM-attested ACME, PKCS#11 / TPM2-resident node keys) are
// injected by the caller instead, since they need a certificate authority
// that belongs to the daemon rather than to node construction.
func (o *NodeOptions) resolveSoftwareRaftMTLS(ctx context.Context, members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
	mat, adv, err := clusterenroll.Resolve(ctx, o.ClusterEnrollOptions(members), o.Logger)
	if err != nil {
		return nil, nil, err
	}
	o.Logger.Info("Raft inter-node mTLS auto-provisioned via cluster enrollment",
		"data_dir", o.raftTLSCacheDir(),
		"advertising", adv != nil)
	return &qrdbnode.RaftMTLSConfig{
		CACert: mat.CACertPEM,
		Cert:   mat.CertPEM,
		Key:    mat.KeyPEM,
	}, adv, nil
}

// raftTLSCacheDir returns the directory auto-provisioned cluster TLS material
// is cached in.
func (o *NodeOptions) raftTLSCacheDir() string {
	return filepath.Join(o.StoragePath, RaftTLSCacheSubdir)
}
