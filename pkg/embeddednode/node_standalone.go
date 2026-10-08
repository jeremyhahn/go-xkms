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

//go:build !raft

package embeddednode

import (
	"context"
	"path/filepath"
	"slices"

	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

// NewNode hosts a standalone (single-node) go-qrdb engine in process. This is
// the default build; the clustered path lives in node_cluster.go under
// `-tags raft`.
//
// A clustered configuration in this build fails with
// [ErrClusterRequiresRaftBuild] rather than silently running unclustered.
func NewNode(ctx context.Context, opts *NodeOptions) (*NodeResult, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if opts.Cluster.Enabled {
		return nil, ErrClusterRequiresRaftBuild
	}

	opts.Logger.Info("Hosting qrdb engine in-process via NewStandaloneNode")
	nodeOpts := append(slices.Clone(opts.NodeOptions), serviceprincipal.Option())
	node, err := qrdbnode.NewStandaloneNode(ctx, opts.QRDB, opts.ServerOptions, nodeOpts...)
	if err != nil {
		return nil, err
	}
	return &NodeResult{Node: node}, nil
}

// raftTLSCacheDir returns the directory auto-provisioned cluster TLS material
// is cached in. Unused on the standalone path but kept on both builds so the
// options mapping is tag-independent.
func (o *NodeOptions) raftTLSCacheDir() string {
	return filepath.Join(o.StoragePath, RaftTLSCacheSubdir)
}
