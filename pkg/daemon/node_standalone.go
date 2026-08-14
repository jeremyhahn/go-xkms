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

package daemon

import (
	"context"
	"path/filepath"

	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
)

// NewNode hosts a standalone (single-node) go-qrdb engine in process. This is
// the default build; the clustered path lives in node_cluster.go under
// `-tags raft`.
//
// A clustered configuration in this build fails with
// [ErrClusterRequiresRaftBuild] rather than silently running unclustered.
func NewNode(ctx context.Context, opts *Options) (*Result, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if opts.Cluster.Enabled {
		return nil, ErrClusterRequiresRaftBuild
	}

	opts.Logger.Info("Hosting qrdb engine in-process via NewStandaloneNode")
	node, err := qrdbnode.NewStandaloneNode(ctx, opts.QRDB, opts.ServerOptions, opts.NodeOptions...)
	if err != nil {
		return nil, err
	}
	return &Result{Node: node}, nil
}

// raftTLSCacheDir returns the directory auto-provisioned cluster TLS material
// is cached in. Unused on the standalone path but kept on both builds so the
// options mapping is tag-independent.
func (o *Options) raftTLSCacheDir() string {
	return filepath.Join(o.StoragePath, RaftTLSCacheSubdir)
}
