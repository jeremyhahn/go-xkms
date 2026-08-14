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

package server

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/daemon"
)

// ErrClusterRequiresRaftBuild is returned when cluster.enabled is set but xkms
// was built without the raft build tag. Clustering pulls in the Raft transport
// and is compiled in only with `-tags raft`.
var ErrClusterRequiresRaftBuild = daemon.ErrClusterRequiresRaftBuild

// newQRDBNode hosts a standalone (single-node) qrdb engine through the shared
// pkg/daemon node builder — the single node-construction path for the stack.
// This is the default build; the clustered path lives in qrdb_node_cluster.go
// under `-tags raft`. If cluster.enabled is set in this build, pkg/daemon
// fails loudly rather than silently running unclustered.
func (s *Server) newQRDBNode(qcfg *qrdbsdk.DaemonConfig, serverOpts []qrdbsdk.ServerOption, nodeOpts []qrdbnode.NodeOption) (*qrdbnode.Node, error) {
	res, err := daemon.NewNode(s.ctx, &daemon.Options{
		QRDB:          qcfg,
		Cluster:       daemon.ClusterOptions{Enabled: s.config.Cluster.Enabled},
		StoragePath:   s.config.Storage.Path,
		Logger:        s.logger,
		ServerOptions: serverOpts,
		NodeOptions:   nodeOpts,
	})
	if err != nil {
		return nil, err
	}
	return res.Node, nil
}
