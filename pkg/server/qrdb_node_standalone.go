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
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
)

// ErrClusterRequiresRaftBuild is returned when cluster.enabled is set but xkms
// was built without the raft build tag. Clustering pulls in the Raft transport
// and is compiled in only with `-tags raft`.
var ErrClusterRequiresRaftBuild = errors.New(
	"server: clustering requires building xkms with -tags raft")

// newQRDBNode hosts a standalone (single-node) qrdb engine. This is the default
// build; the clustered path lives in qrdb_node_cluster.go under `-tags raft`.
// If cluster.enabled is set in this build, it fails loudly rather than silently
// running unclustered.
func (s *Server) newQRDBNode(qcfg *qrdbsdk.DaemonConfig, serverOpts []qrdbsdk.ServerOption, nodeOpts []qrdbnode.NodeOption) (*qrdbnode.Node, error) {
	if s.config.Cluster.Enabled {
		return nil, ErrClusterRequiresRaftBuild
	}
	s.logger.Info("Hosting qrdb engine in-process via NewStandaloneNode")
	return qrdbnode.NewStandaloneNode(s.ctx, qcfg, serverOpts, nodeOpts...)
}
