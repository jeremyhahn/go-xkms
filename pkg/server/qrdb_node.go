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

package server

import (
	qrdbconfig "github.com/jeremyhahn/go-qrdb/pkg/config"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
)

// buildXKMSQRDBConfig translates the xkms configuration into the qrdb node
// configuration used to construct the in-process engine. xkms hosts qrdb as
// its single core: the node is the one database and the source of identity,
// bootstrap, and clustering.
//
// The node runs with its own seal subsystem DISABLED. xkms's barrier is the
// single barrier in the system — it is qrdb's StorageBarrier implementation
// (pkg/seal aliases it directly), layered over the node's KV by
// initializeBarrier with xkms's hardware seal strategies on top. Enabling the
// node's own seal as well would create a redundant second barrier, which is
// exactly the duplication this unification removes.
//
// Standalone hosting maps:
//   - Storage.Path  -> Raft.DataDir (Pebble root)
//   - embedded      -> Databases[0] = {default, mvcc, pebble|memory}
func (s *Server) buildXKMSQRDBConfig() *qrdbconfig.Config {
	qcfg := &qrdbconfig.Config{}

	// Data directory: the qrdb node reads Raft.DataDir for the Pebble root,
	// both for standalone and single-node clusters.
	qcfg.Raft.DataDir = s.config.Storage.Path

	// Inner storage engine for the embedded node. xkms's Storage.Backend value
	// ("qrdb") selects qrdb hosting; the node's own data-plane engine is Pebble
	// when a data directory is configured, otherwise in-memory.
	innerBackend := "pebble"
	if qcfg.Raft.DataDir == "" {
		innerBackend = "memory"
	}
	qcfg.Databases = []qrdbconfig.DatabaseConfig{
		{Name: "default", Engine: "mvcc", Backend: innerBackend},
	}

	// The node carries no barrier of its own; xkms's StorageBarrier is the
	// single barrier (see initializeBarrier). Leaving Seal.Enabled false lets
	// the node boot fully so node.Client() is immediately available.
	qcfg.Seal.Enabled = false

	return qcfg
}

// initEmbeddedQRDBNode constructs the in-process qrdb standalone node that is
// xkms's single core engine: the one database plus the source of identity,
// bootstrap, and clustering. On success the node is retained on s.qrdbNode and
// its SDK client on s.qrdbClient; the server owns both lifecycles and tears
// them down in Shutdown via stopQRDBNode.
//
// The node's own seal is disabled (see buildXKMSQRDBConfig): xkms's barrier —
// qrdb's StorageBarrier implementation with xkms hardware seal strategies — is
// the single barrier, layered over this node's KV by initializeBarrier. The
// hardware auth-factor registry is wired separately into the API layer.
func (s *Server) initEmbeddedQRDBNode() error {
	s.logger.Info("Hosting qrdb engine in-process via NewStandaloneNode")

	qcfg := s.buildXKMSQRDBConfig()

	nodeOpts := []qrdbnode.NodeOption{
		qrdbnode.WithLogger(s.logger),
	}

	node, err := qrdbnode.NewStandaloneNode(s.ctx, qcfg, nil, nodeOpts...)
	if err != nil {
		return &QRDBNodeError{Stage: "new standalone node", Err: err}
	}

	s.qrdbNode = node
	s.qrdbClient = node.Client()
	s.logger.Info("qrdb engine started in-process", "data_dir", qcfg.Raft.DataDir)

	return nil
}

// stopQRDBNode closes the hosted qrdb node and clears the references. It is
// idempotent; a nil node is silently skipped.
func (s *Server) stopQRDBNode() error {
	node := s.qrdbNode
	if node == nil {
		return nil
	}
	s.qrdbNode = nil
	s.qrdbClient = nil
	if err := node.Close(); err != nil {
		return &QRDBNodeError{Stage: "close", Err: err}
	}
	return nil
}
