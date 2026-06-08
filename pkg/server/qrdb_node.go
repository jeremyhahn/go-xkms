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
	"fmt"
	"time"

	qrdbconfig "github.com/jeremyhahn/go-qrdb/pkg/config"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

	// Map cluster configuration onto the qrdb Raft config. These fields are
	// consumed only by the clustered node path (built with -tags raft); for a
	// standalone node they are ignored. Validation (config.Validate) guarantees
	// the required fields are present when Cluster.Enabled.
	if s.config.Cluster.Enabled {
		qcfg.Raft.ReplicaID = s.config.Cluster.NodeID
		qcfg.Raft.ShardID = s.config.Cluster.ShardID
		qcfg.Raft.DeploymentID = s.config.Cluster.DeploymentID
		qcfg.Raft.RaftAddress = s.config.Cluster.RaftAddress
		qcfg.Raft.ListenAddress = s.config.Cluster.ListenAddress
		qcfg.Raft.Peers = s.config.Cluster.Peers
		qcfg.Raft.Join = s.config.Cluster.Join
	}

	return qcfg
}

// defaultQRDBAuditRingCapacity is the in-memory audit ring size used when
// file audit is disabled. The node always receives a queryable logger so audit
// emission and querying function even without persistent file audit.
const defaultQRDBAuditRingCapacity = 1024

// newQRDBAuditSink builds the compliance-grade audit sink injected into the
// embedded qrdb node. When file audit is configured (Auth.Audit.Enabled with a
// Path) it returns the HMAC-chained file logger; otherwise it returns an
// in-memory ring buffer so Client().Audit() always emits and queries
// successfully. The returned sink is retained on s.qrdbAuditSink and closed
// during Shutdown.
func (s *Server) newQRDBAuditSink() (qrdbsdk.NodeAuditLogger, error) {
	if a := s.config.Auth.Audit; a != nil && a.Enabled && a.Path != "" {
		sink, err := qrdbsdk.NewAuditFileLogger(a.Path)
		if err != nil {
			return nil, err
		}
		s.logger.Info("qrdb node audit sink: HMAC-chained file logger", "path", a.Path)
		return sink, nil
	}
	s.logger.Info("qrdb node audit sink: in-memory ring buffer",
		"capacity", defaultQRDBAuditRingCapacity)
	return qrdbsdk.NewAuditRingBuffer(defaultQRDBAuditRingCapacity), nil
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
	qcfg := s.buildXKMSQRDBConfig()

	sink, err := s.newQRDBAuditSink()
	if err != nil {
		return &QRDBNodeError{Stage: "new qrdb audit sink", Err: err}
	}
	s.qrdbAuditSink = sink

	nodeOpts := []qrdbnode.NodeOption{
		qrdbnode.WithLogger(s.logger),
	}

	// The audit sink is wired into the node so Client().Audit() emits to the
	// HMAC-chained subsystem; without it the node has no default audit logger.
	serverOpts := []qrdbsdk.ServerOption{
		qrdbsdk.WithAuditLogger(sink),
	}

	// newQRDBNode is build-tag specific: the default (!raft) build hosts a
	// standalone node; the -tags raft build hosts a clustered node when
	// Cluster.Enabled, falling back to standalone otherwise.
	node, err := s.newQRDBNode(qcfg, serverOpts, nodeOpts)
	if err != nil {
		return &QRDBNodeError{Stage: "new qrdb node", Err: err}
	}

	s.qrdbNode = node
	s.qrdbClient = node.Client()
	s.logger.Info("qrdb engine started in-process",
		"data_dir", qcfg.Raft.DataDir, "clustered", s.config.Cluster.Enabled)

	// A clustered node cannot serve writes until a leader is elected; gate
	// startup readiness on it. Standalone nodes skip this.
	if s.config.Cluster.Enabled {
		if err := s.waitForClusterLeader(); err != nil {
			return err
		}
	}

	return nil
}

// waitForClusterLeader blocks until the cluster elects a leader for the
// configured shard, or a timeout elapses. It polls the qrdb cluster client and
// respects server shutdown via s.ctx.
func (s *Server) waitForClusterLeader() error {
	const (
		timeout  = 30 * time.Second
		interval = 250 * time.Millisecond
	)
	shardID := s.config.Cluster.ShardID
	if shardID == 0 {
		shardID = 1
	}
	deadline := time.Now().Add(timeout)
	for {
		if _, hasLeader, err := s.qrdbClient.Cluster().Leader(s.ctx, shardID); err == nil && hasLeader {
			s.logger.Info("cluster leader elected", "shard_id", shardID)
			return nil
		}
		if time.Now().After(deadline) {
			return &QRDBNodeError{
				Stage: "await cluster leader",
				Err:   fmt.Errorf("no leader elected for shard %d within %s", shardID, timeout),
			}
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(interval):
		}
	}
}

// stopQRDBNode closes the hosted qrdb node and clears the references. It is
// idempotent; a nil node is silently skipped.
func (s *Server) stopQRDBNode() error {
	node := s.qrdbNode
	if node == nil {
		return nil
	}
	sink := s.qrdbAuditSink
	s.qrdbNode = nil
	s.qrdbClient = nil
	s.qrdbAuditSink = nil
	if err := node.Close(); err != nil {
		return &QRDBNodeError{Stage: "close", Err: err}
	}
	// Close the audit sink after the node so no in-flight emit races the
	// underlying file handle / buffer. The interface always exposes Close.
	if sink != nil {
		if err := sink.Close(); err != nil {
			return &QRDBNodeError{Stage: "close audit sink", Err: err}
		}
	}
	return nil
}
