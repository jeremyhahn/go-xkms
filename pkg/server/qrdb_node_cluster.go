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

package server

import (
	"fmt"
	"os"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	quicraftconfig "github.com/jeremyhahn/go-quicraft/pkg/config"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// ErrRaftTLSRead is returned when one of the operator-supplied Raft mTLS PEM
// files cannot be read at node boot. It carries the offending field name and
// file path so the operator can correct the deployment.
type ErrRaftTLSRead struct {
	Field string
	Path  string
	Err   error
}

// Error returns the error message.
func (e *ErrRaftTLSRead) Error() string {
	return fmt.Sprintf("server: cluster raft_tls %s: cannot read %q: %v", e.Field, e.Path, e.Err)
}

// Unwrap returns the underlying I/O error.
func (e *ErrRaftTLSRead) Unwrap() error { return e.Err }

// newQRDBNode hosts a clustered qrdb engine when cluster.enabled is set,
// replicating all datastore state (keys, users, RBAC, custodian, shares, CA
// serials/revocations, …) across the cluster via Raft. When clustering is not
// enabled it falls back to a standalone node, so a raft-built binary still runs
// single-node. The Raft parameters were mapped onto qcfg.Raft by
// buildXKMSQRDBConfig; the initial membership comes from Cluster.Peers.
func (s *Server) newQRDBNode(qcfg *qrdbsdk.DaemonConfig, serverOpts []qrdbsdk.ServerOption, nodeOpts []qrdbnode.NodeOption) (*qrdbnode.Node, error) {
	if !s.config.Cluster.Enabled {
		s.logger.Info("Hosting qrdb engine in-process via NewStandaloneNode")
		return qrdbnode.NewStandaloneNode(s.ctx, qcfg, serverOpts, nodeOpts...)
	}

	members, err := s.config.Cluster.Members()
	if err != nil {
		return nil, err
	}

	// Raft mTLS is only consulted for multi-node clusters; a single-node
	// cluster uses an in-process transport that needs no peer certificates.
	if len(members) > 1 && s.config.Cluster.RaftTLS.Enabled() {
		mtls, err := loadRaftMTLS(s.config.Cluster.RaftTLS)
		if err != nil {
			return nil, err
		}
		nodeOpts = append(nodeOpts, qrdbnode.WithRaftMTLS(mtls))
		s.logger.Info("Raft inter-node mTLS enabled",
			"ca_cert_file", s.config.Cluster.RaftTLS.CACertFile,
			"cert_file", s.config.Cluster.RaftTLS.CertFile)
	}

	s.logger.Info("Hosting clustered qrdb engine via NewClusteredNode",
		"node_id", s.config.Cluster.NodeID,
		"shard_id", qcfg.Raft.ShardID,
		"raft_address", s.config.Cluster.RaftAddress,
		"members", len(members),
		"join", s.config.Cluster.Join)

	return qrdbnode.NewClusteredNode(s.ctx, qcfg, members, serverOpts, nodeOpts...)
}

// loadRaftMTLS reads the operator-supplied PEM files referenced by cfg and
// builds the quicraft MTLSConfig consumed by qrdbnode.WithRaftMTLS. The PEM
// material is operator-supplied and deliberately independent of the runtime
// xkms CA (which the node itself hosts). Read failures surface as ErrRaftTLSRead.
func loadRaftMTLS(cfg config.RaftTLSConfig) (*quicraftconfig.MTLSConfig, error) {
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, &ErrRaftTLSRead{Field: "ca_cert_file", Path: cfg.CACertFile, Err: err}
	}
	cert, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, &ErrRaftTLSRead{Field: "cert_file", Path: cfg.CertFile, Err: err}
	}
	key, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, &ErrRaftTLSRead{Field: "key_file", Path: cfg.KeyFile, Err: err}
	}
	return &quicraftconfig.MTLSConfig{
		CACert: caCert,
		Cert:   cert,
		Key:    key,
	}, nil
}
