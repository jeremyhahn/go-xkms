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
	"context"
	"fmt"
	"os"
	"path/filepath"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

// defaultRaftTrustDomain is the SPIFFE trust domain stamped into auto-provisioned
// Raft node certificates when RaftEnrollment.TrustDomain is unset.
const defaultRaftTrustDomain = embeddednode.DefaultTrustDomain

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
func (s *Server) newQRDBNode(qcfg *qrdbsdk.DaemonConfig, serverOpts []qrdbserver.ServerOption, nodeOpts []qrdbnode.NodeOption) (*qrdbnode.Node, error) {
	res, err := embeddednode.NewNode(s.nodeBuildContext(), &embeddednode.NodeOptions{
		QRDB:             qcfg,
		Cluster:          s.nodeClusterOptions(),
		Logger:           s.logger,
		ServerOptions:    serverOpts,
		NodeOptions:      nodeOpts,
		RaftMTLSResolver: s.resolveRaftMTLS,
	})
	if err != nil {
		return nil, err
	}
	if res.Advertiser != nil {
		s.raftClusterAdvertiser = res.Advertiser
	}
	return res.Node, nil
}

// nodeClusterOptions maps the xkms cluster configuration onto the shared
// pkg/embeddednode topology options.
func (s *Server) nodeClusterOptions() embeddednode.ClusterOptions {
	return embeddednode.ClusterOptions{
		Enabled:     s.config.Cluster.Enabled,
		NodeID:      s.config.Cluster.NodeID,
		RaftAddress: s.config.Cluster.RaftAddress,
		Peers:       s.config.Cluster.Peers,
		Join:        s.config.Cluster.Join,
	}
}

// raftNoiseBindHost resolves the bind host for the Noise NK enrollment listener
// the first node of a multi-node cluster starts: the explicit
// cluster.raft_enrollment.advertise_noise_host when set, otherwise the server
// bind host.
//
// go-qrdb's clusterenroll will not choose one (go-qrdb#167) and refuses an
// empty value, so this is the single place xkms answers the question. The
// fallback is Server.Host and not the Raft address host on purpose: this is a
// LISTENER, and a node whose APIs are contained to one interface must have its
// enrollment socket contained to the same one.
func (s *Server) raftNoiseBindHost() string {
	if host := s.config.Cluster.RaftEnrollment.AdvertiseNoiseHost; host != "" {
		return host
	}
	return s.config.Server.Host
}

// resolveRaftMTLS supplies pkg/embeddednode with the inter-node mTLS material for a
// multi-node cluster, applying xkms's provisioning precedence. These strategies
// stay here rather than in pkg/embeddednode because they depend on the runtime
// TrustedCA and key-strategy dependencies the daemon owns.
//
//  1. operator-supplied explicit PEM files (RaftTLS)
//  2. the TrustedCA as the cluster CA: TPM-attested ACME enroll-01, or a
//     leaf issued in-process for the node key on RaftEnrollment.KeyBackend
//     (tpm2/pkcs11, or the software backend when unset)
func (s *Server) resolveRaftMTLS(_ context.Context, members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
	if s.config.Cluster.RaftTLS.Enabled() {
		mtls, err := loadRaftMTLS(s.config.Cluster.RaftTLS)
		if err != nil {
			return nil, nil, err
		}
		s.logger.Info("Raft inter-node mTLS from operator-supplied files",
			"ca_cert_file", s.config.Cluster.RaftTLS.CACertFile,
			"cert_file", s.config.Cluster.RaftTLS.CertFile)
		return mtls, nil, nil
	}

	// Every auto-enrolled mode issues from the TrustedCA through its
	// crypto.Signer; no cluster CA key is written to disk (go-xkms#1381).
	mtls, adv, err := s.provisionRaftClusterTrustedCA(members)
	if err != nil {
		return nil, nil, err
	}
	s.logger.Info("Raft inter-node mTLS issued by the TrustedCA",
		"acme", s.config.Cluster.RaftEnrollment.ACME.Enabled,
		"key_backend", s.config.Cluster.RaftEnrollment.KeyBackend,
		"data_dir", filepath.Join(s.config.Datastore.Path, clusterCACacheSubdir),
		"cluster_ca_cn", s.config.Cluster.RaftEnrollment.ClusterCACN,
		"advertising", adv != nil)
	return mtls, adv, nil
}

// loadRaftMTLS reads the operator-supplied PEM files referenced by cfg and
// builds the qrdbnode.RaftMTLSConfig consumed by qrdbnode.WithRaftMTLS. The PEM
// material is operator-supplied and deliberately independent of the runtime
// xkms CA (which the node itself hosts). Read failures surface as ErrRaftTLSRead.
func loadRaftMTLS(cfg config.RaftTLSConfig) (*qrdbnode.RaftMTLSConfig, error) {
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
	return &qrdbnode.RaftMTLSConfig{
		CACert: caCert,
		Cert:   cert,
		Key:    key,
	}, nil
}

// splitClusterPeers splits the comma-separated "id=addr" peer list into the
// slice form clusterenroll uses to derive a bootstrap server URL. An empty list
// yields nil.
func splitClusterPeers(peers string) []string {
	return embeddednode.ClusterOptions{Peers: peers}.PeerList()
}
