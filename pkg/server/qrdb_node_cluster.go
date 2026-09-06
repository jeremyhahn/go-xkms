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

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/daemon"
)

// defaultRaftTrustDomain is the SPIFFE trust domain stamped into auto-provisioned
// Raft node certificates when RaftEnrollment.TrustDomain is unset.
const defaultRaftTrustDomain = daemon.DefaultTrustDomain

// raftTLSCacheSubdir is the subdirectory of Storage.Path where auto-provisioned
// cluster TLS material (CA + node cert/key + Noise key) is cached so restarts
// reuse it.
const raftTLSCacheSubdir = daemon.RaftTLSCacheSubdir

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
	res, err := daemon.NewNode(s.ctx, &daemon.Options{
		QRDB:             qcfg,
		Cluster:          s.daemonClusterOptions(),
		StoragePath:      s.config.Storage.Path,
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

// daemonClusterOptions maps the xkms cluster configuration onto the shared
// pkg/daemon topology options.
func (s *Server) daemonClusterOptions() daemon.ClusterOptions {
	enr := s.config.Cluster.RaftEnrollment
	return daemon.ClusterOptions{
		Enabled:            s.config.Cluster.Enabled,
		NodeID:             s.config.Cluster.NodeID,
		RaftAddress:        s.config.Cluster.RaftAddress,
		Peers:              s.config.Cluster.Peers,
		Join:               s.config.Cluster.Join,
		TrustDomain:        enr.TrustDomain,
		AdvertiseNoisePort: enr.AdvertiseNoisePort,
		AdvertiseNoiseHost: s.raftNoiseBindHost(),
		Bootstrap: clusterenroll.BootstrapOptions{
			NoiseKey:   enr.Bootstrap.NoiseKey,
			NoiseAddr:  enr.Bootstrap.NoiseAddr,
			SPKIPin:    enr.Bootstrap.SPKIPin,
			ServerAddr: enr.Bootstrap.ServerAddr,
			DANEDNS:    enr.Bootstrap.DANEDNS,
			DANEDoT:    enr.Bootstrap.DANEDoT,
			DirectURL:  enr.Bootstrap.DirectURL,
		},
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

// resolveRaftMTLS supplies pkg/daemon with the inter-node mTLS material for a
// multi-node cluster, applying xkms's provisioning precedence. These strategies
// stay here rather than in pkg/daemon because they depend on the runtime
// TrustedCA and key-strategy dependencies the daemon owns.
//
//  1. operator-supplied explicit PEM files (RaftTLS)
//  2. TPM-attested ACME enroll-01 against the runtime TrustedCA
//  2. hardware-resident node key (tpm2/pkcs11), key never leaves the device
//  3. software node key auto-provisioned via the shared enrollment toolkit
func (s *Server) resolveRaftMTLS(_ context.Context, members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
	switch {
	case s.config.Cluster.RaftTLS.Enabled():
		mtls, err := loadRaftMTLS(s.config.Cluster.RaftTLS)
		if err != nil {
			return nil, nil, err
		}
		s.logger.Info("Raft inter-node mTLS from operator-supplied files",
			"ca_cert_file", s.config.Cluster.RaftTLS.CACertFile,
			"cert_file", s.config.Cluster.RaftTLS.CertFile)
		return mtls, nil, nil

	case s.config.Cluster.RaftEnrollment.ACME.Enabled:
		mtls, adv, err := s.provisionRaftClusterACME(members)
		if err != nil {
			return nil, nil, err
		}
		s.logger.Info("Raft inter-node mTLS via TPM-attested ACME cluster enrollment",
			"data_dir", filepath.Join(s.config.Storage.Path, clusterCACacheSubdir),
			"cluster_ca_cn", s.config.Cluster.RaftEnrollment.ClusterCACN,
			"advertising", adv != nil)
		return mtls, adv, nil

	case s.config.Cluster.RaftEnrollment.KeyBackend != "":
		return s.provisionRaftClusterTLSHardware(members)

	default:
		mtls, adv, err := s.provisionRaftClusterTLS(members)
		if err != nil {
			return nil, nil, err
		}
		s.logger.Info("Raft inter-node mTLS auto-provisioned via cluster enrollment",
			"data_dir", filepath.Join(s.config.Storage.Path, raftTLSCacheSubdir),
			"advertising", adv != nil)
		return mtls, adv, nil
	}
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

// provisionRaftClusterTLS auto-provisions the inter-node Raft mTLS material by
// delegating to go-qrdb's shared cluster-TLS enrollment (clusterenroll.Resolve).
// The first node generates a dedicated self-signed cluster CA and returns a
// running Noise advertiser for peer enrollment; joining nodes (RaftEnrollment.
// Bootstrap configured) fetch the CA and issue their own leaf. Generated material
// is cached under {Storage.Path}/raft-tls so restarts reuse it. The returned
// Advertiser is nil except on the first (bootstrapping) node.
func (s *Server) provisionRaftClusterTLS(members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
	mat, adv, err := clusterenroll.Resolve(s.ctx, s.buildClusterEnrollOptions(members), s.logger)
	if err != nil {
		return nil, nil, err
	}
	return &qrdbnode.RaftMTLSConfig{
		CACert: mat.CACertPEM,
		Cert:   mat.CertPEM,
		Key:    mat.KeyPEM,
	}, adv, nil
}

// buildClusterEnrollOptions maps the xkms cluster configuration onto the qrdb
// clusterenroll Options by delegating to the shared pkg/daemon mapping, which
// applies the trust-domain and advertise-port defaults and computes SingleNode
// from the membership. It is pure (no side effects) so the mapping can be
// unit-tested without starting the Noise advertiser.
func (s *Server) buildClusterEnrollOptions(members map[uint64]string) *clusterenroll.Options {
	opts := &daemon.Options{
		Cluster:     s.daemonClusterOptions(),
		StoragePath: s.config.Storage.Path,
	}
	return opts.ClusterEnrollOptions(members)
}

// splitClusterPeers splits the comma-separated "id=addr" peer list into the
// slice form clusterenroll uses to derive a bootstrap server URL. An empty list
// yields nil.
func splitClusterPeers(peers string) []string {
	return daemon.ClusterOptions{Peers: peers}.PeerList()
}
