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
	"path/filepath"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// defaultRaftTrustDomain is the SPIFFE trust domain stamped into auto-provisioned
// Raft node certificates when RaftEnrollment.TrustDomain is unset.
const defaultRaftTrustDomain = "xkms.cluster"

// raftTLSCacheSubdir is the subdirectory of Storage.Path where auto-provisioned
// cluster TLS material (CA + node cert/key + Noise key) is cached so restarts
// reuse it.
const raftTLSCacheSubdir = "raft-tls"

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

	// Raft mTLS is only consulted for multi-node clusters; a single-node cluster
	// uses an in-process transport that needs no peer certificates. The Raft QUIC
	// transport mandates mTLS for multi-node, so the material comes from either
	// operator-supplied files (RaftTLS, which takes precedence) or auto-provisioned
	// cluster enrollment (RaftEnrollment) — never nothing.
	if len(members) > 1 {
		var mtls *qrdbnode.RaftMTLSConfig
		switch {
		case s.config.Cluster.RaftTLS.Enabled():
			// Precedence 1: operator-supplied explicit PEM files.
			mtls, err = loadRaftMTLS(s.config.Cluster.RaftTLS)
			if err != nil {
				return nil, err
			}
			s.logger.Info("Raft inter-node mTLS from operator-supplied files",
				"ca_cert_file", s.config.Cluster.RaftTLS.CACertFile,
				"cert_file", s.config.Cluster.RaftTLS.CertFile)
		case s.config.Cluster.RaftEnrollment.ACME.Enabled:
			// Precedence 2: TPM-attested ACME enroll-01 with the runtime
			// TrustedCA as the single cluster trust anchor. The first node
			// pre-stages the CA and issues its own leaf; joiners enroll their
			// attested node key through an existing node's ACME directory.
			var adv *clusterenroll.Advertiser
			mtls, adv, err = s.provisionRaftClusterACME(members)
			if err != nil {
				return nil, err
			}
			if adv != nil {
				s.raftClusterAdvertiser = adv
			}
			s.logger.Info("Raft inter-node mTLS via TPM-attested ACME cluster enrollment",
				"data_dir", filepath.Join(s.config.Storage.Path, clusterCACacheSubdir),
				"cluster_ca_cn", s.config.Cluster.RaftEnrollment.ClusterCACN,
				"advertising", adv != nil)
		case s.config.Cluster.RaftEnrollment.KeyBackend != "":
			// Precedence 2: hardware-resident node key (tpm2/pkcs11) — the key
			// is generated in and never leaves the device; the Raft transport
			// gets a signer-backed certificate via the quicraft Certificate seam.
			var adv *clusterenroll.Advertiser
			mtls, adv, err = s.provisionRaftClusterTLSHardware(members)
			if err != nil {
				return nil, err
			}
			if adv != nil {
				s.raftClusterAdvertiser = adv
			}
		default:
			// Precedence 3: software node key auto-provisioned via the shared
			// cluster-TLS enrollment toolkit.
			var adv *clusterenroll.Advertiser
			mtls, adv, err = s.provisionRaftClusterTLS(members)
			if err != nil {
				return nil, err
			}
			if adv != nil {
				s.raftClusterAdvertiser = adv
			}
			s.logger.Info("Raft inter-node mTLS auto-provisioned via cluster enrollment",
				"data_dir", filepath.Join(s.config.Storage.Path, raftTLSCacheSubdir),
				"advertising", adv != nil)
		}
		nodeOpts = append(nodeOpts, qrdbnode.WithRaftMTLS(mtls))
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
// clusterenroll Options, applying defaults (trust domain, advertise port) and
// computing SingleNode from the membership. It is pure (no side effects) so the
// mapping can be unit-tested without starting the Noise advertiser.
func (s *Server) buildClusterEnrollOptions(members map[uint64]string) *clusterenroll.Options {
	enr := s.config.Cluster.RaftEnrollment

	trustDomain := enr.TrustDomain
	if trustDomain == "" {
		trustDomain = defaultRaftTrustDomain
	}
	advPort := enr.AdvertiseNoisePort
	if advPort == 0 {
		advPort = clusterenroll.DefaultNoisePort
	}

	return &clusterenroll.Options{
		RaftAddress: s.config.Cluster.RaftAddress,
		TrustDomain: trustDomain,
		DataDir:     filepath.Join(s.config.Storage.Path, raftTLSCacheSubdir),
		SingleNode:  len(members) <= 1,
		Bootstrap: clusterenroll.BootstrapOptions{
			NoiseKey:        enr.Bootstrap.NoiseKey,
			NoiseAddr:       enr.Bootstrap.NoiseAddr,
			SPKIPin:         enr.Bootstrap.SPKIPin,
			ServerAddr:      enr.Bootstrap.ServerAddr,
			DANEDNS:         enr.Bootstrap.DANEDNS,
			DANEDoT:         enr.Bootstrap.DANEDoT,
			DirectURL:       enr.Bootstrap.DirectURL,
			DiscoveryMethod: "static",
			Peers:           splitClusterPeers(s.config.Cluster.Peers),
		},
		Advertise: clusterenroll.AdvertiseOptions{
			NoisePort: advPort,
		},
	}
}

// splitClusterPeers splits the comma-separated "id=addr" peer list into the
// slice form clusterenroll uses to derive a bootstrap server URL. An empty list
// yields nil.
func splitClusterPeers(peers string) []string {
	peers = strings.TrimSpace(peers)
	if peers == "" {
		return nil
	}
	parts := strings.Split(peers, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
