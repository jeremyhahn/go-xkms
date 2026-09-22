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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// provisionRaftClusterACME provisions inter-node Raft mTLS material via
// TPM-attested ACME enroll-01, with the runtime TrustedCA as the single cluster
// trust anchor. The first node pre-stages the CA hierarchy from CAConfig (the
// datastore does not exist yet) and issues its own transport leaf; joining nodes
// fetch the trust anchor via truststrap and enroll their attested node key
// through the existing node's ACME directory. It returns the qrdb WithRaftMTLS
// material and, on the first node, the running Noise advertiser to stop at
// shutdown.
func (s *Server) provisionRaftClusterACME(members map[uint64]string) (*qrdbnode.RaftMTLSConfig, *clusterenroll.Advertiser, error) {
	// Build the cluster CA key custody strategy and retain it: it is stateful
	// (the barrier strategy holds its bootstrap key-storage handle for
	// promotion), so initializeCA uses this SAME instance for RuntimeBackend so
	// that any node — not just the first — can issue.
	strategy, err := clusterca.NewKeyStrategy(clusterca.KeyStrategyName(s.config.Cluster.RaftEnrollment.CAKeyStrategy))
	if err != nil {
		return nil, nil, err
	}
	s.clusterCAKeyStrategy = strategy

	// The pre-node Backends seam the provisioner uses to pre-stage the CA and
	// issue this node's transport leaf comes from the strategy's bootstrap
	// backends (node-local for barrier/tpm-kek, the shared HSM for hsm).
	deps, err := s.clusterStrategyDeps(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	backends, err := strategy.BootstrapBackends(s.ctx, deps)
	if err != nil {
		return nil, nil, err
	}

	opts, err := s.buildClusterACMEOptions(members, backends)
	if err != nil {
		return nil, nil, err
	}

	provisioner, err := clusterca.New(opts, s.logger)
	if err != nil {
		return nil, nil, err
	}
	result, err := provisioner.Provision(s.ctx)
	if err != nil {
		return nil, nil, err
	}

	// Joining node: after enrollment, fetch any wrapped provisioning material the
	// cluster CA key strategy delivers (the tpm-kek cluster seed) from the
	// enrolling node and hand it to the strategy, so RuntimeBackend can derive
	// the KEK. A no-op for barrier/hsm (which implement no EnrollmentSecretStrategy).
	if es, ok := clusterca.EnrollmentSecretStrategyOf(strategy); ok &&
		s.config.Cluster.RaftEnrollment.ACME.DirectoryURL != "" {
		if err := s.fetchClusterEnrollmentSecret(s.ctx, es, result.MTLS); err != nil {
			return nil, nil, err
		}
	}
	return result.MTLS, result.Advertiser, nil
}

// fetchClusterEnrollmentSecret runs on a JOINING node after enrollment: it reads
// this node's EK certificate and attestation-key public area from the TPM, POSTs
// them together with its just-issued node certificate to the enrolling node's
// secret-delivery endpoint, and hands the returned (TPM-wrapped) material to the
// strategy's ConsumeEnrollmentSecret.
func (s *Server) fetchClusterEnrollmentSecret(ctx context.Context, es clusterca.EnrollmentSecretStrategy, mtls *qrdbnode.RaftMTLSConfig) error {
	tpmBackend, ok := s.nodeSealTPM.(*tpm2backend.Backend)
	if !ok {
		return clusterca.ErrNoTPMCredentials
	}
	tpm := tpmBackend.TPM()
	ekCert, err := tpm.EKCertificate()
	if err != nil {
		return err
	}
	akProfile, err := tpm.AKProfile()
	if err != nil {
		return err
	}
	ekPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekCert.Raw})

	baseURL, err := clusterSecretBaseURL(s.config.Cluster.RaftEnrollment.ACME.DirectoryURL)
	if err != nil {
		return err
	}
	client := clusterSecretHTTPClient(mtls.CACert)

	secrets, err := clusterca.FetchClusterSecrets(ctx, client, baseURL, mtls.Cert, ekPEM, akProfile.AKPub)
	if err != nil {
		return err
	}
	for _, material := range secrets {
		if err := es.ConsumeEnrollmentSecret(ctx, material); err != nil {
			return err
		}
	}
	s.logger.Info("fetched and consumed cluster enrollment secret via post-enrollment delivery")
	return nil
}

// clusterSecretBaseURL derives the scheme://host[:port] base of the delivery
// endpoint from the ACME directory URL (the delivery endpoint is co-hosted).
func clusterSecretBaseURL(directoryURL string) (string, error) {
	u, err := url.Parse(directoryURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", &ErrRaftTLSRead{Field: "acme.directory_url", Path: directoryURL}
	}
	return u.Scheme + "://" + u.Host, nil
}

// clusterSecretHTTPClient builds an HTTP client that trusts the cluster CA anchor
// for the delivery fetch. Confidentiality of the material is guaranteed
// independently by the TPM credential-activation wrapping, so this protects
// integrity/authenticity of the transport.
func clusterSecretHTTPClient(caPEM []byte) *http.Client {
	pool := x509.NewCertPool()
	if len(caPEM) > 0 {
		pool.AppendCertsFromPEM(caPEM)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// buildClusterACMEOptions maps the xkms cluster configuration onto the clusterca
// Options. The first node (no bootstrap directory) pre-stages the CA from
// CAConfig; joining nodes (DirectoryURL set) enroll against it. The mapping is
// pure so it can be unit-tested without provisioning.
func (s *Server) buildClusterACMEOptions(members map[uint64]string, backends func(string) (xkms.Backend, error)) (*clusterca.Options, error) {
	enr := s.config.Cluster.RaftEnrollment

	trustDomain := enr.TrustDomain
	if trustDomain == "" {
		trustDomain = defaultRaftTrustDomain
	}
	advPort := enr.AdvertiseNoisePort
	if advPort == 0 {
		advPort = clusterenroll.DefaultNoisePort
	}
	challengePort := enr.ACME.ChallengePort
	if challengePort == "" {
		challengePort = defaultClusterACMEChallengePort
	}

	opts := &clusterca.Options{
		RaftAddress: s.config.Cluster.RaftAddress,
		NodeID:      s.config.Cluster.NodeID,
		TrustDomain: trustDomain,
		Members:     members,
		DataDir:     filepath.Join(s.config.Storage.Path, clusterCACacheSubdir),
		ACME: &clusterca.ACMEOptions{
			DirectoryURL:  enr.ACME.DirectoryURL,
			ChallengePort: challengePort,
			// The enroll-01 exchange is a daemon listener: it binds
			// server.host like every other one (#140).
			ChallengeHost: s.config.Server.Host,
		},
		KeyBackend: enr.KeyBackend,
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
			NoiseHost: s.raftNoiseBindHost(),
		},
		Backends:    backends,
		CAConfig:    s.config.CA,
		ClusterCACN: enr.ClusterCACN,
	}
	return opts, nil
}

// defaultClusterACMEChallengePort is the local HTTP port a node serves the
// enroll-01 credential-activation exchange on while enrolling, matching the
// clusterca and ACME server defaults.
const defaultClusterACMEChallengePort = "8080"
