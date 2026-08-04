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
	"crypto/x509"
	"path/filepath"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	clustercapkg "github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// clusterCAKeyProtection builds the KeyProtection for the cluster CA keystore
// from the cluster enrollment configuration.
func (s *Server) clusterCAKeyProtection() clustercapkg.KeyProtection {
	enr := s.config.Cluster.RaftEnrollment
	return clustercapkg.KeyProtection{
		Mode:       clustercapkg.KeyProtectionMode(enr.CAKeyProtection),
		Passphrase: enr.CAKeyPassphrase,
		// Plaintext ("none") only reaches here when the operator started in
		// insecure/development mode: ComplianceGaps refuses it otherwise.
		AllowInsecure: clustercapkg.KeyProtectionMode(enr.CAKeyProtection) == clustercapkg.KeyProtectNone,
	}
}

// clusterStrategyDeps assembles the dependencies a cluster CA key strategy
// needs. Pre-node calls pass nil replicated storage (bootstrap); post-node calls
// (initializeCA) pass the qrdb-routed replicated stores.
func (s *Server) clusterStrategyDeps(replicatedKey, replicatedCert storage.Backend) *clustercapkg.StrategyDeps {
	deps := &clustercapkg.StrategyDeps{
		NodeLocalDataDir:      filepath.Join(s.config.Storage.Path, clusterCACacheSubdir),
		CAConfig:              s.config.CA,
		Protection:            s.clusterCAKeyProtection(),
		ReplicatedKeyStorage:  replicatedKey,
		ReplicatedCertStorage: replicatedCert,
		TPMSealer:             s.nodeSealTPM,
		// Bootstrapping is true on the node that pre-stages the CA (no joiner
		// directory URL) — the tpm-kek strategy generates the cluster seed only
		// there; joiners fetch it after enrollment.
		Bootstrapping: s.config.Cluster.RaftEnrollment.ACME.DirectoryURL == "",
		Logger:        s.logger,
	}
	// The shared HSM backend (hsm strategy) is the configured pkcs11 backend
	// when present; harmless for the other strategies.
	if hsm, ok := s.backends[string(xkms.BackendPKCS11)]; ok {
		deps.HSMBackend = hsm
	}
	// The TPM credential activator (tpm-kek strategy) is the single shared TPM
	// opened by the seal autodetect, when a TPM is present. Absent → tpm-kek
	// fails closed (it requires a TPM).
	if tpmBackend, ok := s.nodeSealTPM.(*tpm2backend.Backend); ok {
		deps.Credentials = tpmBackend.TPM()
	}
	return deps
}

// ClusterSecretDeliveryService builds the post-enrollment secret-delivery
// service for the active cluster CA key strategy, or nil when the strategy
// delivers no enrollment material (barrier/hsm) or no cluster strategy is
// active. The composition root (cmd/xkmsd) mounts its Handler on the ACME
// server so joining nodes fetch their wrapped provisioning material after
// enrollment. The requesting node is authorized by its cluster-CA-signed
// certificate.
func (s *Server) ClusterSecretDeliveryService() *clustercapkg.SecretDeliveryService {
	if s.clusterCAKeyStrategy == nil {
		return nil
	}
	es, ok := clustercapkg.EnrollmentSecretStrategyOf(s.clusterCAKeyStrategy)
	if !ok {
		return nil
	}
	var pool *x509.CertPool
	if s.ca != nil {
		if p, err := s.ca.CABundleCertPool(); err == nil {
			pool = p
		}
	}
	svc := clustercapkg.NewSecretDeliveryService(s.logger, pool, es.SecretProvider())
	if !svc.HasProviders() {
		return nil
	}
	return svc
}

// resolveClusterCARuntimeBackend resolves this node's runtime cluster CA
// keystore via the configured strategy. For the barrier strategy the first
// node's bootstrap key is promoted into the replicated store and every node
// loads it, so any node can issue.
func (s *Server) resolveClusterCARuntimeBackend() (xkms.Backend, error) {
	replicatedKey, err := s.createStorage("cluster-ca-keys")
	if err != nil {
		return nil, err
	}
	replicatedCert, err := s.createStorage("cluster-ca-certs")
	if err != nil {
		return nil, err
	}
	return s.clusterCAKeyStrategy.RuntimeBackend(s.ctx, s.clusterStrategyDeps(replicatedKey, replicatedCert))
}
