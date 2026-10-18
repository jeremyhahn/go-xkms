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
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// clusterCAKeyProtection builds the KeyProtection for the cluster CA keystore
// from the cluster enrollment configuration, resolving any credential://
// reference in CAKeyPassphrase through the server's secret registry.
func (s *Server) clusterCAKeyProtection() (clustercapkg.KeyProtection, error) {
	enr := s.config.Cluster.RaftEnrollment

	passphrase, err := s.resolveClusterCAKeyPassphrase(enr.CAKeyPassphrase)
	if err != nil {
		return clustercapkg.KeyProtection{}, &ErrServiceInit{
			Service: "cluster CA key passphrase credential", Err: err,
		}
	}

	return clustercapkg.KeyProtection{
		Mode:       clustercapkg.KeyProtectionMode(enr.CAKeyProtection),
		Passphrase: passphrase,
		// AllowInsecure is the clusterca library's own permission to write a
		// plaintext key, and it is derived from the "none" mode alone. It is not
		// a daemon override: config.ComplianceGaps reports "none" and cmd/xkmsd
		// refuses to start with it, so only an embedded or test caller of this
		// package reaches here with it set.
		AllowInsecure: clustercapkg.KeyProtectionMode(enr.CAKeyProtection) == clustercapkg.KeyProtectNone,
	}, nil
}

// resolveClusterCAKeyPassphrase converts sv (a types.SecretValue carrying
// either a plaintext passphrase or a credential:// reference) into a
// *secure.Secret, the type clustercapkg.KeyProtection.Passphrase requires.
// An empty/unset Raw — no passphrase configured — returns (nil, nil), which
// KeyProtection treats identically to the pre-enclave empty-string default.
//
// types.SecretValueBytes is the single read path: when this call runs after
// Server.resolveConfigSecrets has already walked the loaded configuration
// (the post-node path, from initializeCA), sv's enclave is already populated
// and WithBytes wins outright. A plain operator-supplied passphrase resolves
// the same way whether or not that walk has run yet, since it is never
// reference-shaped. The one case genuinely unresolved here is a
// credential:// reference on the PRE-node cluster-ACME bootstrap path (this
// function's other caller, provisionRaftClusterTrustedCA, runs before the
// credential service — and so resolveConfigSecrets — exist): that now fails
// closed with *types.SecretReferenceUnresolvedError instead of the previous
// direct buildSecretRegistry().Resolve call's registry fallback, which would
// have silently used the unclaimed reference text itself as the passphrase.
func (s *Server) resolveClusterCAKeyPassphrase(sv *types.SecretValue) (*secure.Secret, error) {
	plaintext, err := types.SecretValueBytes(s.ctx, sv)
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return nil, nil
	}
	// secure.NewSecret wipes the slice it seals; plaintext is SecretValueBytes'
	// own private copy, not sv's enclave, so nothing else is left exposed.
	return secure.NewSecret(s.ctx, plaintext)
}

// clusterStrategyDeps assembles the dependencies a cluster CA key strategy
// needs. Pre-node calls pass nil replicated storage (bootstrap); post-node calls
// (initializeCA) pass the qrdb-routed replicated stores.
func (s *Server) clusterStrategyDeps(replicatedKey, replicatedCert storage.Backend) (*clustercapkg.StrategyDeps, error) {
	protection, err := s.clusterCAKeyProtection()
	if err != nil {
		return nil, err
	}
	deps := &clustercapkg.StrategyDeps{
		NodeLocalDataDir:      filepath.Join(s.config.Datastore.Path, clusterCACacheSubdir),
		CAConfig:              s.config.CA,
		Protection:            protection,
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
	return deps, nil
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
	deps, err := s.clusterStrategyDeps(replicatedKey, replicatedCert)
	if err != nil {
		return nil, err
	}
	return s.clusterCAKeyStrategy.RuntimeBackend(s.ctx, deps)
}
