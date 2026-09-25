// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	clustercapkg "github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file covers the cluster CA key-custody wiring in
// cluster_ca_strategy.go that go-xkms#705 batch 3 found untested:
// clusterCAKeyProtection, clusterStrategyDeps, resolveClusterCARuntimeBackend
// and ClusterSecretDeliveryService. The "none" key-protection mode is used
// throughout so these tests exercise the real (*Server) wiring end to end
// without requiring a TPM/HSM: KeyProtectNone's AllowInsecure resolves the
// keystore password without a sealer, matching what
// TestResolveClusterCAKeyPassphrase_* already proves about the passphrase
// half of this file.

// clusterRuntimeTestServer builds a minimal *Server whose storage backend is
// the in-memory storage.Backend (fast, hermetic) and whose Cluster.RaftEnrollment
// selects the "none" key-protection mode so clusterCAKeyProtection/
// clusterStrategyDeps resolve without hardware.
func clusterRuntimeTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
		Cluster: config.ClusterConfig{
			RaftEnrollment: config.RaftEnrollmentConfig{
				CAKeyProtection: "none",
			},
		},
	}
	return newMinimalServer(t, cfg)
}

// TestClusterCAKeyProtection_NoneMode proves the KeyProtection built from
// config.RaftEnrollmentConfig.CAKeyProtection carries the configured mode and
// derives AllowInsecure from it alone (never a separate daemon-level flag).
func TestClusterCAKeyProtection_NoneMode(t *testing.T) {
	s := clusterRuntimeTestServer(t)

	protection, err := s.clusterCAKeyProtection()
	require.NoError(t, err)
	assert.Equal(t, clustercapkg.KeyProtectNone, protection.Mode)
	assert.True(t, protection.AllowInsecure, "KeyProtectNone must derive AllowInsecure from the mode alone")
	assert.Nil(t, protection.Passphrase, "no CAKeyPassphrase was configured")
}

// TestClusterCAKeyProtection_PassphraseCredentialError proves a
// credential:// reference that cannot be resolved surfaces as an
// *ErrServiceInit from clusterCAKeyProtection, not a silent empty passphrase.
func TestClusterCAKeyProtection_PassphraseCredentialError(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	s.config.Cluster.RaftEnrollment.CAKeyProtection = "passphrase"
	s.config.Cluster.RaftEnrollment.CAKeyPassphrase = &types.SecretValue{Raw: "operator-secret"}

	_, err := s.clusterCAKeyProtection()
	require.Error(t, err)
	var svcErr *ErrServiceInit
	require.ErrorAs(t, err, &svcErr)
}

// TestClusterStrategyDeps_BuildsFromConfig proves clusterStrategyDeps
// resolves the node-local data dir under storage.path, carries the CA
// config, and computes Bootstrapping from whether a joiner directory URL is
// configured.
func TestClusterStrategyDeps_BuildsFromConfig(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	s.config.Storage.Path = t.TempDir()

	deps, err := s.clusterStrategyDeps(nil, nil)
	require.NoError(t, err)
	require.NotNil(t, deps)
	assert.Contains(t, deps.NodeLocalDataDir, s.config.Storage.Path)
	assert.True(t, deps.Bootstrapping, "no ACME directory URL configured: this node pre-stages the CA")
	assert.Nil(t, deps.ReplicatedKeyStorage)
	assert.Nil(t, deps.ReplicatedCertStorage)
}

// TestClusterStrategyDeps_NotBootstrappingWhenJoining proves a configured
// ACME directory URL (a joiner) flips Bootstrapping to false: only the
// pre-staging node generates the cluster seed.
func TestClusterStrategyDeps_NotBootstrappingWhenJoining(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	s.config.Storage.Path = t.TempDir()
	s.config.Cluster.RaftEnrollment.ACME.DirectoryURL = "https://ca.example.com/acme/directory"

	deps, err := s.clusterStrategyDeps(nil, nil)
	require.NoError(t, err)
	assert.False(t, deps.Bootstrapping)
}

// TestResolveClusterCARuntimeBackend_BarrierStrategy proves
// resolveClusterCARuntimeBackend wires createStorage's replicated key/cert
// stores and the resolved KeyProtection into the configured
// ClusterCAKeyStrategy and returns a working xkms.Backend, using the
// "barrier" strategy (the default) end to end over in-memory storage.
func TestResolveClusterCARuntimeBackend_BarrierStrategy(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	s.config.Storage.Path = t.TempDir()

	strategy, err := clustercapkg.NewKeyStrategy(clustercapkg.KeyStrategyBarrier)
	require.NoError(t, err)
	s.clusterCAKeyStrategy = strategy

	backend, err := s.resolveClusterCARuntimeBackend()
	require.NoError(t, err)
	require.NotNil(t, backend)
}

// TestClusterSecretDeliveryService_NilStrategy proves a deployment with no
// active cluster CA key strategy (the non-cluster-ACME default) gets no
// secret-delivery service rather than a nil-strategy panic.
func TestClusterSecretDeliveryService_NilStrategy(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	assert.Nil(t, s.ClusterSecretDeliveryService())
}

// TestClusterSecretDeliveryService_StrategyDeliversNoMaterial proves that a
// strategy which delivers no enrollment material (barrier -- the key lives in
// the replicated barrier-encrypted store, nothing to fetch post-enrollment)
// yields a nil service, matching ClusterSecretDeliveryService's documented
// "no cluster strategy is active" / "delivers no enrollment material" cases.
func TestClusterSecretDeliveryService_StrategyDeliversNoMaterial(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	strategy, err := clustercapkg.NewKeyStrategy(clustercapkg.KeyStrategyBarrier)
	require.NoError(t, err)
	s.clusterCAKeyStrategy = strategy

	assert.Nil(t, s.ClusterSecretDeliveryService())
}

// TestInitializeCA_ClusterKeyStrategyRoutesKeystore proves initializeCA's
// cluster-ACME branch: when s.clusterCAKeyStrategy is set, the CA's signing
// keystore -- for every StoreType, via backendForStore -- comes from
// resolveClusterCARuntimeBackend rather than a lookup in s.backends (which
// stays empty here), so a cluster-ACME deployment's CA composes with no
// backends.* section configured at all.
func TestInitializeCA_ClusterKeyStrategyRoutesKeystore(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory", Path: t.TempDir()},
		CA: &ca.MultiIdentityCAConfig{
			SelectedCA: 0,
			Identity: []ca.Identity{{
				IsRoot:  true,
				Valid:   1,
				Subject: ca.Subject{CommonName: "Cluster Test CA"},
				Keys: []*types.KeyConfig{{
					KeyAlgorithm: types.AlgorithmECDSA,
					ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
				}},
			}},
		},
		Cluster: config.ClusterConfig{
			RaftEnrollment: config.RaftEnrollmentConfig{CAKeyProtection: "none"},
		},
	})
	s.ctx = context.Background()
	require.Empty(t, s.backends, "the cluster-ACME branch must never consult s.backends")

	strategy, err := clustercapkg.NewKeyStrategy(clustercapkg.KeyStrategyBarrier)
	require.NoError(t, err)
	s.clusterCAKeyStrategy = strategy

	require.NoError(t, s.initializeCA())
	require.NotNil(t, s.ca)
}

// TestResolveClusterCARuntimeBackend_StorageCreateFails proves that a
// storage backend which cannot build the replicated key/cert stores (an
// unsupported storage.backend) surfaces that error rather than calling into
// the strategy with a nil/incomplete deps.
func TestResolveClusterCARuntimeBackend_StorageCreateFails(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	s.config.Storage.Backend = "not-a-real-backend"

	strategy, err := clustercapkg.NewKeyStrategy(clustercapkg.KeyStrategyBarrier)
	require.NoError(t, err)
	s.clusterCAKeyStrategy = strategy

	_, err = s.resolveClusterCARuntimeBackend()
	require.Error(t, err)
}

// TestClusterStrategyDeps_CarriesHSMBackendWhenRegistered proves the shared
// PKCS#11 backend, when registered, is threaded into StrategyDeps.HSMBackend
// (the hsm strategy's dependency) even though this deployment is using the
// barrier strategy -- clusterStrategyDeps wires it unconditionally,
// harmlessly, for whichever strategy is active.
func TestClusterStrategyDeps_CarriesHSMBackendWhenRegistered(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	s.config.Storage.Path = t.TempDir()
	hsm := &minimalBackend{}
	s.backends = map[string]xkms.Backend{string(xkms.BackendPKCS11): hsm}

	deps, err := s.clusterStrategyDeps(nil, nil)
	require.NoError(t, err)
	assert.Same(t, hsm, deps.HSMBackend)
}

// TestClusterStrategyDeps_NoHSMBackendRegistered proves the HSMBackend field
// stays nil when no pkcs11 backend is registered, rather than panicking on
// the map lookup.
func TestClusterStrategyDeps_NoHSMBackendRegistered(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	s.config.Storage.Path = t.TempDir()

	deps, err := s.clusterStrategyDeps(nil, nil)
	require.NoError(t, err)
	assert.Nil(t, deps.HSMBackend)
}
