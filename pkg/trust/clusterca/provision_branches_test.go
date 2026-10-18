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

package clusterca

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestNew_DefaultsLoggerWhenNil verifies a nil logger is replaced with the
// process default rather than being stored and dereferenced at the first log
// call during provisioning.
func TestNew_DefaultsLoggerWhenNil(t *testing.T) {
	p, err := New(&Options{
		RaftAddress:     "127.0.0.1:8331",
		TrustDomain:     "test.cluster",
		DataDir:         t.TempDir(),
		Backends:        softwareBackends(t),
		NodeKeyBackends: softwareBackends(t),
		CAConfig:        clusterCAConfig(),
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, p.logger)

	// The provisioner must be usable — a nil logger would panic here.
	res, err := p.Provision(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
}

// TestProvisionHardwareKey_PropagatesNodeKeyFailure verifies hardware-mode
// provisioning aborts when the node key can neither be loaded nor generated,
// instead of issuing a certificate for a key that does not exist.
func TestProvisionHardwareKey_PropagatesNodeKeyFailure(t *testing.T) {
	p, err := New(&Options{
		RaftAddress:     "127.0.0.1:8332",
		TrustDomain:     "test.cluster",
		DataDir:         t.TempDir(),
		KeyBackend:      "software",
		Backends:        closedBackends(t),
		NodeKeyBackends: closedBackends(t),
		CAConfig:        clusterCAConfig(),
	}, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

// TestProvisionHardwareKey_PropagatesDataDirFailure verifies that failing to
// stage the TrustedCA's certificates under the data directory aborts
// hardware-mode provisioning.
func TestProvisionHardwareKey_PropagatesDataDirFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	p, err := New(&Options{
		RaftAddress:     "127.0.0.1:8333",
		TrustDomain:     "test.cluster",
		DataDir:         blocker,
		KeyBackend:      "software",
		Backends:        softwareBackends(t),
		NodeKeyBackends: softwareBackends(t),
		CAConfig:        clusterCAConfig(),
	}, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

// TestNodeSigner_FailsWhenKeyCanNeitherLoadNorGenerate verifies the node
// transport key helper reports failure rather than returning a nil signer that
// would panic during the TLS handshake.
func TestNodeSigner_FailsWhenKeyCanNeitherLoadNorGenerate(t *testing.T) {
	backends := closedBackends(t)
	backend, err := backends("software")
	require.NoError(t, err)

	p, err := New(&Options{
		RaftAddress:     "127.0.0.1:8334",
		TrustDomain:     "test.cluster",
		DataDir:         t.TempDir(),
		Backends:        backends,
		NodeKeyBackends: backends,
		CAConfig:        clusterCAConfig(),
	}, testLogger())
	require.NoError(t, err)

	signer, err := p.nodeSigner(context.Background(), backend.KeyProvider())
	require.Error(t, err)
	assert.Nil(t, signer)
}

// TestIssueNodeLeaf_WithoutClusterCACNUsesIssuingIdentity verifies that leaving
// ClusterCACN unset issues from the CA's own issuing identity and reports that
// identity's certificate as the chain issuer.
func TestIssueNodeLeaf_WithoutClusterCACNUsesIssuingIdentity(t *testing.T) {
	dataDir := t.TempDir()
	opts := firstNodeOptions(t, dataDir, softwareBackends(t))
	opts.ClusterCACN = "" // select the CA's default issuing identity

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.NoError(t, err)

	leaf := res.MTLS.Certificate.Leaf
	require.NotNil(t, leaf)
	assert.NotEqual(t, "Cluster Test Cluster CA", leaf.Issuer.CommonName,
		"without ClusterCACN the leaf comes from the default issuing identity")

	// It must still chain to the advertised anchor.
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(res.MTLS.CACert))
}

// TestIssueNodeLeaf_PropagatesSigningFailure verifies a CA that refuses to sign
// the node CSR aborts provisioning instead of returning an empty certificate.
func TestIssueNodeLeaf_PropagatesSigningFailure(t *testing.T) {
	wantErr := errors.New("ca refused to sign")

	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.ClusterCACN = ""
	opts.CAConfig = nil
	anchorPEM, intermediate, _ := miniChain(t, "spiffe://test.cluster/node/127.0.0.1:8301")
	opts.CA = &signOnlyFailingIssuer{err: wantErr, anchorPEM: anchorPEM, caCert: intermediate}

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.ErrorIs(t, err, wantErr)
	assert.Nil(t, res)
}

// signOnlyFailingIssuer produces a usable CA bundle and certificate but refuses
// to sign, isolating the SignCSR failure path from anchor-retrieval failures.
type signOnlyFailingIssuer struct {
	err       error
	anchorPEM []byte
	caCert    *x509.Certificate
}

func (i *signOnlyFailingIssuer) SignCSR(context.Context, []byte, *ca.SignOptions) (*x509.Certificate, error) {
	return nil, i.err
}

func (i *signOnlyFailingIssuer) CABundle() ([]byte, error) { return i.anchorPEM, nil }

func (i *signOnlyFailingIssuer) CACertificate() (*x509.Certificate, error) {
	return i.caCert, nil
}

// TestTPMKEKStrategy_BootstrapNodeFailsWhenSeedCannotBeSealed verifies the
// bootstrap node aborts when it cannot seal the cluster seed. Continuing would
// pre-stage a CA whose KEK is lost on the next restart.
func TestTPMKEKStrategy_BootstrapNodeFailsWhenSeedCannotBeSealed(t *testing.T) {
	sealFailure := errors.New("tpm seal refused")
	deps := tpmKEKDeps(t, true)
	deps.TPMSealer = &errSealer{canSeal: true, sealErr: sealFailure, unsealErr: sealFailure}

	resolve, err := (&tpmKEKStrategy{}).BootstrapBackends(context.Background(), deps)
	require.ErrorIs(t, err, sealFailure)
	assert.Nil(t, resolve)
}

// TestTPMKEKStrategy_BootstrapFailsOnUnusableDataDir verifies node-local
// keystore construction failures surface rather than yielding a resolver over
// storage that silently drops keys.
func TestTPMKEKStrategy_BootstrapFailsOnUnusableDataDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	deps := tpmKEKDeps(t, false)
	deps.NodeLocalDataDir = blocker
	deps.CAConfig = nil

	resolve, err := (&tpmKEKStrategy{}).BootstrapBackends(context.Background(), deps)
	require.Error(t, err)
	assert.Nil(t, resolve)
}

// TestTPMKEKStrategy_RuntimePropagatesPromotionFailure verifies that failing to
// copy the KEK-wrapped CA key into the replicated store aborts. Reporting
// success would leave the cluster CA reachable from exactly one node.
func TestTPMKEKStrategy_RuntimePropagatesPromotionFailure(t *testing.T) {
	ctx := context.Background()
	deps := tpmKEKDeps(t, true)
	deps.CAConfig = nil
	// This test writes into the node-local store; route its data dir through
	// the helper that absorbs the asynchronous writes during cleanup.
	deps.NodeLocalDataDir = nodeLocalDataDir(t)

	s := &tpmKEKStrategy{}
	_, err := s.BootstrapBackends(ctx, deps)
	require.NoError(t, err)
	require.NotNil(t, s.bootstrapKeyStorage)
	t.Cleanup(func() { _ = s.bootstrapKeyStorage.Close() })

	require.NoError(t, s.bootstrapKeyStorage.Put(ctx, "ca/cluster", []byte("kek-wrapped")))

	// A replicated store that cannot accept writes must fail the promotion.
	require.NoError(t, deps.ReplicatedKeyStorage.Close())

	backend, err := s.RuntimeBackend(ctx, deps)
	require.Error(t, err)
	assert.Nil(t, backend)
}

// TestTPMKEKStrategy_ConsumeEnrollmentSecretFailsWhenSeedCannotBePersisted
// verifies a recovered seed that cannot be sealed locally is reported as a
// failure. Caching it only in memory would make the node unable to decrypt the
// CA keystore after a restart.
func TestTPMKEKStrategy_ConsumeEnrollmentSecretFailsWhenSeedCannotBePersisted(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	deps := tpmKEKDeps(t, false)
	deps.NodeLocalDataDir = blocker

	s := &tpmKEKStrategy{deps: deps}

	blob, err := json.Marshal(&wrappedCredential{
		CredentialBlob: make([]byte, clusterSeedLen), EncryptedSecret: []byte("enc"),
	})
	require.NoError(t, err)

	err = s.ConsumeEnrollmentSecret(context.Background(),
		&ProvisionedSecret{OID: clusterSeedOID, Data: blob})
	require.Error(t, err)
	assert.Empty(t, s.seed, "an unpersistable seed must not be cached as if it were durable")
}

// TestBarrierStrategy_RuntimePropagatesPromotionFailure verifies the barrier
// strategy aborts when the cluster CA key cannot be promoted into the
// replicated store.
func TestBarrierStrategy_RuntimePropagatesPromotionFailure(t *testing.T) {
	ctx := context.Background()
	deps := &StrategyDeps{
		NodeLocalDataDir:      nodeLocalDataDir(t),
		CAConfig:              ca.DefaultMultiIdentityCAConfigWithIntermediate(),
		Protection:            KeyProtection{Mode: KeyProtectPassphrase, Passphrase: mustSecret(t, "cluster-ca-secret")},
		ReplicatedKeyStorage:  storage.NewMemory(),
		ReplicatedCertStorage: storage.NewMemory(),
	}

	s := &barrierStrategy{}
	_, err := s.BootstrapBackends(ctx, deps)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.closeBootstrapStorage() })

	require.NoError(t, s.bootstrapKeyStorage.Put(ctx, "ca/cluster-intermediate", []byte("wrapped")))
	require.NoError(t, deps.ReplicatedKeyStorage.Close())

	backend, err := s.RuntimeBackend(ctx, deps)
	require.Error(t, err)
	assert.Nil(t, backend)
}

// TestPersistStagedCACerts_PropagatesIdentityLookupFailure verifies that being
// unable to collect one of the configured CA certificates aborts, rather than
// writing a partial staged set the runtime CA would fail to Load against.
func TestPersistStagedCACerts_PropagatesIdentityLookupFailure(t *testing.T) {
	wantErr := errors.New("identity not found")
	dataDir := t.TempDir()

	opts := firstNodeOptions(t, dataDir, softwareBackends(t))
	p, err := New(opts, testLogger())
	require.NoError(t, err)

	err = p.persistStagedCACerts(context.Background(), &identityFailingIssuer{err: wantErr})
	require.ErrorIs(t, err, wantErr)

	_, statErr := os.Stat(StagedCACertsPath(dataDir))
	assert.True(t, os.IsNotExist(statErr), "no partial staged-CA file may be written")
}

// identityFailingIssuer implements ca.IdentityIssuer but fails every per-identity
// lookup.
type identityFailingIssuer struct{ err error }

func (i *identityFailingIssuer) SignCSR(context.Context, []byte, *ca.SignOptions) (*x509.Certificate, error) {
	return nil, i.err
}
func (i *identityFailingIssuer) CABundle() ([]byte, error) { return nil, i.err }
func (i *identityFailingIssuer) CACertificate() (*x509.Certificate, error) {
	return nil, i.err
}
func (i *identityFailingIssuer) IssuerForIdentity(context.Context, string) (crypto.Signer, *x509.Certificate, error) {
	return nil, nil, i.err
}
