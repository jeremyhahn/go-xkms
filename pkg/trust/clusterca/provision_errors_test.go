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
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// failingIssuer is a CAIssuer whose bundle retrieval fails, modelling a CA that
// is reachable but cannot produce a trust anchor.
type failingIssuer struct{ err error }

func (i *failingIssuer) SignCSR(context.Context, []byte, *ca.SignOptions) (*x509.Certificate, error) {
	return nil, i.err
}
func (i *failingIssuer) CABundle() ([]byte, error)                 { return nil, i.err }
func (i *failingIssuer) CACertificate() (*x509.Certificate, error) { return nil, i.err }

// closedBackends returns a Backends seam over a software backend whose storage
// has been closed, so key generation and lookup both fail. This models a
// keystore that is configured but unusable at provisioning time.
func closedBackends(t *testing.T) func(string) (xkms.Backend, error) {
	t.Helper()

	keyStore := storage.NewMemory()
	certStore := storage.NewMemory()

	sw, err := software.NewBackend(&software.Config{KeyStorage: keyStore})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: sw, CertStorage: certStore})
	require.NoError(t, err)

	require.NoError(t, keyStore.Close())

	return func(string) (xkms.Backend, error) { return backend, nil }
}

// TestProvisionFirstNode_PropagatesBackendResolutionFailure verifies ACME
// first-node provisioning aborts when the key backend cannot be resolved,
// rather than continuing with a partially-built identity.
func TestProvisionFirstNode_PropagatesBackendResolutionFailure(t *testing.T) {
	wantErr := errors.New("keystore offline")

	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.Backends = func(string) (xkms.Backend, error) { return nil, wantErr }

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.ErrorIs(t, err, wantErr)
	assert.Nil(t, res)
}

// TestProvisionFirstNode_PropagatesCABundleFailure verifies that a running CA
// which cannot produce its trust anchor aborts provisioning. Continuing would
// leave the node with a certificate and no anchor to validate peers against.
func TestProvisionFirstNode_PropagatesCABundleFailure(t *testing.T) {
	wantErr := errors.New("ca bundle unavailable")

	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.CAConfig = nil
	opts.CA = &failingIssuer{err: wantErr}

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.ErrorIs(t, err, wantErr)
	assert.Nil(t, res)
}

// TestProvisionFirstNode_PropagatesNodeKeyFailure verifies that an unusable
// keystore aborts provisioning instead of yielding a certificate the node has
// no key for.
func TestProvisionFirstNode_PropagatesNodeKeyFailure(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), closedBackends(t))

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

// TestProvisionFirstNode_UnknownClusterCAFailsClosed verifies that naming a
// cluster CA identity that does not exist in the configured hierarchy aborts.
// Silently falling back to the default issuing identity would place node
// certificates under an intermediate that peers do not expect.
func TestProvisionFirstNode_UnknownClusterCAFailsClosed(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.ClusterCACN = "No Such Cluster CA"

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

// TestProvisionFirstNode_CacheWriteFailureAborts verifies that being unable to
// persist the freshly issued identity is fatal. Returning success would make
// the node re-run the destructive first-node pre-stage on its next boot.
func TestProvisionFirstNode_CacheWriteFailureAborts(t *testing.T) {
	// A regular file where DataDir should be makes every cache write fail.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	opts := firstNodeOptions(t, blocker, softwareBackends(t))

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

// TestStageBootstrapCA_PropagatesBackendFailure verifies pre-staging aborts
// when the keystore backing the CA identities cannot be resolved, rather than
// creating a CA whose keys have nowhere to live.
func TestStageBootstrapCA_PropagatesBackendFailure(t *testing.T) {
	wantErr := errors.New("keystore backend missing")

	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.Backends = func(string) (xkms.Backend, error) { return nil, wantErr }

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	bootstrapCA, err := p.stageBootstrapCA(context.Background())
	require.ErrorIs(t, err, wantErr)
	assert.Nil(t, bootstrapCA)
}

// TestProvisionLocalCA_FailsOnUnusableDataDir verifies the local-CA path on
// the default software key backend reports a failure when it cannot cache the
// node identity it was issued.
func TestProvisionLocalCA_FailsOnUnusableDataDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	p, err := New(&Options{
		RaftAddress:     "127.0.0.1:8321",
		TrustDomain:     "test.cluster",
		DataDir:         blocker,
		Members:         map[uint64]string{1: "127.0.0.1:8321"},
		Backends:        softwareBackends(t),
		NodeKeyBackends: softwareBackends(t),
		CAConfig:        clusterCAConfig(),
	}, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

// TestProvisionFromFiles_ReportsWhichFileIsMissing verifies each missing file is
// named in the error, so an operator can fix the specific path rather than
// guessing which of the three is wrong.
func TestProvisionFromFiles_ReportsWhichFileIsMissing(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.pem")
	require.NoError(t, os.WriteFile(present, []byte("material"), 0o600))
	absent := filepath.Join(dir, "absent.pem")

	tests := []struct {
		name      string
		files     *ExplicitFiles
		wantField string
	}{
		{
			name:      "missing CA cert",
			files:     &ExplicitFiles{CACertFile: absent, CertFile: present, KeyFile: present},
			wantField: "CACertFile",
		},
		{
			name:      "missing cert",
			files:     &ExplicitFiles{CACertFile: present, CertFile: absent, KeyFile: present},
			wantField: "CertFile",
		},
		{
			name:      "missing key",
			files:     &ExplicitFiles{CACertFile: present, CertFile: present, KeyFile: absent},
			wantField: "KeyFile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(&Options{RaftTLSFiles: tt.files}, testLogger())
			require.NoError(t, err)

			res, err := p.Provision(context.Background())
			var readErr *ErrFileRead
			require.ErrorAs(t, err, &readErr)
			assert.Equal(t, tt.wantField, readErr.Field)
			assert.Nil(t, res)
		})
	}
}

// TestBarrierStrategy_BootstrapFailsOnUnusableDataDir verifies the barrier
// strategy reports a failure when its node-local store cannot be created,
// instead of returning a resolver that hands out broken backends.
func TestBarrierStrategy_BootstrapFailsOnUnusableDataDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	s := &barrierStrategy{}
	resolve, err := s.BootstrapBackends(context.Background(), &StrategyDeps{
		NodeLocalDataDir: blocker,
		Protection:       KeyProtection{Mode: KeyProtectPassphrase, Passphrase: mustSecret(t, "x")},
	})
	require.Error(t, err)
	assert.Nil(t, resolve)
}

// TestBarrierStrategy_CloseBootstrapStorageIsSafeWhenUnused verifies closing a
// strategy that never opened node-local storage is a no-op. Shutdown paths call
// this unconditionally, so it must not panic or error on a joiner.
func TestBarrierStrategy_CloseBootstrapStorageIsSafeWhenUnused(t *testing.T) {
	s := &barrierStrategy{}
	require.NoError(t, s.closeBootstrapStorage())
	require.NoError(t, s.closeBootstrapStorage(), "closing twice must stay safe")
}

// TestBarrierStrategy_CloseBootstrapStorageReleasesBothStores verifies both the
// key and cert handles are released. Leaving one open keeps a file lock on the
// node-local directory across a reconfiguration.
func TestBarrierStrategy_CloseBootstrapStorageReleasesBothStores(t *testing.T) {
	ctx := context.Background()
	s := &barrierStrategy{}

	_, err := s.BootstrapBackends(ctx, &StrategyDeps{
		NodeLocalDataDir: nodeLocalDataDir(t),
		CAConfig:         ca.DefaultMultiIdentityCAConfigWithIntermediate(),
		Protection:       KeyProtection{Mode: KeyProtectPassphrase, Passphrase: mustSecret(t, "secret")},
	})
	require.NoError(t, err)
	require.NotNil(t, s.bootstrapKeyStorage)
	require.NotNil(t, s.bootstrapCertStorage)

	require.NoError(t, s.closeBootstrapStorage())

	// A closed store must refuse further writes rather than silently accepting
	// data that will never be persisted.
	require.Error(t, s.bootstrapKeyStorage.Put(ctx, "after/close", []byte("x")))
}

// closeErrorBackend is a storage.Backend whose Close always fails, so
// closeBootstrapStorage's error-aggregation path can be exercised without a
// real storage failure.
type closeErrorBackend struct {
	storage.Backend
	err error
}

func (b *closeErrorBackend) Close() error { return b.err }

// TestBarrierStrategy_CloseBootstrapStorageJoinsBothFailures verifies that a
// Close failure on either store is reported, and that failures on both are
// joined rather than the second silently discarding the first -- an operator
// diagnosing a stuck node-local directory needs to see every handle that
// refused to release.
func TestBarrierStrategy_CloseBootstrapStorageJoinsBothFailures(t *testing.T) {
	keyErr := errors.New("key store close failed")
	certErr := errors.New("cert store close failed")
	s := &barrierStrategy{
		bootstrapKeyStorage:  &closeErrorBackend{err: keyErr},
		bootstrapCertStorage: &closeErrorBackend{err: certErr},
	}

	err := s.closeBootstrapStorage()
	require.Error(t, err)
	assert.ErrorIs(t, err, keyErr)
	assert.ErrorIs(t, err, certErr)
}

// TestBarrierStrategy_RuntimeRejectsMissingCertStorage verifies both halves of
// the replicated store are required, not just the key half.
func TestBarrierStrategy_RuntimeRejectsMissingCertStorage(t *testing.T) {
	s := &barrierStrategy{}
	_, err := s.RuntimeBackend(context.Background(), &StrategyDeps{
		NodeLocalDataDir:     t.TempDir(),
		Protection:           KeyProtection{Mode: KeyProtectPassphrase, Passphrase: mustSecret(t, "x")},
		ReplicatedKeyStorage: storage.NewMemory(),
	})
	require.ErrorIs(t, err, ErrStrategyMisconfigured)
}

// TestBarrierStrategy_RuntimePropagatesProtectionFailure verifies an
// unresolvable key protection aborts the runtime backend rather than silently
// building a keystore whose CA keys are unencrypted.
func TestBarrierStrategy_RuntimePropagatesProtectionFailure(t *testing.T) {
	s := &barrierStrategy{}
	_, err := s.RuntimeBackend(context.Background(), &StrategyDeps{
		NodeLocalDataDir:      t.TempDir(),
		CAConfig:              ca.DefaultMultiIdentityCAConfigWithIntermediate(),
		Protection:            KeyProtection{Mode: KeyProtectAuto}, // no passphrase, no sealer
		ReplicatedKeyStorage:  storage.NewMemory(),
		ReplicatedCertStorage: storage.NewMemory(),
	})
	var noProtection *ErrNoSecureCAKeyProtection
	require.ErrorAs(t, err, &noProtection)
}

// TestNewSoftwareBackend_RequiresBothStores verifies backend composition
// refuses to build over a missing key or certificate store. Returning a usable
// backend here would silently discard every CA key or certificate written to
// it, which surfaces much later as an empty keystore on a peer node.
func TestNewSoftwareBackend_RequiresBothStores(t *testing.T) {
	t.Run("missing key storage", func(t *testing.T) {
		backend, err := newSoftwareBackend(nil, storage.NewMemory())
		require.Error(t, err)
		assert.Nil(t, backend)
	})

	t.Run("missing certificate storage", func(t *testing.T) {
		backend, err := newSoftwareBackend(storage.NewMemory(), nil)
		require.Error(t, err)
		assert.Nil(t, backend)
	})

	t.Run("both stores present", func(t *testing.T) {
		backend, err := newSoftwareBackend(storage.NewMemory(), storage.NewMemory())
		require.NoError(t, err)
		require.NotNil(t, backend)
	})
}
