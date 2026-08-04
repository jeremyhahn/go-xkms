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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

// TestNewKeyStrategy verifies the factory returns the barrier default, fails
// closed for recognized-but-unimplemented strategies, and errors on unknown.
func TestNewKeyStrategy(t *testing.T) {
	for _, name := range []KeyStrategyName{"", KeyStrategyBarrier} {
		strat, err := NewKeyStrategy(name)
		require.NoError(t, err)
		require.Equal(t, KeyStrategyBarrier, strat.Name())
	}

	hsm, err := NewKeyStrategy(KeyStrategyHSM)
	require.NoError(t, err)
	require.Equal(t, KeyStrategyHSM, hsm.Name())

	tpmkek, err := NewKeyStrategy(KeyStrategyTPMKEK)
	require.NoError(t, err)
	require.Equal(t, KeyStrategyTPMKEK, tpmkek.Name())
	// tpm-kek delivers an enrollment secret; it must expose the optional seam.
	_, ok := EnrollmentSecretStrategyOf(tpmkek)
	require.True(t, ok, "tpm-kek must implement EnrollmentSecretStrategy")

	// barrier/hsm deliver no enrollment secret — they must NOT implement it.
	barrier, _ := NewKeyStrategy(KeyStrategyBarrier)
	_, ok = EnrollmentSecretStrategyOf(barrier)
	require.False(t, ok, "barrier must not implement EnrollmentSecretStrategy")

	_, err = NewKeyStrategy("bogus")
	require.ErrorIs(t, err, ErrUnknownKeyStrategy)
}

// TestHSMStrategy verifies the shared-HSM strategy resolves both bootstrap and
// runtime keystores to the supplied HSM backend, and fails closed without one.
func TestHSMStrategy(t *testing.T) {
	ctx := context.Background()
	s := &hsmStrategy{}

	// No HSM backend → fail closed.
	_, err := s.BootstrapBackends(ctx, &StrategyDeps{})
	require.ErrorIs(t, err, ErrStrategyMisconfigured)
	_, err = s.RuntimeBackend(ctx, &StrategyDeps{})
	require.ErrorIs(t, err, ErrStrategyMisconfigured)

	// With an HSM backend, both resolve to it (no promotion, same store pre/post).
	hsm, err := newSoftwareBackend(storage.NewMemory(), storage.NewMemory())
	require.NoError(t, err)
	deps := &StrategyDeps{HSMBackend: hsm}

	resolve, err := s.BootstrapBackends(ctx, deps)
	require.NoError(t, err)
	got, err := resolve("pkcs11")
	require.NoError(t, err)
	require.Equal(t, hsm, got)

	runtime, err := s.RuntimeBackend(ctx, deps)
	require.NoError(t, err)
	require.Equal(t, hsm, runtime)
}

// TestBarrierStrategy_RuntimeRequiresReplicatedStorage verifies the runtime
// backend fails closed when the replicated store is absent.
func TestBarrierStrategy_RuntimeRequiresReplicatedStorage(t *testing.T) {
	s := &barrierStrategy{}
	_, err := s.RuntimeBackend(context.Background(), &StrategyDeps{
		NodeLocalDataDir: t.TempDir(),
		Protection:       KeyProtection{Mode: KeyProtectPassphrase, Passphrase: "x"},
	})
	require.ErrorIs(t, err, ErrStrategyMisconfigured)
}

// TestPromoteKeyStorage verifies every entry is copied from source to
// destination storage.
func TestPromoteKeyStorage(t *testing.T) {
	ctx := context.Background()
	src := storage.NewMemory()
	dst := storage.NewMemory()
	require.NoError(t, src.Put(ctx, "ca/root", []byte("root-blob")))
	require.NoError(t, src.Put(ctx, "ca/cluster", []byte("cluster-blob")))

	require.NoError(t, promoteKeyStorage(ctx, src, dst))

	got, err := dst.Get(ctx, "ca/root")
	require.NoError(t, err)
	require.Equal(t, []byte("root-blob"), got)
	got, err = dst.Get(ctx, "ca/cluster")
	require.NoError(t, err)
	require.Equal(t, []byte("cluster-blob"), got)
}

// TestBarrierStrategy_BootstrapThenPromote verifies the end-to-end promotion:
// a key blob written to the node-local bootstrap store is copied into the
// replicated store when RuntimeBackend runs (first node), and the runtime
// backend is built over the replicated store.
func TestBarrierStrategy_BootstrapThenPromote(t *testing.T) {
	ctx := context.Background()
	deps := &StrategyDeps{
		NodeLocalDataDir:      t.TempDir(),
		CAConfig:              ca.DefaultMultiIdentityCAConfigWithIntermediate(),
		Protection:            KeyProtection{Mode: KeyProtectPassphrase, Passphrase: "cluster-ca-secret"},
		ReplicatedKeyStorage:  storage.NewMemory(),
		ReplicatedCertStorage: storage.NewMemory(),
	}

	s := &barrierStrategy{}
	resolve, err := s.BootstrapBackends(ctx, deps)
	require.NoError(t, err)
	require.NotNil(t, resolve)
	caBackend, err := resolve("software")
	require.NoError(t, err)
	require.NotNil(t, caBackend)
	require.NotNil(t, s.bootstrapKeyStorage, "bootstrap key storage must be retained for promotion")

	// Simulate the CA having created a signing-key blob in the node-local store.
	require.NoError(t, s.bootstrapKeyStorage.Put(ctx, "ca/cluster-intermediate", []byte("wrapped-key")))

	runtime, err := s.RuntimeBackend(ctx, deps)
	require.NoError(t, err)
	require.NotNil(t, runtime)

	// Promotion must have copied the key blob into the replicated store so
	// every node can load it.
	got, err := deps.ReplicatedKeyStorage.Get(ctx, "ca/cluster-intermediate")
	require.NoError(t, err)
	require.Equal(t, []byte("wrapped-key"), got)
}

// TestBarrierStrategy_JoinerNoPromotion verifies that a node with no bootstrap
// key (a joiner) does not error and simply loads from the replicated store.
func TestBarrierStrategy_JoinerNoPromotion(t *testing.T) {
	ctx := context.Background()
	deps := &StrategyDeps{
		NodeLocalDataDir:      t.TempDir(),
		CAConfig:              ca.DefaultMultiIdentityCAConfigWithIntermediate(),
		Protection:            KeyProtection{Mode: KeyProtectPassphrase, Passphrase: "cluster-ca-secret"},
		ReplicatedKeyStorage:  storage.NewMemory(),
		ReplicatedCertStorage: storage.NewMemory(),
	}
	// A joiner never ran BootstrapBackend, so bootstrapKeyStorage is nil.
	s := &barrierStrategy{}
	runtime, err := s.RuntimeBackend(ctx, deps)
	require.NoError(t, err)
	require.NotNil(t, runtime)
	// Sanity: a genuinely unrelated error type is not masked.
	require.False(t, errors.Is(err, ErrStrategyMisconfigured))
}
