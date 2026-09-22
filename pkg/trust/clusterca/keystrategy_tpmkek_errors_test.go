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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// errSealer is a types.Sealer whose operations fail, used to prove seal/unseal
// failures propagate instead of being mistaken for "no seed yet".
type errSealer struct {
	canSeal   bool
	sealErr   error
	unsealErr error
}

func (e *errSealer) CanSeal() bool { return e.canSeal }

func (e *errSealer) Seal(context.Context, []byte, *types.SealOptions) (*types.SealedData, error) {
	return nil, e.sealErr
}

func (e *errSealer) Unseal(context.Context, *types.SealedData, *types.UnsealOptions) ([]byte, error) {
	return nil, e.unsealErr
}

// errActivator fails credential activation, modelling a node whose TPM is not
// the one the secret was wrapped to.
type errActivator struct{ err error }

func (e *errActivator) MakeCredentialWithExternalEK(*x509.Certificate, []byte, []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, e.err
}

func (e *errActivator) ActivateCredential([]byte, []byte) ([]byte, error) {
	return nil, e.err
}

// TestTPMKEKStrategy_KEKProtectionRequiresSeed verifies the KEK cannot be
// derived without a seed. Returning a zero-valued KeyProtection here would
// silently encrypt the CA signing keys under an empty passphrase.
func TestTPMKEKStrategy_KEKProtectionRequiresSeed(t *testing.T) {
	s := &tpmKEKStrategy{}

	protection, err := s.kekProtection()
	require.ErrorIs(t, err, ErrSeedUnavailable)
	assert.Empty(t, protection.Passphrase)
	assert.Empty(t, protection.Mode)
}

// TestTPMKEKStrategy_KEKIsSeedDerivedAndDistinct verifies the derived KEK is a
// deterministic function of the seed and that different seeds yield different
// KEKs. A KEK that did not vary with the seed would make every cluster's CA
// keystore decryptable with the same passphrase.
func TestTPMKEKStrategy_KEKIsSeedDerivedAndDistinct(t *testing.T) {
	a := &tpmKEKStrategy{seed: make([]byte, clusterSeedLen)}
	b := &tpmKEKStrategy{seed: make([]byte, clusterSeedLen)}
	b.seed[0] = 1

	pa, err := a.kekProtection()
	require.NoError(t, err)
	pb, err := b.kekProtection()
	require.NoError(t, err)

	assert.Equal(t, KeyProtectPassphrase, pa.Mode)
	assert.NotEqual(t, secretBytes(t, pa.Passphrase), secretBytes(t, pb.Passphrase),
		"a one-bit seed change must change the KEK")
	assert.Len(t, secretBytes(t, pa.Passphrase), 64, "the KEK is a hex-encoded 32-byte value")
}

// TestTPMKEKStrategy_EnsureSeedRequiresTPM verifies seed handling refuses to
// proceed without a TPM sealer. The seed is the cluster CA's root secret; it
// must never be held unsealed because hardware happens to be absent.
func TestTPMKEKStrategy_EnsureSeedRequiresTPM(t *testing.T) {
	deps := tpmKEKDeps(t, true)
	deps.TPMSealer = nil

	s := &tpmKEKStrategy{}
	err := s.ensureSeed(context.Background(), deps)
	require.ErrorIs(t, err, ErrNoTPMCredentials)
	assert.Empty(t, s.seed)
}

// TestTPMKEKStrategy_EnsureSeedPropagatesSealFailure verifies a bootstrap node
// that cannot seal its freshly generated seed fails rather than continuing with
// an unpersisted seed that would be lost on restart.
func TestTPMKEKStrategy_EnsureSeedPropagatesSealFailure(t *testing.T) {
	sealFailure := errors.New("tpm seal refused")
	deps := tpmKEKDeps(t, true)
	deps.TPMSealer = &errSealer{canSeal: true, sealErr: sealFailure, unsealErr: sealFailure}

	s := &tpmKEKStrategy{}
	err := s.ensureSeed(context.Background(), deps)
	require.ErrorIs(t, err, sealFailure)
	assert.Empty(t, s.seed, "no seed may be retained when it could not be sealed")
}

// TestTPMKEKStrategy_SealedSeedSurvivesRestart verifies a restarted node
// recovers its seed from the node-local sealed blob rather than generating a
// new one, which would orphan every key already wrapped under the old KEK.
func TestTPMKEKStrategy_SealedSeedSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	deps := tpmKEKDeps(t, true)

	first := &tpmKEKStrategy{}
	require.NoError(t, first.ensureSeed(ctx, deps))
	require.Len(t, first.seed, clusterSeedLen)

	// The sealed blob is on disk and owner-only.
	info, err := os.Stat(first.sealedSeedPath(deps))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// A restarted node (not bootstrapping) recovers the same seed.
	restarted := &tpmKEKStrategy{}
	restartDeps := tpmKEKDeps(t, false)
	restartDeps.NodeLocalDataDir = deps.NodeLocalDataDir
	restartDeps.TPMSealer = deps.TPMSealer

	require.NoError(t, restarted.ensureSeed(ctx, restartDeps))
	assert.Equal(t, first.seed, restarted.seed)
}

// TestTPMKEKStrategy_LoadSealedSeedRejectsCorruptBlob verifies a damaged or
// tampered sealed-seed file is reported as an error. A joiner must not silently
// treat a corrupt blob as "no seed" and generate its own, forking the cluster.
func TestTPMKEKStrategy_LoadSealedSeedRejectsCorruptBlob(t *testing.T) {
	ctx := context.Background()
	deps := tpmKEKDeps(t, false)
	s := &tpmKEKStrategy{}

	require.NoError(t, os.MkdirAll(deps.NodeLocalDataDir, 0o700))
	require.NoError(t, os.WriteFile(s.sealedSeedPath(deps), []byte("{not json"), 0o600))

	seed, err := s.loadSealedSeed(ctx, deps)
	require.Error(t, err)
	assert.Nil(t, seed)

	// A non-bootstrapping node with an unreadable blob must fail closed.
	require.ErrorIs(t, s.ensureSeed(ctx, deps), ErrSeedUnavailable)
}

// TestTPMKEKStrategy_LoadSealedSeedPropagatesUnsealFailure verifies that a blob
// this node's TPM cannot unseal (e.g. moved from another machine, or PCR state
// changed) surfaces as a failure instead of a fresh seed.
func TestTPMKEKStrategy_LoadSealedSeedPropagatesUnsealFailure(t *testing.T) {
	ctx := context.Background()

	// Seal with a working sealer...
	sealed := tpmKEKDeps(t, true)
	s := &tpmKEKStrategy{}
	require.NoError(t, s.ensureSeed(ctx, sealed))

	// ...then attempt to load with a sealer that cannot unseal it.
	unsealFailure := errors.New("tpm unseal refused: pcr mismatch")
	broken := tpmKEKDeps(t, false)
	broken.NodeLocalDataDir = sealed.NodeLocalDataDir
	broken.TPMSealer = &errSealer{canSeal: true, unsealErr: unsealFailure}

	other := &tpmKEKStrategy{}
	seed, err := other.loadSealedSeed(ctx, broken)
	require.ErrorIs(t, err, unsealFailure)
	assert.Nil(t, seed)
}

// TestTPMKEKStrategy_StoreSealedSeedFailsOnUnusableDataDir verifies a write
// failure is surfaced. Believing the seed was persisted when it was not would
// lose the cluster CA on the next restart.
func TestTPMKEKStrategy_StoreSealedSeedFailsOnUnusableDataDir(t *testing.T) {
	deps := tpmKEKDeps(t, true)

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	deps.NodeLocalDataDir = blocker

	s := &tpmKEKStrategy{}
	require.Error(t, s.storeSealedSeed(context.Background(), deps, make([]byte, clusterSeedLen)))
}

// TestTPMKEKStrategy_BootstrapRequiresTPMCredentials verifies both TPM seams
// (sealer and credential activator) are mandatory. The strategy's entire
// security argument rests on them, so a missing one must fail closed rather
// than degrade to a software-protected keystore.
func TestTPMKEKStrategy_BootstrapRequiresTPMCredentials(t *testing.T) {
	ctx := context.Background()

	t.Run("no sealer", func(t *testing.T) {
		deps := tpmKEKDeps(t, true)
		deps.TPMSealer = nil
		_, err := (&tpmKEKStrategy{}).BootstrapBackends(ctx, deps)
		require.ErrorIs(t, err, ErrNoTPMCredentials)
	})

	t.Run("no credential activator", func(t *testing.T) {
		deps := tpmKEKDeps(t, true)
		deps.Credentials = nil
		_, err := (&tpmKEKStrategy{}).BootstrapBackends(ctx, deps)
		require.ErrorIs(t, err, ErrNoTPMCredentials)
	})
}

// TestTPMKEKStrategy_JoinerBootstrapsWithoutSeed verifies a joining node can
// still build a node-local keystore for its transport key before it has the
// cluster seed. Failing here would make it impossible to enroll at all.
func TestTPMKEKStrategy_JoinerBootstrapsWithoutSeed(t *testing.T) {
	deps := tpmKEKDeps(t, false)
	deps.CAConfig = nil // a joiner pre-stages no CA

	s := &tpmKEKStrategy{}
	resolve, err := s.BootstrapBackends(context.Background(), deps)
	require.NoError(t, err)
	require.NotNil(t, resolve)
	assert.Empty(t, s.seed, "a joiner must not invent a cluster seed")
}

// TestTPMKEKStrategy_RuntimeRequiresReplicatedStorage verifies the runtime
// keystore refuses to run without the replicated store it is supposed to be
// built over.
func TestTPMKEKStrategy_RuntimeRequiresReplicatedStorage(t *testing.T) {
	ctx := context.Background()

	t.Run("no key storage", func(t *testing.T) {
		deps := tpmKEKDeps(t, true)
		deps.ReplicatedKeyStorage = nil
		_, err := (&tpmKEKStrategy{}).RuntimeBackend(ctx, deps)
		require.ErrorIs(t, err, ErrStrategyMisconfigured)
	})

	t.Run("no cert storage", func(t *testing.T) {
		deps := tpmKEKDeps(t, true)
		deps.ReplicatedCertStorage = nil
		_, err := (&tpmKEKStrategy{}).RuntimeBackend(ctx, deps)
		require.ErrorIs(t, err, ErrStrategyMisconfigured)
	})
}

// TestTPMKEKStrategy_RuntimePromotesBootstrapKey verifies the bootstrap node's
// KEK-wrapped key blobs are copied into the replicated store so every node can
// load the cluster CA.
func TestTPMKEKStrategy_RuntimePromotesBootstrapKey(t *testing.T) {
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

	backend, err := s.RuntimeBackend(ctx, deps)
	require.NoError(t, err)
	require.NotNil(t, backend)

	got, err := deps.ReplicatedKeyStorage.Get(ctx, "ca/cluster")
	require.NoError(t, err)
	assert.Equal(t, []byte("kek-wrapped"), got)
}

// TestTPMKEKStrategy_ConsumeEnrollmentSecretIgnoresForeignMaterial verifies
// material that is nil or carries another provider's OID is skipped without
// error, so unrelated secrets in a delivery batch do not abort enrollment.
func TestTPMKEKStrategy_ConsumeEnrollmentSecretIgnoresForeignMaterial(t *testing.T) {
	ctx := context.Background()
	s := &tpmKEKStrategy{}

	require.NoError(t, s.ConsumeEnrollmentSecret(ctx, nil))
	require.NoError(t, s.ConsumeEnrollmentSecret(ctx, &ProvisionedSecret{
		OID:  []int{1, 2, 3, 4},
		Data: []byte("someone else's secret"),
	}))
	assert.Empty(t, s.seed, "foreign material must never populate the cluster seed")
}

// TestTPMKEKStrategy_ConsumeEnrollmentSecretRejectsBadInput covers the failure
// modes of seed recovery. Each must fail closed: accepting a malformed or
// wrong-length seed would silently derive a KEK that cannot decrypt the CA key.
func TestTPMKEKStrategy_ConsumeEnrollmentSecretRejectsBadInput(t *testing.T) {
	ctx := context.Background()

	t.Run("no TPM deps retained", func(t *testing.T) {
		s := &tpmKEKStrategy{}
		err := s.ConsumeEnrollmentSecret(ctx, &ProvisionedSecret{OID: clusterSeedOID, Data: []byte("{}")})
		require.ErrorIs(t, err, ErrNoTPMCredentials)
	})

	t.Run("malformed credential JSON", func(t *testing.T) {
		s := &tpmKEKStrategy{deps: tpmKEKDeps(t, false)}
		err := s.ConsumeEnrollmentSecret(ctx, &ProvisionedSecret{
			OID: clusterSeedOID, Data: []byte("not json"),
		})
		require.Error(t, err)
		assert.Empty(t, s.seed)
	})

	t.Run("credential activation fails", func(t *testing.T) {
		activationFailure := errors.New("not this node's TPM")
		deps := tpmKEKDeps(t, false)
		deps.Credentials = &errActivator{err: activationFailure}
		s := &tpmKEKStrategy{deps: deps}

		blob, err := json.Marshal(&wrappedCredential{
			CredentialBlob: make([]byte, clusterSeedLen), EncryptedSecret: []byte("enc"),
		})
		require.NoError(t, err)

		err = s.ConsumeEnrollmentSecret(ctx, &ProvisionedSecret{OID: clusterSeedOID, Data: blob})
		require.ErrorIs(t, err, activationFailure)
		assert.Empty(t, s.seed)
	})

	t.Run("activated seed has wrong length", func(t *testing.T) {
		s := &tpmKEKStrategy{deps: tpmKEKDeps(t, false)}

		// The fake activator echoes credentialBlob back as the seed.
		blob, err := json.Marshal(&wrappedCredential{
			CredentialBlob: []byte("too-short"), EncryptedSecret: []byte("enc"),
		})
		require.NoError(t, err)

		err = s.ConsumeEnrollmentSecret(ctx, &ProvisionedSecret{OID: clusterSeedOID, Data: blob})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected length")
		assert.Empty(t, s.seed)
	})
}

// TestTPMKEKSecretProvider_RejectsIncompleteRequests verifies the seed is only
// ever wrapped when there is a concrete TPM identity to wrap it to. Wrapping to
// a missing or partial identity would either fail obscurely or, worse, produce
// material recoverable by the wrong node.
func TestTPMKEKSecretProvider_RejectsIncompleteRequests(t *testing.T) {
	ctx := context.Background()

	t.Run("no credential activator", func(t *testing.T) {
		p := &tpmKEKSecretProvider{strategy: &tpmKEKStrategy{}}
		_, err := p.ProvisionFor(ctx, &NodeSecretRequest{})
		require.ErrorIs(t, err, ErrNoTPMCredentials)
	})

	t.Run("no seed to wrap", func(t *testing.T) {
		p := &tpmKEKSecretProvider{strategy: &tpmKEKStrategy{deps: tpmKEKDeps(t, false)}}
		_, err := p.ProvisionFor(ctx, &NodeSecretRequest{})
		require.ErrorIs(t, err, ErrSeedUnavailable)
	})

	seeded := func(t *testing.T) *tpmKEKSecretProvider {
		t.Helper()
		s := &tpmKEKStrategy{deps: tpmKEKDeps(t, true), seed: make([]byte, clusterSeedLen)}
		return &tpmKEKSecretProvider{strategy: s}
	}

	t.Run("nil request", func(t *testing.T) {
		_, err := seeded(t).ProvisionFor(ctx, nil)
		require.Error(t, err)
	})

	t.Run("missing EK certificate", func(t *testing.T) {
		_, err := seeded(t).ProvisionFor(ctx, &NodeSecretRequest{IAKPublic: []byte("iak")})
		require.Error(t, err)
	})

	t.Run("missing IAK public area", func(t *testing.T) {
		_, err := seeded(t).ProvisionFor(ctx, &NodeSecretRequest{EKCertificate: &x509.Certificate{}})
		require.Error(t, err)
	})

	t.Run("credential wrapping fails", func(t *testing.T) {
		wrapFailure := errors.New("make credential failed")
		deps := tpmKEKDeps(t, true)
		deps.Credentials = &errActivator{err: wrapFailure}
		p := &tpmKEKSecretProvider{
			strategy: &tpmKEKStrategy{deps: deps, seed: make([]byte, clusterSeedLen)},
		}
		_, err := p.ProvisionFor(ctx, &NodeSecretRequest{
			EKCertificate: &x509.Certificate{}, IAKPublic: []byte("iak"),
		})
		require.ErrorIs(t, err, wrapFailure)
	})
}

// TestStrategyDeps_LoggerDefaults verifies deps without an explicit logger
// still return a usable one, so strategy code can log unconditionally without
// a nil check at every call site.
func TestStrategyDeps_LoggerDefaults(t *testing.T) {
	deps := &StrategyDeps{}
	require.NotNil(t, deps.logger())

	custom := testLogger()
	withLogger := &StrategyDeps{Logger: custom}
	assert.Same(t, custom, withLogger.logger())
}

// TestPromoteKeyStorage_PropagatesDestinationFailure verifies promotion stops
// and reports when the replicated store rejects a write, rather than silently
// leaving the cluster CA key node-local.
func TestPromoteKeyStorage_PropagatesDestinationFailure(t *testing.T) {
	ctx := context.Background()
	src := storage.NewMemory()
	require.NoError(t, src.Put(ctx, "ca/cluster", []byte("blob")))

	dst := storage.NewMemory()
	require.NoError(t, dst.Close())

	err := promoteKeyStorage(ctx, src, dst)
	require.Error(t, err, "a closed destination store must not be reported as a successful promotion")
}
