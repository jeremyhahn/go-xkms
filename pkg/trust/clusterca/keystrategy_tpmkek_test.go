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
	"bytes"
	"context"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

// fakeCredentialActivator models TPM credential activation in software: the
// "credential" is just the secret, so ActivateCredential returns it back. Enough
// to exercise the wrap→deliver→unwrap path without a real TPM.
type fakeCredentialActivator struct{ lastSecret []byte }

func (f *fakeCredentialActivator) MakeCredentialWithExternalEK(_ *x509.Certificate, _ []byte, secret []byte) ([]byte, []byte, []byte, error) {
	f.lastSecret = append([]byte(nil), secret...)
	// credentialBlob carries the (would-be TPM-encrypted) secret; encryptedSecret
	// carries a marker. The fake activator simply returns credentialBlob.
	return append([]byte(nil), secret...), []byte("enc"), nil, nil
}
func (f *fakeCredentialActivator) ActivateCredential(credentialBlob, _ []byte) ([]byte, error) {
	return append([]byte(nil), credentialBlob...), nil
}

func tpmKEKDeps(t *testing.T, bootstrapping bool) *StrategyDeps {
	t.Helper()
	return &StrategyDeps{
		NodeLocalDataDir:      t.TempDir(),
		CAConfig:              ca.DefaultMultiIdentityCAConfigWithIntermediate(),
		ReplicatedKeyStorage:  storage.NewMemory(),
		ReplicatedCertStorage: storage.NewMemory(),
		TPMSealer:             newFakeSealer(),
		Credentials:           &fakeCredentialActivator{},
		Bootstrapping:         bootstrapping,
	}
}

// TestTPMKEKStrategy_BootstrapGeneratesSeed verifies the bootstrap node
// generates a seed, seals it locally, and derives a deterministic KEK.
func TestTPMKEKStrategy_BootstrapGeneratesSeed(t *testing.T) {
	ctx := context.Background()
	deps := tpmKEKDeps(t, true)
	s := &tpmKEKStrategy{}

	resolve, err := s.BootstrapBackends(ctx, deps)
	require.NoError(t, err)
	require.NotNil(t, resolve)
	require.Len(t, s.seed, clusterSeedLen, "bootstrap must generate a cluster seed")

	// KEK is deterministic in the seed.
	p1, err := s.kekProtection(t.Context())
	require.NoError(t, err)
	p2, err := s.kekProtection(t.Context())
	require.NoError(t, err)
	require.Equal(t, secretBytes(t, p1.Passphrase), secretBytes(t, p2.Passphrase))
	require.NotEmpty(t, secretBytes(t, p1.Passphrase))
}

// TestTPMKEKStrategy_JoinerNeedsSeed verifies a joining node (not bootstrapping,
// no delivered seed) fails closed rather than inventing its own seed.
func TestTPMKEKStrategy_JoinerNeedsSeed(t *testing.T) {
	ctx := context.Background()
	deps := tpmKEKDeps(t, false)
	s := &tpmKEKStrategy{}
	s.deps = deps
	_, err := s.RuntimeBackend(ctx, deps)
	require.ErrorIs(t, err, ErrSeedUnavailable)
}

// TestTPMKEKStrategy_SeedDeliveryRoundTrip verifies the end-to-end decoupled
// flow: the bootstrap node's provider wraps the seed for a joiner, and the
// joiner's ConsumeEnrollmentSecret recovers the SAME seed (so both derive the
// same KEK). Uses the optional EnrollmentSecretStrategy seam.
func TestTPMKEKStrategy_SeedDeliveryRoundTrip(t *testing.T) {
	ctx := context.Background()

	// Bootstrap node generates the seed and exposes the provider.
	first := &tpmKEKStrategy{}
	firstDeps := tpmKEKDeps(t, true)
	_, err := first.BootstrapBackends(ctx, firstDeps)
	require.NoError(t, err)

	es, ok := EnrollmentSecretStrategyOf(first)
	require.True(t, ok)
	provider := es.SecretProvider()

	material, err := provider.ProvisionFor(ctx, &NodeSecretRequest{
		NodeURI:       "spiffe://xkms.cluster/node/10.0.0.2:63001",
		EKCertificate: &x509.Certificate{},
		IAKPublic:     []byte("iak-pub"),
	})
	require.NoError(t, err)
	require.NotNil(t, material)
	require.True(t, material.OID.Equal(clusterSeedOID))

	// Joiner consumes the material and recovers the identical seed.
	joiner := &tpmKEKStrategy{}
	joinerDeps := tpmKEKDeps(t, false)
	_, err = joiner.BootstrapBackends(ctx, joinerDeps) // retains deps
	require.NoError(t, err)

	joinerES, ok := EnrollmentSecretStrategyOf(joiner)
	require.True(t, ok)
	require.NoError(t, joinerES.ConsumeEnrollmentSecret(ctx, material))

	require.True(t, bytes.Equal(first.seed, joiner.seed), "joiner must recover the same cluster seed")

	// Both derive the same KEK → both can load the KEK-wrapped CA key.
	fp, err := first.kekProtection(t.Context())
	require.NoError(t, err)
	jp, err := joiner.kekProtection(t.Context())
	require.NoError(t, err)
	require.Equal(t, secretBytes(t, fp.Passphrase), secretBytes(t, jp.Passphrase))

	// And the joiner can now build a runtime backend.
	backend, err := joiner.RuntimeBackend(ctx, joinerDeps)
	require.NoError(t, err)
	require.NotNil(t, backend)
}

// TestTPMKEKStrategy_ForeignMaterialIgnored verifies material with a non-seed
// OID is ignored (no seed set, no error).
func TestTPMKEKStrategy_ForeignMaterialIgnored(t *testing.T) {
	ctx := context.Background()
	s := &tpmKEKStrategy{}
	s.deps = tpmKEKDeps(t, false)
	err := s.ConsumeEnrollmentSecret(ctx, &ProvisionedSecret{OID: []int{1, 2, 3}, Data: []byte("x")})
	require.NoError(t, err)
	require.Empty(t, s.seed)
}

// TestTPMKEKStrategy_SeedCacheRestart verifies that a second strategy instance
// on the same node (a restart) recovers the seed from the TPM-sealed node-local
// cache instead of regenerating it — so the KEK (and thus the CA key) survives
// restarts.
func TestTPMKEKStrategy_SeedCacheRestart(t *testing.T) {
	ctx := context.Background()
	deps := tpmKEKDeps(t, true)

	first := &tpmKEKStrategy{}
	_, err := first.BootstrapBackends(ctx, deps)
	require.NoError(t, err)
	require.Len(t, first.seed, clusterSeedLen)

	// A fresh instance with the SAME data dir + sealer must load the cached seed.
	restarted := &tpmKEKStrategy{}
	require.NoError(t, restarted.ensureSeed(ctx, deps))
	require.Equal(t, first.seed, restarted.seed, "restart must recover the sealed seed, not regenerate")
}

// TestTPMKEKStrategy_MissingTPM verifies tpm-kek fails closed without a TPM.
func TestTPMKEKStrategy_MissingTPM(t *testing.T) {
	ctx := context.Background()
	s := &tpmKEKStrategy{}
	_, err := s.BootstrapBackends(ctx, &StrategyDeps{NodeLocalDataDir: t.TempDir()})
	require.ErrorIs(t, err, ErrNoTPMCredentials)
}
