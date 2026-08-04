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

//go:build tpm_simulator

package clusterca

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestTPMKEKStrategy_RealTPMCredentialActivation exercises the tpm-kek seed
// delivery against a REAL TPM (the in-memory simulator): the bootstrap node
// generates the seed and its provider wraps it with TPM2_MakeCredential to the
// node's EK, and a joining node recovers the identical seed with
// TPM2_ActivateCredential — proving the strategy drives the genuine
// credential-activation primitive end to end. Runs in the devcontainer via
// `make integration-test` (the `tpm_simulator` build tag); never touches host
// TPM hardware.
func TestTPMKEKStrategy_RealTPMCredentialActivation(t *testing.T) {
	ctx := context.Background()

	backend, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator: true,
		KeyDir:       t.TempDir(),
		CN:           "clusterca-tpmkek-sim",
	})
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()
	tpm := backend.TPM()

	ekCert, err := tpm.EKCertificate()
	if err != nil {
		t.Skip("EK certificate not available in simulator")
	}
	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)
	iakPub := tpm2.Marshal(iakAttrs.TPMAttributes.Public)

	newDeps := func(bootstrapping bool) *StrategyDeps {
		return &StrategyDeps{
			NodeLocalDataDir:      t.TempDir(),
			CAConfig:              ca.DefaultMultiIdentityCAConfigWithIntermediate(),
			ReplicatedKeyStorage:  storage.NewMemory(),
			ReplicatedCertStorage: storage.NewMemory(),
			TPMSealer:             backend,
			Credentials:           tpm,
			Bootstrapping:         bootstrapping,
		}
	}

	// Bootstrap node: generate the seed; provider wraps it to the EK via a real
	// TPM2_MakeCredential.
	first := &tpmKEKStrategy{}
	_, err = first.BootstrapBackends(ctx, newDeps(true))
	require.NoError(t, err)
	require.Len(t, first.seed, clusterSeedLen)

	es, ok := EnrollmentSecretStrategyOf(first)
	require.True(t, ok)
	material, err := es.SecretProvider().ProvisionFor(ctx, &NodeSecretRequest{
		NodeURI:       "spiffe://xkms.cluster/node/10.0.0.2:63001",
		EKCertificate: ekCert,
		IAKPublic:     iakPub,
	})
	require.NoError(t, err)
	require.NotNil(t, material)

	// Joining node: recover the seed via a real TPM2_ActivateCredential.
	joiner := &tpmKEKStrategy{}
	_, err = joiner.BootstrapBackends(ctx, newDeps(false))
	require.NoError(t, err)
	joinerES, ok := EnrollmentSecretStrategyOf(joiner)
	require.True(t, ok)
	require.NoError(t, joinerES.ConsumeEnrollmentSecret(ctx, material))

	require.True(t, bytes.Equal(first.seed, joiner.seed),
		"real TPM credential activation must recover the identical cluster seed")
}
