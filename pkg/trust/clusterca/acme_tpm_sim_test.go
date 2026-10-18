//go:build tpm_simulator

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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tpmBackedBackend is an xkms.Backend that also exposes the underlying TPM,
// mirroring how a composition root wires the "tpm2" key backend. The
// provisioner type-asserts for exactly this shape to reach enroll-01 material.
type tpmBackedBackend struct {
	xkms.Backend
	tpm  pkgtpm2.TrustedPlatformModule
	keys store.KeyBackend
}

func (b *tpmBackedBackend) TPM() pkgtpm2.TrustedPlatformModule { return b.tpm }

func (b *tpmBackedBackend) KeyBackend() store.KeyBackend { return b.keys }

// newSimulatorTPMBackend builds a tpm2 backend over the in-process TPM
// simulator. It never touches host TPM hardware (/dev/tpm*).
func newSimulatorTPMBackend(t *testing.T) *tpm2backend.Backend {
	t.Helper()

	backend, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator: true,
		Keys:         tpmblobtest.New(t),
		CN:           "clusterca-acme-sim",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	return backend
}

// TestAcmeNodeSigner_TPMWithoutProvisionedIDevIDFailsClosed verifies that a
// genuine TPM which has no IDevID provisioned is refused rather than silently
// falling back to a software key.
//
// This is the substitution the attested mode exists to prevent: the node's
// identity must be the TPM-resident IDevID, so "TPM present but no IDevID" has
// to be an error, not a downgrade. Exercised against the real TPM simulator, so
// the failure comes from the TPM stack itself rather than a hand-written stub.
func TestIdevidSigner_TPMWithoutProvisionedIDevIDFailsClosed(t *testing.T) {
	tpmBackend := newSimulatorTPMBackend(t)

	wrapped, err := xkms.New(&xkms.BackendConfig{
		Backend:     tpmBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	backend := &tpmBackedBackend{Backend: wrapped, tpm: tpmBackend.TPM(), keys: tpmBackend.KeyBackend()}

	signer, err := idevidSigner(backend, "tpm2")
	require.Error(t, err, "a TPM with no provisioned IDevID must not yield a node signer")
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "idevid",
		"the error must name the missing IDevID so an operator knows what to provision")
}

// TestProvision_LocalCATPMReloadRestoresNodeKey verifies a restarted local-CA
// node with a TPM transport key reloads the named key it was provisioned
// with, not the IDevID, and that the key TLS signs with is the certificate's.
func TestProvision_LocalCATPMReloadRestoresNodeKey(t *testing.T) {
	tpmBackend := newSimulatorTPMBackend(t)
	dataDir := t.TempDir()
	caBackends := softwareBackends(t)
	nodeKeys, err := NewNodeKeyBackends(&NodeKeyBackendsParams{
		DataDir:     nodeLocalDataDir(t),
		HardwareTPM: tpmBackend,
	})
	require.NoError(t, err)

	provision := func() *Result {
		p, err := New(&Options{
			RaftAddress:     "127.0.0.1:8316",
			NodeID:          1,
			TrustDomain:     "test.cluster",
			DataDir:         dataDir,
			Members:         map[uint64]string{1: "127.0.0.1:8316"},
			KeyBackend:      "tpm2",
			Backends:        caBackends,
			NodeKeyBackends: nodeKeys,
			CAConfig:        clusterCAConfig(),
		}, testLogger())
		require.NoError(t, err)
		res, err := p.Provision(context.Background())
		require.NoError(t, err)
		return res
	}

	first := provision()
	second := provision()

	leaf := second.MTLS.Certificate.Leaf
	assert.Equal(t, first.MTLS.Certificate.Leaf.Raw, leaf.Raw, "the restart must reload the cached certificate")

	signer, ok := second.MTLS.Certificate.PrivateKey.(crypto.Signer)
	require.True(t, ok, "the TLS private key must be a crypto.Signer")
	digest := sha256.Sum256([]byte("raft transport handshake"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "the node key is ECDSA P-256")
	assert.True(t, ecdsa.VerifyASN1(public, digest[:], sig),
		"TLS must sign with the key the certificate names")
}

// TestNodeLocalBackends_ReusesSharedTPMForHardwareKeys verifies the "tpm2" key
// backend resolves to the already-open TPM handle rather than a software
// keystore. Reusing the single open device is what keeps the TPM from being
// opened twice (a second open hangs against swtpm), and it is what makes the
// node transport key genuinely hardware-resident.
func TestNodeLocalBackends_ReusesSharedTPMForHardwareKeys(t *testing.T) {
	tpmBackend := newSimulatorTPMBackend(t)

	resolve, err := NewNodeLocalBackends(context.Background(), &NodeLocalBackendsParams{
		DataDir:     nodeLocalDataDir(t),
		Protection:  KeyProtection{Mode: KeyProtectPassphrase, Passphrase: mustSecret(t, "cluster-ca-secret")},
		HardwareTPM: tpmBackend,
		Logger:      testLogger(),
	})
	require.NoError(t, err)

	hardware, err := resolve("tpm2")
	require.NoError(t, err)
	require.NotNil(t, hardware)

	software, err := resolve("software")
	require.NoError(t, err)

	assert.NotSame(t, software, hardware,
		"the tpm2 backend must be the shared TPM, not the software keystore")
	assert.Equal(t, types.BackendTypeTPM2, hardware.KeyProvider().Type(),
		"the resolved tpm2 backend must be backed by the TPM key provider")

	// A joining node type-asserts the resolved backend for the TPM to run
	// enroll-01; without it the join fails with ErrNoTPM.
	provider, ok := hardware.(tpmProvider)
	require.True(t, ok, "the tpm2 backend must expose the TPM for enroll-01")
	assert.Same(t, tpmBackend.TPM(), provider.TPM())
	assert.Same(t, tpmBackend.KeyBackend(), provider.KeyBackend())

	_, ok = software.(tpmProvider)
	assert.False(t, ok, "the software backend has no TPM to expose")
}
