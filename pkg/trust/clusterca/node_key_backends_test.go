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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestNewNodeKeyBackends_RequiresDataDir verifies the resolver is refused
// without a directory for the software node key.
func TestNewNodeKeyBackends_RequiresDataDir(t *testing.T) {
	for name, params := range map[string]*NodeKeyBackendsParams{
		"nil params":    nil,
		"empty DataDir": {},
	} {
		t.Run(name, func(t *testing.T) {
			resolve, err := NewNodeKeyBackends(params)
			var missing *ErrMissingOption
			require.ErrorAs(t, err, &missing)
			assert.Equal(t, "DataDir", missing.Field)
			assert.Nil(t, resolve)
		})
	}
}

// TestNewNodeKeyBackends_RefusesUnconfiguredHardware verifies a hardware
// backend the node does not have is refused by name, never answered with
// the software backend.
func TestNewNodeKeyBackends_RefusesUnconfiguredHardware(t *testing.T) {
	resolve, err := NewNodeKeyBackends(&NodeKeyBackendsParams{DataDir: nodeLocalDataDir(t)})
	require.NoError(t, err)

	backend, err := resolve("pkcs11")
	var notConfigured *ErrNodeKeyBackendNotConfigured
	require.ErrorAs(t, err, &notConfigured)
	assert.Equal(t, "pkcs11", notConfigured.KeyBackend)
	assert.Nil(t, backend)

	backend, err = resolve("tpm2")
	var noTPM *ErrNoTPM
	require.ErrorAs(t, err, &noTPM)
	assert.Equal(t, "tpm2", noTPM.KeyBackend)
	assert.Nil(t, backend)
}

// TestNewNodeKeyBackends_ResolvesConfiguredBackends verifies a configured
// hardware backend resolves to itself and software to the node-local store.
func TestNewNodeKeyBackends_ResolvesConfiguredBackends(t *testing.T) {
	hsm, err := softwareBackends(t)("pkcs11")
	require.NoError(t, err)
	resolve, err := NewNodeKeyBackends(&NodeKeyBackendsParams{
		DataDir:  nodeLocalDataDir(t),
		Hardware: map[string]types.KeyProvider{"pkcs11": hsm.KeyProvider()},
	})
	require.NoError(t, err)

	got, err := resolve("pkcs11")
	require.NoError(t, err)
	assert.Same(t, hsm.KeyProvider(), got.KeyProvider())

	software, err := resolve("software")
	require.NoError(t, err)
	assert.NotSame(t, hsm.KeyProvider(), software.KeyProvider(), "software resolves to the node-local store, not a hardware backend")
}

// TestProvision_LocalCAUnconfiguredHardwareNodeKeyIsRefused verifies a node
// configured for a PKCS#11 transport key that it does not have refuses to
// provision instead of minting a software key under PKCS#11 provenance, even
// when CA custody would resolve the name.
func TestProvision_LocalCAUnconfiguredHardwareNodeKeyIsRefused(t *testing.T) {
	nodeKeys, err := NewNodeKeyBackends(&NodeKeyBackendsParams{DataDir: nodeLocalDataDir(t)})
	require.NoError(t, err)

	p, err := New(&Options{
		RaftAddress:     "127.0.0.1:8314",
		NodeID:          1,
		TrustDomain:     "test.cluster",
		DataDir:         t.TempDir(),
		Members:         map[uint64]string{1: "127.0.0.1:8314"},
		KeyBackend:      "pkcs11",
		Backends:        softwareBackends(t),
		NodeKeyBackends: nodeKeys,
		CAConfig:        clusterCAConfig(),
	}, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	var unavailable *ErrKeyBackendUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, "pkcs11", unavailable.KeyBackend)
	var notConfigured *ErrNodeKeyBackendNotConfigured
	require.ErrorAs(t, err, &notConfigured)
	assert.Nil(t, res)
	assertNoSoftwareNodeKey(t, p, nodeKeys)
}

// TestProvision_LocalCANodeKeyLivesInConfiguredBackend verifies the
// transport key is generated in the backend KeyBackend names, and that the
// node-local software store holds no key for it.
func TestProvision_LocalCANodeKeyLivesInConfiguredBackend(t *testing.T) {
	hsm, err := softwareBackends(t)("pkcs11")
	require.NoError(t, err)
	nodeKeys, err := NewNodeKeyBackends(&NodeKeyBackendsParams{
		DataDir:  nodeLocalDataDir(t),
		Hardware: map[string]types.KeyProvider{"pkcs11": hsm.KeyProvider()},
	})
	require.NoError(t, err)

	p, err := New(&Options{
		RaftAddress:     "127.0.0.1:8315",
		NodeID:          1,
		TrustDomain:     "test.cluster",
		DataDir:         t.TempDir(),
		Members:         map[uint64]string{1: "127.0.0.1:8315"},
		KeyBackend:      "pkcs11",
		Backends:        softwareBackends(t),
		NodeKeyBackends: nodeKeys,
		CAConfig:        clusterCAConfig(),
	}, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.NoError(t, err)
	assertNodeKeyIn(t, p, hsm, res.MTLS.Certificate.Leaf.PublicKey)
	assertNoSoftwareNodeKey(t, p, nodeKeys)
}

// assertNodeKeyIn checks backend holds the node's transport key and that its
// public half is the certificate's.
func assertNodeKeyIn(t *testing.T, p *Provisioner, backend xkms.Backend, certPublic any) {
	t.Helper()

	kp := backend.KeyProvider()
	signer, err := kp.Signer(context.Background(), p.nodeKeyAttributes(kp))
	require.NoError(t, err, "the transport key must live in the configured backend")
	assert.True(t, publicKeysEqual(signer.Public(), certPublic),
		"the certificate must carry the configured backend's key")
}

// assertNoSoftwareNodeKey checks the node-local software store holds no
// transport key for p.
func assertNoSoftwareNodeKey(t *testing.T, p *Provisioner, nodeKeys func(string) (xkms.Backend, error)) {
	t.Helper()

	software, err := nodeKeys("software")
	require.NoError(t, err)
	kp := software.KeyProvider()
	_, err = kp.Signer(context.Background(), p.nodeKeyAttributes(kp))
	assert.Error(t, err, "no transport key may exist in the software store")
}
