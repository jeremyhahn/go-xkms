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

//go:build tpm_simulator

package localtpm_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/localtpm"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/localtpmtest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
)

// simPCR is the PCR the test policy selects: an application PCR a
// locality-0 caller may extend.
const simPCR = 23

// openSimHost opens the policy service over a provisioned simulator.
func openSimHost(t *testing.T) *localtpm.Host {
	t.Helper()
	return localtpmtest.OpenSimulator(t, t.TempDir(), localtpmtest.MemoryStores)
}

// encryptionKey is an EC P-256 encryption key bound to policy.
func encryptionKey(cn, policy string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN: cn, KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeEncryption,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()}, TPMPolicy: policy,
	}
}

func TestHost_CreatesKeysUnderANamedPolicy(t *testing.T) {
	host := openSimHost(t)
	ctx := t.Context()

	_, err := host.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{
		Name:     "boot",
		Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{simPCR})},
	})
	require.NoError(t, err)

	attrs := encryptionKey("vault-key", "boot")
	_, err = host.Backend().GenerateKey(ctx, attrs)
	require.NoError(t, err)

	// The backend records the assignment, so the policy lists the key and
	// cannot be deleted under it.
	objects, err := host.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, []string{"key/vault-key"}, objects.Objects)
	assert.Error(t, host.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{Name: "boot"}))

	// The TPM authorizes the key through the policy: ECDH works while the
	// PCR holds its approved value and is refused once it drifts.
	token, err := vaultkey.NewBackendToken(ctx, host.Backend(), attrs)
	require.NoError(t, err)
	sealed, err := vaultkey.Seal(token.Public())
	require.NoError(t, err)
	fingerprint, err := vaultkey.Fingerprint(token.Public())
	require.NoError(t, err)
	factor := vaultkey.Factor{Fingerprint: fingerprint, Algorithm: sealed.Algorithm, Challenge: sealed.Challenge, Check: sealed.Check}
	opened, err := vaultkey.Open(ctx, token, factor)
	require.NoError(t, err)
	assert.Equal(t, sealed.Secret, opened)

	require.NoError(t, host.TPM().ExtendPCR(simPCR, "sha256", []byte("platform change")))
	_, err = vaultkey.Open(ctx, token, factor)
	assert.Error(t, err, "the TPM enforces the policy on use")
}

func TestHost_SealsAndUnsealsObjects(t *testing.T) {
	host := openSimHost(t)
	ctx := t.Context()
	require.NoError(t, host.SealObject(ctx, "secret", types.TPMPolicyPlatform, []byte("payload")))
	data, err := host.UnsealObject(ctx, "secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("payload"), data)
	require.NoError(t, host.DeleteObject(ctx, "secret"))
	require.NoError(t, host.DeleteObject(ctx, "secret"), "deleting a missing object is not an error")
	_, err = host.AutoUnsealPolicy(ctx)
	assert.Error(t, err, "no policy carries the auto-unseal mark")
}

func TestOpen_StoreOpenFailureIsABuildError(t *testing.T) {
	host := openSimHost(t)
	tpm, keys := host.TPM(), host.Keys()

	_, err := localtpm.Open(localtpm.Params{TPM: tpm})
	assert.ErrorIs(t, err, localtpm.ErrNoKeys)
	_, err = localtpm.Open(localtpm.Params{TPM: tpm, Keys: keys})
	assert.ErrorIs(t, err, localtpm.ErrNoDataDir)
	_, err = localtpm.Open(localtpm.Params{TPM: tpm, Keys: keys, DataDir: t.TempDir()})
	assert.ErrorIs(t, err, localtpm.ErrNoStoreOpener)

	unavailable := errors.New("store unavailable")
	_, err = localtpm.Open(localtpm.Params{
		TPM: tpm, Keys: keys, DataDir: t.TempDir(),
		OpenStore: func(string) (storage.Backend, error) { return nil, unavailable },
	})
	var buildErr *localtpm.BuildError
	assert.ErrorAs(t, err, &buildErr)
	assert.ErrorIs(t, err, unavailable)
}

func TestOpenDevice_OpensAnUnprovisionedSimulatorAsItIs(t *testing.T) {
	// Provisioning is an operator action; the device opens regardless.
	device, err := localtpm.OpenDevice(localtpm.DeviceParams{DataDir: t.TempDir(), UseSimulator: true})
	require.NoError(t, err)
	assert.NotNil(t, device.TPM())
	assert.NoError(t, device.Close())
}

// TestHost_ServesThePolicyAPI drives every TPM policy API operation through
// the local service, in the system scope, as `xkey tpm policy` does.
func TestHost_ServesThePolicyAPI(t *testing.T) {
	host := openSimHost(t)
	ctx := t.Context()
	boot := &transport.TPMPolicyRequest{Name: "boot"}

	_, err := host.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{
		Name:     "boot",
		Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{simPCR})},
	})
	require.NoError(t, err)
	assert.NotNil(t, host.Service())

	got, err := host.TPMPolicyGet(ctx, boot)
	require.NoError(t, err)
	assert.True(t, got.Approved)
	list, err := host.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Policies, 1)
	assert.Equal(t, "boot", list.Policies[0].Name)

	described, err := host.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: "boot", Description: "firmware"})
	require.NoError(t, err)
	assert.Equal(t, "firmware", described.Description)
	marked, err := host.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: "boot", Enabled: true})
	require.NoError(t, err)
	assert.True(t, marked.AutoUnseal)
	name, err := host.AutoUnsealPolicy(ctx)
	require.NoError(t, err)
	assert.Equal(t, "boot", name)

	_, err = host.Backend().GenerateKey(ctx, encryptionKey("k1", "boot"))
	require.NoError(t, err)
	objectPolicy, err := host.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{KeyID: "k1"})
	require.NoError(t, err)
	assert.Equal(t, "boot", objectPolicy.Policy)

	// Drift, verify, re-approve.
	require.NoError(t, host.TPM().ExtendPCR(simPCR, "sha256", []byte("platform change")))
	verified, err := host.TPMPolicyVerify(ctx, boot)
	require.NoError(t, err)
	assert.False(t, verified.Match)
	_, err = host.TPMPolicyUpdate(ctx, boot)
	require.NoError(t, err)
	verified, err = host.TPMPolicyVerify(ctx, boot)
	require.NoError(t, err)
	assert.True(t, verified.Match)

	revoked, err := host.TPMPolicyRevoke(ctx, boot)
	require.NoError(t, err)
	assert.False(t, revoked.Approved)
	_, err = host.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{})
	require.NoError(t, err)

	// The key holds the policy; once it is gone the policy can go.
	require.NoError(t, host.Unassign(ctx, "key", "k1"))
	require.NoError(t, host.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{Name: "boot"}))
	_, err = host.TPMPolicyGet(ctx, boot)
	assert.Error(t, err)
}

func TestOpenHost_FailsOverAnUnprovisionedSimulator(t *testing.T) {
	// A fresh simulator has no Platform SRK, so the policy service cannot be
	// built over it, and the device is closed again.
	_, err := localtpm.OpenHost(localtpm.DeviceParams{DataDir: t.TempDir(), UseSimulator: true}, localtpmtest.MemoryStores)
	assert.Error(t, err)
	device, err := localtpm.OpenDevice(localtpm.DeviceParams{DataDir: t.TempDir(), UseSimulator: true})
	require.NoError(t, err, "the simulator was released")
	assert.NoError(t, device.Close())
}
