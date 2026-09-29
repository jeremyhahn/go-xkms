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

// These tests run the local TPM policy service -- the in-process service
// xKey runs over its own TPM -- against the in-process TPM 2.0 simulator, so
// every policy is enforced by real TPM policy sessions. The simulator and all
// stores are in memory; nothing touches the host.
package services

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// simPCR is the PCR the test policies select: an application PCR a
// locality-0 caller may extend, and not the platform PCR (16).
const simPCR = 23

// simQuietLogger discards the TPM's logging.
var simQuietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// simTPM is a provisioned simulator TPM with its in-memory key store.
type simTPM struct {
	tpm  xkms.TrustedPlatformModule
	keys xkms.TPMKeyBackend
}

// openSimTPM opens and provisions the in-process simulator. It is closed
// when the test ends; the simulator allows one open instance per process.
func openSimTPM(t *testing.T) *simTPM {
	t.Helper()
	factory, err := xkms.NewTPMStorageFactory(simQuietLogger, "")
	require.NoError(t, err)
	cfg := xkms.DefaultTPMConfig
	cfg.UseSimulator = true
	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Logger:    simQuietLogger,
		Config:    &cfg,
		BlobStore: factory.BlobStore(),
		Backend:   factory.KeyBackend(),
	})
	if err != nil {
		require.ErrorIs(t, err, xkms.ErrTPMNotInitialized, "a fresh simulator only needs provisioning")
	}
	require.NotNil(t, tpm)
	t.Cleanup(func() {
		assert.NoError(t, tpm.Close())
		assert.NoError(t, factory.Close())
	})
	require.NoError(t, tpm.Provision(nil))
	require.NoError(t, xkms.EnrollSimulatorPlatformSRK(tpm, &cfg))
	return &simTPM{tpm: tpm, keys: factory.KeyBackend()}
}

// openSimLocal opens the local TPM policy service over the simulator, with
// its registry in memory, and a TPMPolicyService in local mode over it.
func openSimLocal(t *testing.T) (*simTPM, *LocalTPMPolicies, *TPMPolicyService) {
	t.Helper()
	sim := openSimTPM(t)
	local, err := OpenLocalTPMPolicies(LocalTPMPolicyParams{
		TPM:       sim.tpm,
		Keys:      sim.keys,
		DataDir:   t.TempDir(),
		OpenStore: func(string) (xkms.StorageBackend, error) { return xkms.NewStorageMemory(), nil },
		Logger:    simQuietLogger,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, local.Close()) })
	svc := NewTPMPolicyService()
	svc.SetContext(context.Background())
	svc.SetLocal(local)
	return sim, local, svc
}

// newSimKeyBackend returns a TPM2 key backend over the simulator, as xKey's
// local key store is: its keys may name a policy, and the service's resolver
// on the TPM supplies it.
func newSimKeyBackend(t *testing.T, sim *simTPM) *xkms.TPM2Backend {
	t.Helper()
	store, err := xkms.NewMemoryBackend()
	require.NoError(t, err)
	backend, err := xkms.NewTPM2BackendWithTPM(&xkms.TPM2BackendExternalConfig{
		TPM:        sim.tpm,
		KeyBackend: xkms.NewFileBackend(simQuietLogger, store),
		Logger:     simQuietLogger,
	})
	require.NoError(t, err)
	return backend
}

// createSimKey creates an ECDSA signing key bound to policy and records it,
// as KeyService does for a local TPM key.
func createSimKey(t *testing.T, svc *TPMPolicyService, backend *xkms.TPM2Backend, cn, policy string) *xkms.KeyAttributes {
	t.Helper()
	attrs := &xkms.KeyAttributes{
		CN:                 cn,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            xkms.KeyTypeSigning,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		TPMPolicy:          policy,
	}
	_, err := backend.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)
	require.NoError(t, svc.assignLocal(context.Background(), xkms.TPMObjectKindKey, cn, policy))
	return attrs
}

// signWith signs a digest with the key, which the TPM authorizes through the
// key's policy.
func signWith(backend *xkms.TPM2Backend, attrs *xkms.KeyAttributes) error {
	signer, err := backend.Signer(context.Background(), attrs)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte("xkey tpm policy test"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	return err
}

// driftPCR extends simPCR, so it no longer holds the value a policy
// captured.
func driftPCR(t *testing.T, sim *simTPM) {
	t.Helper()
	require.NoError(t, sim.tpm.ExtendPCR(simPCR, "sha256", []byte("platform change")))
}

func TestLocalTPMPolicies_PolicyLifecycleWithKeys(t *testing.T) {
	sim, _, svc := openSimLocal(t)
	assert.Equal(t, TPMPolicyModeLocal, svc.GetStatus().Mode)
	assert.Equal(t, "system", svc.GetStatus().Scope)

	created, err := svc.CreatePolicy("boot", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)
	assert.Len(t, created.PCRValues, 1, "the value is captured from the TPM")
	assert.True(t, created.Approved)

	backend := newSimKeyBackend(t, sim)
	k1 := createSimKey(t, svc, backend, "key-one", "boot")
	createSimKey(t, svc, backend, "key-two", "boot")
	require.NoError(t, signWith(backend, k1))

	// Both keys are listed against the policy.
	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	require.Len(t, policies, 2)
	assert.Equal(t, 2, policies[1].ObjectCount)
	objects, err := svc.PolicyObjects("boot")
	require.NoError(t, err)
	assert.Equal(t, []string{"key/key-one", "key/key-two"}, objects)
	keyPolicy, err := svc.KeyPolicy("key-one")
	require.NoError(t, err)
	assert.Equal(t, "boot", keyPolicy.Policy)

	// Deleting the policy is refused, and the refusal lists both keys.
	err = svc.DeletePolicy("boot", "")
	var inUse *xkms.TPMPolicyInUseError
	require.ErrorAs(t, err, &inUse)
	assert.Equal(t, []string{"key/key-one", "key/key-two"}, inUse.Objects)

	// A platform change: verify reports it, and the TPM refuses the key.
	driftPCR(t, sim)
	v, err := svc.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.False(t, v.Match)
	assert.Equal(t, []uint{simPCR}, v.Mismatched)
	assert.Error(t, signWith(backend, k1), "the TPM enforces the policy on use")

	// Update re-captures and re-approves; the same key works again, with no
	// re-key.
	updated, err := svc.UpdatePolicy("boot")
	require.NoError(t, err)
	assert.NotEqual(t, created.PCRValues[simPCR], updated.PCRValues[simPCR])
	v, err = svc.VerifyPolicy("boot")
	require.NoError(t, err)
	assert.True(t, v.Match)
	assert.True(t, v.Approved)
	require.NoError(t, signWith(backend, k1))

	// Rotating the authority re-approves every policy: still no re-key.
	rotated, err := svc.RotateAuthority()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), rotated.Generation)
	require.NoError(t, signWith(backend, k1))

	// Revoke withdraws the approval: the TPM refuses the key.
	revoked, err := svc.RevokePolicy("boot")
	require.NoError(t, err)
	assert.False(t, revoked.Approved)
	assert.Error(t, signWith(backend, k1))

	// With its keys gone, the policy can be deleted.
	require.NoError(t, svc.unassignLocal(context.Background(), xkms.TPMObjectKindKey, "key-one"))
	require.NoError(t, svc.unassignLocal(context.Background(), xkms.TPMObjectKindKey, "key-two"))
	require.NoError(t, svc.DeletePolicy("boot", ""))
	_, err = svc.GetPolicy("boot")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
}

func TestLocalTPMPolicies_AutoUnsealAttribute(t *testing.T) {
	_, _, svc := openSimLocal(t)
	_, err := svc.CreatePolicy("first", "sha256", []uint{simPCR}, true, "")
	require.NoError(t, err)
	_, err = svc.CreatePolicy("second", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)

	first, err := svc.GetPolicy("first")
	require.NoError(t, err)
	assert.True(t, first.AutoUnseal)

	_, err = svc.SetAutoUnseal("second", true)
	require.NoError(t, err)
	first, err = svc.GetPolicy("first")
	require.NoError(t, err)
	assert.False(t, first.AutoUnseal, "at most one policy per scope carries auto-unseal")

	_, err = svc.CreatePolicy("first", "sha256", []uint{simPCR}, false, "")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyExists)
}

func TestLocalTPMPolicies_SealedObjectFollowsItsPolicy(t *testing.T) {
	sim, local, svc := openSimLocal(t)
	_, err := svc.CreatePolicy("boot", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, local.SealObject(ctx, "secret", "boot", []byte("sealed data")))
	objects, err := svc.PolicyObjects("boot")
	require.NoError(t, err)
	assert.Equal(t, []string{"sealed/secret"}, objects, "the backend records the sealed object")

	data, err := local.UnsealObject(ctx, "secret")
	require.NoError(t, err)
	assert.Equal(t, []byte("sealed data"), data)

	driftPCR(t, sim)
	_, err = local.UnsealObject(ctx, "secret")
	assert.Error(t, err, "the TPM refuses the object after a PCR change")

	require.NoError(t, local.DeleteObject(ctx, "secret"), "deleting needs no unseal")
	objects, err = svc.PolicyObjects("boot")
	require.NoError(t, err)
	assert.Empty(t, objects)
	require.NoError(t, svc.DeletePolicy("boot", ""))
}

func TestLocalTPMPolicies_ObjectOperationsNeedAName(t *testing.T) {
	_, local, _ := openSimLocal(t)
	ctx := context.Background()
	assert.ErrorIs(t, local.SealObject(ctx, "", "", []byte("x")), ErrTPMObjectNameRequired)
	_, err := local.UnsealObject(ctx, "")
	assert.ErrorIs(t, err, ErrTPMObjectNameRequired)
	assert.ErrorIs(t, local.DeleteObject(ctx, ""), ErrTPMObjectNameRequired)
	var kindErr *xkms.InvalidTPMObjectKindError
	assert.ErrorAs(t, local.Assign(ctx, "bogus", "k", ""), &kindErr)
	assert.ErrorAs(t, local.Unassign(ctx, "bogus", "k"), &kindErr)
}

// newSimPassphraseBarrier initializes a passphrase barrier in a temporary
// directory and seals it.
func newSimPassphraseBarrier(t *testing.T, password string) *BarrierService {
	t.Helper()
	barrier := NewBarrierService(t.TempDir(), simQuietLogger)
	require.NoError(t, barrier.Initialize(password, string(xkms.StrategyPassphrase)))
	require.NoError(t, barrier.Seal())
	require.False(t, barrier.IsUnsealed())
	return barrier
}

func TestBarrierAutoUnseal_TPMReleasesTheCredentialOnlyUnderThePolicy(t *testing.T) {
	sim, local, svc := openSimLocal(t)
	const password = "correct horse battery staple"
	barrier := newSimPassphraseBarrier(t, password)
	auto := NewBarrierAutoUnsealService(WithBarrierAutoUnsealLocal(local), WithBarrierAutoUnsealBarrier(barrier),
		WithBarrierAutoUnsealLogger(simQuietLogger))
	ctx := context.Background()
	strategy := string(xkms.StrategyPassphrase)

	// Nothing configured: a silent no-op.
	ok, err := auto.TryAutoUnseal(ctx, strategy)
	require.NoError(t, err)
	assert.False(t, ok)

	_, err = svc.CreatePolicy("boot", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)
	require.NoError(t, auto.EnableAutoUnseal("boot", password))

	status, err := auto.GetAutoUnsealStatus()
	require.NoError(t, err)
	assert.True(t, status.PolicyConfigured)
	assert.Equal(t, "boot", status.PolicyName)
	assert.True(t, status.CredentialSealed)
	assert.True(t, status.PCRsMatch)
	assert.True(t, status.BarrierSealed)

	// The credential object is bound to the policy, so it cannot be
	// deleted from under auto-unseal.
	err = svc.DeletePolicy("boot", "")
	var inUse *xkms.TPMPolicyInUseError
	require.ErrorAs(t, err, &inUse)
	assert.Equal(t, []string{"sealed/" + BarrierAutoUnsealObject}, inUse.Objects)

	ok, err = auto.TryAutoUnseal(ctx, strategy)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, barrier.IsUnsealed())

	// After a PCR change the TPM refuses the policy session, and the barrier
	// stays sealed for a manual unseal.
	require.NoError(t, barrier.Seal())
	driftPCR(t, sim)
	status, err = auto.GetAutoUnsealStatus()
	require.NoError(t, err)
	assert.False(t, status.PCRsMatch)
	ok, err = auto.TryAutoUnseal(ctx, strategy)
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealRefused)
	assert.False(t, barrier.IsUnsealed())

	// Updating the policy approves the new state; auto-unseal works again.
	_, err = svc.UpdatePolicy("boot")
	require.NoError(t, err)
	ok, err = auto.TryAutoUnseal(ctx, strategy)
	require.NoError(t, err)
	assert.True(t, ok)

	// Disabling clears the mark and the credential: nothing is configured.
	require.NoError(t, auto.DisableAutoUnseal())
	status, err = auto.GetAutoUnsealStatus()
	require.NoError(t, err)
	assert.False(t, status.PolicyConfigured)
	require.NoError(t, svc.DeletePolicy("boot", ""))
}

func TestBarrierAutoUnseal_MovedMarkFailsClosed(t *testing.T) {
	_, local, svc := openSimLocal(t)
	barrier := newSimPassphraseBarrier(t, "barrier password")
	auto := NewBarrierAutoUnsealService(WithBarrierAutoUnsealLocal(local), WithBarrierAutoUnsealBarrier(barrier),
		WithBarrierAutoUnsealLogger(simQuietLogger))
	ctx := context.Background()

	for _, name := range []string{"boot", "other"} {
		_, err := svc.CreatePolicy(name, "sha256", []uint{simPCR}, false, "")
		require.NoError(t, err)
	}

	// A mark with no credential sealed under it is not enrolled.
	_, err := svc.SetAutoUnseal("other", true)
	require.NoError(t, err)
	ok, err := auto.TryAutoUnseal(ctx, string(xkms.StrategyPassphrase))
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealNotEnrolled)

	// Moving the mark away from the credential's policy fails closed.
	require.NoError(t, auto.EnableAutoUnseal("boot", "barrier password"))
	_, err = svc.SetAutoUnseal("other", true)
	require.NoError(t, err)
	ok, err = auto.TryAutoUnseal(ctx, string(xkms.StrategyPassphrase))
	assert.False(t, ok)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealPolicyMoved)
	status, err := auto.GetAutoUnsealStatus()
	require.NoError(t, err)
	assert.False(t, status.CredentialSealed)
}

func TestBarrierAutoUnseal_WrongCredentialIsReportedAsABarrierFailure(t *testing.T) {
	_, local, svc := openSimLocal(t)
	barrier := newSimPassphraseBarrier(t, "the real password")
	auto := NewBarrierAutoUnsealService(WithBarrierAutoUnsealLocal(local), WithBarrierAutoUnsealBarrier(barrier),
		WithBarrierAutoUnsealLogger(simQuietLogger))
	_, err := svc.CreatePolicy("boot", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)
	require.NoError(t, auto.EnableAutoUnseal("boot", "not the password"))

	ok, err := auto.TryAutoUnseal(context.Background(), string(xkms.StrategyPassphrase))
	assert.False(t, ok)
	assert.True(t, errors.Is(err, ErrBarrierAutoUnsealFailed))
}

// echoSealClient is a local seal client that reports the object it was
// asked to seal as the one it sealed, as the embedded xkms client does.
func echoSealClient() *sealMockClient {
	mc := defaultSealMockClient()
	mc.sealFn = func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
		return &transport.SealResponse{Backend: req.Backend, Ciphertext: req.Data, KeyID: req.KeyID}, nil
	}
	return mc
}

func TestSealService_LocalBlobUnderNamedPolicyIsRecordedAndForgotten(t *testing.T) {
	_, _, policies := openSimLocal(t)
	_, err := policies.CreatePolicy("boot", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)

	seal := NewSealService(t.TempDir())
	seal.SetContext(context.Background())
	seal.SetLocalClient(echoSealClient())
	seal.SetTPMPolicyService(policies)

	req := validSealRequest()
	req.TPMPolicy = "boot"
	entry, err := seal.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "boot", entry.TPMPolicy)

	objects, err := policies.PolicyObjects("boot")
	require.NoError(t, err)
	assert.Equal(t, []string{"sealed/" + sealedObjectPrefix + entry.ID}, objects)
	assert.Error(t, policies.DeletePolicy("boot", ""), "the blob keeps its policy")

	require.NoError(t, seal.DeleteBlob(entry.ID))
	objects, err = policies.PolicyObjects("boot")
	require.NoError(t, err)
	assert.Empty(t, objects)
	require.NoError(t, policies.DeletePolicy("boot", ""))
}

func TestSealService_ServerBlobIsNotRecordedLocally(t *testing.T) {
	_, _, policies := openSimLocal(t)
	_, err := policies.CreatePolicy("boot", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)

	seal := newSealServiceWithMockClient(t, echoSealClient())
	seal.SetTPMPolicyService(policies)
	req := validSealRequest()
	req.TPMPolicy = "boot"
	_, err = seal.SealData(req)
	require.NoError(t, err)

	objects, err := policies.PolicyObjects("boot")
	require.NoError(t, err)
	assert.Empty(t, objects, "the server records the objects it seals")
}

func TestKeyService_LocalTPMKeyIsRecordedAndForgotten(t *testing.T) {
	_, _, policies := openSimLocal(t)
	_, err := policies.CreatePolicy("boot", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)

	var sent *transport.GenerateKeyRequest
	client := &mockClient{
		generateKeyFn: func(_ context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
			sent = req
			return &transport.GenerateKeyResponse{KeyID: "tpm2:signing:ecdsa-p256:" + req.KeyID}, nil
		},
		deleteKeyFn: func(context.Context, string, string) (*transport.DeleteKeyResponse, error) {
			return &transport.DeleteKeyResponse{}, nil
		},
	}
	keys := NewKeyService()
	keys.SetContext(context.Background())
	keys.SetLocalClient(client)
	keys.SetTPMPolicyService(policies)

	_, err = keys.GenerateKey("local", &GenerateKeyParams{KeyID: "signer", Backend: "tpm2", Algorithm: "ecdsa", TPMPolicy: "boot"})
	require.NoError(t, err)
	require.NotNil(t, sent)
	assert.Equal(t, "boot", sent.TPMPolicy)

	info, err := policies.KeyPolicy("signer")
	require.NoError(t, err)
	assert.Equal(t, "boot", info.Policy)

	require.NoError(t, keys.DeleteKey("local", "tpm2", "tpm2:signing:ecdsa-p256:signer"))
	_, err = policies.KeyPolicy("signer")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotAssigned)
}

func TestSetupWizard_EnableBarrierAutoUnsealCreatesThePolicyOnce(t *testing.T) {
	_, local, policies := openSimLocal(t)
	wizard := &SetupWizardService{}
	wizard.SetTPMPolicyService(policies)
	wizard.SetBarrierAutoUnsealService(NewBarrierAutoUnsealService(WithBarrierAutoUnsealLocal(local),
		WithBarrierAutoUnsealLogger(simQuietLogger)))

	require.NoError(t, wizard.enableBarrierAutoUnseal("barrier password", ""))
	p, err := policies.GetPolicy(wizardAutoUnsealPolicy)
	require.NoError(t, err)
	assert.Equal(t, wizardAutoUnsealPCRs, p.PCRs)
	assert.True(t, p.AutoUnseal)

	// A re-run reuses the policy instead of failing on it.
	require.NoError(t, wizard.enableBarrierAutoUnseal("barrier password", ""))
	objects, err := policies.PolicyObjects(wizardAutoUnsealPolicy)
	require.NoError(t, err)
	assert.Equal(t, []string{"sealed/" + BarrierAutoUnsealObject}, objects)
}

func TestLocalTPMPolicies_ErrorsFromTheService(t *testing.T) {
	_, local, svc := openSimLocal(t)
	ctx := context.Background()
	assert.NotNil(t, local.Service())

	_, err := svc.VerifyPolicy("missing")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
	_, err = svc.UpdatePolicy("missing")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
	_, err = svc.SetAutoUnseal("missing", true)
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
	assert.ErrorIs(t, svc.DeletePolicy("missing", ""), xkms.ErrTPMPolicyNotFound)
	_, err = svc.PolicyObjects("missing")
	assert.NoError(t, err, "an unknown policy simply has no objects")
	_, err = svc.KeyPolicy("never-created")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotAssigned)
	_, err = local.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{KeyID: "k", Kind: "bogus"})
	var kindErr *xkms.InvalidTPMObjectKindError
	assert.ErrorAs(t, err, &kindErr)
	_, err = local.AutoUnsealPolicy(ctx)
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
	assert.NoError(t, local.DeleteObject(ctx, "never-sealed"), "deleting a missing object is not an error")
}

func TestLocalTPMPolicies_SharesTheTPMAccessor(t *testing.T) {
	sim := openSimTPM(t)
	accessor := NewTPMAccessor(func() xkms.TrustedPlatformModule { return sim.tpm })
	local, err := OpenLocalTPMPolicies(LocalTPMPolicyParams{
		TPM:       sim.tpm,
		Keys:      sim.keys,
		DataDir:   t.TempDir(),
		OpenStore: func(string) (xkms.StorageBackend, error) { return xkms.NewStorageMemory(), nil },
		Accessor:  accessor,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, local.Close()) })

	svc := NewTPMPolicyService()
	svc.SetLocal(local)
	_, err = svc.CreatePolicy("boot", "sha256", []uint{simPCR}, false, "")
	require.NoError(t, err)
	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 2)

	// With the accessor shut down, every operation reports it rather than
	// racing the TPM's other users.
	accessor.Shutdown()
	_, err = svc.ListPolicies()
	assert.ErrorIs(t, err, ErrTPMShuttingDown)
}

func TestOpenLocalTPMPolicies_StoreOpenFailure(t *testing.T) {
	sim := openSimTPM(t)
	errStore := errors.New("store unavailable")
	_, err := OpenLocalTPMPolicies(LocalTPMPolicyParams{
		TPM:       sim.tpm,
		Keys:      sim.keys,
		DataDir:   t.TempDir(),
		OpenStore: func(string) (xkms.StorageBackend, error) { return nil, errStore },
	})
	assert.ErrorIs(t, err, ErrLocalTPMPolicyBuildFailed)
	assert.ErrorIs(t, err, errStore)
}

func TestKeyService_UnrecordableKeyIsDeletedAgain(t *testing.T) {
	_, _, policies := openSimLocal(t)
	var deleted string
	client := &mockClient{
		generateKeyFn: func(_ context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
			return &transport.GenerateKeyResponse{KeyID: "tpm2:signing:ecdsa-p256:" + req.KeyID}, nil
		},
		deleteKeyFn: func(_ context.Context, _, keyID string) (*transport.DeleteKeyResponse, error) {
			deleted = keyID
			return &transport.DeleteKeyResponse{}, nil
		},
	}
	keys := NewKeyService()
	keys.SetContext(context.Background())
	keys.SetLocalClient(client)
	keys.SetTPMPolicyService(policies)

	// The policy does not exist, so the assignment cannot be recorded.
	_, err := keys.GenerateKey("local", &GenerateKeyParams{KeyID: "signer", Backend: "tpm2", Algorithm: "ecdsa", TPMPolicy: "missing"})
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
	assert.Equal(t, "tpm2:signing:ecdsa-p256:signer", deleted)
}

func TestSealService_UnrecordableBlobIsNotKept(t *testing.T) {
	_, _, policies := openSimLocal(t)
	seal := NewSealService(t.TempDir())
	seal.SetContext(context.Background())
	seal.SetLocalClient(echoSealClient())
	seal.SetTPMPolicyService(policies)

	req := validSealRequest()
	req.TPMPolicy = "missing"
	_, err := seal.SealData(req)
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyNotFound)
	blobs, err := seal.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}
