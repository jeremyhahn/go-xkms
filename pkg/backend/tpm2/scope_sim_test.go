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

package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// scopePCR is the application PCR the test policies select; it is not the
// platform PCR the scopes' own objects are bound to.
const scopePCR = 23

// scopedFixture is a simulator-backed TPM2 backend with a TPM policy service
// installed as its scope provider.
type scopedFixture struct {
	t       *testing.T
	ctx     context.Context
	backend *Backend
	svc     *tpmpolicy.Service
}

// newScopedFixture opens the simulator, builds the policy service over the
// backend's own TPM, key store and Platform SRK, and installs it.
func newScopedFixture(t *testing.T) *scopedFixture {
	t.Helper()
	backend, err := NewBackend(&Config{UseSimulator: true, Keys: tpmblobtest.New(t)})
	require.NoError(t, err)
	tpm, ok := backend.TPM().(*pkgtpm2.TPM2)
	require.True(t, ok)
	registry, err := tpmpolicy.NewRegistry(testutil.NewMemoryDAOFactory(), 0)
	require.NoError(t, err)
	svc, err := tpmpolicy.NewService(tpmpolicy.Config{
		Registry:    registry,
		TPM:         tpm,
		PlatformSRK: backend.SRKAttributes(),
		Keys:        backend.KeyBackend(),
		TenantKeys:  tpmblobtest.New(t),
		Sealer:      tpm,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	backend.SetScopeProvider(svc)
	t.Cleanup(func() {
		require.NoError(t, svc.Close())
		require.NoError(t, backend.Close())
	})
	return &scopedFixture{t: t, ctx: context.Background(), backend: backend, svc: svc}
}

// createPolicy creates a SHA-256 policy over scopePCR in tenant's scope.
func (f *scopedFixture) createPolicy(tenant, name string) {
	f.t.Helper()
	_, err := f.svc.CreatePolicy(f.ctx, tenant, tpmpolicy.CreatePolicyRequest{Name: name, Branches: []tpmpolicy.Branch{tpmpolicy.PCRBranch("sha256", scopePCR)}})
	require.NoError(f.t, err)
}

// ecKey returns the attributes of an ECDSA P-256 signing key.
func ecKey(tenant, cn, policy string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            cn,
		TenantID:      tenant,
		TPMPolicy:     policy,
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		Hash:          crypto.SHA256,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
}

// signAndVerify signs with the key attrs names and verifies the signature
// against its public key, so a pass proves the TPM used that very key.
func (f *scopedFixture) signAndVerify(attrs *types.KeyAttributes) {
	f.t.Helper()
	signer, err := f.backend.Signer(f.ctx, attrs)
	require.NoError(f.t, err)
	digest := sha256.Sum256([]byte("scoped backend test"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(f.t, err)
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(f.t, ok)
	assert.True(f.t, ecdsa.VerifyASN1(pub, digest[:], sig))
}

// listed returns the listed key of tenant named cn, or nil.
func (f *scopedFixture) listed(tenant, cn string) *types.KeyAttributes {
	f.t.Helper()
	keys, err := f.backend.ListKeys(f.ctx)
	require.NoError(f.t, err)
	for _, k := range keys {
		if k.TenantID == tenant && k.CN == cn {
			return k
		}
	}
	return nil
}

// TestScopedBackend_NamedPolicyKeys proves keys created with a named policy
// are recorded against it, listed with it, usable under it, and keep the
// policy from being deleted until they are.
func TestScopedBackend_NamedPolicyKeys(t *testing.T) {
	f := newScopedFixture(t)
	f.createPolicy("", "boot")

	first := ecKey("", "boot-signer-a", "boot")
	second := ecKey("", "boot-signer-b", "boot")
	_, err := f.backend.GenerateKey(f.ctx, first)
	require.NoError(t, err)
	_, err = f.backend.GenerateKey(f.ctx, second)
	require.NoError(t, err)

	objects, err := f.svc.ObjectsOf(f.ctx, "", "boot")
	require.NoError(t, err)
	assert.Equal(t, []string{"key/boot-signer-a", "key/boot-signer-b"}, objects)

	listed := f.listed("", "boot-signer-a")
	require.NotNil(t, listed)
	assert.Equal(t, "boot", listed.TPMPolicy)
	assert.Equal(t, x509.ECDSA, listed.KeyAlgorithm)

	f.signAndVerify(first)
	f.signAndVerify(second)

	var inUse *tpmpolicy.PolicyInUseError
	require.ErrorAs(t, f.svc.DeletePolicy(f.ctx, "", "boot", nil), &inUse)
	assert.Equal(t, []string{"key/boot-signer-a", "key/boot-signer-b"}, inUse.Objects)

	require.NoError(t, f.backend.DeleteKey(f.ctx, first))
	require.NoError(t, f.backend.DeleteKey(f.ctx, second))
	require.NoError(t, f.svc.DeletePolicy(f.ctx, "", "boot", nil))
}

// TestScopedBackend_UnknownPolicyIsRefused proves a key cannot be created
// under a policy its scope does not have, and nothing is recorded for it.
func TestScopedBackend_UnknownPolicyIsRefused(t *testing.T) {
	f := newScopedFixture(t)
	_, err := f.backend.GenerateKey(f.ctx, ecKey("", "orphan", "missing"))
	require.ErrorIs(t, err, tpmpolicy.ErrPolicyNotFound)
	assert.Nil(t, f.listed("", "orphan"))
}

// TestScopedBackend_TenantsAreIsolated proves two tenants' keys of the same
// name are separate objects in separate scopes: each lists and signs with
// its own, and deleting one leaves the other.
func TestScopedBackend_TenantsAreIsolated(t *testing.T) {
	f := newScopedFixture(t)
	acme := ecKey("acme", "signer", "")
	globex := ecKey("globex", "signer", "")
	_, err := f.backend.GenerateKey(f.ctx, acme)
	require.NoError(t, err)
	_, err = f.backend.GenerateKey(f.ctx, globex)
	require.NoError(t, err)

	acmeListed := f.listed("acme", "signer")
	require.NotNil(t, acmeListed)
	assert.Equal(t, types.TPMPolicyPlatform, acmeListed.TPMPolicy)
	require.NotNil(t, f.listed("globex", "signer"))
	assert.Nil(t, f.listed("", "signer"), "a tenant key is not a system key")

	f.signAndVerify(acme)
	f.signAndVerify(globex)

	acmeSigner, err := f.backend.Signer(f.ctx, acme)
	require.NoError(t, err)
	globexSigner, err := f.backend.Signer(f.ctx, globex)
	require.NoError(t, err)
	assert.NotEqual(t, acmeSigner.Public(), globexSigner.Public(), "the same name in two tenants is two keys")

	require.NoError(t, f.backend.DeleteKey(f.ctx, acme))
	assert.Nil(t, f.listed("acme", "signer"))
	require.NotNil(t, f.listed("globex", "signer"))
	f.signAndVerify(globex)
}

// TestScopedBackend_ModeNoneRefusesTheTenant proves a tenant whose TPM mode
// is none cannot create a TPM key, with the policy service's typed error.
func TestScopedBackend_ModeNoneRefusesTheTenant(t *testing.T) {
	f := newScopedFixture(t)
	require.NoError(t, f.svc.SetMode(f.ctx, "initech", tpmpolicy.ModeNone, nil))

	_, err := f.backend.GenerateKey(f.ctx, ecKey("initech", "signer", ""))
	require.ErrorIs(t, err, tpmpolicy.ErrTPMModeNone)
	var scopeErr *ScopeError
	require.ErrorAs(t, err, &scopeErr)
	assert.Equal(t, "initech", scopeErr.Tenant)
}

// TestScopedBackend_SealWithNamedPolicy proves a tenant's sealed object is
// bound to a named policy of its scope, recorded against it, and unseals in
// that scope.
func TestScopedBackend_SealWithNamedPolicy(t *testing.T) {
	f := newScopedFixture(t)
	f.createPolicy("acme", "boot")
	secret := []byte("tenant sealed secret")

	attrs := &types.KeyAttributes{CN: "vault-key", TenantID: "acme", TPMPolicy: "boot", StoreType: types.StoreTPM2}
	sealed, err := f.backend.Seal(f.ctx, secret, &types.SealOptions{KeyAttributes: attrs})
	require.NoError(t, err)
	assert.Equal(t, types.BackendTypeTPM2, sealed.Backend)

	assignment, err := f.svc.PolicyOf(f.ctx, "acme", tpmpolicy.ObjectSealed, "vault-key")
	require.NoError(t, err)
	assert.Equal(t, "boot", assignment.Policy)
	assert.NotEmpty(t, assignment.AuthPolicy)

	unsealAttrs := &types.KeyAttributes{CN: "vault-key", TenantID: "acme", StoreType: types.StoreTPM2}
	plain, err := f.backend.Unseal(f.ctx, sealed, &types.UnsealOptions{KeyAttributes: unsealAttrs})
	require.NoError(t, err)
	assert.Equal(t, secret, plain)

	_, err = f.backend.Unseal(f.ctx, sealed, &types.UnsealOptions{KeyAttributes: &types.KeyAttributes{CN: "vault-key", TenantID: "globex"}})
	assert.Error(t, err, "another tenant's scope cannot load the object")
}

// TestScopedBackend_SymmetricKeysInEveryScope proves the system scope and a
// shared tenant both hold symmetric keys: the tenant's is sealed under its own
// storage key in its own store, encrypts and decrypts through an encrypter
// that outlives the call that made it, and is invisible to another tenant.
func TestScopedBackend_SymmetricKeysInEveryScope(t *testing.T) {
	f := newScopedFixture(t)
	system := &types.KeyAttributes{CN: "system-aes", SymmetricAlgorithm: types.SymmetricAES256GCM, KeyType: types.KeyTypeSecret}
	_, err := f.backend.GenerateSymmetricKey(f.ctx, system)
	require.NoError(t, err)
	_, err = f.backend.GetSymmetricKey(f.ctx, system)
	require.NoError(t, err)
	assignment, err := f.svc.PolicyOf(f.ctx, "", tpmpolicy.ObjectKey, "system-aes")
	require.NoError(t, err)
	assert.Equal(t, types.TPMPolicyPlatform, assignment.Policy)

	tenant := &types.KeyAttributes{CN: "tenant-aes", TenantID: "acme", SymmetricAlgorithm: types.SymmetricAES256GCM, KeyType: types.KeyTypeSecret}
	_, err = f.backend.GenerateSymmetricKey(f.ctx, tenant)
	require.NoError(t, err)
	assignment, err = f.svc.PolicyOf(f.ctx, "acme", tpmpolicy.ObjectKey, "tenant-aes")
	require.NoError(t, err)
	assert.Equal(t, types.TPMPolicyPlatform, assignment.Policy)

	encrypter, err := f.backend.SymmetricEncrypter(f.ctx, &types.KeyAttributes{CN: "tenant-aes", TenantID: "acme", SymmetricAlgorithm: types.SymmetricAES256GCM, KeyType: types.KeyTypeSecret})
	require.NoError(t, err)
	encrypted, err := encrypter.Encrypt([]byte("acme data"), nil)
	require.NoError(t, err)
	decrypted, err := encrypter.Decrypt(encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("acme data"), decrypted)

	other := &types.KeyAttributes{CN: "tenant-aes", TenantID: "globex", SymmetricAlgorithm: types.SymmetricAES256GCM, KeyType: types.KeyTypeSecret}
	_, err = f.backend.GetSymmetricKey(f.ctx, other)
	require.Error(t, err, "another tenant cannot see acme's symmetric key")
}

// TestScopedBackend_ReservedObjectsAreHidden proves the policy service's own
// objects are neither listed nor deletable through the backend.
func TestScopedBackend_ReservedObjectsAreHidden(t *testing.T) {
	f := newScopedFixture(t)
	f.createPolicy("", "boot") // creates the system scope's authority

	keys, err := f.backend.ListKeys(f.ctx)
	require.NoError(t, err)
	for _, k := range keys {
		assert.False(t, tpmpolicy.IsReservedObject(k.CN), "listed reserved object %q", k.CN)
	}
	err = f.backend.DeleteKey(f.ctx, &types.KeyAttributes{CN: "tpm-policy-authority-1"})
	require.ErrorIs(t, err, ErrReservedObject)
	assert.True(t, f.backend.TenantBoundSealing())
}
