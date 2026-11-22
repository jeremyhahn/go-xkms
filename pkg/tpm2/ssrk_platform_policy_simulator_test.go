//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestProvisionSSRKHasNoAuthPolicy is the invariant itself, read back from the
// TPM: after provisioning, the object persisted at the shared SRK handle has an
// empty AuthPolicy.
//
// An AuthPolicy there would be the stale-from-birth policy this change removes:
// ProvisionOwner creates the SSRK before CreatePlatformPolicy extends the
// golden measurement, so whatever PCR state it described is gone by the time
// Provision returns.
func TestProvisionSSRKHasNoAuthPolicy(t *testing.T) {
	h := newSimHarness(t, nil)

	_, pub, err := h.TPM.ReadHandle(tpm2.TPMHandle(h.TPM.config.SSRK.Handle))
	require.NoError(t, err, "provisioning must persist a shared SRK")

	assert.Empty(t, pub.AuthPolicy.Buffer,
		"the shared SRK must be persisted with no authorization policy")

	attrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	assert.False(t, (attrs.TPMPolicy == types.TPMPolicyPlatform),
		"the shared SRK's attributes must not claim a platform policy")
}

// TestSSRKPlatformPolicyConfigRejectedBeforeAnySRKIsCreated closes the loop
// between the configuration boundary and the TPM: a configuration asking for a
// platform-policy SSRK is refused where it is parsed, so provisioning is never
// reached and no key is created at the shared SRK handle.
func TestSSRKPlatformPolicyConfigRejectedBeforeAnySRKIsCreated(t *testing.T) {
	sim, err := OpenSimulator()
	require.NoError(t, err, "TPM simulator must be available; build with -tags tpm_simulator")
	t.Cleanup(func() { _ = sim.Close() })

	const configYAML = `
device: simulator
hash: SHA-256
ssrk:
  handle: 0x81000001
  algorithm: RSA
  platform-policy: true
  rsa:
    keysize: 2048
`

	var config Config
	err = yaml.Unmarshal([]byte(configYAML), &config)

	var policyErr *SSRKPlatformPolicyError
	require.ErrorAs(t, err, &policyErr,
		"the configuration must be rejected before it can provision anything")
	require.NotNil(t, config.SSRK)
	require.Zero(t, *config.SSRK, "nothing from the rejected section may be applied")

	// Nothing reached the TPM: the shared SRK handle is unoccupied.
	_, err = tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(0x81000001),
	}.Execute(sim.Transport())
	require.Error(t, err, "no SRK may be created from a rejected configuration")
	assert.Equal(t, tpm2.TPMRC(0x18b), err, "expected TPM_RC_HANDLE")
}

// ssrkChildAttrs builds a plain signing key beneath the shared SRK: no platform
// policy anywhere, which is what every child of the SSRK now looks like.
func ssrkChildAttrs(t *testing.T, h *simHarness, cn string) *types.KeyAttributes {
	t.Helper()

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	return &types.KeyAttributes{
		CN:                 cn,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.RSA,
		KeyType:            types.KeyTypeSigning,
		Parent:             srkAttrs,
		RSAAttributes:      &types.RSAAttributes{KeySize: 2048},
		SignatureAlgorithm: x509.SHA256WithRSA,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
}

// TestLegacySSRKWithPlatformPolicyStillLoadable is the upgrade case. A
// deployment provisioned before this change has a shared SRK whose public area
// carries an AuthPolicy — the stale one. That key must keep working: it is the
// parent of every sealed object and child key on the machine, and TPM2_Create
// cannot re-derive it without orphaning them (the template is an input to the
// derivation, TPM 2.0 Part 1, Section 27.2).
//
// It keeps working because the SRK templates set userWithAuth, so the USER role
// can be satisfied with the auth value regardless of the policy sitting in the
// public area, and because SSRKAttributes reports what the read path needs —
// never a platform policy it would then try to satisfy.
func TestLegacySSRKWithPlatformPolicyStillLoadable(t *testing.T) {
	h := newSimHarness(t, nil)

	const legacyHandle = uint32(0x81000005)

	// Recreate the pre-change shape: a shared SRK created WITH the platform
	// policy, exactly as SRKAttributesFromConfig used to produce it.
	legacy, err := SRKAttributesFromConfig(*h.TPM.config.SSRK)
	require.NoError(t, err)
	legacy.TPMAttributes.Handle = tpm2.TPMHandle(legacyHandle)
	legacy.TPMAttributes.HierarchyAuth = nil
	legacy.TPMPolicy = types.TPMPolicyPlatform
	require.NoError(t, h.TPM.CreateSRK(legacy))

	_, pub, err := h.TPM.ReadHandle(tpm2.TPMHandle(legacyHandle))
	require.NoError(t, err)
	require.NotEmpty(t, pub.AuthPolicy.Buffer,
		"the fixture must reproduce a policy-bound shared SRK")

	// Point the configuration at it, as an upgraded deployment's would be.
	h.TPM.config.SSRK.Handle = legacyHandle
	h.TPM.ssrkAttrs = nil

	attrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err, "a pre-existing policy-bound shared SRK must still be readable")
	assert.False(t, (attrs.TPMPolicy == types.TPMPolicyPlatform),
		"the read path must not adopt a policy the shared SRK is never created with")
	assert.Equal(t, tpm2.TPMHandle(legacyHandle), attrs.TPMAttributes.Handle)

	// And it must still parent keys.
	child := ssrkChildAttrs(t, h, "legacy-ssrk-child")
	childPub, err := h.TPM.CreateRSA(child, h.Backend, true)
	require.NoError(t, err, "a legacy policy-bound shared SRK must still load children")
	require.NotNil(t, childPub)

	digest := sha256.Sum256([]byte("signed beneath a legacy policy-bound shared SRK"))
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: child,
		Backend:       h.Backend,
	})
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(childPub, crypto.SHA256, digest[:], signature))

	// The stale policy was stale from birth; a further measurement change
	// cannot make the password path any staler.
	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	signature, err = h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: child,
		Backend:       h.Backend,
	})
	require.NoError(t, err,
		"authorization of a legacy shared SRK goes through its auth value, not its stale policy")
	require.NoError(t, rsa.VerifyPKCS1v15(childPub, crypto.SHA256, digest[:], signature))
}
