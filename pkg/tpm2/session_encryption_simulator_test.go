//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test/tpmbus"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// capture routes h's TPM through a new bus capture.
func capture(h *simHarness) *tpmbus.Capture {
	c := tpmbus.New(h.TPM.transport)
	h.TPM.transport = c
	return c
}

// createPSRK creates a Platform SRK whose authValue is userPIN under an owner
// hierarchy whose authorization has been changed to soPIN. It carries the
// platform policy exactly when the harness configuration asks for one
// (PlatformSRKConfig.PlatformPolicy, set by newSimConfig).
func createPSRK(t *testing.T, h *simHarness, soPIN, userPIN []byte) *types.KeyAttributes {
	t.Helper()
	owner := tpm2.TPMRHOwner
	require.NoError(t, h.TPM.SetHierarchyAuth(nil, mustPassword(soPIN), &owner))

	psrkAttrs, err := PlatformSRKAttributesFromConfig(h.TPM.config)
	require.NoError(t, err)
	require.Equal(t, h.TPM.config.PlatformSRK.PlatformPolicy, psrkAttrs.PlatformPolicy,
		"the Platform SRK must carry the platform policy exactly when configured to")
	psrkAttrs.Password = mustPassword(userPIN)
	psrkAttrs.TPMAttributes.HierarchyAuth = mustPassword(soPIN)
	require.NoError(t, h.TPM.CreateSRK(psrkAttrs))
	return psrkAttrs
}

// TestSessionEncryption_SOPINNeverCrossesTheBus provisions a TPM from scratch
// with an SO PIN and proves the PIN never appears on the bus. Provisioning
// changes the lockout, endorsement and owner authorizations before any EK
// exists -- so those sessions are salted against the ephemeral NULL-hierarchy
// key -- then creates and persists the EK, SSRK and IAK under the new
// authorization.
func TestSessionEncryption_SOPINNeverCrossesTheBus(t *testing.T) {
	h := newSimHarness(t, nil)
	soPIN := []byte("so-pin-3f9a1c77e2")
	bus := capture(h)

	require.NoError(t, h.TPM.Provision(mustPassword(soPIN)))

	bus.RequireAbsent(t, "the SO PIN", soPIN)
	bus.RequireSessionAttr(t, tpm2.TPMCCHierarchyChanegAuth, tpmbus.SessionAttrDecrypt)
	bus.RequireSessionAttr(t, tpm2.TPMCCCreatePrimary, tpmbus.SessionAttrDecrypt)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCHierarchyChanegAuth)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCCreatePrimary)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCEvictControl)
}

// TestSessionEncryption_PSRKCreationProtectsBothPINs proves that creating the
// Platform SRK sends neither its USER PIN (the sensitive area's userAuth) nor
// the SO PIN (the owner hierarchy authorization) in plaintext.
func TestSessionEncryption_PSRKCreationProtectsBothPINs(t *testing.T) {
	h := newSimHarness(t, nil)
	soPIN := []byte("so-pin-8b41d0e9aa")
	userPIN := []byte("user-pin-5c2e77f031")
	bus := capture(h)

	createPSRK(t, h, soPIN, userPIN)

	bus.RequireAbsent(t, "the SO PIN", soPIN)
	bus.RequireAbsent(t, "the USER PIN", userPIN)
	bus.RequireSessionAttr(t, tpm2.TPMCCCreatePrimary, tpmbus.SessionAttrDecrypt)
	bus.RequireNoPasswordSession(t, tpm2.TPMCCCreatePrimary)
	bus.RequireNoPasswordSession(t, tpm2.TPMCCEvictControl)
	bus.RequireAllSessionsSalted(t)
}

// TestSessionEncryption_SealUnderPSRKWithPINs seals a secret under the
// Platform SRK through the PolicyAuthValue (PIN) branch of the platform
// policy -- both for the PSRK and for the sealed object -- and unseals it,
// proving the secret, the USER PIN and the object PIN never cross the bus in
// plaintext and that every PIN-bearing policy session is salted.
func TestSessionEncryption_SealUnderPSRKWithPINs(t *testing.T) {
	h := newSimHarness(t, nil)
	userPIN := []byte("user-pin-a7d3e1f094")
	objectPIN := []byte("object-pin-19c0b6e2d8")
	secret := []byte("pkcs11-user-pin-SECRET-6e1d")
	psrkAttrs := createPSRK(t, h, []byte("so-pin-2d7c90e1b4"), userPIN)

	keyAttrs := &types.KeyAttributes{
		CN:             "session-encryption-pin-seal",
		KeyType:        types.KeyTypeHMAC,
		Parent:         psrkAttrs,
		Password:       mustPassword(objectPIN),
		PlatformPolicy: true,
		SealData:       types.NewSealData(secret),
		StoreType:      types.StoreTPM2,
	}

	bus := capture(h)
	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)
	unsealed, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, unsealed)

	bus.RequireAbsent(t, "the sealed secret", secret)
	bus.RequireAbsent(t, "the USER PIN", userPIN)
	bus.RequireAbsent(t, "the object PIN", objectPIN)
	bus.RequireSessionAttr(t, tpm2.TPMCCCreate, tpmbus.SessionAttrDecrypt)
	bus.RequireSessionAttr(t, tpm2.TPMCCUnseal, tpmbus.SessionAttrEncrypt)
	bus.RequireAllSessionsSalted(t)
}

// TestSessionEncryption_AutoUnsealThroughPCRBranch reproduces the auto-unseal
// of a pre-barrier secret such as the PKCS#11 PIN: sealed under the Platform
// SRK with the platform policy and unsealed through the PCR branch, with no
// PIN presented. The PCR-branch policy sessions cannot encrypt, so the secret
// must still leave the TPM encrypted under a separate salted session.
func TestSessionEncryption_AutoUnsealThroughPCRBranch(t *testing.T) {
	h := newSimHarness(t, nil)
	secret := []byte("pkcs11-user-pin-AUTO-UNSEAL-4b8f")
	psrkAttrs := createPSRK(t, h, []byte("so-pin-e0a4c9173b"), []byte("user-pin-7f21c3a8d6"))

	// The auto-unseal path holds no PIN for the PSRK: it is authorized
	// through the PCR branch of its platform policy.
	pcrBranchParent := *psrkAttrs
	pcrBranchParent.Password = nil

	keyAttrs := &types.KeyAttributes{
		CN:             "session-encryption-auto-unseal",
		KeyType:        types.KeyTypeHMAC,
		Parent:         &pcrBranchParent,
		PlatformPolicy: true,
		SealData:       types.NewSealData(secret),
		StoreType:      types.StoreTPM2,
	}

	bus := capture(h)
	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)
	unsealed, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, unsealed)

	bus.RequireAbsent(t, "the auto-unsealed secret", secret)
	bus.RequireSessionAttr(t, tpm2.TPMCCCreate, tpmbus.SessionAttrDecrypt)
	bus.RequireSessionAttr(t, tpm2.TPMCCUnseal, tpmbus.SessionAttrEncrypt)
}

// TestSessionEncryption_NVSecretUnderOwnerAuth writes a secret to an NV index
// under the owner hierarchy's SO PIN and reads it back, proving neither the
// secret nor the SO PIN crosses the bus in plaintext.
func TestSessionEncryption_NVSecretUnderOwnerAuth(t *testing.T) {
	h := newSimHarness(t, nil)
	soPIN := []byte("so-pin-c61e0f2a97")
	secret := []byte("nv-sealed-SECRET-0b7d52")
	owner := tpm2.TPMRHOwner
	require.NoError(t, h.TPM.SetHierarchyAuth(nil, mustPassword(soPIN), &owner))

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	parent := *ekAttrs
	tpmAttrs := *ekAttrs.TPMAttributes
	tpmAttrs.HierarchyAuth = mustPassword(soPIN)
	parent.TPMAttributes = &tpmAttrs

	keyAttrs := &types.KeyAttributes{
		Parent:   &parent,
		SealData: types.NewSealData(secret),
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(nvramOwnerIndex),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	bus := capture(h)
	require.NoError(t, h.TPM.NVWrite(keyAttrs))
	got, err := h.TPM.NVRead(keyAttrs, uint16(len(secret)))
	require.NoError(t, err)
	require.Equal(t, secret, got)

	bus.RequireAbsent(t, "the NV secret", secret)
	bus.RequireAbsent(t, "the SO PIN", soPIN)
	bus.RequireSessionAttr(t, tpm2.TPMCCNVDefineSpace, tpmbus.SessionAttrDecrypt)
	bus.RequireSessionAttr(t, tpm2.TPMCCNVWrite, tpmbus.SessionAttrDecrypt)
	bus.RequireSessionAttr(t, tpm2.TPMCCNVRead, tpmbus.SessionAttrEncrypt)
	bus.RequireNoPasswordSession(t, tpm2.TPMCCNVWrite)
}

// TestSessionEncryption_GetRandomEncrypted proves random bytes drawn from the
// TPM -- key material wherever the TPM is the entropy source -- leave it
// encrypted: the bytes returned to the caller never appear in the response.
func TestSessionEncryption_GetRandomEncrypted(t *testing.T) {
	h := newSimHarness(t, nil)
	bus := capture(h)

	random := make([]byte, 32)
	n, err := h.TPM.readChunk(random, len(random))
	require.NoError(t, err)
	require.Equal(t, len(random), n)

	bus.RequireAbsent(t, "the random bytes", random)
	bus.RequireSessionAttr(t, tpm2.TPMCCGetRandom, tpmbus.SessionAttrEncrypt)
	bus.RequireAllSessionsSalted(t)
}

// TestSessionEncryption_SaltKeyWithoutEK proves saltKey falls back to an
// ephemeral NULL-hierarchy key only when no EK is resident, and releases it:
// with the EK handle pointed at an empty slot, the session still starts and
// no transient object is left behind.
func TestSessionEncryption_SaltKeyWithoutEK(t *testing.T) {
	h := newSimHarness(t, nil)
	h.TPM.config.EK.Handle = 0x81010FFF // an unpopulated persistent handle

	handle, pub, release, err := h.TPM.saltKey()
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMHTTransient, tpm2.TPMHT(handle>>24),
		"without an EK the salt key is a transient NULL-hierarchy key")
	require.Equal(t, tpm2.TPMAlgECC, pub.Type)
	require.NoError(t, release())

	_, _, err = h.TPM.ReadHandle(handle)
	require.Error(t, err, "release must flush the ephemeral salt key")

	session, closer, err := h.TPM.HMACSession([]byte("auth"))
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NoError(t, closer())
}

// TestSessionEncryption_SaltKeyReadFailure proves a salt key lookup that fails
// for any reason other than an absent EK is returned, never answered with an
// unsalted session.
func TestSessionEncryption_SaltKeyReadFailure(t *testing.T) {
	h := newSimHarness(t, nil)
	h.TPM.transport = failingTransport{}

	_, _, _, err := h.TPM.saltKey()
	require.ErrorIs(t, err, ErrSaltKey)

	_, _, err = h.TPM.HMACSession([]byte("auth"))
	require.ErrorIs(t, err, ErrSaltKey)
}
