//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers first-boot Platform SRK enrollment: the moment an operator's
// PIN becomes the authorization value of the TPM object that guards platform
// sealing. Each test owns one simulator via newSimHarness (the go-tpm-tools
// simulator is a process-global singleton, so only one may be live at a time).

// newEnrollHarness returns a harness whose configured EK and Shared SRK
// hierarchy auths match the empty hierarchy auth that provisioning actually
// installs.
//
// This matters: TPM2.ProvisionOwner OVERRIDES the configured hierarchy auth
// with the soPIN it was called with (provision.go). PlatformKeyStore never
// reads a hierarchy auth from configuration at all -- PlatformSRKConfig has
// no such field -- so the Platform SRK's owner-hierarchy authorization comes
// only from the soPIN argument threaded through
// Initialize/EnrollPlatformSRK/ensureSRKAuth at the moment of the operation.
// The harness provisions with Provision(nil), i.e. an empty hierarchy auth,
// so every owner-hierarchy command the key store issues with no soPIN
// argument matches what the TPM actually carries. See
// TestEnrollPlatformSRK_OwnerHierarchyAuth_SuppliedByCaller for the case
// where the TPM's owner hierarchy carries a real auth value.
func newEnrollHarness(t *testing.T) *simHarness {
	t.Helper()
	return newSimHarness(t, func(c *Config) {
		c.SSRK.HierarchyAuth = nil
		c.EK.HierarchyAuth = nil
	})
}

// newPlatformKeyStore builds a PlatformKeyStore over the harness's TPM and
// per-test storage. The PIN state file lives in the test's temp dir so nothing
// touches the host.
func newPlatformKeyStore(t *testing.T, h *simHarness) *PlatformKeyStore {
	t.Helper()

	pks, err := NewPlatformKeyStore(
		h.Logger,
		h.TPM,
		h.Backend,
		h.TPM.config,
		filepath.Join(t.TempDir(), "pin-state.json"),
	)
	require.NoError(t, err)
	return pks
}

// TestEnrollPlatformSRK_FirstBoot_CreatesSRKBoundToPIN proves enrollment
// actually creates the Platform SRK on the TPM and binds the operator PIN as
// its authorization value. Before enrollment the handle is empty; afterwards
// the correct PIN authorizes and a wrong PIN is rejected. This is the whole
// point of enrollment, so all three properties are asserted together.
func TestEnrollPlatformSRK_FirstBoot_CreatesSRKBoundToPIN(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	srkHandle := tpm2.TPMHandle(h.TPM.config.PlatformSRK.SRKHandle)
	_, _, err := h.TPM.ReadHandle(srkHandle)
	require.Error(t, err, "precondition: the platform SRK must not exist before enrollment")
	require.False(t, pks.IsAuthReady(), "precondition: auth must not be ready before enrollment")

	const userPIN = "operator-pin-4821"
	require.NoError(t, pks.EnrollPlatformSRK("", userPIN))

	// The SRK now exists on the TPM at the configured handle.
	name, _, err := h.TPM.ReadHandle(srkHandle)
	require.NoError(t, err, "enrollment must persist the platform SRK")
	assert.NotEmpty(t, name.Buffer)

	assert.True(t, pks.IsAuthReady(), "enrollment must leave the auth state ready")
	assert.True(t, pks.IsInitialized())
	assert.True(t, pks.IsProvisioned())

	// The enrolled PIN authorizes; anything else does not.
	assert.NoError(t, pks.VerifyAuth(userPIN),
		"the enrolled PIN must authorize against the platform SRK")
	assert.ErrorIs(t, pks.VerifyAuth("not-the-pin"), ErrAuthFailed,
		"a wrong PIN must be reported as an auth failure, not a generic error")
}

// TestEnrollPlatformSRK_SecondBoot_IsIdempotent proves the daemon can call
// enrollment unconditionally on every boot. Once the SRK auth is in a known-good
// state, a second enrollment must report ErrPlatformSRKAlreadyEnrolled rather
// than re-creating the SRK -- re-creating it would destroy every object sealed
// under the previous SRK.
func TestEnrollPlatformSRK_SecondBoot_IsIdempotent(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	const userPIN = "operator-pin-4821"
	require.NoError(t, pks.EnrollPlatformSRK("", userPIN))

	srkHandle := tpm2.TPMHandle(h.TPM.config.PlatformSRK.SRKHandle)
	nameBefore, _, err := h.TPM.ReadHandle(srkHandle)
	require.NoError(t, err)

	err = pks.EnrollPlatformSRK("", userPIN)
	assert.ErrorIs(t, err, ErrPlatformSRKAlreadyEnrolled,
		"a repeat enrollment must be reported as already-enrolled, not as a failure")

	nameAfter, _, err := h.TPM.ReadHandle(srkHandle)
	require.NoError(t, err)
	assert.Equal(t, nameBefore.Buffer, nameAfter.Buffer,
		"a repeat enrollment must not replace the platform SRK; doing so would "+
			"orphan every object sealed under it")

	// The original PIN must still work after the no-op second enrollment.
	assert.NoError(t, pks.VerifyAuth(userPIN))
}

// TestEnrollPlatformSRK_EmptyPIN_Rejected proves an empty PIN cannot be
// enrolled. An SRK with an empty auth value would be usable by any process on
// the machine, silently defeating the PIN.
func TestEnrollPlatformSRK_EmptyPIN_Rejected(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	err := pks.EnrollPlatformSRK("", "")
	assert.ErrorIs(t, err, ErrPlatformSRKEnrollEmptyPIN)

	srkHandle := tpm2.TPMHandle(h.TPM.config.PlatformSRK.SRKHandle)
	_, _, readErr := h.TPM.ReadHandle(srkHandle)
	assert.Error(t, readErr,
		"a rejected enrollment must not have created an SRK")
	assert.False(t, pks.IsAuthReady())
}

// TestPlatformKeyStore_ChangeAuth_RotatesPIN proves a PIN change is a real
// rotation on the TPM: the new PIN authorizes afterwards and the old one stops
// working. A rotation that left the old PIN valid would be a security defect.
func TestPlatformKeyStore_ChangeAuth_RotatesPIN(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	const oldPIN = "original-pin-1111"
	const newPIN = "rotated-pin-2222"
	require.NoError(t, pks.EnrollPlatformSRK("", oldPIN))
	require.NoError(t, pks.VerifyAuth(oldPIN))

	require.NoError(t, pks.ChangeAuth(oldPIN, newPIN))

	assert.NoError(t, pks.VerifyAuth(newPIN),
		"the rotated PIN must authorize after the change")
	assert.ErrorIs(t, pks.VerifyAuth(oldPIN), ErrAuthFailed,
		"the superseded PIN must no longer authorize")
}

// TestPlatformKeyStore_ChangeAuth_WrongCurrentPIN_Rejected proves a PIN change
// requires knowledge of the current PIN. Without this check anyone able to call
// the API could lock the real operator out.
func TestPlatformKeyStore_ChangeAuth_WrongCurrentPIN_Rejected(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	const goodPIN = "original-pin-1111"
	require.NoError(t, pks.EnrollPlatformSRK("", goodPIN))

	err := pks.ChangeAuth("wrong-current-pin", "attacker-chosen-pin")
	assert.ErrorIs(t, err, ErrAuthFailed,
		"a PIN change must not proceed without the current PIN")

	// The original PIN must be untouched, and the attacker's must not work.
	assert.NoError(t, pks.VerifyAuth(goodPIN),
		"a rejected PIN change must leave the original PIN in force")
	assert.ErrorIs(t, pks.VerifyAuth("attacker-chosen-pin"), ErrAuthFailed)
}

// TestPlatformKeyStore_UninitializedOperations_ReturnTypedError proves the
// operations that require an initialized store report that precisely, rather
// than dereferencing a nil SRK or reporting a bogus auth failure.
func TestPlatformKeyStore_UninitializedOperations_ReturnTypedError(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	require.False(t, pks.IsInitialized(), "precondition: the store is not initialized")

	assert.ErrorIs(t, pks.VerifyAuth("any-pin"), ErrPlatformKeyStoreNotInitialized)
	assert.ErrorIs(t, pks.ChangeAuth("any-pin", "new-pin"), ErrPlatformKeyStoreNotInitialized)
}

// TestNewPlatformKeyStore_InvalidArguments_ReturnTypedErrors covers the
// constructor's precondition checks. Each missing collaborator must be named
// specifically so a misconfiguration is diagnosable.
func TestNewPlatformKeyStore_InvalidArguments_ReturnTypedErrors(t *testing.T) {
	h := newSimHarness(t, nil)
	statePath := filepath.Join(t.TempDir(), "pin-state.json")

	t.Run("nil TPM", func(t *testing.T) {
		pks, err := NewPlatformKeyStore(h.Logger, nil, h.Backend, h.TPM.config, statePath)
		assert.Nil(t, pks)
		assert.ErrorIs(t, err, ErrPlatformKeyStoreNilTPM)
	})
	t.Run("nil backend", func(t *testing.T) {
		pks, err := NewPlatformKeyStore(h.Logger, h.TPM, nil, h.TPM.config, statePath)
		assert.Nil(t, pks)
		assert.ErrorIs(t, err, ErrPlatformKeyStoreNilBackend)
	})
	t.Run("nil config", func(t *testing.T) {
		pks, err := NewPlatformKeyStore(h.Logger, h.TPM, h.Backend, nil, statePath)
		assert.Nil(t, pks)
		assert.ErrorIs(t, err, ErrPlatformKeyStoreNilConfig)
	})
}

// TestPlatformKeyStore_SRKAttributes_TrackEnrollment proves the cached SRK
// attributes become usable only after enrollment, and then describe the handle
// the SRK was actually created at. TPM2.PlatformSRKAttributes syncs from these,
// so stale or wrong values here surface later as TPM_RC_BAD_AUTH during sealing.
func TestPlatformKeyStore_SRKAttributes_TrackEnrollment(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	require.NoError(t, pks.EnrollPlatformSRK("", "operator-pin-4821"))

	attrs := pks.SRKAttributes()
	require.NotNil(t, attrs)
	require.NotNil(t, attrs.TPMAttributes)
	assert.Equal(t, tpm2.TPMHandle(h.TPM.config.PlatformSRK.SRKHandle),
		attrs.TPMAttributes.Handle,
		"the cached attributes must describe the enrolled handle")

	// TPM2.PlatformSRKAttributes must now resolve, syncing from the key store.
	h.TPM.SetPlatformKeyStore(pks)
	t.Cleanup(func() { h.TPM.SetPlatformKeyStore(nil) })

	tpmAttrs, err := h.TPM.PlatformSRKAttributes()
	require.NoError(t, err,
		"the platform SRK must resolve once the key store has enrolled it")
	assert.Equal(t, attrs.TPMAttributes.Handle, tpmAttrs.TPMAttributes.Handle,
		"TPM2 must report the same platform SRK the key store enrolled")

	assert.Same(t, pks, h.TPM.PlatformKeyStore(),
		"the TPM must expose the key store that was installed on it")
}

// TestPlatformKeyStore_GetLockoutInfo_ReportsTPMCounters proves the lockout
// report is sourced from the TPM's real dictionary-attack properties and is
// self-consistent, rather than returning the hardcoded fallback values.
func TestPlatformKeyStore_GetLockoutInfo_ReportsTPMCounters(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	failed, maxFail, interval, recovery, err := pks.GetLockoutInfo()
	require.NoError(t, err)

	assert.GreaterOrEqual(t, maxFail, 1,
		"a TPM must tolerate at least one auth failure before lockout")
	assert.LessOrEqual(t, failed, maxFail,
		"the failed-attempt count cannot exceed the configured maximum")
	assert.GreaterOrEqual(t, interval, 0)
	assert.GreaterOrEqual(t, recovery, 0)

	props, err := h.TPM.FixedProperties()
	require.NoError(t, err)
	assert.Equal(t, int(props.MaxAuthFail), maxFail,
		"GetLockoutInfo must report the TPM's own MaxAuthFail property")
	assert.Equal(t, int(props.LockoutCounter), failed,
		"GetLockoutInfo must report the TPM's own lockout counter")
}

// TestEnrollPlatformSRK_OwnerHierarchyAuth_SuppliedByCaller proves the fix for
// the defect this file previously only diagnosed: the Platform SRK is a
// persistent object in the TPM owner hierarchy, so a hierarchy carrying an auth
// value can only be enrolled by a caller that supplies it. EnrollPlatformSRK
// used to hardcode an empty owner hierarchy auth, which made first-boot
// enrollment impossible on any TPM that ProvisionOwner had given one -- the
// deployed configuration for every operator who set an SO PIN.
//
// The harness provisions with an empty owner auth and then installs a real one,
// which is exactly the state ProvisionOwner(soPIN) leaves behind. Configuration
// supplies no Platform SRK hierarchy auth at all -- PlatformSRKConfig has no
// such field -- so nothing but the caller's argument can satisfy the TPM.
func TestEnrollPlatformSRK_OwnerHierarchyAuth_SuppliedByCaller(t *testing.T) {
	const ownerAuth = "owner-hierarchy-secret"
	const userPIN = "operator-pin-4821"

	h := newEnrollHarness(t)

	ownerHierarchy := tpm2.TPMRHOwner
	require.NoError(t,
		h.TPM.SetHierarchyAuth(nil, mustPassword(t, []byte(ownerAuth)), &ownerHierarchy),
		"precondition: the owner hierarchy must carry an auth value")
	t.Cleanup(func() {
		// Hand the hierarchy back unauthenticated so the harness teardown and
		// any simulator-wide state observe the value they started with.
		_ = h.TPM.SetHierarchyAuth(mustPassword(t, []byte(ownerAuth)), nil, &ownerHierarchy)
	})

	pks := newPlatformKeyStore(t, h)

	// Without the hierarchy auth the TPM refuses to create the persistent SRK,
	// and the failure names the hierarchy rather than surfacing a bare
	// TPM_RC_BAD_AUTH.
	err := pks.EnrollPlatformSRK("", userPIN)
	require.Error(t, err,
		"enrollment must not succeed without the owner hierarchy auth")
	assert.ErrorIs(t, err, ErrPlatformSRKHierarchyAuth)
	assert.False(t, pks.IsAuthReady())

	srkHandle := tpm2.TPMHandle(h.TPM.config.PlatformSRK.SRKHandle)
	_, _, readErr := h.TPM.ReadHandle(srkHandle)
	require.Error(t, readErr,
		"a rejected enrollment must not have created an SRK")

	// Supplying it enrolls for real: the SRK exists and the operator PIN is
	// bound to it as the authorization value.
	require.NoError(t, pks.EnrollPlatformSRK(ownerAuth, userPIN),
		"the owner hierarchy auth supplied by the caller must be honoured")

	name, _, err := h.TPM.ReadHandle(srkHandle)
	require.NoError(t, err, "enrollment must persist the platform SRK")
	assert.NotEmpty(t, name.Buffer)

	assert.True(t, pks.IsAuthReady())
	assert.NoError(t, pks.VerifyAuth(userPIN),
		"the enrolled PIN must authorize against the platform SRK")
	assert.ErrorIs(t, pks.VerifyAuth("not-the-pin"), ErrAuthFailed)
}

// TestEnrollPlatformSRK_DefaultSealUnseal_PCRBranchUnattended proves the
// high-level TPM2.Seal/Unseal API -- the entry point the barrier's
// TPM2Strategy and PlatformSealer actually call through
// defaultSealKeyAttributes/defaultUnsealKeyAttributes -- authorizes the
// enrolled Platform SRK on its PolicyPCR branch with NO PlatformKeyStore
// attached to the TPM instance: exactly the state an unattended daemon boot
// is in before any operator has presented a PIN.
//
// Configuration is the source of truth here: TPM2.PlatformSRKAttributes
// takes PlatformPolicy from PlatformSRKAttributesFromConfig on this path too
// (not only when a PlatformKeyStore is attached to sync from), so
// CreateSession still selects PlatformPolicySession instead of a plain
// password session with empty auth bytes -- which would be refused with
// TPM_RC_AUTH_FAIL against the SRK's real, non-empty (enrolled) auth value.
func TestEnrollPlatformSRK_DefaultSealUnseal_PCRBranchUnattended(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	const userPIN = "operator-pin-4821"
	require.NoError(t, pks.EnrollPlatformSRK("", userPIN))

	// No PlatformKeyStore is attached to h.TPM: this is the unattended state.
	secret := []byte("auto-unsealed-through-the-default-api")
	ctx := context.Background()

	sealed, err := h.TPM.Seal(ctx, secret, nil)
	require.NoError(t, err,
		"sealing through the default API must succeed unattended, via the SRK's PCR branch")

	recovered, err := h.TPM.Unseal(ctx, sealed, nil)
	require.NoError(t, err,
		"unsealing through the default API must succeed unattended, via the SRK's PCR branch")
	assert.Equal(t, secret, recovered)

	// The platform changes state. Unattended, with no PIN to offer, the PCR
	// branch must refuse -- that is the platform binding working as intended,
	// not a defect: an unattended process that could still open this object
	// after the measurements moved would defeat the point of sealing to them.
	h.extendPlatformPCR(t, []byte("post-enrollment-measurement"))

	_, err = h.TPM.Unseal(ctx, sealed, nil)
	require.Error(t, err,
		"unattended unseal must not survive a platform change: there is no PIN to fall back to")
	assert.Equal(t, ErrPolicyCheckFailed, err)
}

// TestEnrollPlatformSRK_DefaultSealUnseal_PINBranchViaPlatformKeyStore proves
// the same high-level API authorizes the enrolled Platform SRK on its
// PolicyAuthValue branch once a PlatformKeyStore with the enrolled PIN is
// attached to the TPM instance (TPM2.PlatformSRKAttributes syncs the
// Password from it), and that this keeps working after the platform state
// changes -- the PIN, not the live PCR state, is what TPM2_Load checks on
// this branch.
func TestEnrollPlatformSRK_DefaultSealUnseal_PINBranchViaPlatformKeyStore(t *testing.T) {
	h := newEnrollHarness(t)
	pks := newPlatformKeyStore(t, h)

	const userPIN = "operator-pin-4821"
	require.NoError(t, pks.EnrollPlatformSRK("", userPIN))

	secret := []byte("sealed-through-the-default-api")
	ctx := context.Background()

	// TPM2.PlatformSRKAttributes syncs the enrolled Password onto the
	// resolved parent only once the PlatformKeyStore is attached, and the
	// session then authorizes the SRK on its PolicyAuthValue branch.
	h.TPM.SetPlatformKeyStore(pks)
	t.Cleanup(func() { h.TPM.SetPlatformKeyStore(nil) })

	sealed, err := h.TPM.Seal(ctx, secret, nil)
	require.NoError(t, err, "sealing must succeed on the PIN branch")

	recovered, err := h.TPM.Unseal(ctx, sealed, nil)
	require.NoError(t, err, "unsealing must succeed on the PIN branch")
	assert.Equal(t, secret, recovered)

	// The platform changes state. The PIN branch, still attached, must not
	// care -- this is the property that makes the PIN a real recovery path
	// rather than a second way to reach the same PCR-gated door.
	h.extendPlatformPCR(t, []byte("post-enrollment-measurement"))

	sealed2, err := h.TPM.Seal(ctx, secret, nil)
	require.NoError(t, err,
		"the PIN branch must still authorize the Platform SRK after a platform change")
	recovered2, err := h.TPM.Unseal(ctx, sealed2, nil)
	require.NoError(t, err)
	assert.Equal(t, secret, recovered2)
}
