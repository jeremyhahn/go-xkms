//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
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

// newEnrollHarness returns a harness whose configured SSRK hierarchy auth
// matches the hierarchy auth that provisioning actually installs.
//
// This matters: TPM2.ProvisionOwner OVERRIDES the configured hierarchy auth
// with the soPIN it was called with (provision.go), whereas the PlatformKeyStore
// derives its own hierarchy auth from config.SSRK.HierarchyAuth verbatim
// (buildSRKAttrsFromConfig). The harness provisions with Provision(nil), i.e.
// an empty hierarchy auth, so the config must say the same or every owner-
// hierarchy command from the key store fails with TPM_RC_BAD_AUTH. See
// TestEnrollPlatformSRK_HierarchyAuthMismatch_ReportsBadAuth, which pins that
// divergence.
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

// TestEnrollPlatformSRK_HierarchyAuthMismatch_ReportsBadAuth pins the diagnosis
// emitted when the configured owner hierarchy auth is not the one the TPM
// actually carries.
//
// TPM2.ProvisionOwner overrides the configured hierarchy auth with the soPIN it
// was called with:
//
//	srkAttrs.TPMAttributes.HierarchyAuth = soPIN
//
// so the auth actually installed on the TPM is whatever Provision() received.
// PlatformKeyStore, by contrast, builds its SRK attributes via
// buildSRKAttrsFromConfig, which takes config.SSRK.HierarchyAuth verbatim and
// never learns what Provision() actually used.
//
// When those two disagree -- the default in this package's own sample config,
// which declares "changeme" while Provision(nil) installs an empty auth --
// first-boot enrollment fails. It used to fail with a bare TPM_RC_BAD_AUTH
// naming neither the hierarchy nor the mismatch; it now reports
// ErrPlatformSRKHierarchyAuth, which names both and says how to supply the auth.
//
// The caller-supplied soPIN cannot rescue this particular configuration: the
// hierarchy the TPM carries here is the EMPTY one, and an empty soPIN means
// "leave the configured hierarchy auth in force" rather than "the hierarchy auth
// is empty". Supplying a non-empty owner hierarchy auth IS honoured -- see
// TestEnrollPlatformSRK_OwnerHierarchyAuth_SuppliedByCaller.
func TestEnrollPlatformSRK_HierarchyAuthMismatch_ReportsBadAuth(t *testing.T) {
	// Provision(nil) installs an EMPTY owner hierarchy auth...
	h := newSimHarness(t, nil)
	// ...while the default config claims a non-empty one.
	require.NotEmpty(t, h.TPM.config.SSRK.HierarchyAuth,
		"precondition: the sample config declares a hierarchy auth")

	pks := newPlatformKeyStore(t, h)

	err := pks.EnrollPlatformSRK("", "operator-pin-4821")
	require.Error(t, err,
		"a hierarchy auth mismatch must not silently enroll")
	assert.ErrorIs(t, err, ErrPlatformSRKHierarchyAuth,
		"the failure must name the owner hierarchy and the missing auth value")
	assert.True(t, isTPMBadAuth(err) || isTPMAuthError(err),
		"the underlying TPM authorization failure must still be unwrappable, got %v", err)

	assert.False(t, pks.IsAuthReady(),
		"a failed enrollment must not report the auth state as ready")
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
// which is exactly the state ProvisionOwner(soPIN) leaves behind, while the
// configured SRK hierarchy auth stays empty so nothing but the caller's argument
// can satisfy the TPM.
func TestEnrollPlatformSRK_OwnerHierarchyAuth_SuppliedByCaller(t *testing.T) {
	const ownerAuth = "owner-hierarchy-secret"
	const userPIN = "operator-pin-4821"

	h := newEnrollHarness(t)
	require.Empty(t, h.TPM.config.SSRK.HierarchyAuth,
		"precondition: the config must supply no hierarchy auth, so only the "+
			"caller's argument can authorize the owner hierarchy")

	ownerHierarchy := tpm2.TPMRHOwner
	require.NoError(t,
		h.TPM.SetHierarchyAuth(nil, mustPassword([]byte(ownerAuth)), &ownerHierarchy),
		"precondition: the owner hierarchy must carry an auth value")
	t.Cleanup(func() {
		// Hand the hierarchy back unauthenticated so the harness teardown and
		// any simulator-wide state observe the value they started with.
		_ = h.TPM.SetHierarchyAuth(mustPassword([]byte(ownerAuth)), nil, &ownerHierarchy)
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
