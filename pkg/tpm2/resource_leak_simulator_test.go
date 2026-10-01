//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A TPM holds only a handful of transient object slots and authorization
// sessions. Any operation that abandons one on an error path degrades the
// device until the connection is torn down, and the failure then surfaces on an
// unrelated operation -- which is exactly what makes this bug class expensive to
// diagnose in the field. This package already carries one fix for it
// (auth_session_leak_simulator_test.go).
//
// The tests below assert that ordinary, caller-triggerable failures leave the
// TPM's transient object and session counts unchanged. Each test owns one
// simulator via newSimHarness; the go-tpm-tools simulator is a process-global
// singleton, so only one may be live at a time.

// tpmResourceCounts captures the TPM-side resources whose exhaustion breaks
// later, unrelated operations.
type tpmResourceCounts struct {
	transientObjects int
	loadedSessions   int
	savedSessions    int
}

// countTPMResources reads the live transient object and session counts.
func countTPMResources(t *testing.T, h *simHarness) tpmResourceCounts {
	t.Helper()

	handles, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	return tpmResourceCounts{
		transientObjects: len(handles),
		loadedSessions:   loadedSessionCount(t, h.TPM.transport),
		savedSessions:    savedSessionCount(t, h.TPM.transport),
	}
}

// TestUnsealKey_WrongPassword_LeaksNoResources proves the most common
// user-triggerable failure -- a wrong PIN on a sealed object -- is clean.
// A leak here would mean a user who mistypes their PIN a few times degrades the
// TPM until the daemon restarts, turning a recoverable mistake into an outage.
func TestUnsealKey_WrongPassword_LeaksNoResources(t *testing.T) {
	h := newSimHarness(t, nil)

	secret := []byte("pin-protected-secret")
	correct := mustPassword([]byte("correct-pin-0000"))
	keyAttrs := sealedKeyAttrs(t, h, "leak-check-sealed", false, correct)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	// Prime any lazily-created state so the baseline is stable.
	got, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	before := countTPMResources(t, h)

	const attempts = 20
	for i := 0; i < attempts; i++ {
		wrong := sealedKeyAttrs(t, h, "leak-check-sealed", false,
			mustPassword([]byte("wrong-pin")))
		out, err := h.TPM.UnsealKey(wrong, h.Backend)
		require.Error(t, err, "attempt %d: a wrong PIN must fail", i)
		require.Nil(t, out)
	}

	after := countTPMResources(t, h)
	assert.Equal(t, before.transientObjects, after.transientObjects,
		"%d wrong-PIN unseals must not strand transient objects", attempts)
	assert.Equal(t, before.loadedSessions, after.loadedSessions,
		"%d wrong-PIN unseals must not strand loaded sessions", attempts)
	assert.Equal(t, before.savedSessions, after.savedSessions,
		"%d wrong-PIN unseals must not strand saved sessions", attempts)

	// Sustained guessing must also have tripped the TPM's dictionary-attack
	// protection: after this many failures even the CORRECT PIN is refused.
	// That is the desired security behaviour -- brute-forcing a sealed object's
	// PIN must become impossible rather than merely slow -- and it is only
	// reachable because the object's auth value is DA-protected.
	_, err = h.TPM.UnsealKey(keyAttrs, h.Backend)
	assert.Error(t, err,
		"after %d wrong PINs the TPM must be in dictionary-attack lockout, "+
			"refusing even the correct PIN", attempts)
}

// TestUnsealKey_FewWrongPasswords_TPMStaysUsable is the counterpart to the
// lockout assertion above: a small number of mistyped PINs, below the TPM's
// configured maxAuthFail, must NOT lock the user out. Without this, a
// regression that locked the TPM on the first mistake would still satisfy the
// lockout test.
func TestUnsealKey_FewWrongPasswords_TPMStaysUsable(t *testing.T) {
	h := newSimHarness(t, nil)

	props, err := h.TPM.FixedProperties()
	require.NoError(t, err)
	require.Greater(t, props.MaxAuthFail, uint32(1),
		"precondition: the TPM must tolerate more than one auth failure")

	secret := []byte("pin-protected-secret")
	correct := mustPassword([]byte("correct-pin-0000"))
	keyAttrs := sealedKeyAttrs(t, h, "few-failures-sealed", false, correct)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err = h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	// Stay strictly below the lockout threshold.
	wrong := sealedKeyAttrs(t, h, "few-failures-sealed", false,
		mustPassword([]byte("wrong-pin")))
	out, err := h.TPM.UnsealKey(wrong, h.Backend)
	require.Error(t, err, "a wrong PIN must fail")
	require.Nil(t, out)

	recovered, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err,
		"a single mistyped PIN must not lock the user out of their own secret")
	assert.Equal(t, secret, recovered)
}

// TestUnsealKey_MissingKey_LeaksNoResources proves the "key not found" path --
// which the product itself documents as expected during fresh initialization --
// does not accumulate sessions. This path runs on every boot before the barrier
// is provisioned, so a leak would compound at exactly the worst moment.
func TestUnsealKey_MissingKey_LeaksNoResources(t *testing.T) {
	h := newSimHarness(t, nil)

	// Seal and unseal once so all lazily-initialized state exists.
	warmup := sealedKeyAttrs(t, h, "warmup-key", false, mustPassword([]byte("warmup-password")))
	warmup.SealData = types.NewSealData([]byte("warmup"))
	_, err := h.TPM.SealKey(warmup, h.Backend, true)
	require.NoError(t, err)
	_, err = h.TPM.UnsealKey(warmup, h.Backend)
	require.NoError(t, err)

	before := countTPMResources(t, h)

	const attempts = 20
	for i := 0; i < attempts; i++ {
		missing := sealedKeyAttrs(t, h, "no-such-sealed-object", false, nil)
		out, err := h.TPM.UnsealKey(missing, h.Backend)
		require.Error(t, err, "attempt %d: a missing key must fail", i)
		require.Nil(t, out)
	}

	after := countTPMResources(t, h)
	assert.Equal(t, before.transientObjects, after.transientObjects,
		"%d missing-key unseals must not strand transient objects", attempts)
	assert.Equal(t, before.loadedSessions, after.loadedSessions,
		"%d missing-key unseals must not strand loaded sessions", attempts)
	assert.Equal(t, before.savedSessions, after.savedSessions,
		"%d missing-key unseals must not strand saved sessions", attempts)
}

// TestLoadKeyPair_CorruptBlobs_LeakNoResources proves a corrupted or truncated
// stored blob -- disk corruption, a partial write, a tampered backup -- fails
// without accumulating TPM state.
func TestLoadKeyPair_CorruptBlobs_LeakNoResources(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "corruptible-key", x509.RSA, types.KeyTypeSigning)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)
	h.TPM.Flush(attrs.TPMAttributes.Handle)

	priv, err := h.Backend.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	require.NotEmpty(t, priv)

	corrupted := append([]byte(nil), priv...)
	corrupted[len(corrupted)-1] ^= 0xFF
	require.NoError(t, h.Backend.Save(attrs, corrupted, store.FSEXT_PRIVATE_BLOB, true))

	before := countTPMResources(t, h)

	const attempts = 15
	for i := 0; i < attempts; i++ {
		loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
		require.Error(t, err, "attempt %d: a corrupted private blob must not load", i)
		require.Nil(t, loaded)
	}

	after := countTPMResources(t, h)
	assert.Equal(t, before.transientObjects, after.transientObjects,
		"%d failed loads must not strand transient objects", attempts)
	assert.Equal(t, before.loadedSessions, after.loadedSessions,
		"%d failed loads must not strand loaded sessions", attempts)
	assert.Equal(t, before.savedSessions, after.savedSessions,
		"%d failed loads must not strand saved sessions", attempts)
}

// TestSealKey_OversizedSecret_LeaksNoResources proves that rejecting a secret
// too large for TPM2B_SENSITIVE_DATA is clean. The rejection happens inside
// TPM2_Create, after the authorization session has been established, so this
// exercises the session-cleanup path specifically.
func TestSealKey_OversizedSecret_LeaksNoResources(t *testing.T) {
	h := newSimHarness(t, nil)

	warmup := sealedKeyAttrs(t, h, "warmup-key", false, mustPassword([]byte("warmup-password")))
	warmup.SealData = types.NewSealData([]byte("warmup"))
	_, err := h.TPM.SealKey(warmup, h.Backend, true)
	require.NoError(t, err)

	before := countTPMResources(t, h)

	oversized := make([]byte, 4096)
	const attempts = 15
	for i := 0; i < attempts; i++ {
		attrs := sealedKeyAttrs(t, h, "oversized-secret", false, mustPassword([]byte("oversized-password")))
		attrs.SealData = types.NewSealData(oversized)
		resp, err := h.TPM.SealKey(attrs, h.Backend, true)
		require.Error(t, err, "attempt %d: an oversized secret must be rejected", i)
		require.Nil(t, resp)
	}

	after := countTPMResources(t, h)
	assert.Equal(t, before.transientObjects, after.transientObjects,
		"%d oversized seals must not strand transient objects", attempts)
	assert.Equal(t, before.loadedSessions, after.loadedSessions,
		"%d oversized seals must not strand loaded sessions", attempts)
	assert.Equal(t, before.savedSessions, after.savedSessions,
		"%d oversized seals must not strand saved sessions", attempts)

	// The TPM must still be able to seal afterwards.
	ok := sealedKeyAttrs(t, h, "post-rejection-key", false, mustPassword([]byte("post-rejection-password")))
	ok.SealData = types.NewSealData([]byte("still works"))
	_, err = h.TPM.SealKey(ok, h.Backend, true)
	assert.NoError(t, err, "the TPM must remain usable after repeated rejections")
}

// TestDeleteKey_UnknownKey_LeaksNoResources proves repeated deletion of a
// non-existent key is clean. Deletion of an already-absent key is a normal
// idempotent-cleanup pattern, so it must not degrade the device.
func TestDeleteKey_UnknownKey_LeaksNoResources(t *testing.T) {
	h := newSimHarness(t, nil)

	warmup := childKeyAttrs(t, h, "warmup-rsa", x509.RSA, types.KeyTypeSigning)
	_, err := h.TPM.CreateRSA(warmup, h.Backend, true)
	require.NoError(t, err)
	h.TPM.Flush(warmup.TPMAttributes.Handle)

	before := countTPMResources(t, h)

	const attempts = 15
	for i := 0; i < attempts; i++ {
		missing := childKeyAttrs(t, h, "never-existed-key", x509.RSA, types.KeyTypeSigning)
		require.Error(t, h.TPM.DeleteKey(missing, h.Backend),
			"attempt %d: deleting a non-existent key must fail", i)
	}

	after := countTPMResources(t, h)
	assert.Equal(t, before.transientObjects, after.transientObjects,
		"%d failed deletes must not strand transient objects", attempts)
	assert.Equal(t, before.loadedSessions, after.loadedSessions,
		"%d failed deletes must not strand loaded sessions", attempts)
	assert.Equal(t, before.savedSessions, after.savedSessions,
		"%d failed deletes must not strand saved sessions", attempts)
}

// TestPlatformPolicySession_RepeatedUse_LeaksNoSessions proves the canonical
// policy-session entry point closes what it opens, on both branches. It is
// called on every platform-sealed unseal, so a leak of even one session per
// call would exhaust the TPM within a few dozen operations.
func TestPlatformPolicySession_RepeatedUse_LeaksNoSessions(t *testing.T) {
	h := newSimHarness(t, nil)

	// Prime the policy digest cache so the baseline is stable.
	session, closer, err := h.TPM.PlatformPolicySession(nil)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NoError(t, closer())

	before := countTPMResources(t, h)

	const iterations = 25
	t.Run("PCR branch", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			s, close, err := h.TPM.PlatformPolicySession(nil)
			require.NoError(t, err, "iteration %d: the PCR branch must succeed", i)
			require.NotNil(t, s)
			require.NoError(t, close())
		}
	})

	t.Run("password branch", func(t *testing.T) {
		for i := 0; i < iterations; i++ {
			s, close, err := h.TPM.PlatformPolicySession([]byte("a-platform-pin"))
			require.NoError(t, err, "iteration %d: the password branch must succeed", i)
			require.NotNil(t, s)
			require.NoError(t, close())
		}
	})

	after := countTPMResources(t, h)
	assert.Equal(t, before.loadedSessions, after.loadedSessions,
		"%d policy sessions across both branches must all be closed", 2*iterations)
	assert.Equal(t, before.savedSessions, after.savedSessions,
		"no policy session may be left saved in TPM memory")
}

// TestPlatformPolicySession_BothBranchesProduceSameDigest proves the PolicyOR
// construction works as designed: the PCR branch and the password branch must
// satisfy the SAME final policy digest, because that single digest is what gets
// bound to sealed objects as their AuthPolicy. If the branches produced
// different digests, one of the two unlock paths could never open anything.
func TestPlatformPolicySession_BothBranchesProduceSameDigest(t *testing.T) {
	h := newSimHarness(t, nil)

	_, closePCR, err := h.TPM.PlatformPolicySession(nil)
	require.NoError(t, err)
	pcrDigest := append([]byte(nil), h.TPM.policyDigest.Buffer...)
	require.NoError(t, closePCR())
	require.NotEmpty(t, pcrDigest, "the PCR branch must produce a policy digest")

	_, closePw, err := h.TPM.PlatformPolicySession([]byte("a-platform-pin"))
	require.NoError(t, err)
	pwDigest := append([]byte(nil), h.TPM.policyDigest.Buffer...)
	require.NoError(t, closePw())

	assert.Equal(t, pcrDigest, pwDigest,
		"both PolicyOR branches must satisfy the same policy digest, otherwise one "+
			"of the two unlock paths can never open a sealed object")

	// And that digest must be the one attached to sealed objects.
	bound, err := h.TPM.PlatformPolicyDigest()
	require.NoError(t, err)
	assert.Equal(t, bound.Buffer, pcrDigest,
		"the session digest must equal the digest bound to sealed objects")
}

// TestPlatformPolicySession_InvalidPCRBank_ReturnsTypedError covers the
// misconfiguration path of the canonical policy entry point.
func TestPlatformPolicySession_InvalidPCRBank_ReturnsTypedError(t *testing.T) {
	h := newSimHarness(t, nil)

	before := countTPMResources(t, h)

	saved := h.TPM.config.PlatformPCRBank
	h.TPM.config.PlatformPCRBank = "not-a-hash-algorithm"
	t.Cleanup(func() { h.TPM.config.PlatformPCRBank = saved })

	session, closer, err := h.TPM.PlatformPolicySession(nil)
	require.Error(t, err, "an unknown PCR bank must be rejected")
	assert.Nil(t, session)
	assert.Nil(t, closer)
	assert.ErrorIs(t, err, ErrPlatformPolicySession)

	after := countTPMResources(t, h)
	assert.Equal(t, before.loadedSessions, after.loadedSessions,
		"a rejected policy session must not have opened a session")
}
