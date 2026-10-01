//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// loadSealedObject loads a sealed object's blobs under its parent and returns
// the transient handle, flushed when the test ends. It does nothing an
// attacker holding the blobs and the parent's authorization could not do.
func loadSealedObject(t *testing.T, h *simHarness, attrs *types.KeyAttributes) *tpm2.LoadResponse {
	t.Helper()
	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	t.Cleanup(func() { h.TPM.Flush(loaded.ObjectHandle) })
	return loaded
}

// requireUnsealRefused asserts that TPM2_Unseal of loaded under auth is
// refused by the TPM with one of the given response codes.
func requireUnsealRefused(
	t *testing.T,
	h *simHarness,
	loaded *tpm2.LoadResponse,
	auth tpm2.Session,
	codes ...tpm2.TPMRC) {

	t.Helper()
	out, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   auth,
		},
	}.Execute(h.TPM.transport)
	require.Error(t, err, "the TPM released a policy-sealed secret: %q", unsealedBytes(out))
	for _, code := range codes {
		if errors.Is(err, code) {
			return
		}
	}
	t.Fatalf("unseal refused with %v, want one of %v", err, codes)
}

// unsealedBytes returns the secret a successful unseal released, for the
// failure message.
func unsealedBytes(out *tpm2.UnsealResponse) []byte {
	if out == nil {
		return nil
	}
	return out.OutData.Buffer
}

// TestSeal_PlatformPolicyWithoutPassword_EmptyPasswordUnsealRefused is the
// proof for the USERWITHAUTH bypass. A secret sealed to the platform policy
// with no password must not answer its USER role to a plain empty-password
// authorization: that would release it without evaluating the policy at all.
// The platform PCR is moved first, so the only thing that could open the
// object is a path that skips the policy.
func TestSeal_PlatformPolicyWithoutPassword_EmptyPasswordUnsealRefused(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := sealedKeyAttrs(t, h, "bypass-userwithauth", true, nil)
	attrs.SealData = types.NewSealData([]byte("policy-bound-secret"))
	_, err := h.TPM.SealKey(attrs, h.Backend, true)
	require.NoError(t, err)

	h.extendPlatformPCR(t, []byte("tampered-boot"))

	loaded := loadSealedObject(t, h, attrs)
	requireUnsealRefused(t, h, loaded, tpm2.PasswordAuth(nil), tpm2.TPMRCAuthUnavailable)
}

// TestSeal_PlatformPolicyWithoutPassword_EmptyAuthValueBranchRefused proves
// the platform policy of a passwordless object carries no PolicyAuthValue
// branch. Such a branch is satisfied by the object's empty authValue, so a
// session taking it would open the object on any platform state.
func TestSeal_PlatformPolicyWithoutPassword_EmptyAuthValueBranchRefused(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := sealedKeyAttrs(t, h, "bypass-authvalue-branch", true, nil)
	attrs.SealData = types.NewSealData([]byte("policy-bound-secret"))
	_, err := h.TPM.SealKey(attrs, h.Backend, true)
	require.NoError(t, err)

	pin, err := h.TPM.loadPlatformPolicyPin(attrs, h.Backend)
	require.NoError(t, err)
	require.NotNil(t, pin)

	h.extendPlatformPCR(t, []byte("tampered-boot"))

	loaded := loadSealedObject(t, h, attrs)
	session, closer, err := h.TPM.platformPolicySession([]byte{}, pin)
	require.NoError(t, err)
	defer h.TPM.closeSession(closer, "attack session")
	requireUnsealRefused(t, h, loaded, session, tpm2.TPMRCPolicyFail)
}

// TestSeal_NamedPolicyWithoutPassword_EmptyPasswordUnsealRefused proves the
// same for an object bound to a named, authorized policy.
func TestSeal_NamedPolicyWithoutPassword_EmptyPasswordUnsealRefused(t *testing.T) {
	f := newPolicyFixture(t)
	attrs := sealedKeyAttrsUnder(f.srk, "bypass-named", nil)
	attrs.TPMPolicy = testPolicyName
	attrs.SealData = types.NewSealData([]byte("policy-bound-secret"))
	_, err := f.h.TPM.SealKey(attrs, f.h.Backend, false)
	require.NoError(t, err)

	loaded := loadSealedObject(t, f.h, attrs)
	requireUnsealRefused(t, f.h, loaded, tpm2.PasswordAuth(nil), tpm2.TPMRCAuthUnavailable)
}

// TestSeal_PlatformPolicyWithPassword_PasswordAloneRefused proves a password
// on a policy-bound object is only honoured inside the policy: a plain
// password authorization carrying the correct password is still refused.
func TestSeal_PlatformPolicyWithPassword_PasswordAloneRefused(t *testing.T) {
	h := newSimHarness(t, nil)
	pin := []byte("object-recovery-pin")
	attrs := sealedKeyAttrs(t, h, "bypass-password-only", true, mustPassword(pin))
	attrs.SealData = types.NewSealData([]byte("policy-bound-secret"))
	_, err := h.TPM.SealKey(attrs, h.Backend, true)
	require.NoError(t, err)

	loaded := loadSealedObject(t, h, attrs)
	requireUnsealRefused(t, h, loaded, tpm2.PasswordAuth(pin), tpm2.TPMRCAuthUnavailable)
}

// requireUserWithAuth asserts the USERWITHAUTH attribute of the sealed
// object the TPM loaded for attrs.
func requireUserWithAuth(t *testing.T, h *simHarness, attrs *types.KeyAttributes, want bool) {
	t.Helper()
	loaded := loadSealedObject(t, h, attrs)
	authPolicy, err := h.TPM.objectAuthPolicy(loaded.ObjectHandle)
	require.NoError(t, err)
	pub, err := tpm2.ReadPublic{ObjectHandle: loaded.ObjectHandle}.Execute(h.TPM.transport)
	require.NoError(t, err)
	public, err := pub.OutPublic.Contents()
	require.NoError(t, err)
	require.Equal(t, want, public.ObjectAttributes.UserWithAuth)
	require.Equal(t, !want, len(authPolicy) > 0, "USERWITHAUTH is cleared exactly when the object has a policy")
}

// TestSeal_PlatformPolicyWithoutPassword_RoundTrip proves a passwordless
// platform seal still opens through its PolicyPCR session on the platform
// state it was sealed on -- including for a caller that does not name the
// policy at unseal -- and is refused once that state moves.
func TestSeal_PlatformPolicyWithoutPassword_RoundTrip(t *testing.T) {
	h := newSimHarness(t, nil)
	secret := []byte("pcr-only-secret")
	attrs := sealedKeyAttrs(t, h, "pcr-only", true, nil)
	attrs.SealData = types.NewSealData(secret)
	_, err := h.TPM.SealKey(attrs, h.Backend, true)
	require.NoError(t, err)
	requireUserWithAuth(t, h, attrs, false)

	got, err := h.TPM.UnsealKey(sealedKeyAttrs(t, h, "pcr-only", true, nil), h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	unnamed := sealedKeyAttrs(t, h, "pcr-only", false, nil)
	got, err = h.TPM.UnsealKey(unnamed, h.Backend)
	require.NoError(t, err, "the object, not the caller's attributes, names its policy")
	require.Equal(t, secret, got)

	h.extendPlatformPCR(t, []byte("tampered-boot"))
	_, err = h.TPM.UnsealKey(sealedKeyAttrs(t, h, "pcr-only", true, nil), h.Backend)
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail)

	_, err = h.TPM.UnsealKey(sealedKeyAttrs(t, h, "pcr-only", true,
		mustPassword([]byte("guess"))), h.Backend)
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail,
		"an object sealed without a password has no password branch to guess")
}

// TestSeal_PlatformPolicyWithPassword_RoundTrip proves both branches of a
// password-carrying platform seal: the PolicyPCR branch opens it without the
// password on the sealed platform state, the PolicyAuthValue branch opens it
// with the password after the state moves, and nothing else does.
func TestSeal_PlatformPolicyWithPassword_RoundTrip(t *testing.T) {
	h := newSimHarness(t, nil)
	secret := []byte("pcr-or-pin-secret")
	pin := []byte("object-recovery-pin")
	attrs := sealedKeyAttrs(t, h, "pcr-or-pin", true, mustPassword(pin))
	attrs.SealData = types.NewSealData(secret)
	_, err := h.TPM.SealKey(attrs, h.Backend, true)
	require.NoError(t, err)
	requireUserWithAuth(t, h, attrs, false)

	got, err := h.TPM.UnsealKey(sealedKeyAttrs(t, h, "pcr-or-pin", true, nil), h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	h.extendPlatformPCR(t, []byte("tampered-boot"))

	_, err = h.TPM.UnsealKey(sealedKeyAttrs(t, h, "pcr-or-pin", true, nil), h.Backend)
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail)

	got, err = h.TPM.UnsealKey(sealedKeyAttrs(t, h, "pcr-or-pin", true, mustPassword(pin)), h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	_, err = h.TPM.UnsealKey(sealedKeyAttrs(t, h, "pcr-or-pin", true,
		mustPassword([]byte("wrong-pin"))), h.Backend)
	require.ErrorIs(t, err, tpm2.TPMRCAuthFail)
}

// TestSeal_NamedPolicyWithPassword_RoundTrip proves an object bound to a
// named policy and a password opens only through the policy with the
// password, and the password alone is refused.
func TestSeal_NamedPolicyWithPassword_RoundTrip(t *testing.T) {
	f := newPolicyFixture(t)
	secret := []byte("named-and-pin-secret")
	pin := []byte("named-object-pin")
	attrs := sealedKeyAttrsUnder(f.srk, "named-pin", mustPassword(pin))
	attrs.TPMPolicy = testPolicyName
	attrs.SealData = types.NewSealData(secret)
	_, err := f.h.TPM.SealKey(attrs, f.h.Backend, false)
	require.NoError(t, err)
	requireUserWithAuth(t, f.h, attrs, false)

	got, err := f.h.TPM.UnsealKey(attrs, f.h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	loaded := loadSealedObject(t, f.h, attrs)
	requireUnsealRefused(t, f.h, loaded, tpm2.PasswordAuth(pin), tpm2.TPMRCAuthUnavailable)
}

// TestSeal_PasswordOnly_RoundTrip proves a seal bound to no policy keeps
// USERWITHAUTH and opens with its password, and with nothing else.
func TestSeal_PasswordOnly_RoundTrip(t *testing.T) {
	h := newSimHarness(t, nil)
	secret := []byte("password-only-secret")
	pin := []byte("object-password")
	attrs := sealedKeyAttrs(t, h, "password-only", false, mustPassword(pin))
	attrs.SealData = types.NewSealData(secret)
	_, err := h.TPM.SealKey(attrs, h.Backend, true)
	require.NoError(t, err)
	requireUserWithAuth(t, h, attrs, true)

	got, err := h.TPM.UnsealKey(sealedKeyAttrs(t, h, "password-only", false, mustPassword(pin)), h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	loaded := loadSealedObject(t, h, attrs)
	requireUnsealRefused(t, h, loaded, tpm2.PasswordAuth(nil), tpm2.TPMRCAuthFail, tpm2.TPMRCBadAuth)
}

// TestSeal_NeitherPolicyNorPassword_Refused proves a seal that would be
// protected by nothing is refused before any object is created.
func TestSeal_NeitherPolicyNorPassword_Refused(t *testing.T) {
	h := newSimHarness(t, nil)
	for name, password := range map[string]types.Password{
		"nil password":   nil,
		"empty password": mustPassword(nil),
	} {
		t.Run(name, func(t *testing.T) {
			attrs := sealedKeyAttrs(t, h, "unprotected", false, password)
			attrs.SealData = types.NewSealData([]byte("would-be-unprotected"))
			_, err := h.TPM.SealKey(attrs, h.Backend, true)
			require.ErrorIs(t, err, ErrSealUnprotected)

			_, err = h.Backend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
			require.Error(t, err, "a refused seal must leave no object behind")
		})
	}
}

// TestSeal_DefaultAttributes_RoundTrip proves the public Seal API with no
// key attributes binds a passwordless seal to the Platform SRK's platform
// policy rather than leaving it unprotected, and that it round-trips through
// Unseal.
func TestSeal_DefaultAttributes_RoundTrip(t *testing.T) {
	h := newSimHarness(t, nil)
	createPlatformPolicySRK(t, h, nil)

	secret := []byte("default-attrs-secret")
	sealed, err := h.TPM.Seal(context.Background(), secret, nil)
	require.NoError(t, err)

	contents, err := UnmarshalPublic(sealed.TPMPublic)
	require.NoError(t, err)
	require.False(t, contents.ObjectAttributes.UserWithAuth)
	require.NotEmpty(t, contents.AuthPolicy.Buffer)

	got, err := h.TPM.Unseal(context.Background(), sealed, nil)
	require.NoError(t, err)
	require.Equal(t, secret, got)
}

// TestSeal_CallerAuthPolicy_OnlyItsPolicySessionUnseals proves a seal bound
// to a caller-computed AuthPolicy digest -- here a PolicyPCR digest, the
// shape a systemd-tpm2 LUKS token carries -- has USERWITHAUTH clear, refuses
// an empty-password TPM2_Unseal, and opens to a policy session reaching the
// digest, as systemd-cryptsetup builds for a systemd-tpm2 token.
func TestSeal_CallerAuthPolicy_OnlyItsPolicySessionUnseals(t *testing.T) {
	h := newSimHarness(t, nil)
	digest, err := h.TPM.platformPCRPolicyDigest()
	require.NoError(t, err)

	secret := []byte("systemd-tpm2-volume-key")
	attrs := sealedKeyAttrs(t, h, "caller-auth-policy", false, nil)
	sealed, err := h.TPM.Seal(context.Background(), secret, &types.SealOptions{
		KeyAttributes: attrs,
		AuthPolicy:    digest.Buffer,
	})
	require.NoError(t, err, "an explicit AuthPolicy is a policy: the seal is not unprotected")

	public, err := UnmarshalPublic(sealed.TPMPublic)
	require.NoError(t, err)
	require.False(t, public.ObjectAttributes.UserWithAuth)
	require.Equal(t, digest.Buffer, public.AuthPolicy.Buffer)

	loaded := loadSealedObject(t, h, attrs)
	requireUnsealRefused(t, h, loaded, tpm2.PasswordAuth(nil), tpm2.TPMRCAuthUnavailable)

	session, closer, err := h.TPM.platformPCRSession()
	require.NoError(t, err)
	defer h.TPM.closeSession(closer, "caller policy session")
	out, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: session},
	}.Execute(h.TPM.transport)
	require.NoError(t, err, "a policy session reaching the digest must unseal")
	require.Equal(t, secret, out.OutData.Buffer)
}

// TestSeal_CallerAuthPolicy_Refusals proves the AuthPolicy option refuses a
// digest the object's name algorithm cannot carry and a seal that also names
// a TPM policy.
func TestSeal_CallerAuthPolicy_Refusals(t *testing.T) {
	h := newSimHarness(t, nil)

	_, err := h.TPM.Seal(context.Background(), []byte("x"), &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "auth-policy-short", false, nil),
		AuthPolicy:    make([]byte, 20),
	})
	require.ErrorIs(t, err, ErrSealAuthPolicySize)

	_, err = h.TPM.Seal(context.Background(), []byte("x"), &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "auth-policy-conflict", true, nil),
		AuthPolicy:    make([]byte, 32),
	})
	require.ErrorIs(t, err, ErrSealAuthPolicyConflict)
}
