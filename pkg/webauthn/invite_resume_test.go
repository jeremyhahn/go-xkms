package webauthn

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inviteAttestation runs the authenticator side of an invite ceremony and
// returns the raw attestation.
func (f *enrollFixture) inviteAttestation(t *testing.T, options *protocol.CredentialCreation, credential virtualwebauthn.Credential) string {
	t.Helper()
	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)
	return virtualwebauthn.CreateAttestationResponse(f.rp, virtualwebauthn.NewAuthenticator(), credential, *parsedOptions)
}

// enrolPendingInvitee creates a pending account and finishes its invite
// ceremony, storing one credential while the account stays pending (as when
// the activation afterwards fails). It returns the account and the enrolled
// credential, whose private key only the invitee's authenticator holds.
func (f *enrollFixture) enrolPendingInvitee(t *testing.T, email string) (User, virtualwebauthn.Credential) {
	t.Helper()
	ctx := context.Background()
	u := f.mustCreatePending(t, email)
	options, sessionID, err := f.svc.BeginInviteRegistration(ctx, u.WebAuthnID())
	require.NoError(t, err)
	credential := newEC2Credential(t)
	parsed, err := parseAttestationResponse(f.inviteAttestation(t, options, credential))
	require.NoError(t, err)
	_, err = f.svc.FinishInviteRegistration(ctx, sessionID, u.WebAuthnID(), parsed)
	require.NoError(t, err)
	return u, credential
}

func (f *enrollFixture) mustCreatePending(t *testing.T, email string) User {
	t.Helper()
	u, err := f.users.Create(context.Background(), email, email)
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecyclePending, nil)
	return u
}

func (f *enrollFixture) requirePending(t *testing.T, u User) {
	t.Helper()
	got, err := f.users.GetByID(context.Background(), u.WebAuthnID())
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.LifecyclePending, got.Lifecycle())
}

// A resume is a possession proof: begin issues a fresh WebAuthn get
// challenge for exactly the enrolled credential, and only that credential's
// valid assertion over it finishes, once.
func TestInviteResume_ValidAssertionResumesOnce(t *testing.T) {
	ctx := context.Background()
	f := newEnrollFixture(t, false)
	issuedAt := time.Now().Add(-time.Minute)
	a, credential := f.enrolPendingInvitee(t, "a@example.com")
	stored, err := f.creds.GetByUserID(ctx, a.WebAuthnID())
	require.NoError(t, err)
	require.Len(t, stored, 1)

	options, sessionID, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
	require.NoError(t, err)
	require.Len(t, options.Response.AllowedCredentials, 1)
	assert.Equal(t, stored[0].ID, []byte(options.Response.AllowedCredentials[0].CredentialID))

	assertion := f.assert(t, options, credential, nil)
	resumed, err := f.svc.FinishInviteResume(ctx, sessionID, a.WebAuthnID(), issuedAt, assertion)
	require.NoError(t, err)
	assert.Equal(t, a.WebAuthnID(), resumed.WebAuthnID())

	creds, err := f.creds.GetByUserID(ctx, a.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 1, "a resume stores no second credential")

	_, err = f.svc.FinishInviteResume(ctx, sessionID, a.WebAuthnID(), issuedAt, assertion)
	require.Error(t, err, "a replayed assertion is refused")
}

// Every finish without a valid assertion by the enrolled credential over the
// session's own challenge is refused, and the account stays pending.
func TestInviteResume_FinishRefusesWithoutPossessionProof(t *testing.T) {
	ctx := context.Background()
	issuedAt := time.Now().Add(-time.Minute)

	t.Run("no assertion", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, _ := f.enrolPendingInvitee(t, "a@example.com")
		_, sessionID, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, err = f.svc.FinishInviteResume(ctx, sessionID, a.WebAuthnID(), issuedAt, nil)
		require.Error(t, err)
		f.requirePending(t, a)
	})

	t.Run("invalid signature", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, credential := f.enrolPendingInvitee(t, "a@example.com")
		options, sessionID, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		assertion := f.assert(t, options, credential, nil)
		sig := assertion.Response.Signature
		sig[len(sig)-1] ^= 0xff
		_, err = f.svc.FinishInviteResume(ctx, sessionID, a.WebAuthnID(), issuedAt, assertion)
		require.Error(t, err)
		f.requirePending(t, a)
	})

	t.Run("assertion over another challenge", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, credential := f.enrolPendingInvitee(t, "a@example.com")
		first, _, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, second, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, err = f.svc.FinishInviteResume(ctx, second, a.WebAuthnID(), issuedAt, f.assert(t, first, credential, nil))
		require.Error(t, err)
		f.requirePending(t, a)
	})

	t.Run("assertion over a stale challenge", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, credential := f.enrolPendingInvitee(t, "a@example.com")
		stale, staleID, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		// The stale session is spent by a failed finish.
		_, err = f.svc.FinishInviteResume(ctx, staleID, a.WebAuthnID(), issuedAt, nil)
		require.Error(t, err)
		staleAssertion := f.assert(t, stale, credential, nil)
		_, err = f.svc.FinishInviteResume(ctx, staleID, a.WebAuthnID(), issuedAt, staleAssertion)
		require.Error(t, err)
		_, fresh, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, err = f.svc.FinishInviteResume(ctx, fresh, a.WebAuthnID(), issuedAt, f.assert(t, stale, credential, nil))
		require.Error(t, err)
		f.requirePending(t, a)
	})

	t.Run("assertion signed by a credential never enrolled", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, _ := f.enrolPendingInvitee(t, "a@example.com")
		options, sessionID, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, err = f.svc.FinishInviteResume(ctx, sessionID, a.WebAuthnID(), issuedAt, f.assert(t, options, newEC2Credential(t), nil))
		require.Error(t, err)
		f.requirePending(t, a)
	})

	t.Run("assertion signed by another account's credential", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, _ := f.enrolPendingInvitee(t, "a@example.com")
		_, credentialB := f.enrolPendingInvitee(t, "b@example.com")
		options, sessionID, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, err = f.svc.FinishInviteResume(ctx, sessionID, a.WebAuthnID(), issuedAt, f.assert(t, options, credentialB, nil))
		require.Error(t, err)
		f.requirePending(t, a)
	})

	t.Run("session begun for another account", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, _ := f.enrolPendingInvitee(t, "a@example.com")
		b, credentialB := f.enrolPendingInvitee(t, "b@example.com")
		options, sessionB, err := f.svc.BeginInviteResume(ctx, b.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, err = f.svc.FinishInviteResume(ctx, sessionB, a.WebAuthnID(), issuedAt, f.assert(t, options, credentialB, nil))
		require.Error(t, err)
		f.requirePending(t, a)
		f.requirePending(t, b)
	})

	t.Run("registration session", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, credential := f.enrolPendingInvitee(t, "a@example.com")
		c := f.mustCreatePending(t, "c@example.com")
		_, regSession, err := f.svc.BeginInviteRegistration(ctx, c.WebAuthnID())
		require.NoError(t, err)
		options, _, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.NoError(t, err)
		_, err = f.svc.FinishInviteResume(ctx, regSession, a.WebAuthnID(), issuedAt, f.assert(t, options, credential, nil))
		require.Error(t, err)
		f.requirePending(t, a)
	})
}

// A resume session never enrols a credential through the registration finish.
func TestInviteResume_SessionCannotEnrolASecondCredential(t *testing.T) {
	ctx := context.Background()
	f := newEnrollFixture(t, false)
	a, _ := f.enrolPendingInvitee(t, "a@example.com")
	_, sessionID, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), time.Now().Add(-time.Minute))
	require.NoError(t, err)
	options, _, err := f.svc.BeginInviteRegistration(ctx, f.mustCreatePending(t, "d@example.com").WebAuthnID())
	require.NoError(t, err)
	parsed, err := parseAttestationResponse(f.inviteAttestation(t, options, newEC2Credential(t)))
	require.NoError(t, err)
	_, err = f.svc.FinishInviteRegistration(ctx, sessionID, a.WebAuthnID(), parsed)
	require.Error(t, err)
	creds, err := f.creds.GetByUserID(ctx, a.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 1)
}

// Begin issues a challenge only for "this invitation's account, pending,
// holding only the credential enrolled since the invitation was issued".
func TestInviteResume_BeginRefusesAnythingElse(t *testing.T) {
	ctx := context.Background()
	issuedAt := time.Now().Add(-time.Minute)

	t.Run("account without a credential", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		c := f.mustCreatePending(t, "c@example.com")
		_, _, err := f.svc.BeginInviteResume(ctx, c.WebAuthnID(), issuedAt)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("credential older than the invitation", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, _ := f.enrolPendingInvitee(t, "a@example.com")
		_, _, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), time.Now().Add(time.Minute))
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("account already active", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, _ := f.enrolPendingInvitee(t, "a@example.com")
		f.setStanding(t, "a@example.com", qrdbsdk.LifecycleActive, nil)
		_, _, err := f.svc.BeginInviteResume(ctx, a.WebAuthnID(), issuedAt)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("empty handle", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		f.enrolPendingInvitee(t, "a@example.com")
		_, _, err := f.svc.BeginInviteResume(ctx, nil, issuedAt)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("unknown account", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		_, _, err := f.svc.BeginInviteResume(ctx, []byte("no-such-handle"), issuedAt)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})
}
