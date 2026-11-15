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
// returns the raw attestation, so a test can parse it more than once: the
// first parse finishes the ceremony, a later one models the client
// re-sending the same finish request after the activation failed.
func (f *enrollFixture) inviteAttestation(t *testing.T, options *protocol.CredentialCreation, credential virtualwebauthn.Credential) string {
	t.Helper()
	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)
	return virtualwebauthn.CreateAttestationResponse(f.rp, virtualwebauthn.NewAuthenticator(), credential, *parsedOptions)
}

// enrolPendingInvitee creates a pending account, finishes its invite
// ceremony (storing one credential while the account stays pending, as when
// the activation afterwards fails), and returns the account and the raw
// attestation of that ceremony.
func (f *enrollFixture) enrolPendingInvitee(t *testing.T, email string) (User, string) {
	t.Helper()
	ctx := context.Background()
	u, err := f.users.Create(ctx, email, email)
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecyclePending, nil)

	options, sessionID, err := f.svc.BeginInviteRegistration(ctx, u.WebAuthnID())
	require.NoError(t, err)
	attestation := f.inviteAttestation(t, options, newEC2Credential(t))
	parsed, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	_, err = f.svc.FinishInviteRegistration(ctx, sessionID, u.WebAuthnID(), parsed)
	require.NoError(t, err)
	return u, attestation
}

func (f *enrollFixture) resume(t *testing.T, invitedHandle []byte, issuedAt time.Time, attestation string) (User, error) {
	t.Helper()
	parsed, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	return f.svc.ResumeInviteRegistration(context.Background(), invitedHandle, issuedAt, parsed)
}

// A pending account holding exactly the credential its invite ceremony
// stored is resumed from the same attestation, with no session: the
// activation that failed after the credential was persisted can be retried.
func TestResumeInviteRegistration_ResumesThePersistedCredential(t *testing.T) {
	f := newEnrollFixture(t, false)
	issuedAt := time.Now().Add(-time.Minute)
	a, attestation := f.enrolPendingInvitee(t, "a@example.com")

	resumed, err := f.resume(t, a.WebAuthnID(), issuedAt, attestation)
	require.NoError(t, err)
	assert.Equal(t, a.WebAuthnID(), resumed.WebAuthnID())

	creds, err := f.creds.GetByUserID(context.Background(), a.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 1, "a resumed enrolment stores no second credential")
}

// Every case that is not "this invitation's account, pending, holding only
// the credential this ceremony created after the invitation was issued" is
// not resumable.
func TestResumeInviteRegistration_RefusesAnythingElse(t *testing.T) {
	ctx := context.Background()
	issuedAt := time.Now().Add(-time.Minute)

	t.Run("another account's credential", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		_, attestationA := f.enrolPendingInvitee(t, "a@example.com")
		b, _ := f.enrolPendingInvitee(t, "b@example.com")
		_, err := f.resume(t, b.WebAuthnID(), issuedAt, attestationA)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("account without a credential", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		_, attestationA := f.enrolPendingInvitee(t, "a@example.com")
		c, err := f.users.Create(ctx, "c@example.com", "C")
		require.NoError(t, err)
		f.setStanding(t, "c@example.com", qrdbsdk.LifecyclePending, nil)
		_, err = f.resume(t, c.WebAuthnID(), issuedAt, attestationA)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("a different credential of the same account", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, _ := f.enrolPendingInvitee(t, "a@example.com")
		// A fresh authenticator's attestation: another credential ID and
		// public key than the one stored for a.
		options, _, err := f.svc.BeginInviteRegistration(ctx, f.mustCreatePending(t, "d@example.com").WebAuthnID())
		require.NoError(t, err)
		forged := f.inviteAttestation(t, options, newEC2Credential(t))
		_, err = f.resume(t, a.WebAuthnID(), issuedAt, forged)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("credential older than the invitation", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, attestation := f.enrolPendingInvitee(t, "a@example.com")
		_, err := f.resume(t, a.WebAuthnID(), time.Now().Add(time.Minute), attestation)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("account already active", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		a, attestation := f.enrolPendingInvitee(t, "a@example.com")
		f.setStanding(t, "a@example.com", qrdbsdk.LifecycleActive, nil)
		_, err := f.resume(t, a.WebAuthnID(), issuedAt, attestation)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})

	t.Run("empty handle", func(t *testing.T) {
		f := newEnrollFixture(t, false)
		_, attestation := f.enrolPendingInvitee(t, "a@example.com")
		_, err := f.resume(t, nil, issuedAt, attestation)
		require.ErrorIs(t, err, ErrInviteNotResumable)
	})
}

func (f *enrollFixture) mustCreatePending(t *testing.T, email string) User {
	t.Helper()
	u, err := f.users.Create(context.Background(), email, email)
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecyclePending, nil)
	return u
}
