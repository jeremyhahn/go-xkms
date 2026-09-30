// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// refusedStates are the lifecycle states go-xkms#1298 names, plus the others
// qrdb defines and an empty (unset) state: none of them may authenticate.
var refusedStates = []qrdbsdk.Lifecycle{
	qrdbsdk.LifecycleSuspended,
	qrdbsdk.LifecycleDisabled,
	qrdbsdk.LifecycleLocked,
	qrdbsdk.LifecyclePending,
	qrdbsdk.LifecycleDeleting,
	"",
}

// setStanding rewrites the standing of the memory-store account email names.
func (f *enrollFixture) setStanding(t *testing.T, email string, state qrdbsdk.Lifecycle, methods []string) {
	t.Helper()
	user, err := f.users.GetByEmail(context.Background(), email)
	require.NoError(t, err)
	du, ok := user.(*DefaultUser)
	require.True(t, ok, "memory store holds *DefaultUser")
	du.SetLifecycle(state)
	du.SetAuthMethods(methods)
}

// beginAssertion begins a user-identified login for email and returns the
// session plus credential's assertion against it.
func (f *enrollFixture) beginAssertion(t *testing.T, email string, credential virtualwebauthn.Credential) (string, *protocol.ParsedCredentialAssertionData) {
	t.Helper()
	options, sessionID, err := f.svc.BeginLoginForEmail(context.Background(), email)
	require.NoError(t, err)
	return sessionID, f.assert(t, options, credential, nil)
}

// assert produces credential's assertion for options. A non-nil userHandle
// is reported in the assertion, as a discoverable passkey does.
func (f *enrollFixture) assert(t *testing.T, options *protocol.CredentialAssertion, credential virtualwebauthn.Credential, userHandle []byte) *protocol.ParsedCredentialAssertionData {
	t.Helper()
	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
	require.NoError(t, err)
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: userHandle})
	authenticator.AddCredential(credential)
	assertion := virtualwebauthn.CreateAssertionResponse(f.rp, authenticator, credential, *parsedOptions)
	parsed, err := parseAssertionResponse(assertion)
	require.NoError(t, err)
	return parsed
}

func TestCheckAccountStanding_Permits(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
	}{
		{name: "no policy states no restriction", methods: nil},
		{name: "policy naming webauthn", methods: []string{"mtls", auth.MethodWebAuthn}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := NewDefaultUser([]byte{1}, "a@example.com", "A")
			user.SetAuthMethods(tt.methods)
			assert.NoError(t, CheckAccountStanding(user))
		})
	}
}

func TestCheckAccountStanding_RefusesInactiveLifecycle(t *testing.T) {
	for _, state := range refusedStates {
		t.Run(string(state), func(t *testing.T) {
			user := NewDefaultUser([]byte{1}, "a@example.com", "A")
			user.SetLifecycle(state)

			var notActive *AccountNotActiveError
			require.True(t, errors.As(CheckAccountStanding(user), &notActive))
			assert.Equal(t, "a@example.com", notActive.Account)
			assert.Equal(t, string(state), notActive.Lifecycle)
		})
	}
}

func TestCheckAccountStanding_RefusesWithdrawnMethod(t *testing.T) {
	user := NewDefaultUser([]byte{1}, "a@example.com", "A")
	user.SetAuthMethods([]string{"mtls", "piv"})

	var refused *auth.AuthMethodNotPermittedError
	require.True(t, errors.As(CheckAccountStanding(user), &refused))
	assert.Equal(t, auth.MethodWebAuthn, refused.Method)
	assert.Equal(t, "a@example.com", refused.Username)
}

func TestAccountNotActiveError_Error(t *testing.T) {
	err := &AccountNotActiveError{Account: "a@example.com", Lifecycle: "suspended"}
	assert.Equal(t, "webauthn: account a@example.com is not active (lifecycle suspended)", err.Error())
}

// TestQRDBAdapter_MaterializeCarriesStanding is the root cause of
// go-xkms#1298: the qrdb record's lifecycle and auth-method policy used to be
// dropped when it was materialized, so nothing downstream could refuse.
func TestQRDBAdapter_MaterializeCarriesStanding(t *testing.T) {
	ctx := context.Background()
	users, _, client, _ := newTestAdapter(t)
	created, err := users.Create(ctx, "standing@example.com", "Standing")
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.LifecycleActive, created.Lifecycle())
	assert.Empty(t, created.AuthMethods())

	id, err := UserIDFromHandle(created.WebAuthnID())
	require.NoError(t, err)
	record, err := client.GetUser(ctx, id)
	require.NoError(t, err)
	record.Lifecycle = string(qrdbsdk.LifecycleSuspended)
	record.AuthMethods = []string{"mtls"}

	byID, err := users.GetByID(ctx, created.WebAuthnID())
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.LifecycleSuspended, byID.Lifecycle())
	assert.Equal(t, []string{"mtls"}, byID.AuthMethods())

	byEmail, err := users.GetByEmail(ctx, "standing@example.com")
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.LifecycleSuspended, byEmail.Lifecycle())
	assert.Error(t, CheckAccountStanding(byEmail))
}

// TestFinishLogin_RefusesAccountNotInGoodStanding covers the race begin
// cannot: the account leaves good standing after its ceremony began. A valid
// assertion must still be refused, with the bare verification failure, on
// both finish entry points.
func TestFinishLogin_RefusesAccountNotInGoodStanding(t *testing.T) {
	type standing struct {
		name    string
		state   qrdbsdk.Lifecycle
		methods []string
	}
	cases := []standing{{name: "webauthn withdrawn", state: qrdbsdk.LifecycleActive, methods: []string{"mtls"}}}
	for _, state := range refusedStates {
		cases = append(cases, standing{name: "lifecycle " + string(state), state: state})
	}
	finishers := map[string]func(*Service, string, *protocol.ParsedCredentialAssertionData) error{
		"FinishLogin": func(s *Service, sessionID string, a *protocol.ParsedCredentialAssertionData) error {
			_, _, err := s.FinishLogin(context.Background(), sessionID, nil, a)
			return err
		},
		"FinishLoginPair": func(s *Service, sessionID string, a *protocol.ParsedCredentialAssertionData) error {
			_, _, err := s.FinishLoginPair(context.Background(), sessionID, nil, a)
			return err
		},
	}
	for finisherName, finish := range finishers {
		for _, tc := range cases {
			t.Run(finisherName+"/"+tc.name, func(t *testing.T) {
				f := newEnrollFixture(t, true)
				const email = "member@example.com"
				_, credential := f.enroll(t, email)

				sessionID, assertion := f.beginAssertion(t, email, credential)
				f.setStanding(t, email, tc.state, tc.methods)

				err := finish(f.svc, sessionID, assertion)
				require.ErrorIs(t, err, ErrVerificationFailed)
				assert.Equal(t, "validate login: verification failed", err.Error(),
					"the refusal must carry no detail about the account's state")
			})
		}
	}
}

// TestFinishLogin_ActiveAccountWithWebAuthnPermitted is the control: the same
// ceremony succeeds for an active account whose policy allows WebAuthn.
func TestFinishLogin_ActiveAccountWithWebAuthnPermitted(t *testing.T) {
	for _, methods := range [][]string{nil, {auth.MethodWebAuthn}} {
		f := newEnrollFixture(t, true)
		const email = "member@example.com"
		_, credential := f.enroll(t, email)
		f.setStanding(t, email, qrdbsdk.LifecycleActive, methods)

		sessionID, assertion := f.beginAssertion(t, email, credential)
		pair, user, err := f.svc.FinishLoginPair(context.Background(), sessionID, nil, assertion)
		require.NoError(t, err, "policy %v", methods)
		assert.NotEmpty(t, pair.AccessToken)
		assert.Equal(t, email, user.Email())
	}
}

// TestFinishLogin_DiscoverableRefusesAccountNotInGoodStanding covers the
// usernameless flow, which names no account at begin: the account is only
// known once the assertion resolves it, so finish is where it is refused.
func TestFinishLogin_DiscoverableRefusesAccountNotInGoodStanding(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	const email = "usernameless@example.com"
	user, credential := f.enroll(t, email)

	login := func() error {
		options, sessionID, err := f.svc.BeginLogin(ctx, nil)
		require.NoError(t, err)
		_, _, err = f.svc.FinishLogin(ctx, sessionID, nil, f.assert(t, options, credential, user.WebAuthnID()))
		return err
	}

	require.NoError(t, login(), "an active account logs in")

	f.setStanding(t, email, qrdbsdk.LifecycleDisabled, nil)
	require.ErrorIs(t, login(), ErrVerificationFailed)

	f.setStanding(t, email, qrdbsdk.LifecycleActive, []string{"piv"})
	require.ErrorIs(t, login(), ErrVerificationFailed)
}

// TestFinishLogin_StandingRefusalIsLogged proves the operator, unlike the
// client, learns why the login was refused.
func TestFinishLogin_StandingRefusalIsLogged(t *testing.T) {
	f := newEnrollFixture(t, true)
	logs := &bytes.Buffer{}
	f.svc.logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	const email = "member@example.com"
	_, credential := f.enroll(t, email)

	sessionID, assertion := f.beginAssertion(t, email, credential)
	f.setStanding(t, email, qrdbsdk.LifecycleLocked, nil)
	_, _, err := f.svc.FinishLogin(context.Background(), sessionID, nil, assertion)
	require.ErrorIs(t, err, ErrVerificationFailed)

	assert.Contains(t, logs.String(), "not in good standing")
	assert.Contains(t, logs.String(), "lifecycle locked")
}

// TestBeginLogin_AccountNotInGoodStandingLooksUnknown is go-xkms#1298's begin
// requirement: an account that may not log in gets exactly the decoy an
// unknown account would, never its real credential descriptors.
func TestBeginLogin_AccountNotInGoodStandingLooksUnknown(t *testing.T) {
	cases := map[string]struct {
		state   qrdbsdk.Lifecycle
		methods []string
	}{
		"suspended":          {state: qrdbsdk.LifecycleSuspended},
		"disabled":           {state: qrdbsdk.LifecycleDisabled},
		"locked":             {state: qrdbsdk.LifecycleLocked},
		"webauthn withdrawn": {state: qrdbsdk.LifecycleActive, methods: []string{"mtls"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newEnrollFixture(t, true)
			ctx := context.Background()
			const email = "member@example.com"
			user, credential := f.enroll(t, email)
			f.setStanding(t, email, tc.state, tc.methods)

			emailDecoy, err := f.svc.decoyUser(decoySubject(decoyKindEmail, []byte(email)))
			require.NoError(t, err)
			handleDecoy, err := f.svc.decoyUser(decoySubject(decoyKindHandle, user.WebAuthnID()))
			require.NoError(t, err)

			byEmail, sessionID, err := f.svc.BeginLoginForEmail(ctx, email)
			require.NoError(t, err)
			assert.NotEmpty(t, sessionID)
			assert.Equal(t, credentialIDs(emailDecoy), allowedIDs(byEmail))
			assert.NotContains(t, allowedIDs(byEmail), credential.ID)

			byHandle, _, err := f.svc.BeginLoginForHandle(ctx, user.WebAuthnID())
			require.NoError(t, err)
			assert.Equal(t, credentialIDs(handleDecoy), allowedIDs(byHandle))

			// The legacy identified form answers "not found", exactly as it
			// does for a handle that names no account.
			_, _, err = f.svc.BeginLogin(ctx, user.WebAuthnID())
			require.ErrorIs(t, err, ErrUserNotFound)
			_, _, unknownErr := f.svc.BeginLogin(ctx, HandleFromUserID(987654321))
			assert.Equal(t, unknownErr.Error(), err.Error())
		})
	}
}

// credentialIDs lists a user's credential IDs in order.
func credentialIDs(user *DefaultUser) [][]byte {
	ids := make([][]byte, len(user.Credentials()))
	for i, c := range user.Credentials() {
		ids[i] = c.ID
	}
	return ids
}

// TestBeginRegistration_RefusesInactiveZeroCredentialAccount is go-xkms#1298's
// enrolment requirement: an account provisioned without a passkey may enrol
// its first one only while active, and is refused otherwise with the same
// ErrRegistrationRefused every other refused enrolment gets.
func TestBeginRegistration_RefusesInactiveZeroCredentialAccount(t *testing.T) {
	for _, allow := range []bool{true, false} {
		for _, state := range refusedStates {
			f := newEnrollFixture(t, allow)
			ctx := context.Background()
			const email = "provisioned@example.com"
			_, err := f.users.Create(ctx, email, "Provisioned")
			require.NoError(t, err)
			f.setStanding(t, email, state, nil)

			_, _, err = f.svc.BeginRegistration(ctx, email, "Provisioned")
			require.ErrorIs(t, err, ErrRegistrationRefused, "allow=%v state=%q", allow, state)
		}
	}
}

// TestBeginInviteRegistration_PendingAccountEnrols is the control: a
// provisioned account (go-xkms#1294 part B leaves it LifecyclePending, not
// active, until redemption) enrolls its first passkey through the
// invite-authorized entry point.
func TestBeginInviteRegistration_PendingAccountEnrols(t *testing.T) {
	f := newEnrollFixture(t, false)
	ctx := context.Background()
	const email = "provisioned@example.com"
	_, err := f.users.Create(ctx, email, "Provisioned")
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecyclePending, nil)

	options, sessionID, err := f.svc.BeginInviteRegistration(ctx, email)
	require.NoError(t, err)
	_, err = f.attestInvite(t, options, sessionID, newEC2Credential(t))
	require.NoError(t, err)
}

// TestFinishInviteRegistration_RefusesAccountDeactivatedMidCeremony closes
// the window between begin and finish: an invite-authorized ceremony started
// against a pending account must not bind a credential if the account left
// pending (activated by another means, or deactivated) before finish runs.
func TestFinishInviteRegistration_RefusesAccountDeactivatedMidCeremony(t *testing.T) {
	f := newEnrollFixture(t, false)
	ctx := context.Background()
	const email = "provisioned@example.com"
	user, err := f.users.Create(ctx, email, "Provisioned")
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecyclePending, nil)

	options, sessionID, err := f.svc.BeginInviteRegistration(ctx, email)
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecycleSuspended, nil)

	_, err = f.attestInvite(t, options, sessionID, newEC2Credential(t))
	require.ErrorIs(t, err, ErrRegistrationRefused)
	creds, err := f.creds.GetByUserID(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Empty(t, creds, "no credential may be stored for the refused account")
}

// TestBeginAddCredential_RefusesInactiveAccount: a session minted before the
// account was deactivated cannot add a passkey to it either.
func TestBeginAddCredential_RefusesInactiveAccount(t *testing.T) {
	f := newEnrollFixture(t, true)
	const email = "member@example.com"
	user, _ := f.enroll(t, email)
	f.setStanding(t, email, qrdbsdk.LifecycleDisabled, nil)

	_, _, err := f.svc.BeginAddCredential(context.Background(), sessionFor(user))
	require.ErrorIs(t, err, ErrRegistrationRefused)
}
