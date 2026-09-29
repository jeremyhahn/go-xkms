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

package xkms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"testing"

	waprotocol "github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// sdkStandingFixture is the SDK FIDO2 surface over one account holding a
// real passkey.
type sdkStandingFixture struct {
	svc           *XKMSService
	waSvc         *webauthn.Service
	authenticator *webauthn.MockAuthenticator
	userID        []byte
	email         string
}

func newSDKStandingFixture(t *testing.T) *sdkStandingFixture {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	waSvc := newConfiguredWebAuthnService(t)
	svc.SetWebAuthn(waSvc)

	const email = "member@example.com"
	authenticator, userID := registerCredentialForLogin(t, svc, waSvc, email, "Member", "example.com", "https://example.com")
	return &sdkStandingFixture{svc: svc, waSvc: waSvc, authenticator: authenticator, userID: userID, email: email}
}

func (f *sdkStandingFixture) setStanding(t *testing.T, state qrdbsdk.Lifecycle, methods []string) {
	t.Helper()
	user, err := f.waSvc.GetUserByEmail(context.Background(), f.email)
	require.NoError(t, err)
	du, ok := user.(*webauthn.DefaultUser)
	require.True(t, ok)
	du.SetLifecycle(state)
	du.SetAuthMethods(methods)
}

func (f *sdkStandingFixture) begin(t *testing.T, email string) *transport.BeginAuthenticationResponse {
	t.Helper()
	resp, err := f.svc.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{Email: email})
	require.NoError(t, err)
	return resp
}

func (f *sdkStandingFixture) finish(t *testing.T, begin *transport.BeginAuthenticationResponse) (*transport.FinishAuthenticationResponse, error) {
	t.Helper()
	var options waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(begin.OptionsJSON), &options))
	assertion, err := f.authenticator.CreateAssertionResponse(options.Response.Challenge, f.userID, "https://example.com")
	require.NoError(t, err)
	assertionJSON, err := json.Marshal(assertion.Raw)
	require.NoError(t, err)
	return f.svc.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{
		SessionID:     begin.SessionID,
		Email:         f.email,
		AssertionJSON: string(assertionJSON),
	})
}

// TestSDKFinishAuthentication_RefusesAccountNotInGoodStanding is go-xkms#1298
// on the SDK surface: a valid passkey for a suspended, disabled or locked
// account, or one whose policy withdraws WebAuthn, is refused with the
// verification failure a wrong assertion gets.
func TestSDKFinishAuthentication_RefusesAccountNotInGoodStanding(t *testing.T) {
	cases := map[string]struct {
		state   qrdbsdk.Lifecycle
		methods []string
	}{
		"suspended":          {state: qrdbsdk.LifecycleSuspended},
		"disabled":           {state: qrdbsdk.LifecycleDisabled},
		"locked":             {state: qrdbsdk.LifecycleLocked},
		"webauthn withdrawn": {state: qrdbsdk.LifecycleActive, methods: []string{"piv"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSDKStandingFixture(t)

			midCeremony := f.begin(t, f.email)
			f.setStanding(t, tc.state, tc.methods)
			for _, begin := range []*transport.BeginAuthenticationResponse{midCeremony, f.begin(t, f.email)} {
				resp, err := f.finish(t, begin)
				require.ErrorIs(t, err, webauthn.ErrVerificationFailed)
				assert.Nil(t, resp)
			}
		})
	}
}

// TestSDKFinishAuthentication_ActiveAccountLogsIn is the control.
func TestSDKFinishAuthentication_ActiveAccountLogsIn(t *testing.T) {
	f := newSDKStandingFixture(t)
	f.setStanding(t, qrdbsdk.LifecycleActive, []string{"mtls", "webauthn"})

	resp, err := f.finish(t, f.begin(t, f.email))
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, f.email, resp.Username)
}

// TestSDKBeginAuthentication_DisabledAccountLooksUnknown: begin for a
// disabled account advertises decoy descriptors, never its real passkey, in
// a response shaped exactly like an unknown email's.
func TestSDKBeginAuthentication_DisabledAccountLooksUnknown(t *testing.T) {
	f := newSDKStandingFixture(t)
	f.setStanding(t, qrdbsdk.LifecycleDisabled, nil)

	disabled := f.begin(t, f.email)
	unknown := f.begin(t, "unknown@example.com")

	assert.NotEmpty(t, disabled.SessionID)
	assert.NotContains(t, disabled.OptionsJSON, base64.RawURLEncoding.EncodeToString(f.authenticator.CredentialID))

	var disabledOpts, unknownOpts map[string]map[string]any
	require.NoError(t, json.Unmarshal([]byte(disabled.OptionsJSON), &disabledOpts))
	require.NoError(t, json.Unmarshal([]byte(unknown.OptionsJSON), &unknownOpts))
	assert.Equal(t, jsonFieldNames(unknownOpts["publicKey"]), jsonFieldNames(disabledOpts["publicKey"]))
}

// TestSDKBeginRegistration_InactiveZeroCredentialAccountRefused: a
// provisioned account that is not active cannot enrol its first passkey.
func TestSDKBeginRegistration_InactiveZeroCredentialAccountRefused(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	waSvc := newConfiguredWebAuthnService(t)
	svc.SetWebAuthn(waSvc)
	ctx := context.Background()

	// A begin creates the account (public registration is open) without
	// enrolling a passkey: the zero-credential onboarding state.
	_, err = svc.BeginRegistration(ctx, &transport.BeginRegistrationRequest{Email: "provisioned@example.com"})
	require.NoError(t, err)
	user, err := waSvc.GetUserByEmail(ctx, "provisioned@example.com")
	require.NoError(t, err)
	du, ok := user.(*webauthn.DefaultUser)
	require.True(t, ok)
	du.SetLifecycle(qrdbsdk.LifecyclePending)

	_, err = svc.BeginRegistration(ctx, &transport.BeginRegistrationRequest{Email: "provisioned@example.com"})
	require.ErrorIs(t, err, webauthn.ErrRegistrationRefused)
}

// jsonFieldNames lists a JSON object's field names in sorted order.
func jsonFieldNames(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
