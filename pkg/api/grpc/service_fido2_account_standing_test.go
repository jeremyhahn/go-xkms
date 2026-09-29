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

package grpc

import (
	"context"
	"encoding/json"
	"testing"

	waprotocol "github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

const standingOrigin = "https://example.com"

// standingFixture is a gRPC service over a relying party holding one account
// with a real passkey.
type standingFixture struct {
	svc           *Service
	rp            *webauthn.Service
	authenticator *webauthn.MockAuthenticator
	user          webauthn.User
}

func newStandingFixture(t *testing.T, email string) *standingFixture {
	t.Helper()
	open := true
	svc, rp := newFIDO2RelyingPartyService(t, &open)
	ctx := context.Background()

	begin, err := svc.BeginRegistration(ctx, &pb.BeginRegistrationRequest{Email: email, DisplayName: email})
	require.NoError(t, err)
	var options waprotocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(begin.OptionsJson), &options))
	user, err := rp.GetUserByEmail(ctx, email)
	require.NoError(t, err)

	authenticator, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	attestation, err := authenticator.CreateAttestationObject(options.Response.Challenge, user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	attestationJSON, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)
	_, err = svc.FinishRegistration(ctx, &pb.FinishRegistrationRequest{
		SessionId:       begin.SessionId,
		AttestationJson: string(attestationJSON),
	})
	require.NoError(t, err)

	return &standingFixture{svc: svc, rp: rp, authenticator: authenticator, user: user}
}

// setStanding rewrites the account's standing in the memory store.
func (f *standingFixture) setStanding(t *testing.T, state qrdbsdk.Lifecycle, methods []string) {
	t.Helper()
	du, ok := f.user.(*webauthn.DefaultUser)
	require.True(t, ok)
	du.SetLifecycle(state)
	du.SetAuthMethods(methods)
}

// begin runs BeginAuthentication for the account.
func (f *standingFixture) begin(t *testing.T) *pb.BeginAuthenticationResponse {
	t.Helper()
	resp, err := f.svc.BeginAuthentication(context.Background(), &pb.BeginAuthenticationRequest{Email: f.user.Email()})
	require.NoError(t, err)
	return resp
}

// finish runs FinishAuthentication with the passkey's assertion for begin.
func (f *standingFixture) finish(t *testing.T, begin *pb.BeginAuthenticationResponse) (*pb.FinishAuthenticationResponse, error) {
	t.Helper()
	var options waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(begin.OptionsJson), &options))
	assertion, err := f.authenticator.CreateAssertionResponse(options.Response.Challenge, f.user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	assertionJSON, err := json.Marshal(assertion.Raw)
	require.NoError(t, err)
	return f.svc.FinishAuthentication(context.Background(), &pb.FinishAuthenticationRequest{
		SessionId:     begin.SessionId,
		Email:         f.user.Email(),
		AssertionJson: string(assertionJSON),
	})
}

// TestFinishAuthentication_RefusesAccountNotInGoodStanding is go-xkms#1298 on
// the gRPC plane: a valid passkey for an account that is not active, or whose
// policy withdraws WebAuthn, mints no token — whether the account left good
// standing mid-ceremony or before begin — and the refusal names no state.
func TestFinishAuthentication_RefusesAccountNotInGoodStanding(t *testing.T) {
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
			f := newStandingFixture(t, "member@example.com")

			midCeremony := f.begin(t)
			f.setStanding(t, tc.state, tc.methods)
			for _, begin := range []*pb.BeginAuthenticationResponse{midCeremony, f.begin(t)} {
				resp, err := f.finish(t, begin)
				require.Error(t, err)
				assert.Nil(t, resp)
				assert.NotEqual(t, codes.OK, status.Code(err))
				msg := status.Convert(err).Message()
				assert.Contains(t, msg, "verification failed")
				assert.NotContains(t, msg, string(tc.state))
				assert.NotContains(t, msg, "not permitted")
			}
		})
	}
}

// TestFinishAuthentication_ActiveAccountLogsIn is the control.
func TestFinishAuthentication_ActiveAccountLogsIn(t *testing.T) {
	f := newStandingFixture(t, "member@example.com")
	f.setStanding(t, qrdbsdk.LifecycleActive, []string{"webauthn"})

	resp, err := f.finish(t, f.begin(t))
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Token)
}
