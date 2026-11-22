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

// user_invite_redeem_test.go drives the FIDO2 invite ceremony through a fake
// authenticator, and the redeem verb's client, PIV and JSON branches.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	webauthnclient "github.com/jeremyhahn/go-xkms/sdk/go/webauthnclient"
)

// fakeAuthenticator answers MakeCredential with attestation or err and
// records the options it was asked to sign.
type fakeAuthenticator struct {
	attestation  []byte
	assertion    []byte
	err          error
	got          *webauthnclient.CeremonyOptions
	gotAssertion *webauthnclient.CeremonyOptions
}

func (f *fakeAuthenticator) MakeCredential(_ context.Context, opts *webauthnclient.CeremonyOptions) ([]byte, error) {
	f.got = opts
	return f.attestation, f.err
}

func (f *fakeAuthenticator) GetAssertion(_ context.Context, opts *webauthnclient.CeremonyOptions) ([]byte, error) {
	f.gotAssertion = opts
	if f.assertion == nil {
		return nil, client.ErrNotSupported
	}
	return f.assertion, f.err
}

func (f *fakeAuthenticator) Available() bool { return true }

// mockInviteCeremonyClient adds the registration half of the invite
// ceremony to mockUserInviteClient.
type mockInviteCeremonyClient struct {
	mockUserInviteClient

	beginResp *client.BeginInviteRegistrationResponse
	beginErr  error
	finishErr error

	gotFinish *client.FinishInviteRegistrationRequest
}

func (m *mockInviteCeremonyClient) BeginInviteRegistration(context.Context, *client.BeginInviteRegistrationRequest) (*client.BeginInviteRegistrationResponse, error) {
	return m.beginResp, m.beginErr
}

func (m *mockInviteCeremonyClient) FinishInviteRegistration(_ context.Context, req *client.FinishInviteRegistrationRequest) (*client.FinishInviteRegistrationResponse, error) {
	m.gotFinish = req
	if m.finishErr != nil {
		return nil, m.finishErr
	}
	return &client.FinishInviteRegistrationResponse{UserID: 7}, nil
}

func TestRedeemInviteFIDO2_CompletesCeremony(t *testing.T) {
	mock := &mockInviteCeremonyClient{beginResp: &client.BeginInviteRegistrationResponse{SessionID: "session-1", OptionsJSON: `{"publicKey":{}}`, Ceremony: client.InviteCeremonyCreate}}
	auth := &fakeAuthenticator{attestation: []byte(`{"id":"cred-1"}`)}
	var prompt bytes.Buffer

	resp, err := redeemInviteFIDO2(context.Background(), mock, NewPrinter("text", &prompt), "acme", "token-1", auth, "https://kms.example.com", nil)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), resp.UserID)
	assert.Contains(t, prompt.String(), "touch your security key")
	assert.Nil(t, auth.gotAssertion, "a create ceremony never asks for an assertion")
	assert.Equal(t, `{"publicKey":{}}`, string(auth.got.OptionsJSON))
	assert.Equal(t, "https://kms.example.com", auth.got.Origin)
	assert.Equal(t, &client.FinishInviteRegistrationRequest{
		TenantID: "acme", Token: "token-1", SessionID: "session-1", AttestationJSON: `{"id":"cred-1"}`,
	}, mock.gotFinish)
}

func TestRedeemInviteFIDO2_Failures(t *testing.T) {
	begun := &client.BeginInviteRegistrationResponse{SessionID: "session-1", OptionsJSON: "{}", Ceremony: client.InviteCeremonyCreate}
	resume := &client.BeginInviteRegistrationResponse{SessionID: "session-2", OptionsJSON: "{}", Ceremony: client.InviteCeremonyGet}
	unknown := &client.BeginInviteRegistrationResponse{SessionID: "session-3", OptionsJSON: "{}", Ceremony: "enrol"}
	cases := []struct {
		name     string
		mock     *mockInviteCeremonyClient
		auth     *fakeAuthenticator
		sentinel error
	}{
		{"begin refused", &mockInviteCeremonyClient{beginErr: errUserInviteBoom}, &fakeAuthenticator{}, ErrBeginInviteRegistrationFailed},
		{"authenticator wants a PIN", &mockInviteCeremonyClient{beginResp: begun}, &fakeAuthenticator{err: fido2.ErrPINRequired}, ErrWebAuthnPINRequired},
		{"authenticator fails", &mockInviteCeremonyClient{beginResp: begun}, &fakeAuthenticator{err: errUserInviteBoom}, ErrFinishInviteRegistrationFailed},
		{"finish refused", &mockInviteCeremonyClient{beginResp: begun, finishErr: errUserInviteBoom}, &fakeAuthenticator{attestation: []byte("{}")}, ErrFinishInviteRegistrationFailed},
		{"no ceremony type", &mockInviteCeremonyClient{beginResp: &client.BeginInviteRegistrationResponse{SessionID: "session-4", OptionsJSON: "{}"}}, &fakeAuthenticator{attestation: []byte("{}")}, ErrUnknownInviteCeremony},
		{"unknown ceremony type", &mockInviteCeremonyClient{beginResp: unknown}, &fakeAuthenticator{attestation: []byte("{}")}, ErrUnknownInviteCeremony},
		{"resume assertion fails", &mockInviteCeremonyClient{beginResp: resume}, &fakeAuthenticator{assertion: []byte("{}"), err: errUserInviteBoom}, ErrFinishInviteRegistrationFailed},
		{"resume wants a PIN", &mockInviteCeremonyClient{beginResp: resume}, &fakeAuthenticator{assertion: []byte("{}"), err: fido2.ErrPINRequired}, ErrWebAuthnPINRequired},
		{"resume finish refused", &mockInviteCeremonyClient{beginResp: resume, finishErr: errUserInviteBoom}, &fakeAuthenticator{assertion: []byte("{}")}, ErrFinishInviteRegistrationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prompt bytes.Buffer
			resp, err := redeemInviteFIDO2(context.Background(), tc.mock, NewPrinter("text", &prompt), "acme", "token-1", tc.auth, "https://kms.example.com", nil)
			assert.ErrorIs(t, err, tc.sentinel)
			assert.Nil(t, resp)
		})
	}
}

// TestRedeemInviteFIDO2_ResumeAssertsWithSoftwareAuthenticator drives the
// resume path with the software authenticator: the first redeem enrols a
// credential (create) whose activation then fails; the retried begin answers
// with a get for exactly that credential, and redeemInviteFIDO2 answers it
// with an assertion by that credential, never a second credential.
func TestRedeemInviteFIDO2_ResumeAssertsWithSoftwareAuthenticator(t *testing.T) {
	const origin = "https://kms.example.com"
	b64 := base64.RawURLEncoding.EncodeToString
	soft := webauthnclient.NewSoftwareAdapter()
	var prompt bytes.Buffer
	printer := NewPrinter("text", &prompt)

	creation := fmt.Sprintf(`{"publicKey":{"challenge":%q,"rp":{"id":"kms.example.com","name":"xkms"},`+
		`"user":{"id":%q,"name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}}`,
		b64([]byte("create-challenge-0123456789abcdef")), b64([]byte("user-handle-7")))
	failing := &mockInviteCeremonyClient{
		beginResp: &client.BeginInviteRegistrationResponse{SessionID: "session-1", OptionsJSON: creation, Ceremony: client.InviteCeremonyCreate},
		finishErr: errUserInviteBoom,
	}
	_, err := redeemInviteFIDO2(context.Background(), failing, printer, "acme", "token-1", soft, origin, nil)
	require.ErrorIs(t, err, ErrFinishInviteRegistrationFailed)
	require.NotNil(t, failing.gotFinish)
	created, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(failing.gotFinish.AttestationJSON))
	require.NoError(t, err, "the create ceremony sends an attestation")
	require.Equal(t, 1, soft.CredentialCount())

	assertionOpts := fmt.Sprintf(`{"publicKey":{"challenge":%q,"rpId":"kms.example.com",`+
		`"allowCredentials":[{"type":"public-key","id":%q}]}}`,
		b64([]byte("resume-challenge-0123456789abcdef")), b64(created.RawID))
	resuming := &mockInviteCeremonyClient{
		beginResp: &client.BeginInviteRegistrationResponse{SessionID: "session-2", OptionsJSON: assertionOpts, Ceremony: client.InviteCeremonyGet},
	}
	resp, err := redeemInviteFIDO2(context.Background(), resuming, printer, "acme", "token-1", soft, origin, nil)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), resp.UserID)
	require.NotNil(t, resuming.gotFinish)
	assert.Equal(t, "session-2", resuming.gotFinish.SessionID)

	_, err = protocol.ParseCredentialCreationResponseBody(strings.NewReader(resuming.gotFinish.AttestationJSON))
	require.Error(t, err, "a resume never sends an attestation")
	asserted, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(resuming.gotFinish.AttestationJSON))
	require.NoError(t, err, "a resume sends an assertion")
	assert.Equal(t, created.RawID, asserted.RawID, "the assertion is by the enrolled credential")
	assert.Equal(t, b64([]byte("resume-challenge-0123456789abcdef")), asserted.Response.CollectedClientData.Challenge, "the assertion signs the resume session's challenge")
	assert.Equal(t, 1, soft.CredentialCount(), "a resume enrols no second credential")
}

// runRedeem runs invite redeem for tenant acme with the given client
// factory result and flags.
func runRedeem(t *testing.T, cfg *Config, flags ...verbFlag) (string, int, string) {
	t.Helper()
	return runVerb(t, cfg, userInviteRedeemCmd, []string{"b64url-secret"}, append([]verbFlag{{"tenant-id", "acme"}}, flags...)...)
}

func TestUserInviteRedeemCmd_ClientFailures(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *Config
		sentinel error
	}{
		{"client factory", &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errUserInviteBoom }}, ErrCreateClientFailed},
		{"connect", newUserInviteTestConfig("text", &mockUserInviteClient{mockUserClient: mockUserClient{connectErr: errUserInviteBoom}}), ErrConnectFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runRedeem(t, tc.cfg)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.Empty(t, out)
		})
	}
}

func TestUserInviteRedeemCmd_PIVFailures(t *testing.T) {
	invite := &client.GetInviteResponse{Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour)}

	t.Run("unreadable certificate", func(t *testing.T) {
		mock := &mockUserInviteClient{getInviteResp: invite}
		_, code, stderr := runRedeem(t, newUserInviteTestConfig("text", mock),
			verbFlag{"method", "piv"}, verbFlag{"piv-cert-file", filepath.Join(t.TempDir(), "absent.pem")})
		assert.Equal(t, 1, code)
		assert.Contains(t, stderr, "absent.pem")
		assert.Nil(t, mock.gotActivatePIV, "nothing is sent without a certificate")
	})

	t.Run("activation refused", func(t *testing.T) {
		mock := &mockUserInviteClient{getInviteResp: invite, activatePIVErr: errUserInviteBoom}
		out, code, stderr := runRedeem(t, newUserInviteTestConfig("text", mock),
			verbFlag{"method", "piv"}, verbFlag{"piv-cert-file", writeTempPEM(t)})
		assert.Equal(t, 1, code)
		assert.Contains(t, stderr, ErrActivateInvitePIVFailed.Error())
		assert.NotContains(t, out, "Account activated.")
	})
}

func TestUserInviteRedeemCmd_PIVJSON(t *testing.T) {
	mock := &mockUserInviteClient{
		getInviteResp:   &client.GetInviteResponse{Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour)},
		activatePIVResp: &client.ActivateInvitePIVResponse{UserID: 42},
	}

	out, code, stderr := runRedeem(t, newUserInviteTestConfig("json", mock),
		verbFlag{"method", "piv"}, verbFlag{"piv-cert-file", writeTempPEM(t)})
	require.Equal(t, -1, code, stderr)
	assert.Equal(t, map[string]any{"success": true, "user_id": "42", "method": "piv"}, lastJSONObject(t, out))
}
