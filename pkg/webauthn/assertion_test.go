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
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const assertionOrigin = "https://example.com"

// signedAssertion signs an assertion of the given ceremony type over
// challenge, as an authenticator and client would produce it.
func signedAssertion(t *testing.T, m *MockAuthenticator, typ string, challenge []byte, origin string) *protocol.ParsedCredentialAssertionData {
	t.Helper()
	m.IncrementSignCount()
	authData, err := m.buildAuthenticatorData(false, nil)
	require.NoError(t, err)
	clientDataJSON := m.buildClientDataJSON(challenge, origin, typ)
	hash := sha256.Sum256(clientDataJSON)
	sig, err := m.sign(slices.Concat(authData, hash[:]))
	require.NoError(t, err)
	return &protocol.ParsedCredentialAssertionData{
		ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{RawID: m.CredentialID},
		Raw: protocol.CredentialAssertionResponse{
			AssertionResponse: protocol.AuthenticatorAssertionResponse{
				AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientDataJSON},
				AuthenticatorData:     authData,
				Signature:             sig,
			},
		},
	}
}

// resignWithCount re-signs a over its client data with the authenticator
// reporting count.
func resignWithCount(t *testing.T, m *MockAuthenticator, a *protocol.ParsedCredentialAssertionData, count uint32) {
	t.Helper()
	m.SignCount = count
	authData, err := m.buildAuthenticatorData(false, nil)
	require.NoError(t, err)
	hash := sha256.Sum256(a.Raw.AssertionResponse.ClientDataJSON)
	sig, err := m.sign(slices.Concat(authData, hash[:]))
	require.NoError(t, err)
	a.Raw.AssertionResponse.AuthenticatorData = authData
	a.Raw.AssertionResponse.Signature = sig
}

func storedCredentialFor(t *testing.T, m *MockAuthenticator, signCount uint32) *Credential {
	t.Helper()
	pub, err := m.PublicKeyBytes()
	require.NoError(t, err)
	return &Credential{
		ID:            m.CredentialID,
		UserID:        []byte("user-1"),
		PublicKey:     pub,
		Authenticator: AuthenticatorData{SignCount: signCount},
	}
}

func TestVerifyAssertion_Valid(t *testing.T) {
	svc := newTestService(t)
	m, err := NewMockAuthenticator("example.com", WithSignCount(4))
	require.NoError(t, err)
	challenge := []byte("caller-held-challenge-0123456789")

	count, err := svc.VerifyAssertion(context.Background(), &AssertionVerification{
		Challenge:               challenge,
		RequireUserPresence:     true,
		RequireUserVerification: true,
		Credential:              storedCredentialFor(t, m, 4),
		Assertion:               signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin),
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(5), count)
}

// A zero counter on both sides is an authenticator that keeps no counter.
func TestVerifyAssertion_ZeroCountersAccepted(t *testing.T) {
	svc := newTestService(t)
	m, err := NewMockAuthenticator("example.com")
	require.NoError(t, err)
	challenge := []byte("caller-held-challenge")
	a := signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)
	resignWithCount(t, m, a, 0)

	count, err := svc.VerifyAssertion(context.Background(), &AssertionVerification{
		Challenge:  challenge,
		Credential: storedCredentialFor(t, m, 0),
		Assertion:  a,
	})
	require.NoError(t, err)
	assert.Zero(t, count)
}

func TestVerifyAssertion_Failures(t *testing.T) {
	challenge := []byte("caller-held-challenge-0123456789")
	tests := []struct {
		name  string
		build func(t *testing.T) *AssertionVerification
		check func(t *testing.T, err error)
	}{
		{
			name:  "nil request",
			build: func(t *testing.T) *AssertionVerification { return nil },
			check: func(t *testing.T, err error) {
				var e *AssertionRequestError
				require.ErrorAs(t, err, &e)
			},
		},
		{
			name: "empty challenge",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				return &AssertionVerification{Credential: storedCredentialFor(t, m, 0), Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionRequestError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, "Challenge", e.Field)
			},
		},
		{
			name: "no stored credential",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				return &AssertionVerification{Challenge: challenge, Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionRequestError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, "Credential", e.Field)
			},
		},
		{
			name: "no assertion",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 0)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionRequestError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, "Assertion", e.Field)
			},
		},
		{
			name: "another credential",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				other, _ := NewMockAuthenticator("example.com")
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, other, 0), Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionCredentialMismatchError
				require.ErrorAs(t, err, &e)
			},
		},
		{
			name: "registration client data",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 0), Assertion: signedAssertion(t, m, "webauthn.create", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionCeremonyTypeError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, "webauthn.create", e.Type)
			},
		},
		{
			name: "another challenge",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				return &AssertionVerification{Challenge: []byte("the-caller-challenge"), Credential: storedCredentialFor(t, m, 0), Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionChallengeMismatchError
				require.ErrorAs(t, err, &e)
			},
		},
		{
			name: "unlisted origin",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 0), Assertion: signedAssertion(t, m, "webauthn.get", challenge, "https://evil.example")}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionOriginError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, "https://evil.example", e.Origin)
			},
		},
		{
			name: "another RP ID",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("other.example")
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 0), Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionRPIDHashError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, "example.com", e.RPID)
			},
		},
		{
			name: "user presence required",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com", WithUserPresent(false))
				return &AssertionVerification{Challenge: challenge, RequireUserPresence: true, Credential: storedCredentialFor(t, m, 0), Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionUserPresenceError
				require.ErrorAs(t, err, &e)
			},
		},
		{
			name: "user verification required",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com", WithUserVerified(false))
				return &AssertionVerification{Challenge: challenge, RequireUserVerification: true, Credential: storedCredentialFor(t, m, 0), Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionUserVerificationError
				require.ErrorAs(t, err, &e)
			},
		},
		{
			name: "bad signature",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				a := signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)
				a.Raw.AssertionResponse.Signature[len(a.Raw.AssertionResponse.Signature)-1] ^= 0xff
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 0), Assertion: a}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionSignatureError
				require.ErrorAs(t, err, &e)
			},
		},
		{
			name: "key of another credential",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				other, _ := NewMockAuthenticator("example.com")
				cred := storedCredentialFor(t, other, 0)
				cred.ID = m.CredentialID
				return &AssertionVerification{Challenge: challenge, Credential: cred, Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionSignatureError
				require.ErrorAs(t, err, &e)
			},
		},
		{
			name: "sign counter replayed",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com", WithSignCount(6))
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 7), Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionSignCountError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, uint32(7), e.Stored)
				assert.Equal(t, uint32(7), e.Received)
			},
		},
		{
			name: "sign counter went backwards",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com", WithSignCount(1))
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 9), Assertion: signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionSignCountError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, uint32(9), e.Stored)
				assert.Equal(t, uint32(2), e.Received)
			},
		},
		{
			name: "counter dropped to zero",
			build: func(t *testing.T) *AssertionVerification {
				m, _ := NewMockAuthenticator("example.com")
				a := signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)
				resignWithCount(t, m, a, 0)
				return &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 3), Assertion: a}
			},
			check: func(t *testing.T, err error) {
				var e *AssertionSignCountError
				require.ErrorAs(t, err, &e)
				assert.Equal(t, uint32(0), e.Received)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestService(t)
			_, err := svc.VerifyAssertion(context.Background(), tc.build(t))
			require.Error(t, err)
			assert.True(t, IsVerificationFailed(err) || errors.As(err, new(*AssertionRequestError)),
				"%v is a verification failure", err)
			tc.check(t, err)
		})
	}
}

// A credential the relying party stores gets its new sign counter, so a
// replay of the same assertion is refused.
func TestVerifyAssertion_PersistsSignCount(t *testing.T) {
	ctx := context.Background()
	cfg := validTestConfig()
	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{Config: cfg, UserStore: users, SessionStore: NewMemorySessionStore(), CredentialStore: creds})
	require.NoError(t, err)

	m, err := NewMockAuthenticator("example.com", WithSignCount(2))
	require.NoError(t, err)
	cred := storedCredentialFor(t, m, 2)
	require.NoError(t, creds.Save(ctx, cred))
	challenge := []byte("caller-held-challenge")
	a := signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)

	count, err := svc.VerifyAssertion(ctx, &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 2), Assertion: a})
	require.NoError(t, err)
	assert.Equal(t, uint32(3), count)

	saved, err := creds.GetByCredentialID(ctx, m.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), saved.Authenticator.SignCount)

	// The caller's stale copy still holds 2; the stored counter refuses the replay.
	_, err = svc.VerifyAssertion(ctx, &AssertionVerification{Challenge: challenge, Credential: storedCredentialFor(t, m, 2), Assertion: a})
	var e *AssertionSignCountError
	require.ErrorAs(t, err, &e)
	assert.Equal(t, uint32(3), e.Stored)
}
