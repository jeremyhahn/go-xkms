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

package auth_factors

import (
	"context"
	"testing"

	"github.com/descope/virtualwebauthn"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// callerAssertion signs an assertion over nonce with the fixture's credential.
func (f *factorFixture) callerAssertion(t *testing.T, nonce []byte, counter uint32) string {
	t.Helper()
	auth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserHandle: f.user.WebAuthnID(),
	})
	cred := f.credential
	cred.Counter = counter
	auth.AddCredential(cred)
	return virtualwebauthn.CreateAssertionResponse(f.rp, auth, cred, virtualwebauthn.AssertionOptions{
		Challenge:        nonce,
		AllowCredentials: []string{string(f.factor.Credential)},
		RelyingPartyID:   f.rp.ID,
	})
}

func (f *factorFixture) verifyNonce(nonce []byte, assertion string) error {
	return f.v.Verify(context.Background(), f.factor, qrdbtransport.VerifyChallenge{
		Type:  qrdbtransport.FactorTypeFIDO2,
		Nonce: nonce,
		MethodMetadata: map[string]string{
			"assertion":     assertion,
			"credential_id": string(f.factor.Credential),
		},
	})
}

// A caller-held nonce is verified without a login session.
func TestWebAuthnFactorVerifier_CallerChallenge(t *testing.T) {
	f := newFactorFixture(t, "caller-challenge@example.com")
	nonce := []byte("caller-held-nonce-0123456789abcd")

	assertion := f.callerAssertion(t, nonce, 5)
	require.NoError(t, f.verifyNonce(nonce, assertion))

	t.Run("replay refused by the sign counter", func(t *testing.T) {
		var countErr *xkmswebauthn.AssertionSignCountError
		require.ErrorAs(t, f.verifyNonce(nonce, assertion), &countErr)
	})

	t.Run("another nonce", func(t *testing.T) {
		other := f.callerAssertion(t, nonce, 9)
		var mismatch *xkmswebauthn.AssertionChallengeMismatchError
		require.ErrorAs(t, f.verifyNonce([]byte("another-nonce-0123456789abcdefgh"), other), &mismatch)
	})

	t.Run("no nonce and no session", func(t *testing.T) {
		var missing *MissingMethodMetadataError
		require.ErrorAs(t, f.verifyNonce(nil, f.callerAssertion(t, nonce, 11)), &missing)
	})
}

// TestWebAuthnFactorVerifier_CallerChallengeRefusesSuspendedAccount proves a
// valid nonce assertion does not verify once its account is suspended.
func TestWebAuthnFactorVerifier_CallerChallengeRefusesSuspendedAccount(t *testing.T) {
	f := newFactorFixture(t, "nonce-suspended@example.com")
	nonce := []byte("caller-held-nonce-0123456789abcd")
	f.setStanding(t, qrdbsdk.LifecycleSuspended, nil)
	require.Error(t, f.verifyNonce(nonce, f.callerAssertion(t, nonce, 5)))
}

// TestWebAuthnFactorVerifier_CallerChallengeRefusesWithdrawnMethod proves a
// valid nonce assertion does not verify once WebAuthn leaves the account's
// AuthMethods.
func TestWebAuthnFactorVerifier_CallerChallengeRefusesWithdrawnMethod(t *testing.T) {
	f := newFactorFixture(t, "nonce-withdrawn@example.com")
	nonce := []byte("caller-held-nonce-0123456789abcd")
	f.setStanding(t, qrdbsdk.LifecycleActive, []string{"piv"})
	require.Error(t, f.verifyNonce(nonce, f.callerAssertion(t, nonce, 5)))
}

// TestWebAuthnFactorVerifier_CallerChallengeSignatureNoMetadata proves a
// nonce challenge carrying the assertion in Signature needs no MethodMetadata.
func TestWebAuthnFactorVerifier_CallerChallengeSignatureNoMetadata(t *testing.T) {
	f := newFactorFixture(t, "nonce-signature@example.com")
	nonce := []byte("caller-held-nonce-0123456789abcd")
	require.NoError(t, f.v.Verify(context.Background(), f.factor, qrdbtransport.VerifyChallenge{
		Type:      qrdbtransport.FactorTypeFIDO2,
		Nonce:     nonce,
		Signature: []byte(f.callerAssertion(t, nonce, 5)),
	}))
}
