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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// TestFinishAuthentication_DecoyAndWrongAssertionUniformResponse is
// go-xkms#1310: a finish against a decoy account (an email that names no
// account) and a finish with a wrong assertion against a real, registered
// account must be byte-identical on the wire -- same gRPC code, same
// message -- so a caller cannot use the response to tell a guessed email
// from a real one it merely signed wrong.
func TestFinishAuthentication_DecoyAndWrongAssertionUniformResponse(t *testing.T) {
	f := newStandingFixture(t, "member@example.com")

	// Real account, wrong assertion: an authenticator that never enrolled a
	// credential for this account signs the real ceremony's challenge.
	realBegin := f.begin(t)
	var realOptions waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(realBegin.OptionsJson), &realOptions))
	forger, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	forgedAssertion, err := forger.CreateAssertionResponse(realOptions.Response.Challenge, f.user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	forgedJSON, err := json.Marshal(forgedAssertion.Raw)
	require.NoError(t, err)
	_, wrongErr := f.svc.FinishAuthentication(context.Background(), &pb.FinishAuthenticationRequest{
		SessionId:     realBegin.SessionId,
		Email:         f.user.Email(),
		AssertionJson: string(forgedJSON),
	})
	require.Error(t, wrongErr)

	// Decoy account: an email that names no account. The real account's own
	// authenticator signs it -- the decoy session names no account to
	// validate against, so the assertion's contents do not matter.
	decoyBegin, err := f.svc.BeginAuthentication(context.Background(), &pb.BeginAuthenticationRequest{Email: "nobody@example.com"})
	require.NoError(t, err)
	var decoyOptions waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(decoyBegin.OptionsJson), &decoyOptions))
	decoyAssertion, err := f.authenticator.CreateAssertionResponse(decoyOptions.Response.Challenge, f.user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	decoyJSON, err := json.Marshal(decoyAssertion.Raw)
	require.NoError(t, err)
	_, decoyErr := f.svc.FinishAuthentication(context.Background(), &pb.FinishAuthenticationRequest{
		SessionId:     decoyBegin.SessionId,
		Email:         "nobody@example.com",
		AssertionJson: string(decoyJSON),
	})
	require.Error(t, decoyErr)

	assert.Equal(t, codes.Unauthenticated, status.Code(wrongErr))
	assert.Equal(t, status.Code(wrongErr), status.Code(decoyErr))
	assert.Equal(t, "verification failed", status.Convert(wrongErr).Message())
	assert.Equal(t, status.Convert(wrongErr).Message(), status.Convert(decoyErr).Message())
}

// TestFinishAuthentication_MissingSessionDistinctFromUniformFailure proves a
// missing (unknown or already-consumed) session keeps its own, distinct
// response -- it reflects the caller's own ceremony bookkeeping, not a guess
// about an account -- rather than being folded into the uniform
// verification-failure response go-xkms#1310 requires for every other
// login-finish failure.
func TestFinishAuthentication_MissingSessionDistinctFromUniformFailure(t *testing.T) {
	f := newStandingFixture(t, "member2@example.com")

	begin := f.begin(t)
	var options waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(begin.OptionsJson), &options))
	assertion, err := f.authenticator.CreateAssertionResponse(options.Response.Challenge, f.user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	assertionJSON, err := json.Marshal(assertion.Raw)
	require.NoError(t, err)

	_, err = f.svc.FinishAuthentication(context.Background(), &pb.FinishAuthenticationRequest{
		SessionId:     "session-that-was-never-issued",
		Email:         f.user.Email(),
		AssertionJson: string(assertionJSON),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.NotEqual(t, "verification failed", status.Convert(err).Message())
}
