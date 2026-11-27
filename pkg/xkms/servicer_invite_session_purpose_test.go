// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
)

// TestInviteSession_PublicRegistrationFinishRefusesIt is the cross-endpoint
// sequence: two invite ceremonies are opened for one invitation, one is
// redeemed through the invite finish, and the other's attestation and session
// ID are posted to the public POST /api/v1/webauthn/registration/finish. The
// account is active by then, so without a purpose bound to the session the
// public finish would enrol a second credential and mint tokens without the
// first credential ever being used. It must refuse, store nothing and mint
// nothing.
func TestInviteSession_PublicRegistrationFinishRefusesIt(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	first, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)
	second, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)
	require.NotEqual(t, first.SessionID, second.SessionID)

	_, err = f.finishRegistration(inviteFixtureTenant, token, first.SessionID, f.attestInvite(t, first.OptionsJSON, newInviteEC2Credential(t)))
	require.NoError(t, err)

	ctx := context.Background()
	user, err := f.svc.webAuthn().GetUserByEmail(ctx, inviteFixtureEmail)
	require.NoError(t, err)
	before, err := f.svc.webAuthn().GetCredentials(ctx, user.WebAuthnID())
	require.NoError(t, err)
	require.Len(t, before, 1, "the redeemed invitation enrolled one credential")

	mux := http.NewServeMux()
	webauthnhttp.MountStdlib(mux, "/api/v1/webauthn", webauthnhttp.NewHandler(f.svc.webAuthn()))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/finish",
		strings.NewReader(f.attestInvite(t, second.OptionsJSON, newInviteEC2Credential(t))))
	req.Header.Set(webauthnhttp.HeaderSessionID, second.SessionID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), webauthnhttp.ErrorCodeRegistrationRefused)
	assert.NotContains(t, rec.Body.String(), `"token"`, "no token is minted")

	after, err := f.svc.webAuthn().GetCredentials(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, after, 1, "the invite session enrolled no second credential")
}
