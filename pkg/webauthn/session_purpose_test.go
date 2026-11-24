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

package webauthn

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinishInviteRegistration_RefusesOrdinarySession: a session opened by
// the public registration begin is not an invite ceremony, even when the
// account it names is pending with no credential by the time it is finished.
// The invite finish refuses it and stores nothing.
func TestFinishInviteRegistration_RefusesOrdinarySession(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	const email = "ordinary@example.com"

	options, sessionID, err := f.svc.BeginRegistration(ctx, email, email)
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecyclePending, nil)
	user, err := f.users.GetByEmail(ctx, email)
	require.NoError(t, err)

	_, err = f.attestInvite(t, user.WebAuthnID(), options, sessionID, newEC2Credential(t))
	require.ErrorIs(t, err, ErrRegistrationRefused)

	creds, err := f.creds.GetByUserID(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Empty(t, creds, "an ordinary session enrols nothing through the invite finish")
}

// TestFinishRegistration_RefusesInviteSession: the service-level half of the
// cross-endpoint check. An invite session finished through the public
// registration finish is refused even after the account turned active.
func TestFinishRegistration_RefusesInviteSession(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	const email = "invitee@example.com"
	u := f.mustCreatePending(t, email)

	options, sessionID, err := f.svc.BeginInviteRegistration(ctx, u.WebAuthnID())
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecycleActive, nil)

	_, err = f.attest(t, options, sessionID, newEC2Credential(t))
	require.ErrorIs(t, err, ErrRegistrationRefused)

	creds, err := f.creds.GetByUserID(ctx, u.WebAuthnID())
	require.NoError(t, err)
	assert.Empty(t, creds, "an invite session enrols nothing through the public finish")
}
