// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package xkms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInviteRegistration_UnknownInviteSameForAnyTenant is Tenant Agent
// ruling 1041 (2): an anonymous caller presenting an unknown invite gets the
// same error whether or not the relying party serves the invite's tenant, so
// the refusal does not reveal which tenant is served. The served-tenant check
// runs only after the invite lookup succeeds.
func TestInviteRegistration_UnknownInviteSameForAnyTenant(t *testing.T) {
	const unknown = "not-a-real-invite-token"

	served := newInviteFixture(t)
	other := newInviteFixtureIn(t, "acme")

	_, servedBegin := served.beginRegistration("", unknown)
	_, otherBegin := other.beginRegistration("acme", unknown)
	require.Error(t, servedBegin)
	require.Error(t, otherBegin)
	require.NotErrorIs(t, otherBegin, ErrInviteTenantNotServed, "begin: an unknown invite must not reveal the served tenant")
	require.Equal(t, servedBegin.Error(), otherBegin.Error(), "begin")

	_, servedFinish := served.finishRegistration("", unknown, "no-session", `{}`)
	_, otherFinish := other.finishRegistration("acme", unknown, "no-session", `{}`)
	require.Error(t, servedFinish)
	require.Error(t, otherFinish)
	require.NotErrorIs(t, otherFinish, ErrInviteTenantNotServed, "finish: an unknown invite must not reveal the served tenant")
	require.Equal(t, servedFinish.Error(), otherFinish.Error(), "finish")
}
