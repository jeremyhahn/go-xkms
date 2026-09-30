// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package scope_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]scope.Scope{
		"tenant": scope.Tenant, " User ": scope.User, "SERVICE": scope.Service,
	} {
		got, err := scope.Parse(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got)
	}
	for _, in := range []string{"", "shared", "users", "tenant/x"} {
		_, err := scope.Parse(in)
		var invalid *scope.InvalidScopeError
		require.ErrorAs(t, err, &invalid, in)
		assert.Equal(t, in, invalid.Value)
	}
}

func TestTenantName(t *testing.T) {
	assert.Equal(t, scope.SystemTenant, scope.TenantName(""))
	assert.Equal(t, scope.SystemTenant, scope.TenantName(scope.SystemTenant))
	assert.Equal(t, "acme", scope.TenantName("acme"))
	assert.True(t, scope.IsSystem(""))
	assert.False(t, scope.IsSystem("acme"))
}

func TestPrefix_Layout(t *testing.T) {
	shared, err := scope.SharedPrefix("acme", "staticpw")
	require.NoError(t, err)
	assert.Equal(t, "acme/staticpw/shared/", shared)

	personal, err := scope.PersonalPrefix("acme", "staticpw", "alice")
	require.NoError(t, err)
	assert.Equal(t, "acme/staticpw/users/alice/", personal)

	service, err := scope.Prefix("acme", "ssh", scope.Service, "ci")
	require.NoError(t, err)
	assert.Equal(t, "acme/ssh/services/ci/", service)

	system, err := scope.SharedPrefix("", "tpm-policies")
	require.NoError(t, err)
	assert.Equal(t, "system/tpm-policies/shared/", system)

	suffix, err := scope.SharedSuffix("tpm-policies")
	require.NoError(t, err)
	assert.Equal(t, "/tpm-policies/shared/", suffix)
}

// A personal prefix of one user is never a prefix of another's, even when one
// subject is a prefix of the other: the trailing separator closes it.
func TestPrefix_UsersDoNotOverlap(t *testing.T) {
	al, err := scope.PersonalPrefix("acme", "staticpw", "al")
	require.NoError(t, err)
	alice, err := scope.PersonalPrefix("acme", "staticpw", "alice")
	require.NoError(t, err)
	assert.NotContains(t, alice, al)
}

func TestPrefix_RefusesUnsafeSegments(t *testing.T) {
	cases := []struct {
		name, tenant, feature, owner string
		sc                           scope.Scope
		field                        string
	}{
		{"tenant slash", "a/b", "f", "", scope.Tenant, "tenant"},
		{"tenant colon", "a:b", "f", "", scope.Tenant, "tenant"},
		{"feature empty", "a", "", "", scope.Tenant, "feature"},
		{"owner empty", "a", "f", "", scope.User, "owner"},
		{"owner traversal", "a", "f", "..", scope.User, "owner"},
		{"owner slash", "a", "f", "x/y", scope.Service, "owner"},
		{"owner nul", "a", "f", "x\x00", scope.User, "owner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scope.Prefix(tc.tenant, tc.feature, tc.sc, tc.owner)
			var seg *scope.InvalidSegmentError
			require.ErrorAs(t, err, &seg)
			assert.Equal(t, tc.field, seg.Field)
		})
	}
	_, err := scope.Prefix("a", "f", scope.Scope("bogus"), "x")
	var invalid *scope.InvalidScopeError
	require.ErrorAs(t, err, &invalid)
	_, err = scope.SharedSuffix("")
	require.Error(t, err)
}

func TestFeaturePrefixAndScopeRoot(t *testing.T) {
	for sc, want := range map[scope.Scope]string{
		scope.Tenant:  "ssh/shared/",
		scope.User:    "ssh/users/alice/",
		scope.Service: "ssh/services/alice/",
	} {
		got, err := scope.FeaturePrefix("ssh", sc, "alice")
		require.NoError(t, err)
		assert.Equal(t, want, got)

		full, err := scope.Prefix("acme", "ssh", sc, "alice")
		require.NoError(t, err)
		assert.Equal(t, "acme/"+want, full, "Prefix is the tenant root plus FeaturePrefix")
	}
	for sc, want := range map[scope.Scope]string{
		scope.Tenant: "ssh/shared/", scope.User: "ssh/users/", scope.Service: "ssh/services/",
	} {
		got, err := scope.ScopeRoot("ssh", sc)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	root, err := scope.TenantRoot("")
	require.NoError(t, err)
	assert.Equal(t, "system/", root)

	_, err = scope.FeaturePrefix("", scope.Tenant, "")
	require.Error(t, err)
	_, err = scope.FeaturePrefix("ssh", scope.User, "")
	require.Error(t, err)
	_, err = scope.FeaturePrefix("ssh", "bogus", "x")
	require.Error(t, err)
	_, err = scope.ScopeRoot("ssh", "bogus")
	require.Error(t, err)
	_, err = scope.ScopeRoot("a/b", scope.User)
	require.Error(t, err)
	_, err = scope.TenantRoot("a/b")
	require.Error(t, err)
}

func TestPrincipalOf(t *testing.T) {
	platform := scope.PrincipalOf(nil)
	assert.True(t, platform.Platform)
	assert.Equal(t, scope.SystemTenant, platform.TenantID)

	root := scope.PrincipalOf(&auth.Identity{Subject: "root", TenantID: scope.SystemTenant})
	assert.True(t, root.Platform)
	assert.Equal(t, "root", root.Subject)

	alice := scope.PrincipalFromContext(auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "acme"}))
	assert.False(t, alice.Platform)
	assert.Equal(t, "acme", alice.TenantID)
	assert.Equal(t, "alice", alice.Subject)
}

func TestAuthorize(t *testing.T) {
	alice := scope.Principal{TenantID: "a", Subject: "alice"}
	root := scope.Principal{TenantID: scope.SystemTenant, Subject: "root", Platform: true}

	allowed := []struct {
		name string
		p    scope.Principal
		t    scope.Target
	}{
		{"tenant user sees shared", alice, scope.Target{TenantID: "a", Scope: scope.Tenant}},
		{"user sees own personal", alice, scope.Target{TenantID: "a", Scope: scope.User, Owner: "alice"}},
		{"platform sees tenant shared", root, scope.Target{TenantID: "a", Scope: scope.Tenant}},
		{"platform sees own personal", root, scope.Target{TenantID: "", Scope: scope.User, Owner: "root"}},
		{"service permission", withService(alice), scope.Target{TenantID: "a", Scope: scope.Service, Owner: "ci"}},
	}
	for _, tc := range allowed {
		assert.NoError(t, tc.p.Authorize(tc.t), tc.name)
	}

	refused := []struct {
		name string
		p    scope.Principal
		t    scope.Target
		want any
	}{
		{"other tenant shared", alice, scope.Target{TenantID: "b", Scope: scope.Tenant}, &scope.CrossTenantError{}},
		{"tenant to system", alice, scope.Target{TenantID: "", Scope: scope.Tenant}, &scope.CrossTenantError{}},
		{"other user personal", alice, scope.Target{TenantID: "a", Scope: scope.User, Owner: "bob"}, &scope.CrossUserError{}},
		{"same subject other tenant", alice, scope.Target{TenantID: "b", Scope: scope.User, Owner: "alice"}, &scope.CrossTenantError{}},
		{"platform to user personal", root, scope.Target{TenantID: "a", Scope: scope.User, Owner: "root"}, &scope.CrossUserError{}},
		{"platform to other personal", root, scope.Target{TenantID: "", Scope: scope.User, Owner: "admin2"}, &scope.CrossUserError{}},
		{"service without permission", alice, scope.Target{TenantID: "a", Scope: scope.Service, Owner: "alice"}, &scope.ServiceScopeError{}},
	}
	for _, tc := range refused {
		err := tc.p.Authorize(tc.t)
		require.Error(t, err, tc.name)
		assert.ErrorIs(t, err, scope.ErrRefused, tc.name)
		assert.IsType(t, tc.want, err, tc.name)
		assert.NotEmpty(t, err.Error())
	}

	var invalid *scope.InvalidScopeError
	err := alice.Authorize(scope.Target{TenantID: "a", Scope: "bogus"})
	require.ErrorAs(t, err, &invalid)
	assert.False(t, errors.Is(err, scope.ErrRefused))
}

func withService(p scope.Principal) scope.Principal {
	p.ServiceAccess = true
	return p
}

func TestInvalidSegmentError_Unwrap(t *testing.T) {
	_, err := scope.SharedPrefix("a:b", "f")
	var seg *scope.InvalidSegmentError
	require.ErrorAs(t, err, &seg)
	require.Error(t, errors.Unwrap(err))
	assert.Contains(t, err.Error(), "a:b")
}
