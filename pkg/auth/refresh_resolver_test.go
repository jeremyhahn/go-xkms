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

package auth

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webAuthnHandleSubject renders id as the base64url, unpadded, big-endian
// 8-byte subject a WebAuthn-issued refresh token carries
// (pkg/webauthn.HandleFromUserID / WebAuthnTokenAdapter.identityFor).
func webAuthnHandleSubject(id uint64) string {
	raw := make([]byte, 8)
	binary.BigEndian.PutUint64(raw, id)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestQRDBUserResolver_ByUsername_ActiveUserCurrentRoles(t *testing.T) {
	fake := testutil.NewQRDBFakeTransport()
	_, err := fake.CreateUser(context.Background(), &qrdbtransport.CreateUserRequest{
		Username: "alice",
		Email:    "alice@example.com",
		Name:     "Alice Admin",
		RoleIDs:  []string{"role-operator"},
	})
	require.NoError(t, err)

	resolver := NewQRDBUserResolver(fake)
	stale := &Identity{
		Subject: "alice",
		Roles:   []string{"role-stale"},
		Metadata: map[string]string{
			"auth_method":          "mtls",
			"cert_serial":          "1234",
			SubjectKindMetadataKey: SubjectKindUsername,
		},
	}

	fresh, err := resolver.ResolveUser(context.Background(), stale)
	require.NoError(t, err)
	assert.Equal(t, "alice", fresh.Subject)
	assert.Equal(t, []string{"role-operator"}, fresh.Roles,
		"the resolved identity must carry the account's CURRENT roles, not the stale snapshot")
	assert.Equal(t, "alice@example.com", fresh.Metadata["email"])
	assert.Equal(t, "Alice Admin", fresh.Metadata["display_name"])
	// Fields the resolver does not own ride forward unchanged.
	assert.Equal(t, "mtls", fresh.Metadata["auth_method"])
	assert.Equal(t, "1234", fresh.Metadata["cert_serial"])
}

func TestQRDBUserResolver_ByWebAuthnHandle_ActiveUserCurrentRoles(t *testing.T) {
	fake := testutil.NewQRDBFakeTransport()
	u, err := fake.CreateUser(context.Background(), &qrdbtransport.CreateUserRequest{
		Username: "bob@example.com",
		Email:    "bob@example.com",
		Name:     "Bob Passkey",
		RoleIDs:  []string{"role-viewer"},
	})
	require.NoError(t, err)

	resolver := NewQRDBUserResolver(fake)
	subject := webAuthnHandleSubject(u.ID)
	id := &Identity{
		Subject: subject,
		Roles:   []string{"role-stale"},
		Metadata: map[string]string{
			"username":             "bob@example.com",
			SubjectKindMetadataKey: SubjectKindUserHandle,
		},
	}

	fresh, err := resolver.ResolveUser(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, subject, fresh.Subject, "the subject the token already carries must not change")
	assert.Equal(t, []string{"role-viewer"}, fresh.Roles,
		"the resolved identity must carry the account's CURRENT roles, not the stale snapshot")
	assert.Equal(t, "bob@example.com", fresh.Metadata["email"])
}

func TestQRDBUserResolver_DisabledUserRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind string
	}{
		{"username", SubjectKindUsername},
		{"user_handle", SubjectKindUserHandle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := testutil.NewQRDBFakeTransport()
			u, err := fake.CreateUser(context.Background(), &qrdbtransport.CreateUserRequest{
				Username: "mallory",
				Email:    "mallory@example.com",
			})
			require.NoError(t, err)
			require.NoError(t, fake.DisableUser(context.Background(), u.ID))

			subject := "mallory"
			if tc.kind == SubjectKindUserHandle {
				subject = webAuthnHandleSubject(u.ID)
			}

			resolver := NewQRDBUserResolver(fake)
			_, err = resolver.ResolveUser(context.Background(), &Identity{
				Subject:  subject,
				Metadata: map[string]string{SubjectKindMetadataKey: tc.kind},
			})
			assert.ErrorIs(t, err, ErrUserDisabled)
		})
	}
}

func TestQRDBUserResolver_DeletedUserRefused(t *testing.T) {
	fake := testutil.NewQRDBFakeTransport()
	u, err := fake.CreateUser(context.Background(), &qrdbtransport.CreateUserRequest{
		Username: "carol",
		Email:    "carol@example.com",
	})
	require.NoError(t, err)
	require.NoError(t, fake.DeleteUser(context.Background(), u.ID))

	resolver := NewQRDBUserResolver(fake)

	_, err = resolver.ResolveUser(context.Background(), &Identity{
		Subject:  "carol",
		Metadata: map[string]string{SubjectKindMetadataKey: SubjectKindUsername},
	})
	assert.ErrorIs(t, err, ErrRefreshSubjectNotFound)

	_, err = resolver.ResolveUser(context.Background(), &Identity{
		Subject:  webAuthnHandleSubject(u.ID),
		Metadata: map[string]string{SubjectKindMetadataKey: SubjectKindUserHandle},
	})
	assert.ErrorIs(t, err, ErrRefreshSubjectNotFound)
}

// TestQRDBUserResolver_DeletedUsernameNeverResolvesAsAnotherUsersHandle is
// the collision regression (go-xkms#1297 review): a deleted mTLS/PIV
// account's username can, by coincidence, be a valid base64url encoding of
// ANOTHER live user's numeric id. Before the subject kind was declared
// explicitly, a not-found username lookup fell back to decoding the subject
// as a WebAuthn handle -- which resolved this token to the OTHER, unrelated,
// still-active account. With sub_kind=username declared, that fallback must
// never run: the refresh is refused, full stop.
func TestQRDBUserResolver_DeletedUsernameNeverResolvesAsAnotherUsersHandle(t *testing.T) {
	fake := testutil.NewQRDBFakeTransport()
	ctx := context.Background()

	// The fake assigns ids sequentially from 1, so the first user created
	// gets id 1 -- the account the collision would hand refresh access to.
	victim, err := fake.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: "victim",
		Email:    "victim@example.com",
		RoleIDs:  []string{"role-admin"},
	})
	require.NoError(t, err)
	require.Equal(t, uint64(1), victim.ID, "test setup: victim must be the account id 1 decodes to")

	collidingUsername := webAuthnHandleSubject(victim.ID)
	attacker, err := fake.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: collidingUsername,
		Email:    "attacker@example.com",
	})
	require.NoError(t, err)
	require.NoError(t, fake.DeleteUser(ctx, attacker.ID))

	resolver := NewQRDBUserResolver(fake)
	fresh, err := resolver.ResolveUser(ctx, &Identity{
		Subject:  collidingUsername,
		Metadata: map[string]string{SubjectKindMetadataKey: SubjectKindUsername},
	})
	assert.Nil(t, fresh)
	assert.ErrorIs(t, err, ErrRefreshSubjectNotFound,
		"a username-declared subject must never fall back to a handle lookup and resolve to a different account")
}

func TestQRDBUserResolver_UserHandleSubjectNotFoundRefused(t *testing.T) {
	resolver := NewQRDBUserResolver(testutil.NewQRDBFakeTransport())

	_, err := resolver.ResolveUser(context.Background(), &Identity{
		Subject:  webAuthnHandleSubject(999),
		Metadata: map[string]string{SubjectKindMetadataKey: SubjectKindUserHandle},
	})
	assert.ErrorIs(t, err, ErrRefreshSubjectNotFound)
}

func TestQRDBUserResolver_MalformedUserHandleRefused(t *testing.T) {
	resolver := NewQRDBUserResolver(testutil.NewQRDBFakeTransport())

	_, err := resolver.ResolveUser(context.Background(), &Identity{
		Subject:  "not-a-valid-handle",
		Metadata: map[string]string{SubjectKindMetadataKey: SubjectKindUserHandle},
	})
	assert.ErrorIs(t, err, ErrRefreshSubjectNotFound)
}

func TestQRDBUserResolver_MissingOrUnknownSubjectKindRefused(t *testing.T) {
	fake := testutil.NewQRDBFakeTransport()
	_, err := fake.CreateUser(context.Background(), &qrdbtransport.CreateUserRequest{
		Username: "alice",
		Email:    "alice@example.com",
	})
	require.NoError(t, err)
	resolver := NewQRDBUserResolver(fake)

	for name, id := range map[string]*Identity{
		"no metadata at all":       {Subject: "alice"},
		"metadata without the key": {Subject: "alice", Metadata: map[string]string{"username": "alice"}},
		"empty value":              {Subject: "alice", Metadata: map[string]string{SubjectKindMetadataKey: ""}},
		"unrecognized value":       {Subject: "alice", Metadata: map[string]string{SubjectKindMetadataKey: "bogus"}},
	} {
		t.Run(name, func(t *testing.T) {
			fresh, err := resolver.ResolveUser(context.Background(), id)
			assert.Nil(t, fresh)
			var kindErr *RefreshSubjectKindError
			assert.ErrorAs(t, err, &kindErr,
				"a token minted before sub_kind existed, or carrying garbage, must simply fail refresh")
		})
	}
}

func TestQRDBUserResolver_NilOrEmptySubjectRefused(t *testing.T) {
	resolver := NewQRDBUserResolver(testutil.NewQRDBFakeTransport())

	_, err := resolver.ResolveUser(context.Background(), nil)
	assert.ErrorIs(t, err, ErrRefreshSubjectNotFound)

	_, err = resolver.ResolveUser(context.Background(), &Identity{})
	assert.ErrorIs(t, err, ErrRefreshSubjectNotFound)
}

// erroringUserClient fails GetUserByUsername with a non-not-found error, so
// ResolveUser must fail closed rather than treat the account as absent.
type erroringUserClient struct {
	qrdbtransport.UserClient
	err error
}

func (e *erroringUserClient) GetUserByUsername(context.Context, string, string) (*qrdbtransport.User, error) {
	return nil, e.err
}

func TestQRDBUserResolver_LookupOutageFailsClosed(t *testing.T) {
	resolver := NewQRDBUserResolver(&erroringUserClient{err: errors.New("qrdb unreachable")})

	_, err := resolver.ResolveUser(context.Background(), &Identity{
		Subject:  "alice",
		Metadata: map[string]string{SubjectKindMetadataKey: SubjectKindUsername},
	})
	var lookupErr *RefreshUserLookupError
	require.ErrorAs(t, err, &lookupErr)
	assert.False(t, errors.Is(err, ErrUserDisabled), "an outage must never read as a resolved, disabled account")
}

// TestQRDBUserResolver_EnabledAfterDisableIsAcceptedAgain proves the check
// is a live re-read on every call, not a cached verdict: an account
// disabled and then re-enabled resolves again.
func TestQRDBUserResolver_EnabledAfterDisableIsAcceptedAgain(t *testing.T) {
	fake := testutil.NewQRDBFakeTransport()
	u, err := fake.CreateUser(context.Background(), &qrdbtransport.CreateUserRequest{
		Username: "dave",
		Email:    "dave@example.com",
	})
	require.NoError(t, err)
	require.NoError(t, fake.DisableUser(context.Background(), u.ID))

	id := &Identity{Subject: "dave", Metadata: map[string]string{SubjectKindMetadataKey: SubjectKindUsername}}
	resolver := NewQRDBUserResolver(fake)
	_, err = resolver.ResolveUser(context.Background(), id)
	require.ErrorIs(t, err, ErrUserDisabled)

	require.NoError(t, fake.EnableUser(context.Background(), u.ID))
	fresh, err := resolver.ResolveUser(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, "dave", fresh.Subject)
}
