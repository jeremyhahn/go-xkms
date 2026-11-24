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

package rest

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	sshtenancy "github.com/jeremyhahn/go-xkms/pkg/ssh/tenancy"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest/offline"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// identityProbeModule serves GET /api/v1/keys under keys:read and records the
// identity the unified server's middleware bound into the request context.
type identityProbeModule struct {
	qrdbserver.BaseModule
	srv  atomic.Pointer[Server]
	seen atomic.Pointer[qrdbsdk.Identity]
}

func (*identityProbeModule) Name() string { return "xkms-identity-probe" }

func (p *identityProbeModule) RegisterHTTP(r *qrdbserver.ModuleHTTPRegistrar) {
	r.Handle(http.MethodGet, "/api/v1/keys", qrdbsdk.Permission("keys:read"),
		func(w http.ResponseWriter, req *http.Request) {
			if id := auth.GetIdentity(req.Context()); id != nil {
				cp := *id
				p.seen.Store(&cp)
			}
			w.WriteHeader(http.StatusOK)
		})
}

func (p *identityProbeModule) AuthenticateHTTP(r *http.Request) (*qrdbsdk.Identity, error) {
	srv := p.srv.Load()
	if srv == nil {
		return nil, errors.New("host server not built yet")
	}
	return srv.AuthenticateHTTP(r)
}

// A passkey request through the unified server is bound to its account by
// go-qrdb's middleware, which rewrites Subject to the account id. The
// principal references persisted under the passkey handle before that --
// key-policy Allowed/DeniedPrincipals, the personal password vault, personal
// OIDC credentials and user-scoped SSH keys and authorized keys --
// still name the caller: a deny of the handle denies, an allow allows, and
// the vault entry written under the handle is still the caller's.
func TestNewHostServer_PasskeyPrincipalReferencesSurviveAccountBinding(t *testing.T) {
	qrdbsdk.RegisterPermissions(qrdbsdk.Permission("keys:read"))
	qrdbsdk.RegisterPermissionScope(qrdbsdk.PermissionScopeSelf, qrdbsdk.Permission("keys:read"))
	probe := &identityProbeModule{}
	node, get := newEnforcingRESTNode(t, probe)
	srv := newEnforcingHostServer(t, node)
	probe.srv.Store(srv)

	ctx := context.Background()
	reader, err := node.Services().Role.CreateRole(ctx, &qrdbsdk.CreateRoleRequest{
		Name:        "keys-reader",
		Permissions: []qrdbsdk.Permission{qrdbsdk.Permission("keys:read")},
	})
	require.NoError(t, err)
	carol, err := node.UserService().CreateUser(ctx, &qrdbuser.CreateUserRequest{
		Username: "carol",
		Email:    "carol@example.com",
		Name:     "carol",
		RoleIDs:  []string{reader.ID},
	})
	require.NoError(t, err)
	handle := base64.RawURLEncoding.EncodeToString(binary.BigEndian.AppendUint64(nil, carol.ID))
	pair, err := srv.tokenIssuer.Mint(ctx, &auth.Identity{
		Subject:  handle,
		TenantID: DefaultWebAuthnTenant,
		Metadata: map[string]string{
			auth.SubjectKindMetadataKey: auth.SubjectKindUserHandle,
			"username":                  "carol",
		},
	})
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, get(pair.AccessToken))
	bound := probe.seen.Load()
	require.NotNil(t, bound, "the request reached the handler with an identity")
	require.Equal(t, carol.ID, bound.UserID, "the middleware bound the request to the account")
	require.Equal(t, handle, auth.PolicySubject(bound), "the bound identity still names the passkey handle for persisted references")

	// A service holding the references persisted before the upgrade, when
	// the identity named the account by its handle.
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{Backends: map[string]xkms.Backend{"software": ks}, DefaultBackend: "software"}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)
	policies, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc.SetKeyPolicyStore(policies)
	_, systemStore, manager := testPasswordSetup(t)
	svc.SetPasswordStore(systemStore)
	svc.SetPasswordStoreManager(manager)

	legacyCtx := auth.WithIdentity(ctx, &auth.Identity{Subject: handle, TenantID: bound.TenantID})
	boundCtx := auth.WithIdentity(ctx, bound)

	_, err = svc.GenerateKey(legacyCtx, &transport.GenerateKeyRequest{KeyID: "carol-key", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)
	setPrincipals := func(allowed, denied []string) {
		t.Helper()
		_, err := svc.SetKeyPolicy(legacyCtx, &transport.SetKeyPolicyRequest{
			Backend: "software", KeyID: "carol-key",
			Policy: &transport.KeyPolicy{AllowedPrincipals: allowed, DeniedPrincipals: denied},
		})
		require.NoError(t, err)
	}
	sign := func() error {
		_, err := svc.Sign(boundCtx, &transport.SignRequest{Backend: "software", KeyID: "carol-key", Data: []byte("payload")})
		return err
	}

	setPrincipals(nil, []string{handle})
	require.Error(t, sign(), "a key policy denying the passkey handle still denies the bound caller")
	setPrincipals([]string{handle}, nil)
	require.NoError(t, sign(), "a key policy allowing the passkey handle still allows the bound caller")

	cred := transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "a test vault passphrase"}
	_, err = svc.PasswordVaultEnroll(legacyCtx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: cred})
	require.NoError(t, err)
	_, err = svc.PasswordAdd(legacyCtx, &transport.PasswordAddRequest{Name: "Carol Private", Password: "carol-secret"})
	require.NoError(t, err)

	personal, err := svc.PasswordList(boundCtx, &transport.PasswordListRequest{Scope: "personal"})
	require.NoError(t, err)
	require.Equal(t, 1, personal.Total, "the personal entry written under the handle is still the bound caller's")
	require.Equal(t, "Carol Private", personal.Passwords[0].Name)

	// A personal OIDC credential stored under the handle before the upgrade.
	svc.SetOIDCCredentialService(offline.NewService(t, scope.TenantName(bound.TenantID)))
	t.Cleanup(func() { svc.SetOIDCCredentialService(nil) })
	expires := time.Now().Add(time.Hour)
	oidcRef := transport.OIDCCredentialRef{Scope: "user", Name: "carol-idp"}
	created, err := svc.OIDCCredentialCreate(legacyCtx, &transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: oidcRef,
		Config:            transport.OIDCCredentialConfig{Template: "anthropic"},
		Tokens:            &transport.OIDCCredentialTokens{AccessToken: "carol-at", ExpiresAt: &expires},
	})
	require.NoError(t, err)
	require.Equal(t, handle, created.Owner, "the pre-upgrade credential is owned by the handle")
	_, err = svc.OIDCCredentialGet(boundCtx, &oidcRef)
	require.NoError(t, err, "the personal OIDC credential stored under the handle is still the bound caller's")
	listed, err := svc.OIDCCredentialList(boundCtx, &transport.OIDCCredentialListRequest{})
	require.NoError(t, err)
	require.Len(t, listed.Credentials, 1, "the bound caller lists the credential stored under the handle")

	// A user-scoped SSH key and authorized key stored under the handle before
	// the upgrade are still the bound caller's, and another user's bound
	// request still cannot reach them.
	sshClient, err := sshtenancy.New(sshtenancy.Options{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sshClient.Close()) })
	_, err = sshClient.Keys().Generate(legacyCtx, sdkssh.GenerateRequest{Scope: "user", Owner: handle, Name: "carol-ssh", Algorithm: "ed25519"})
	require.NoError(t, err)
	exported, err := sshClient.Keys().ExportPublic(legacyCtx, sdkssh.ExportRequest{Scope: "user", Owner: handle, Name: "carol-ssh"})
	require.NoError(t, err)
	require.NoError(t, sshClient.AuthorizedKeys().Add(legacyCtx, sdkssh.AddAuthorizedKeyRequest{
		Scope: "user", Owner: handle, Name: "carol-login", Line: exported.Line,
	}))

	sshKeys, err := sshClient.Keys().List(boundCtx, sdkssh.ListKeysRequest{Scope: "user", Owner: handle})
	require.NoError(t, err, "the bound caller lists the SSH keys stored under the handle")
	require.Len(t, sshKeys, 1)
	require.Equal(t, "carol-ssh", sshKeys[0].Name)
	_, err = sshClient.Keys().ExportPublic(boundCtx, sdkssh.ExportRequest{Scope: "user", Owner: handle, Name: "carol-ssh"})
	require.NoError(t, err, "the bound caller uses the SSH key stored under the handle")
	authorized, err := sshClient.AuthorizedKeys().List(boundCtx, sdkssh.ListAuthorizedKeysRequest{Scope: "user", Owner: handle})
	require.NoError(t, err, "the bound caller lists the authorized keys stored under the handle")
	require.Len(t, authorized, 1)

	// Another passkey user bound to its own account in the same tenant.
	other := *bound
	other.Subject = "9999"
	other.UserID = carol.ID + 1
	other.Metadata = map[string]string{auth.PasskeyHandleMetadataKey: base64.RawURLEncoding.EncodeToString(binary.BigEndian.AppendUint64(nil, carol.ID+1))}
	otherCtx := auth.WithIdentity(ctx, &other)
	otherKeys, err := sshClient.Keys().List(otherCtx, sdkssh.ListKeysRequest{Scope: "user", Owner: handle})
	require.True(t, err != nil || len(otherKeys) == 0, "another user does not list the handle's SSH keys")
	_, err = sshClient.Keys().ExportPublic(otherCtx, sdkssh.ExportRequest{Scope: "user", Owner: handle, Name: "carol-ssh"})
	require.Error(t, err, "another user cannot use the handle's SSH key")
	otherAuthorized, err := sshClient.AuthorizedKeys().List(otherCtx, sdkssh.ListAuthorizedKeysRequest{Scope: "user", Owner: handle})
	require.True(t, err != nil || len(otherAuthorized) == 0, "another user does not list the handle's authorized keys")
}
