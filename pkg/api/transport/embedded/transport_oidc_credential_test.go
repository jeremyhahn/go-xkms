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

package embedded

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest/offline"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func (m *mockService) OIDCCredentialCreate(context.Context, *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	return m.oidcCredential()
}

func (m *mockService) OIDCCredentialImport(context.Context, *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	return m.oidcCredential()
}

func (m *mockService) OIDCCredentialGet(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return m.oidcCredential()
}

func (m *mockService) OIDCCredentialList(context.Context, *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.OIDCCredentialListResponse{}, nil
}

func (m *mockService) OIDCCredentialDelete(context.Context, *transport.OIDCCredentialRef) error {
	if m.shouldFail {
		return errMock
	}
	return nil
}

func (m *mockService) OIDCCredentialRefresh(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return m.oidcCredential()
}

func (m *mockService) OIDCCredentialGetAccessToken(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.OIDCAccessToken{}, nil
}

func (m *mockService) OIDCCredentialDeviceStart(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return m.oidcCredential()
}

func (m *mockService) OIDCCredentialDevicePoll(context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return m.oidcCredential()
}

// oidcCredential answers a credential-returning OIDC credential method.
func (m *mockService) oidcCredential() (*transport.OIDCCredential, error) {
	if m.shouldFail {
		return nil, errMock
	}
	return &transport.OIDCCredential{}, nil
}

// TestOIDCCredential_CallsTheService proves the transport serves the OIDC
// credential API through the XKMSService it embeds, in the caller's tenant.
func TestOIDCCredential_CallsTheService(t *testing.T) {
	svc := &xkms.XKMSService{}
	svc.SetOIDCCredentialService(offline.NewService(t, "acme"))
	tr, err := New(svc)
	require.NoError(t, err)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "acme"})
	ref := transport.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeTenant, Name: "ci"}

	created, err := tr.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: ref, Config: oidccredentialtest.Config(), Tokens: oidccredentialtest.Tokens("at-0"),
	})
	require.NoError(t, err)
	assert.Equal(t, "acme", created.TenantID)

	tok, err := tr.OIDCCredentialGetAccessToken(ctx, &ref)
	require.NoError(t, err)
	assert.Equal(t, "at-0", tok.AccessToken)

	_, err = tr.OIDCCredentialRefresh(ctx, &ref)
	assert.ErrorIs(t, err, credential.ErrNotRefreshable, "the service's error reaches the caller unchanged")
}

// TestOIDCCredential_PassesErrorsThrough proves every OIDC credential method
// returns the service's error unchanged, and its answer when it succeeds.
func TestOIDCCredential_PassesErrorsThrough(t *testing.T) {
	ok, err := New(&mockService{})
	require.NoError(t, err)
	failing, err := New(&mockService{shouldFail: true})
	require.NoError(t, err)
	for name, call := range oidccredentialtest.Calls(context.Background(), ok) {
		t.Run(name, func(t *testing.T) { assert.NoError(t, call()) })
	}
	for name, call := range oidccredentialtest.Calls(context.Background(), failing) {
		t.Run(name+" fails", func(t *testing.T) { assert.ErrorIs(t, call(), errMock) })
	}
}

// TestOIDCCredential_NotConnected proves every OIDC credential method
// refuses once the transport is closed.
func TestOIDCCredential_NotConnected(t *testing.T) {
	tr, err := New(&mockService{})
	require.NoError(t, err)
	require.NoError(t, tr.Close())
	for name, call := range oidccredentialtest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}

func (*mockService) SetSigningKeyBinding(context.Context, *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockService) GetSigningKeyBinding(context.Context, *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	return nil, nil
}
func (*mockService) ListSigningKeyBindings(context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	return nil, nil
}
func (*mockService) DeleteSigningKeyBinding(context.Context, *transport.DeleteSigningKeyBindingRequest) error {
	return nil
}
func (*mockService) ResolveSigningKey(context.Context, *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	return nil, nil
}
func (*mockService) SignCoRIM(context.Context, *transport.SignCoRIMRequest) (*transport.SignedCoRIM, error) {
	return nil, nil
}

func (*mockService) SignImage(context.Context, *transport.SignImageRequest) (*transport.SignedImage, error) {
	return nil, nil
}
