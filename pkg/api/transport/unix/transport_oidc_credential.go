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

package unix

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The OIDC credential API is served by pbconv.OIDCCredentialClient, shared
// with the gRPC transport, once this transport holds a connection.

// oidcCredentials returns the shared OIDC credential client over this
// transport's connection, or ErrNotConnected before it holds one.
func (t *Transport) oidcCredentials() (pbconv.OIDCCredentialClient, error) {
	if t.client == nil {
		return pbconv.OIDCCredentialClient{}, ErrNotConnected
	}
	return pbconv.OIDCCredentialClient{Client: t.client}, nil
}

// OIDCCredentialCreate creates an OIDC credential.
func (t *Transport) OIDCCredentialCreate(ctx context.Context, req *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	c, err := t.oidcCredentials()
	if err != nil {
		return nil, err
	}
	return c.OIDCCredentialCreate(ctx, req)
}

// OIDCCredentialImport imports tokens into an OIDC credential.
func (t *Transport) OIDCCredentialImport(ctx context.Context, req *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	c, err := t.oidcCredentials()
	if err != nil {
		return nil, err
	}
	return c.OIDCCredentialImport(ctx, req)
}

// OIDCCredentialGet returns an OIDC credential's public view.
func (t *Transport) OIDCCredentialGet(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	c, err := t.oidcCredentials()
	if err != nil {
		return nil, err
	}
	return c.OIDCCredentialGet(ctx, req)
}

// OIDCCredentialList lists the OIDC credentials the caller can see.
func (t *Transport) OIDCCredentialList(ctx context.Context, req *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	c, err := t.oidcCredentials()
	if err != nil {
		return nil, err
	}
	return c.OIDCCredentialList(ctx, req)
}

// OIDCCredentialDelete deletes an OIDC credential.
func (t *Transport) OIDCCredentialDelete(ctx context.Context, req *transport.OIDCCredentialRef) error {
	c, err := t.oidcCredentials()
	if err != nil {
		return err
	}
	return c.OIDCCredentialDelete(ctx, req)
}

// OIDCCredentialRefresh refreshes an OIDC credential now.
func (t *Transport) OIDCCredentialRefresh(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	c, err := t.oidcCredentials()
	if err != nil {
		return nil, err
	}
	return c.OIDCCredentialRefresh(ctx, req)
}

// OIDCCredentialGetAccessToken returns a current access token of an OIDC
// credential.
func (t *Transport) OIDCCredentialGetAccessToken(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	c, err := t.oidcCredentials()
	if err != nil {
		return nil, err
	}
	return c.OIDCCredentialGetAccessToken(ctx, req)
}

// OIDCCredentialDeviceStart starts a device login for an OIDC credential.
func (t *Transport) OIDCCredentialDeviceStart(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	c, err := t.oidcCredentials()
	if err != nil {
		return nil, err
	}
	return c.OIDCCredentialDeviceStart(ctx, req)
}

// OIDCCredentialDevicePoll polls an OIDC credential's device login once.
func (t *Transport) OIDCCredentialDevicePoll(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	c, err := t.oidcCredentials()
	if err != nil {
		return nil, err
	}
	return c.OIDCCredentialDevicePoll(ctx, req)
}
