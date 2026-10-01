// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

import (
	"context"
	"net/http"
	"net/url"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// OIDCCredentialsPath is the collection of a tenant's OIDC credentials. The
// server's route table (pkg/api/rest/routes.go) registers a credential's
// routes under it with {scope} and {name} placeholders.
const OIDCCredentialsPath = "/api/v1/oidc/credentials"

// OIDC credential action segments, appended to a credential's path.
const (
	OIDCCredentialActionImport      = "import"
	OIDCCredentialActionRefresh     = "refresh"
	OIDCCredentialActionToken       = "token"
	OIDCCredentialActionDeviceStart = "device"
	OIDCCredentialActionDevicePoll  = "device/poll"
)

// OIDCCredentialPath returns the path of the credential scope/name, followed
// by an optional action ("refresh", "device/poll", ...).
func OIDCCredentialPath(scope, name string, action ...string) string {
	path := OIDCCredentialsPath + "/" + url.PathEscape(scope) + "/" + url.PathEscape(name)
	for _, a := range action {
		path += "/" + a
	}
	return path
}

// OIDCCredentialRefPath returns the path of the credential ref names,
// followed by an optional action, with the tenant and owner the path does
// not carry as query parameters.
func OIDCCredentialRefPath(ref *transport.OIDCCredentialRef, action ...string) string {
	return withQuery(OIDCCredentialPath(ref.Scope, ref.Name, action...), map[string]string{
		"tenant_id": ref.TenantID,
		"owner":     ref.Owner,
	})
}

// OIDCCredentialImportBody is the body of the import route: the reference
// travels in the path and query.
type OIDCCredentialImportBody struct {
	Tokens transport.OIDCCredentialTokens `json:"tokens"`
}

// Compile-time check that the client serves the whole OIDC credential API.
var _ transport.OIDCCredentialService = OIDCCredentialClient{}

// OIDCCredentialClient serves transport.OIDCCredentialService over the REST
// routes. The REST and QUIC transports (QUIC serves the same router over
// HTTP/3) delegate to it with their own Requester.
type OIDCCredentialClient struct {
	// Do performs the requests.
	Do Requester
}

// credential performs a request answered by a credential's public view.
func (c OIDCCredentialClient) credential(ctx context.Context, method, path string, body any) (*transport.OIDCCredential, error) {
	var resp transport.OIDCCredential
	if err := callJSON(ctx, c.Do, method, path, body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OIDCCredentialCreate creates a credential.
func (c OIDCCredentialClient) OIDCCredentialCreate(ctx context.Context, req *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credential(ctx, http.MethodPost, OIDCCredentialsPath, req)
}

// OIDCCredentialImport replaces a credential's login with imported tokens.
func (c OIDCCredentialClient) OIDCCredentialImport(ctx context.Context, req *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	path := OIDCCredentialRefPath(&req.OIDCCredentialRef, OIDCCredentialActionImport)
	return c.credential(ctx, http.MethodPost, path, &OIDCCredentialImportBody{Tokens: req.Tokens})
}

// OIDCCredentialGet returns a credential's public view.
func (c OIDCCredentialClient) OIDCCredentialGet(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credential(ctx, http.MethodGet, OIDCCredentialRefPath(req), nil)
}

// OIDCCredentialList returns the credentials of a tenant the caller can see.
func (c OIDCCredentialClient) OIDCCredentialList(ctx context.Context, req *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.OIDCCredentialListResponse
	path := withQuery(OIDCCredentialsPath, map[string]string{"tenant_id": req.TenantID})
	if err := callJSON(ctx, c.Do, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OIDCCredentialDelete deletes a credential.
func (c OIDCCredentialClient) OIDCCredentialDelete(ctx context.Context, req *transport.OIDCCredentialRef) error {
	if req == nil {
		return ErrNilRequest
	}
	return callJSON(ctx, c.Do, http.MethodDelete, OIDCCredentialRefPath(req), nil, nil)
}

// OIDCCredentialRefresh refreshes a credential now.
func (c OIDCCredentialClient) OIDCCredentialRefresh(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credential(ctx, http.MethodPost, OIDCCredentialRefPath(req, OIDCCredentialActionRefresh), nil)
}

// OIDCCredentialGetAccessToken returns a current access token. The route is
// a POST so the token is never the answer of a cacheable GET.
func (c OIDCCredentialClient) OIDCCredentialGetAccessToken(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.OIDCAccessToken
	if err := callJSON(ctx, c.Do, http.MethodPost, OIDCCredentialRefPath(req, OIDCCredentialActionToken), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OIDCCredentialDeviceStart starts a device login.
func (c OIDCCredentialClient) OIDCCredentialDeviceStart(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credential(ctx, http.MethodPost, OIDCCredentialRefPath(req, OIDCCredentialActionDeviceStart), nil)
}

// OIDCCredentialDevicePoll polls a device login once.
func (c OIDCCredentialClient) OIDCCredentialDevicePoll(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credential(ctx, http.MethodPost, OIDCCredentialRefPath(req, OIDCCredentialActionDevicePoll), nil)
}
