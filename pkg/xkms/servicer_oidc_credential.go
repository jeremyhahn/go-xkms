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

package xkms

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

// Compile-time check that XKMSService serves the OIDC credential API.
var _ transport.OIDCCredentialServicer = (*XKMSService)(nil)

// SetOIDCCredentialService wires the OIDC credential service
// (pkg/oidc/credential) the OIDCCredential* methods delegate to.
func (s *XKMSService) SetOIDCCredentialService(c *credential.Service) { s.oidcCredentials.store(c) }

// OIDCCredentialService returns the wired OIDC credential service, or nil.
func (s *XKMSService) OIDCCredentialService() *credential.Service { return s.oidcCredentials.load() }

// oidcCredentials returns the wired service and the caller's principal.
// The principal comes from the request identity; scope rules -- tenant
// binding, owner-only personal credentials -- are the credential service's.
func (s *XKMSService) oidcCaller(ctx context.Context) (*credential.Service, scope.Principal, error) {
	svc := s.oidcCredentials.load()
	if svc == nil {
		return nil, scope.Principal{}, ErrNotConfigured
	}
	return svc, scope.PrincipalFromContext(ctx), nil
}

// OIDCCredentialCreate creates an OIDC credential.
func (s *XKMSService) OIDCCredentialCreate(ctx context.Context, req *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, p, err := s.oidcCaller(ctx)
	if err != nil {
		return nil, err
	}
	ref, err := credentialRef(&req.OIDCCredentialRef)
	if err != nil {
		return nil, err
	}
	var tokens *credential.Tokens
	if req.Tokens != nil {
		t := credentialTokens(req.Tokens)
		tokens = &t
	}
	c, err := svc.Create(ctx, p, ref, credentialConfig(&req.Config), tokens)
	if err != nil {
		return nil, err
	}
	return OIDCCredentialToTransport(c), nil
}

// OIDCCredentialImport imports tokens into an OIDC credential.
func (s *XKMSService) OIDCCredentialImport(ctx context.Context, req *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, p, err := s.oidcCaller(ctx)
	if err != nil {
		return nil, err
	}
	ref, err := credentialRef(&req.OIDCCredentialRef)
	if err != nil {
		return nil, err
	}
	c, err := svc.ImportTokens(ctx, p, ref, credentialTokens(&req.Tokens))
	if err != nil {
		return nil, err
	}
	return OIDCCredentialToTransport(c), nil
}

// OIDCCredentialGet returns an OIDC credential's public view.
func (s *XKMSService) OIDCCredentialGet(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return s.oidcCredentialOp(ctx, req, (*credential.Service).Get)
}

// OIDCCredentialList lists the OIDC credentials the caller can see.
func (s *XKMSService) OIDCCredentialList(ctx context.Context, req *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, p, err := s.oidcCaller(ctx)
	if err != nil {
		return nil, err
	}
	list, err := svc.List(ctx, p, req.TenantID)
	if err != nil {
		return nil, err
	}
	out := &transport.OIDCCredentialListResponse{Credentials: make([]transport.OIDCCredential, 0, len(list))}
	for _, c := range list {
		out.Credentials = append(out.Credentials, *OIDCCredentialToTransport(c))
	}
	return out, nil
}

// OIDCCredentialDelete deletes an OIDC credential.
func (s *XKMSService) OIDCCredentialDelete(ctx context.Context, req *transport.OIDCCredentialRef) error {
	if req == nil {
		return ErrNilRequest
	}
	svc, p, err := s.oidcCaller(ctx)
	if err != nil {
		return err
	}
	ref, err := credentialRef(req)
	if err != nil {
		return err
	}
	return svc.Delete(ctx, p, ref)
}

// OIDCCredentialRefresh refreshes an OIDC credential now.
func (s *XKMSService) OIDCCredentialRefresh(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return s.oidcCredentialOp(ctx, req, (*credential.Service).Refresh)
}

// OIDCCredentialGetAccessToken returns a current access token of an OIDC
// credential.
func (s *XKMSService) OIDCCredentialGetAccessToken(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, p, err := s.oidcCaller(ctx)
	if err != nil {
		return nil, err
	}
	ref, err := credentialRef(req)
	if err != nil {
		return nil, err
	}
	tok, err := svc.GetAccessToken(ctx, p, ref)
	if err != nil {
		return nil, err
	}
	return &transport.OIDCAccessToken{
		AccessToken: tok.AccessToken,
		TokenType:   tok.TokenType,
		ExpiresAt:   optionalTime(tok.ExpiresAt),
		IDToken:     tok.IDToken,
		Scope:       tok.Scope,
	}, nil
}

// OIDCCredentialDeviceStart starts a device login for an OIDC credential.
func (s *XKMSService) OIDCCredentialDeviceStart(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return s.oidcCredentialOp(ctx, req, (*credential.Service).StartDeviceLogin)
}

// OIDCCredentialDevicePoll polls an OIDC credential's device login once.
func (s *XKMSService) OIDCCredentialDevicePoll(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	return s.oidcCredentialOp(ctx, req, (*credential.Service).PollDeviceLogin)
}

// oidcCredentialOp runs a credential operation that takes a reference and
// returns the credential's view.
func (s *XKMSService) oidcCredentialOp(ctx context.Context, req *transport.OIDCCredentialRef,
	op func(*credential.Service, context.Context, scope.Principal, credential.Ref) (*credential.Credential, error),
) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, p, err := s.oidcCaller(ctx)
	if err != nil {
		return nil, err
	}
	ref, err := credentialRef(req)
	if err != nil {
		return nil, err
	}
	c, err := op(svc, ctx, p, ref)
	if err != nil {
		return nil, err
	}
	return OIDCCredentialToTransport(c), nil
}

// credentialRef converts a transport reference.
func credentialRef(r *transport.OIDCCredentialRef) (credential.Ref, error) {
	sc, err := scope.Parse(r.Scope)
	if err != nil {
		return credential.Ref{}, err
	}
	return credential.Ref{TenantID: r.TenantID, Scope: sc, Owner: r.Owner, Name: r.Name}, nil
}

// credentialConfig converts a transport configuration.
func credentialConfig(c *transport.OIDCCredentialConfig) credential.Config {
	return credential.Config{
		Template:                    c.Template,
		Issuer:                      c.Issuer,
		ClientID:                    c.ClientID,
		ClientSecret:                c.ClientSecret,
		Scopes:                      append([]string(nil), c.Scopes...),
		AuthorizationEndpoint:       c.AuthorizationEndpoint,
		TokenEndpoint:               c.TokenEndpoint,
		DeviceAuthorizationEndpoint: c.DeviceAuthorizationEndpoint,
		TokenEncoding:               oidc.TokenEncoding(c.TokenEncoding),
		DeviceStyle:                 oidc.DeviceStyle(c.DeviceStyle),
		NoRefresh:                   c.NoRefresh,
		TokenLifetime:               time.Duration(c.TokenLifetimeSeconds) * time.Second,
		RefreshMargin:               time.Duration(c.RefreshMarginSeconds) * time.Second,
	}
}

// credentialTokens converts transport tokens.
func credentialTokens(t *transport.OIDCCredentialTokens) credential.Tokens {
	out := credential.Tokens{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		IDToken:      t.IDToken,
		TokenType:    t.TokenType,
		Scope:        t.Scope,
	}
	if t.ExpiresAt != nil {
		out.ExpiresAt = *t.ExpiresAt
	}
	return out
}

// OIDCCredentialToTransport converts a credential's public view to its
// transport form. Every server surface (REST, gRPC, MCP) answers with it.
func OIDCCredentialToTransport(c *credential.Credential) *transport.OIDCCredential {
	out := &transport.OIDCCredential{
		OIDCCredentialRef: transport.OIDCCredentialRef{
			TenantID: c.TenantID,
			Scope:    string(c.Scope),
			Owner:    c.Owner,
			Name:     c.Name,
		},
		Config: transport.OIDCCredentialConfig{
			Template:                    c.Config.Template,
			Issuer:                      c.Config.Issuer,
			ClientID:                    c.Config.ClientID,
			Scopes:                      append([]string(nil), c.Config.Scopes...),
			AuthorizationEndpoint:       c.Config.AuthorizationEndpoint,
			TokenEndpoint:               c.Config.TokenEndpoint,
			DeviceAuthorizationEndpoint: c.Config.DeviceAuthorizationEndpoint,
			TokenEncoding:               string(c.Config.TokenEncoding),
			DeviceStyle:                 string(c.Config.DeviceStyle),
			NoRefresh:                   c.Config.NoRefresh,
			TokenLifetimeSeconds:        int64(c.Config.TokenLifetime / time.Second),
			RefreshMarginSeconds:        int64(c.Config.RefreshMargin / time.Second),
		},
		Status:       string(c.Status),
		StatusReason: c.StatusReason,
		ExpiresAt:    optionalTime(c.ExpiresAt),
		Refreshable:  c.Refreshable,
		LastRefresh:  optionalTime(c.LastRefresh),
		LastError:    c.LastError,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		CreatedBy:    c.CreatedBy,
	}
	if d := c.DeviceLogin; d != nil {
		out.DeviceLogin = &transport.OIDCDeviceLogin{
			UserCode:                d.UserCode,
			VerificationURI:         d.VerificationURI,
			VerificationURIComplete: d.VerificationURIComplete,
			IntervalSeconds:         int64(d.Interval / time.Second),
			ExpiresAt:               d.ExpiresAt,
		}
	}
	return out
}

// optionalTime returns nil for the zero time.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
