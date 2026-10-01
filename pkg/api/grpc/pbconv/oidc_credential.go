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

package pbconv

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// timeToProto converts a time to its proto form; the zero time is absent.
func timeToProto(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// timeFromProto converts a proto time to UTC; an absent time is the zero
// time.
func timeFromProto(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// optionalTimeToProto converts an optional time to its proto form; nil is
// absent.
func optionalTimeToProto(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// optionalTimeFromProto converts a proto time to an optional UTC time; an
// absent time is nil.
func optionalTimeFromProto(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

// OIDCCredentialRefToProto converts a credential reference to its proto
// form.
func OIDCCredentialRefToProto(r *transport.OIDCCredentialRef) *pb.OIDCCredentialRef {
	return &pb.OIDCCredentialRef{TenantId: r.TenantID, Scope: r.Scope, Owner: r.Owner, Name: r.Name}
}

// OIDCCredentialRefFromProto converts a proto credential reference to its
// transport form. An absent reference is the empty one, which the service
// refuses for its missing scope.
func OIDCCredentialRefFromProto(r *pb.OIDCCredentialRef) *transport.OIDCCredentialRef {
	return &transport.OIDCCredentialRef{
		TenantID: r.GetTenantId(),
		Scope:    r.GetScope(),
		Owner:    r.GetOwner(),
		Name:     r.GetName(),
	}
}

// OIDCCredentialConfigToProto converts a provider configuration to its
// proto form.
func OIDCCredentialConfigToProto(c *transport.OIDCCredentialConfig) *pb.OIDCCredentialConfig {
	return &pb.OIDCCredentialConfig{
		Template:                    c.Template,
		Issuer:                      c.Issuer,
		ClientId:                    c.ClientID,
		ClientSecret:                c.ClientSecret,
		Scopes:                      c.Scopes,
		AuthorizationEndpoint:       c.AuthorizationEndpoint,
		TokenEndpoint:               c.TokenEndpoint,
		DeviceAuthorizationEndpoint: c.DeviceAuthorizationEndpoint,
		TokenEncoding:               c.TokenEncoding,
		DeviceStyle:                 c.DeviceStyle,
		NoRefresh:                   c.NoRefresh,
		TokenLifetimeSeconds:        c.TokenLifetimeSeconds,
		RefreshMarginSeconds:        c.RefreshMarginSeconds,
	}
}

// OIDCCredentialConfigFromProto converts a proto provider configuration to
// its transport form.
func OIDCCredentialConfigFromProto(c *pb.OIDCCredentialConfig) transport.OIDCCredentialConfig {
	return transport.OIDCCredentialConfig{
		Template:                    c.GetTemplate(),
		Issuer:                      c.GetIssuer(),
		ClientID:                    c.GetClientId(),
		ClientSecret:                c.GetClientSecret(),
		Scopes:                      c.GetScopes(),
		AuthorizationEndpoint:       c.GetAuthorizationEndpoint(),
		TokenEndpoint:               c.GetTokenEndpoint(),
		DeviceAuthorizationEndpoint: c.GetDeviceAuthorizationEndpoint(),
		TokenEncoding:               c.GetTokenEncoding(),
		DeviceStyle:                 c.GetDeviceStyle(),
		NoRefresh:                   c.GetNoRefresh(),
		TokenLifetimeSeconds:        c.GetTokenLifetimeSeconds(),
		RefreshMarginSeconds:        c.GetRefreshMarginSeconds(),
	}
}

// OIDCCredentialTokensToProto converts imported tokens to their proto form.
func OIDCCredentialTokensToProto(t *transport.OIDCCredentialTokens) *pb.OIDCCredentialTokens {
	return &pb.OIDCCredentialTokens{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		IdToken:      t.IDToken,
		TokenType:    t.TokenType,
		Scope:        t.Scope,
		ExpiresAt:    optionalTimeToProto(t.ExpiresAt),
	}
}

// OIDCCredentialTokensFromProto converts proto imported tokens to their
// transport form.
func OIDCCredentialTokensFromProto(t *pb.OIDCCredentialTokens) transport.OIDCCredentialTokens {
	return transport.OIDCCredentialTokens{
		AccessToken:  t.GetAccessToken(),
		RefreshToken: t.GetRefreshToken(),
		IDToken:      t.GetIdToken(),
		TokenType:    t.GetTokenType(),
		Scope:        t.GetScope(),
		ExpiresAt:    optionalTimeFromProto(t.GetExpiresAt()),
	}
}

// OIDCCredentialCreateRequestToProto converts a create request to its proto
// form; a request without tokens sends none.
func OIDCCredentialCreateRequestToProto(r *transport.OIDCCredentialCreateRequest) *pb.OIDCCredentialCreateRequest {
	out := &pb.OIDCCredentialCreateRequest{
		Ref:    OIDCCredentialRefToProto(&r.OIDCCredentialRef),
		Config: OIDCCredentialConfigToProto(&r.Config),
	}
	if r.Tokens != nil {
		out.Tokens = OIDCCredentialTokensToProto(r.Tokens)
	}
	return out
}

// OIDCCredentialCreateRequestFromProto converts a proto create request to
// its transport form; absent tokens stay nil.
func OIDCCredentialCreateRequestFromProto(r *pb.OIDCCredentialCreateRequest) *transport.OIDCCredentialCreateRequest {
	out := &transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: *OIDCCredentialRefFromProto(r.GetRef()),
		Config:            OIDCCredentialConfigFromProto(r.GetConfig()),
	}
	if r.GetTokens() != nil {
		tokens := OIDCCredentialTokensFromProto(r.GetTokens())
		out.Tokens = &tokens
	}
	return out
}

// OIDCCredentialImportRequestToProto converts an import request to its
// proto form.
func OIDCCredentialImportRequestToProto(r *transport.OIDCCredentialImportRequest) *pb.OIDCCredentialImportRequest {
	return &pb.OIDCCredentialImportRequest{
		Ref:    OIDCCredentialRefToProto(&r.OIDCCredentialRef),
		Tokens: OIDCCredentialTokensToProto(&r.Tokens),
	}
}

// OIDCCredentialImportRequestFromProto converts a proto import request to
// its transport form.
func OIDCCredentialImportRequestFromProto(r *pb.OIDCCredentialImportRequest) *transport.OIDCCredentialImportRequest {
	return &transport.OIDCCredentialImportRequest{
		OIDCCredentialRef: *OIDCCredentialRefFromProto(r.GetRef()),
		Tokens:            OIDCCredentialTokensFromProto(r.GetTokens()),
	}
}

// OIDCDeviceLoginToProto converts a device login in progress to its proto
// form; nil is absent.
func OIDCDeviceLoginToProto(d *transport.OIDCDeviceLogin) *pb.OIDCDeviceLogin {
	if d == nil {
		return nil
	}
	return &pb.OIDCDeviceLogin{
		UserCode:                d.UserCode,
		VerificationUri:         d.VerificationURI,
		VerificationUriComplete: d.VerificationURIComplete,
		IntervalSeconds:         d.IntervalSeconds,
		ExpiresAt:               timeToProto(d.ExpiresAt),
	}
}

// OIDCDeviceLoginFromProto converts a proto device login to its transport
// form; absent is nil.
func OIDCDeviceLoginFromProto(d *pb.OIDCDeviceLogin) *transport.OIDCDeviceLogin {
	if d == nil {
		return nil
	}
	return &transport.OIDCDeviceLogin{
		UserCode:                d.GetUserCode(),
		VerificationURI:         d.GetVerificationUri(),
		VerificationURIComplete: d.GetVerificationUriComplete(),
		IntervalSeconds:         d.GetIntervalSeconds(),
		ExpiresAt:               timeFromProto(d.GetExpiresAt()),
	}
}

// OIDCCredentialToProto converts a credential's public view to its proto
// form.
func OIDCCredentialToProto(c *transport.OIDCCredential) *pb.OIDCCredential {
	return &pb.OIDCCredential{
		Ref:          OIDCCredentialRefToProto(&c.OIDCCredentialRef),
		Config:       OIDCCredentialConfigToProto(&c.Config),
		Status:       c.Status,
		StatusReason: c.StatusReason,
		ExpiresAt:    optionalTimeToProto(c.ExpiresAt),
		Refreshable:  c.Refreshable,
		LastRefresh:  optionalTimeToProto(c.LastRefresh),
		LastError:    c.LastError,
		DeviceLogin:  OIDCDeviceLoginToProto(c.DeviceLogin),
		CreatedAt:    timeToProto(c.CreatedAt),
		UpdatedAt:    timeToProto(c.UpdatedAt),
		CreatedBy:    c.CreatedBy,
	}
}

// OIDCCredentialFromProto converts a proto credential to its transport
// form.
func OIDCCredentialFromProto(c *pb.OIDCCredential) *transport.OIDCCredential {
	return &transport.OIDCCredential{
		OIDCCredentialRef: *OIDCCredentialRefFromProto(c.GetRef()),
		Config:            OIDCCredentialConfigFromProto(c.GetConfig()),
		Status:            c.GetStatus(),
		StatusReason:      c.GetStatusReason(),
		ExpiresAt:         optionalTimeFromProto(c.GetExpiresAt()),
		Refreshable:       c.GetRefreshable(),
		LastRefresh:       optionalTimeFromProto(c.GetLastRefresh()),
		LastError:         c.GetLastError(),
		DeviceLogin:       OIDCDeviceLoginFromProto(c.GetDeviceLogin()),
		CreatedAt:         timeFromProto(c.GetCreatedAt()),
		UpdatedAt:         timeFromProto(c.GetUpdatedAt()),
		CreatedBy:         c.GetCreatedBy(),
	}
}

// OIDCCredentialListResponseToProto converts a credential list to its proto
// form.
func OIDCCredentialListResponseToProto(r *transport.OIDCCredentialListResponse) *pb.OIDCCredentialListResponse {
	out := &pb.OIDCCredentialListResponse{Credentials: make([]*pb.OIDCCredential, 0, len(r.Credentials))}
	for i := range r.Credentials {
		out.Credentials = append(out.Credentials, OIDCCredentialToProto(&r.Credentials[i]))
	}
	return out
}

// OIDCCredentialListResponseFromProto converts a proto credential list to
// its transport form; an empty list decodes as [] rather than null.
func OIDCCredentialListResponseFromProto(r *pb.OIDCCredentialListResponse) *transport.OIDCCredentialListResponse {
	out := &transport.OIDCCredentialListResponse{Credentials: make([]transport.OIDCCredential, 0, len(r.GetCredentials()))}
	for _, c := range r.GetCredentials() {
		out.Credentials = append(out.Credentials, *OIDCCredentialFromProto(c))
	}
	return out
}

// OIDCAccessTokenToProto converts a current access token to its proto form.
func OIDCAccessTokenToProto(t *transport.OIDCAccessToken) *pb.OIDCAccessToken {
	return &pb.OIDCAccessToken{
		AccessToken: t.AccessToken,
		TokenType:   t.TokenType,
		ExpiresAt:   optionalTimeToProto(t.ExpiresAt),
		IdToken:     t.IDToken,
		Scope:       t.Scope,
	}
}

// OIDCAccessTokenFromProto converts a proto access token to its transport
// form.
func OIDCAccessTokenFromProto(t *pb.OIDCAccessToken) *transport.OIDCAccessToken {
	return &transport.OIDCAccessToken{
		AccessToken: t.GetAccessToken(),
		TokenType:   t.GetTokenType(),
		ExpiresAt:   optionalTimeFromProto(t.GetExpiresAt()),
		IDToken:     t.GetIdToken(),
		Scope:       t.GetScope(),
	}
}
