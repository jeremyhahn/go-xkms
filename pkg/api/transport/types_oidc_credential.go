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

package transport

import (
	"context"
	"time"
)

// OIDCCredentialService manages server-side OIDC credentials
// (pkg/oidc/credential): named OAuth/OIDC logins held on the tenant barrier
// and refreshed by the server, tenant-shared or personal. Consumers never
// hold a refresh token; they ask OIDCCredentialGetAccessToken for a current
// access token by reference.
type OIDCCredentialService interface {
	// OIDCCredentialCreate creates a credential, with tokens when they are
	// at hand (an import) or pending a device login or import otherwise.
	OIDCCredentialCreate(ctx context.Context, req *OIDCCredentialCreateRequest) (*OIDCCredential, error)

	// OIDCCredentialImport replaces a credential's login with tokens
	// obtained elsewhere and makes it active.
	OIDCCredentialImport(ctx context.Context, req *OIDCCredentialImportRequest) (*OIDCCredential, error)

	// OIDCCredentialGet returns a credential's public view (no tokens).
	OIDCCredentialGet(ctx context.Context, req *OIDCCredentialRef) (*OIDCCredential, error)

	// OIDCCredentialList returns the credentials of a tenant the caller can
	// see: the shared ones, and in the caller's own tenant its personal ones.
	OIDCCredentialList(ctx context.Context, req *OIDCCredentialListRequest) (*OIDCCredentialListResponse, error)

	// OIDCCredentialDelete deletes a credential.
	OIDCCredentialDelete(ctx context.Context, req *OIDCCredentialRef) error

	// OIDCCredentialRefresh refreshes a credential now.
	OIDCCredentialRefresh(ctx context.Context, req *OIDCCredentialRef) (*OIDCCredential, error)

	// OIDCCredentialGetAccessToken returns a current access token,
	// refreshing first when the token is inside its refresh margin.
	OIDCCredentialGetAccessToken(ctx context.Context, req *OIDCCredentialRef) (*OIDCAccessToken, error)

	// OIDCCredentialDeviceStart starts a device login; the returned
	// credential's DeviceLogin carries the user code.
	OIDCCredentialDeviceStart(ctx context.Context, req *OIDCCredentialRef) (*OIDCCredential, error)

	// OIDCCredentialDevicePoll polls the device login once: the credential
	// stays pending until the user approves.
	OIDCCredentialDevicePoll(ctx context.Context, req *OIDCCredentialRef) (*OIDCCredential, error)
}

// OIDC credential scopes (pkg/scope).
const (
	// OIDCCredentialScopeTenant is a tenant-shared credential.
	OIDCCredentialScopeTenant = "tenant"

	// OIDCCredentialScopeUser is a personal credential, visible only to its
	// owner.
	OIDCCredentialScopeUser = "user"
)

// OIDCCredentialRef names a credential.
type OIDCCredentialRef struct {
	// TenantID is the tenant holding the credential; empty is the caller's.
	TenantID string `json:"tenant_id,omitempty"`

	// Scope is "tenant" (shared) or "user" (personal).
	Scope string `json:"scope"`

	// Owner is the owning subject of a personal credential; empty is the
	// caller.
	Owner string `json:"owner,omitempty"`

	// Name is the credential's name within its scope.
	Name string `json:"name"`
}

// OIDCCredentialConfig is a credential's provider configuration. A template
// fills every field left empty; endpoints left empty are discovered from the
// issuer at creation.
type OIDCCredentialConfig struct {
	Template                    string   `json:"template,omitempty"`
	Issuer                      string   `json:"issuer,omitempty"`
	ClientID                    string   `json:"client_id,omitempty"`
	ClientSecret                string   `json:"client_secret,omitempty"`
	Scopes                      []string `json:"scopes,omitempty"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint               string   `json:"token_endpoint,omitempty"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint,omitempty"`

	// TokenEncoding is "form" (default) or "json".
	TokenEncoding string `json:"token_encoding,omitempty"`

	// DeviceStyle is "rfc8628" (default) or "openai".
	DeviceStyle string `json:"device_style,omitempty"`

	// NoRefresh marks a provider whose tokens cannot be refreshed.
	NoRefresh bool `json:"no_refresh,omitempty"`

	// TokenLifetimeSeconds dates an imported opaque token of a NoRefresh
	// provider.
	TokenLifetimeSeconds int64 `json:"token_lifetime_seconds,omitempty"`

	// RefreshMarginSeconds is how long before expiry the server refreshes;
	// zero is the default (five minutes).
	RefreshMarginSeconds int64 `json:"refresh_margin_seconds,omitempty"`
}

// OIDCCredentialTokens are tokens imported into a credential.
type OIDCCredentialTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// ExpiresAt is when the access token expires; nil reads it from a JWT
	// access token or the template's token lifetime.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// OIDCCredentialCreateRequest creates a credential.
type OIDCCredentialCreateRequest struct {
	OIDCCredentialRef
	Config OIDCCredentialConfig  `json:"config"`
	Tokens *OIDCCredentialTokens `json:"tokens,omitempty"`
}

// OIDCCredentialImportRequest imports tokens into a credential.
type OIDCCredentialImportRequest struct {
	OIDCCredentialRef
	Tokens OIDCCredentialTokens `json:"tokens"`
}

// OIDCCredentialListRequest lists a tenant's credentials.
type OIDCCredentialListRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

// OIDCCredentialListResponse holds the visible credentials.
type OIDCCredentialListResponse struct {
	Credentials []OIDCCredential `json:"credentials"`
}

// OIDCDeviceLogin is a device login in progress: what the user needs to
// approve it.
type OIDCDeviceLogin struct {
	UserCode                string    `json:"user_code"`
	VerificationURI         string    `json:"verification_uri"`
	VerificationURIComplete string    `json:"verification_uri_complete,omitempty"`
	IntervalSeconds         int64     `json:"interval_seconds"`
	ExpiresAt               time.Time `json:"expires_at"`
}

// OIDC credential statuses.
const (
	OIDCCredentialStatusPending         = "pending"
	OIDCCredentialStatusActive          = "active"
	OIDCCredentialStatusReloginRequired = "relogin_required"
	OIDCCredentialStatusExpired         = "expired"
)

// OIDCCredential is a credential's public view: everything but its tokens
// and client secret.
type OIDCCredential struct {
	OIDCCredentialRef
	Config       OIDCCredentialConfig `json:"config"`
	Status       string               `json:"status"`
	StatusReason string               `json:"status_reason,omitempty"`
	ExpiresAt    *time.Time           `json:"expires_at,omitempty"`
	Refreshable  bool                 `json:"refreshable"`
	LastRefresh  *time.Time           `json:"last_refresh,omitempty"`
	LastError    string               `json:"last_error,omitempty"`
	DeviceLogin  *OIDCDeviceLogin     `json:"device_login,omitempty"`
	CreatedAt    time.Time            `json:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
	CreatedBy    string               `json:"created_by,omitempty"`
}

// OIDCAccessToken is a current access token of a credential.
type OIDCAccessToken struct {
	AccessToken string     `json:"access_token"`
	TokenType   string     `json:"token_type"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`

	// IDToken is the login's ID token, when it has one (the codex CLI's
	// chatgptAuthTokens mode needs it with the access token).
	IDToken string `json:"id_token,omitempty"`

	Scope string `json:"scope,omitempty"`
}

// OIDCCredentialServicer serves the OIDC credential API. Its method set is
// OIDCCredentialService's: every transport calls through it unchanged.
type OIDCCredentialServicer interface {
	OIDCCredentialService
}
