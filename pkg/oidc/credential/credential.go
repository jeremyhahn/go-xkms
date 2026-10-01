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

// Package credential is xkmsd's server-side OIDC credential service: named
// OAuth/OIDC logins held on the tenant barrier and kept fresh by the server.
//
// A credential is tenant-shared (scope.Tenant, visible to every user of the
// tenant) or personal (scope.User, visible only to its owner -- not even to
// a system-tenant caller). Its record lives at the pkg/scope layout,
// {tenant}/oidc/shared/{name} or {tenant}/oidc/users/{subject}/{name}, on the
// tenant's barrier. A personal credential is sealed by the tenant barrier,
// not a per-user key: the server must read it unattended to refresh it, so
// its privacy is the authorization rule, which no caller but the owner
// passes.
//
// Logins arrive by a device flow the server runs (StartDeviceLogin,
// PollDeviceLogin) or by importing tokens obtained elsewhere
// (ImportTokens). The server refreshes each credential before its access
// token expires -- a leader-elected Scheduler on a cluster, and on demand in
// GetAccessToken -- so consumers never hold a refresh token: they ask for a
// current access token by reference. A refresh token that rotates on use is
// persisted with compare-and-swap under a per-credential lock, and a refresh
// the provider rejects (invalid_grant, refresh_token_reused, ...) moves the
// credential to StatusReloginRequired and emits EventReloginRequired.
//
// The OIDC protocol work (endpoints, device flow, refresh, error
// classification) is pkg/oidc's, the one core xkey's local OIDC also uses.
package credential

import (
	"regexp"
	"slices"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

// Feature is the pkg/scope feature segment credentials are stored under.
const Feature = "oidc"

// namePattern is the credential name rule: a storage segment that is safe in
// every transport's path and never hidden.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`)

// ValidName reports whether name is a valid credential name.
func ValidName(name string) bool {
	return namePattern.MatchString(name)
}

// Ref names a credential: its tenant, its scope, the owning subject of a
// personal credential, and its name.
type Ref struct {
	// TenantID is the tenant holding the credential ("" is the caller's).
	TenantID string `json:"tenant_id,omitempty"`

	// Scope is scope.Tenant (shared) or scope.User (personal).
	Scope scope.Scope `json:"scope"`

	// Owner is the owning subject of a personal credential. Empty means the
	// caller; it is ignored for a shared credential.
	Owner string `json:"owner,omitempty"`

	// Name is the credential's name within its scope.
	Name string `json:"name"`
}

// Status is a credential's lifecycle state.
type Status string

const (
	// StatusPending is a credential with no tokens yet: a device login is in
	// progress or tokens are still to be imported.
	StatusPending Status = "pending"

	// StatusActive is a credential with a usable login.
	StatusActive Status = "active"

	// StatusReloginRequired is a credential whose refresh token the provider
	// rejected. A new device login or import restores it.
	StatusReloginRequired Status = "relogin_required"

	// StatusExpired is a credential whose non-refreshable token expired. A
	// new import restores it.
	StatusExpired Status = "expired"
)

// Config is a credential's provider configuration.
type Config struct {
	// Template is a pkg/oidc provider template ("openai", "google", ...)
	// whose values fill every field left empty.
	Template string `json:"template,omitempty"`

	// Issuer is the provider's issuer URL.
	Issuer string `json:"issuer,omitempty"`

	// ClientID is the OAuth client ID.
	ClientID string `json:"client_id,omitempty"`

	// ClientSecret is the client secret of a confidential client.
	ClientSecret string `json:"client_secret,omitempty"`

	// Scopes are the scopes requested at login.
	Scopes []string `json:"scopes,omitempty"`

	// AuthorizationEndpoint, TokenEndpoint and DeviceAuthorizationEndpoint
	// are the provider's endpoints. When TokenEndpoint is empty they are
	// discovered from Issuer at creation and recorded here.
	AuthorizationEndpoint       string `json:"authorization_endpoint,omitempty"`
	TokenEndpoint               string `json:"token_endpoint,omitempty"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	// TokenEncoding is how token requests are encoded ("form" or "json").
	TokenEncoding oidc.TokenEncoding `json:"token_encoding,omitempty"`

	// DeviceStyle is the provider's device login protocol.
	DeviceStyle oidc.DeviceStyle `json:"device_style,omitempty"`

	// NoRefresh marks a provider whose tokens cannot be refreshed: the
	// credential is tracked to its expiry and imported again.
	NoRefresh bool `json:"no_refresh,omitempty"`

	// TokenLifetime is how long an imported token of a NoRefresh provider
	// lives when the token does not say.
	TokenLifetime time.Duration `json:"token_lifetime,omitempty"`

	// RefreshMargin is how long before expiry the access token is
	// refreshed. Zero means DefaultRefreshMargin.
	RefreshMargin time.Duration `json:"refresh_margin,omitempty"`
}

// DefaultRefreshMargin is how long before expiry a credential's access
// token is refreshed when its Config names no margin. It matches the codex
// CLI's own five-minute window.
const DefaultRefreshMargin = 5 * time.Minute

// unknownExpiryRefreshAge is how old a refreshable login whose access token
// carries no expiry may grow before it is refreshed anyway.
const unknownExpiryRefreshAge = 24 * time.Hour

// margin returns the effective refresh margin.
func (c *Config) margin() time.Duration {
	if c.RefreshMargin > 0 {
		return c.RefreshMargin
	}
	return DefaultRefreshMargin
}

// flowSupported reports whether the configured template permits flow. A
// credential without a template is a custom provider and permits every
// flow its endpoints allow.
func (c *Config) flowSupported(flow oidc.Flow) bool {
	if c.Template == "" {
		return true
	}
	tmpl, err := oidc.GetTemplate(c.Template)
	if err != nil {
		return false
	}
	if len(tmpl.Flows) == 0 {
		// A browser-login template also accepts tokens obtained by that
		// login elsewhere, and a device login where its provider offers one.
		return flow != oidc.FlowDevice || c.DeviceAuthorizationEndpoint != ""
	}
	return slices.Contains(tmpl.Flows, flow)
}

// Tokens are tokens imported into a credential.
type Tokens struct {
	// AccessToken is the access token. Required.
	AccessToken string `json:"access_token"`

	// RefreshToken is the refresh token, when the login has one.
	RefreshToken string `json:"refresh_token,omitempty"`

	// IDToken is the ID token, when the login has one.
	IDToken string `json:"id_token,omitempty"`

	// TokenType is the access token's type ("Bearer" when empty).
	TokenType string `json:"token_type,omitempty"`

	// Scope is the granted scope.
	Scope string `json:"scope,omitempty"`

	// ExpiresAt is when the access token expires. When zero it is read from
	// a JWT access token's exp claim, or from the template's TokenLifetime.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Credential is the public view of a credential: everything but its tokens.
type Credential struct {
	Ref

	// Config is the provider configuration, with ClientSecret removed.
	Config Config `json:"config"`

	// Status is the lifecycle state.
	Status Status `json:"status"`

	// StatusReason explains StatusReloginRequired and StatusExpired.
	StatusReason string `json:"status_reason,omitempty"`

	// ExpiresAt is when the current access token expires (zero: unknown).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Refreshable is true when the login holds a refresh token the server
	// can redeem.
	Refreshable bool `json:"refreshable"`

	// LastRefresh is when the server last refreshed or imported the login.
	LastRefresh time.Time `json:"last_refresh,omitempty"`

	// LastError is the most recent refresh failure a later refresh may
	// still overcome, cleared by the next success.
	LastError string `json:"last_error,omitempty"`

	// DeviceLogin is the device login in progress, if any.
	DeviceLogin *DeviceLogin `json:"device_login,omitempty"`

	// CreatedAt and UpdatedAt are the record's timestamps; CreatedBy is the
	// subject that created it.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// DeviceLogin is the public half of a device login in progress: what the
// user needs to approve it.
type DeviceLogin struct {
	UserCode                string        `json:"user_code"`
	VerificationURI         string        `json:"verification_uri"`
	VerificationURIComplete string        `json:"verification_uri_complete,omitempty"`
	Interval                time.Duration `json:"interval"`
	ExpiresAt               time.Time     `json:"expires_at"`
}

// AccessToken is a current access token served by GetAccessToken.
type AccessToken struct {
	// AccessToken is the bearer token.
	AccessToken string `json:"access_token"`

	// TokenType is the token's type, normally "Bearer".
	TokenType string `json:"token_type"`

	// ExpiresAt is when the token expires (zero: unknown).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// IDToken is the login's ID token, when it has one. A consumer such as
	// the codex CLI's chatgptAuthTokens mode needs it alongside the access
	// token.
	IDToken string `json:"id_token,omitempty"`

	// Scope is the granted scope.
	Scope string `json:"scope,omitempty"`
}

// EventType names a credential event.
type EventType string

const (
	// EventRefreshed is emitted after a successful refresh.
	EventRefreshed EventType = "oidc_credential.refreshed"

	// EventReloginRequired is emitted when the provider rejects a refresh
	// token and the credential needs a new login.
	EventReloginRequired EventType = "oidc_credential.relogin_required"

	// EventExpired is emitted when a non-refreshable token expires.
	EventExpired EventType = "oidc_credential.expired"
)

// Event is a credential state change.
type Event struct {
	Type   EventType `json:"type"`
	Ref    Ref       `json:"ref"`
	Reason string    `json:"reason,omitempty"`
	Time   time.Time `json:"time"`
}
