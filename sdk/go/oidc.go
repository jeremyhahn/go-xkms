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
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Server-side OIDC credentials. A connected client reaches them through
// Client (OIDCCredentialCreate, OIDCCredentialGetAccessToken, ...); an
// embedding host builds the service in-process with these.

// OIDCCredentialService is the server-side OIDC credential service.
type OIDCCredentialService = credential.Service

// OIDCCredentialServiceParams are BuildOIDCCredentialService's inputs.
type OIDCCredentialServiceParams = compose.OIDCCredentialParams

// OIDCCredentialEvent is a credential state change (refreshed,
// relogin_required, expired) delivered to OIDCCredentialService.Subscribe.
type OIDCCredentialEvent = credential.Event

// OIDC credential scopes and statuses on the wire.
const (
	OIDCCredentialScopeTenant           = transport.OIDCCredentialScopeTenant
	OIDCCredentialScopeUser             = transport.OIDCCredentialScopeUser
	OIDCCredentialStatusPending         = transport.OIDCCredentialStatusPending
	OIDCCredentialStatusActive          = transport.OIDCCredentialStatusActive
	OIDCCredentialStatusReloginRequired = transport.OIDCCredentialStatusReloginRequired
	OIDCCredentialStatusExpired         = transport.OIDCCredentialStatusExpired
)

// OIDC credential event types.
const (
	OIDCCredentialEventRefreshed       = credential.EventRefreshed
	OIDCCredentialEventReloginRequired = credential.EventReloginRequired
	OIDCCredentialEventExpired         = credential.EventExpired
)

// OIDC credential errors a caller distinguishes.
var (
	ErrOIDCCredentialNotFound        = credential.ErrNotFound
	ErrOIDCCredentialReloginRequired = credential.ErrReloginRequired
	ErrOIDCCredentialTokenExpired    = credential.ErrTokenExpired
	ErrOIDCCredentialNoLogin         = credential.ErrNoLogin
)

// BuildOIDCCredentialService builds the OIDC credential service over a
// tenant barrier registry and the host qrdb node's lease primitive, and
// starts its refresh scheduler.
var BuildOIDCCredentialService = compose.BuildOIDCCredentialService

// The codex CLI's auth.json (pkg/oidc).

// CodexAuth is a ChatGPT login read from a codex auth.json.
type CodexAuth = oidc.CodexAuth

var (
	// ParseCodexAuth reads a ChatGPT login from a codex auth.json, to import
	// it as an OIDC credential without logging in again.
	ParseCodexAuth = oidc.ParseCodexAuth

	// CodexAuthTokensFile renders a codex auth.json in the
	// "chatgptAuthTokens" mode, in which codex uses the tokens and never
	// refreshes them.
	CodexAuthTokensFile = oidc.CodexAuthTokensFile
)

// CodexAuthTokens returns the tokens of a codex login in the form an OIDC
// credential import takes, the expiry read from the access token.
func CodexAuthTokens(auth *CodexAuth) *OIDCCredentialTokens {
	if auth == nil || auth.Tokens == nil {
		return nil
	}
	tokens := &OIDCCredentialTokens{
		AccessToken:  auth.Tokens.AccessToken,
		RefreshToken: auth.Tokens.RefreshToken,
		IDToken:      auth.Tokens.IDToken,
		TokenType:    auth.Tokens.TokenType,
	}
	if !auth.Tokens.Expiry.IsZero() {
		exp := auth.Tokens.Expiry
		tokens.ExpiresAt = &exp
	}
	return tokens
}

// CodexAuthFile renders the codex auth.json a workload uses for a current
// access token served by OIDCCredentialGetAccessToken: the
// "chatgptAuthTokens" mode, so codex never redeems a refresh token -- the
// server stays the only party that does -- and the refresh token is not in
// the file at all.
func CodexAuthFile(token *OIDCAccessToken, now time.Time) ([]byte, error) {
	if token == nil {
		return nil, oidc.ErrCodexAuthInvalid
	}
	return oidc.CodexAuthTokensFile(token.AccessToken, token.IDToken, "", now)
}
