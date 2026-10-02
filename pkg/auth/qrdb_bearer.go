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

package auth

import (
	"context"
	"errors"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"google.golang.org/grpc/metadata"
)

// ErrBearerNotAccepted is returned when a request carries a bearer token but
// the host's authentication does not verify bearer tokens: no authenticator
// is installed, or the installed one is the no-op authenticator. The qrdb
// chain reports it as unauthenticated.
var ErrBearerNotAccepted = errors.New("auth: bearer tokens are not accepted")

// AuthenticatorSource yields the authenticator in force for one request.
// *LiveAuthenticator is one, so a reload applies to the next request; a host
// with a fixed authenticator wraps it with NewLiveAuthenticator.
type AuthenticatorSource interface {
	// Load returns the current authenticator, or nil when none is installed.
	Load() Authenticator
}

// QRDBBearerAuthenticator carries a host's session tokens (the ones its login
// plane mints, or an operator's external-IdP JWTs) into an embedded go-qrdb
// node's authenticator chain, through the node's WithAuthenticators option.
// That chain on its own knows only mTLS: without this bridge a token the host
// issued is refused on the node's transports while the host's own REST
// surface accepts it.
//
// It verifies with the authenticator its source has in force, read once per
// request, and never admits a request through the no-op authenticator:
// disabled host authentication must not turn an arbitrary bearer header into
// a qrdb identity.
type QRDBBearerAuthenticator struct {
	source AuthenticatorSource

	// authorization reads the request's raw Authorization value from its
	// context: qrdb's accessor, which every node transport (the HTTP header on
	// REST and MCP, the metadata on gRPC and the Unix socket) feeds.
	authorization func(context.Context) string
}

// NewQRDBBearerAuthenticator returns a bearer authenticator over source,
// reading Authorization through qrdb's accessor. Register it on the node with
// node.WithAuthenticators.
func NewQRDBBearerAuthenticator(source AuthenticatorSource) *QRDBBearerAuthenticator {
	return &QRDBBearerAuthenticator{source: source, authorization: qrdbsdk.HTTPAuthorizationFromContext}
}

// Compile-time check: a bearer authenticator whose login method qrdb's chain
// cannot observe.
var _ qrdbsdk.UnobservableMethodAuthenticator = (*QRDBBearerAuthenticator)(nil)

// Name implements qrdbsdk.Authenticator.
func (b *QRDBBearerAuthenticator) Name() string { return "jwt" }

// MethodUnobservable implements qrdbsdk.UnobservableMethodAuthenticator. A
// session token says who the caller is, not how they logged in, so the chain
// cannot check the account's permitted-method policy against it; the issuer
// did, when it minted the token (qrdbsdk.CheckAuthMethod at login).
func (b *QRDBBearerAuthenticator) MethodUnobservable() bool { return true }

// Authenticate implements qrdbsdk.Authenticator. A request without a bearer
// token is declined with qrdbsdk.ErrUnauthenticated, so the next
// authenticator in the chain decides.
func (b *QRDBBearerAuthenticator) Authenticate(ctx context.Context) (*qrdbsdk.Identity, error) {
	header := bearerValue(b.authorization(ctx))
	if header == "" {
		return nil, qrdbsdk.ErrUnauthenticated
	}
	var delegate Authenticator
	if b.source != nil {
		delegate = b.source.Load()
	}
	if delegate == nil || delegate.Name() == noOpAuthenticatorName {
		return nil, ErrBearerNotAccepted
	}
	return delegate.AuthenticateGRPC(ctx, metadata.Pairs("authorization", header))
}

// bearerValue returns v when it is a "Bearer <token>" Authorization value, or
// "" when it carries no bearer token.
func bearerValue(v string) string {
	if strings.HasPrefix(v, "Bearer ") && strings.TrimSpace(strings.TrimPrefix(v, "Bearer ")) != "" {
		return v
	}
	return ""
}
