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

package server

import (
	"context"
	"errors"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"google.golang.org/grpc/metadata"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// ErrBearerNotAccepted is returned when a request carries a bearer token
// but xkmsd's authentication does not verify bearer tokens (it is disabled,
// or not yet initialized). The chain reports it as unauthenticated.
var ErrBearerNotAccepted = errors.New("xkmsd: bearer tokens are not accepted")

// bearerAuthenticator carries xkmsd's session tokens (the ones its login
// plane mints, or an operator's external-IdP JWTs) into the embedded qrdb
// node's own authenticator chain, through qrdb's WithAuthenticators seam.
// The unified server's gRPC and MCP surfaces authenticate in that chain,
// which on its own knows only mTLS: without this a token xkmsd issued was
// refused there while REST accepted it.
//
// It verifies with the authenticator xkmsd has in force (the live one, so a
// reload applies here too), and never admits a request through the no-op
// authenticator: disabled xkms authentication must not turn an arbitrary
// bearer header into a qrdb identity.
type bearerAuthenticator struct {
	live *auth.LiveAuthenticator

	// authorization reads the request's raw Authorization value from its
	// context: qrdb's accessor, which every transport (the HTTP header on
	// REST and MCP, the metadata on gRPC and the Unix socket) feeds.
	authorization func(context.Context) string
}

// newBearerAuthenticator returns a bearer authenticator over xkmsd's live
// authenticator, reading Authorization through qrdb's accessor.
func newBearerAuthenticator(live *auth.LiveAuthenticator) *bearerAuthenticator {
	return &bearerAuthenticator{live: live, authorization: qrdbsdk.HTTPAuthorizationFromContext}
}

// Compile-time check: a bearer authenticator whose login method qrdb's
// chain cannot observe.
var _ qrdbsdk.UnobservableMethodAuthenticator = (*bearerAuthenticator)(nil)

// Name implements qrdbsdk.Authenticator.
func (b *bearerAuthenticator) Name() string { return "jwt" }

// MethodUnobservable implements qrdbsdk.UnobservableMethodAuthenticator. A
// session token says who the caller is, not how they logged in, so the
// chain cannot check the account's permitted-method policy against it; the
// issuer did, when it minted the token (the PIV login's
// auth.CheckAuthMethod, the WebAuthn login's account standing).
func (b *bearerAuthenticator) MethodUnobservable() bool { return true }

// Authenticate implements qrdbsdk.Authenticator. A request without a bearer
// token is declined with qrdbsdk.ErrUnauthenticated, so the next
// authenticator in the chain decides.
func (b *bearerAuthenticator) Authenticate(ctx context.Context) (*qrdbsdk.Identity, error) {
	header := bearerValue(b.authorization(ctx))
	if header == "" {
		return nil, qrdbsdk.ErrUnauthenticated
	}
	delegate := b.live.Load()
	if delegate == nil || delegate.Name() == auth.NewNoOpAuthenticator().Name() {
		return nil, ErrBearerNotAccepted
	}
	return delegate.AuthenticateGRPC(ctx, metadata.Pairs("authorization", header))
}

// bearerValue returns v when it is a "Bearer <token>" Authorization value,
// or "" when it carries no bearer token.
func bearerValue(v string) string {
	if strings.HasPrefix(v, "Bearer ") && strings.TrimSpace(strings.TrimPrefix(v, "Bearer ")) != "" {
		return v
	}
	return ""
}
