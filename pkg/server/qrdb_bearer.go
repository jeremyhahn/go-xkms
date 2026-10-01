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

var (
	// ErrNoBearerToken is returned when a request carries no bearer token,
	// so the next authenticator in the qrdb chain decides.
	ErrNoBearerToken = errors.New("xkmsd: no bearer token")

	// ErrBearerNotAccepted is returned when xkmsd's authentication does not
	// verify bearer tokens (it is disabled, or not yet initialized).
	ErrBearerNotAccepted = errors.New("xkmsd: bearer tokens are not accepted")
)

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
}

// Compile-time check against qrdb's authenticator interface.
var _ qrdbsdk.Authenticator = (*bearerAuthenticator)(nil)

// Name implements qrdbsdk.Authenticator. It is the method an account's
// permitted-authentication-method policy is checked against.
func (b *bearerAuthenticator) Name() string { return "jwt" }

// Authenticate implements qrdbsdk.Authenticator.
func (b *bearerAuthenticator) Authenticate(ctx context.Context) (*qrdbsdk.Identity, error) {
	header := bearerHeader(ctx)
	if header == "" {
		return nil, ErrNoBearerToken
	}
	delegate := b.live.Load()
	if delegate == nil || delegate.Name() == auth.NewNoOpAuthenticator().Name() {
		return nil, ErrBearerNotAccepted
	}
	return delegate.AuthenticateGRPC(ctx, metadata.Pairs("authorization", header))
}

// bearerHeader returns the request's "Bearer <token>" authorization value,
// or "" when it carries none. gRPC requests carry it as metadata.
func bearerHeader(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, v := range md.Get("authorization") {
		if strings.HasPrefix(v, "Bearer ") && strings.TrimSpace(strings.TrimPrefix(v, "Bearer ")) != "" {
			return v
		}
	}
	return ""
}
