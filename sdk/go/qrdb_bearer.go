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

import "github.com/jeremyhahn/go-xkms/pkg/auth"

// Bearer tokens on an embedded go-qrdb node. A host that embeds a qrdb node
// and mints its own session tokens registers QRDBBearerAuthenticator with the
// node's WithAuthenticators option, so the node's transports accept the
// tokens the host issues. Without it the node's chain knows only mTLS.

// Authenticator authenticates an HTTP request or gRPC metadata into an
// identity. xkms's JWT, OIDC, mTLS and static-token authenticators implement
// it.
type Authenticator = auth.Authenticator

// LiveAuthenticator holds the authenticator in force and swaps it atomically
// on reload. It is an Authenticator and an AuthenticatorSource.
type LiveAuthenticator = auth.LiveAuthenticator

// NewLiveAuthenticator returns a holder delegating to an authenticator; nil
// installs none, and authentication then fails closed.
var NewLiveAuthenticator = auth.NewLiveAuthenticator

// AuthenticatorSource yields the authenticator in force for one request.
type AuthenticatorSource = auth.AuthenticatorSource

// QRDBBearerAuthenticator verifies a request's "Bearer" Authorization value
// with its source's authenticator on behalf of a qrdb node's chain. It
// declines a request with no bearer token (the next authenticator decides),
// refuses one when no authenticator or the no-op authenticator is in force,
// and reports its login method as unobservable: the token's issuer enforced
// the account's permitted-method policy when it minted the token.
type QRDBBearerAuthenticator = auth.QRDBBearerAuthenticator

// NewQRDBBearerAuthenticator returns a QRDBBearerAuthenticator over a source.
var NewQRDBBearerAuthenticator = auth.NewQRDBBearerAuthenticator

// ErrBearerNotAccepted is the refusal of a bearer token when the source has
// no authenticator, or only the no-op one, in force.
var ErrBearerNotAccepted = auth.ErrBearerNotAccepted
