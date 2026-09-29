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

package token

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// UserResolver re-checks the CURRENT state of the user behind a refresh
// token at refresh time (go-xkms#1297): without one, Refresh rebuilds the
// identity from the refresh token's own claims alone
// (identityFromClaims), so a user disabled or deleted after login keeps
// refreshing, and a role change never reaches an already-issued session.
//
// pkg/auth's QRDBUserResolver is the production implementation, resolving
// the qrdb-backed identity plane the same way MTLSAuthenticator's UserStore
// does for mTLS logins (it cannot be declared here: pkg/auth/token already
// imports pkg/auth, so the reverse import would cycle, and it satisfies
// this interface structurally instead).
//
// A nil UserResolver on Config is valid only when there is no identity
// plane to re-check against -- it mirrors MTLSAuthenticator's own optional
// UserStore, which likewise trusts the credential it is given when unset.
type UserResolver interface {
	// ResolveUser looks up the CURRENT record for id -- the identity
	// Refresh rebuilt from the presented refresh token's own claims via
	// identityFromClaims -- and returns a fresh identity carrying the
	// account's current roles and metadata. Any non-nil error refuses the
	// refresh: a disabled or deleted account, an account whose subject no
	// longer resolves, or a resolver that cannot currently answer must all
	// stop the refresh from minting a new access token.
	ResolveUser(ctx context.Context, id *auth.Identity) (*auth.Identity, error)
}
