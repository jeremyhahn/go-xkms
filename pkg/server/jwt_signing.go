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
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
)

// initializeTokenIssuer provisions the session-token signing key and builds
// the token issuer behind every login flow (WebAuthn passkey login, PIV/mTLS
// cert login) and the /api/v1/auth session endpoints. Runs after the
// keystore is initialized; a missing xkms service (no backends) leaves the
// issuer nil and the login surfaces unmounted.
//
// Provisioning and issuer construction are delegated to rest.BuildTokenIssuer
// — the construction path shared with a host's self-built REST surface
// (pkg/api/rest NewHostServer / pkg/apimodule), so xkmsd and a host mint and
// verify session tokens identically.
func (s *Server) initializeTokenIssuer() error {
	// Use the server's own freshly initialized backends, not the xkms
	// singleton: a stale singleton from a previous composition (tests,
	// reload) would hand back closed backends.
	backend, ok := s.backends[s.defaultBackendName]
	if !ok || backend == nil {
		s.logger.Info("Token issuer skipped: no default backend")
		return nil
	}

	cn := ""
	issuerName := ""
	var audience []string
	if s.config.WebAuthn != nil {
		cn = s.config.WebAuthn.JWTKeyID
		issuerName = s.config.WebAuthn.JWTIssuer
		audience = s.config.WebAuthn.JWTAudience
	}

	accessTTL, refreshTTL := s.sessionTTLs()
	var callContext func(context.Context) (context.Context, error)
	var userLookup rest.RefreshUserLookup
	if s.qrdbNode != nil {
		callContext = systemServiceContext(s.qrdbNode)
		userLookup = nodeUsers{node: s.qrdbNode}
	}

	issuer, err := rest.BuildTokenIssuer(s.ctx, rest.TokenIssuerParams{
		Backend:      backend,
		BackendName:  s.defaultBackendName,
		SigningKeyCN: cn,
		IssuerName:   issuerName,
		Audience:     audience,
		AccessTTL:    accessTTL,
		RefreshTTL:   refreshTTL,
		QRDBClient:   s.qrdbClient,
		CallContext:  callContext,
		UserLookup:   userLookup,
		Logger:       s.logger,
		Retry:        retryNotLeader,
	})
	if err != nil {
		// A signing-key backend failure (provisioning or signer
		// construction) is soft: the login surfaces stay unmounted and the
		// daemon still serves — loudly, so the operator knows browser and
		// desktop logins cannot work on this deployment. On a cluster this
		// runs while the initial leader election may still be settling;
		// retryNotLeader absorbs the transient not-leader condition.
		// Anything else (a refresh-store or issuer config error) is a
		// programming/configuration error worth aborting startup over.
		var backendErr *rest.TokenIssuerBackendError
		if errors.As(err, &backendErr) {
			s.logger.Error("Token issuer disabled: JWT signing key provisioning failed; "+
				"WebAuthn and PIV/mTLS logins will not work",
				"backend", s.defaultBackendName, "error", err)
			return nil
		}
		return &ErrServiceInit{Service: "token issuer", Err: err}
	}

	if cn == "" {
		cn = rest.DefaultJWTSigningKeyCN
	}
	s.tokenIssuer = issuer
	s.logger.Info("Token issuer initialized",
		"key", cn,
		"backend", s.defaultBackendName,
		"access_ttl", accessTTL.String(),
		"refresh_ttl", refreshTTL.String())
	return nil
}

// nodeUsers answers the refresh user re-check from the embedded node's user
// service, in the tenant the re-check binds on the context. The node's
// service principal lives in the system tenant and may not read a holder in
// another one, so the client path would refuse every non-system-tenant
// refresh. The service is read per call: it is nil until the node has booted.
// systemServiceContext binds the refresh store's qrdb calls to the node's
// service principal in the system tenant, whatever tenant the incoming
// context carries. Node.ServiceContext replaces only the identity: the
// anonymous login stores records in the system tenant, while an
// authenticated logout arrives with the holder's tenant bound, where the
// principal's self-scope grants do not reach and the revoke was refused.
func systemServiceContext(node *qrdbnode.Node) func(context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		return node.ServiceContext(qrdbsdk.ContextWithTenant(ctx, qrdbsdk.SystemTenantID))
	}
}

type nodeUsers struct {
	node *qrdbnode.Node
}

func (n nodeUsers) GetUser(ctx context.Context, id uint64) (*qrdbsdk.User, error) {
	users := n.node.UserService()
	if users == nil {
		return nil, ErrQRDBNodeNotServing
	}
	return users.GetUser(ctx, id)
}

func (n nodeUsers) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbsdk.User, error) {
	users := n.node.UserService()
	if users == nil {
		return nil, ErrQRDBNodeNotServing
	}
	return users.GetUserByUsername(ctx, tenantID, username)
}

// sessionTTLs resolves the configured token lifetimes. Config validation
// already proved the strings parse, so parse failures fall back to defaults.
func (s *Server) sessionTTLs() (access, refresh time.Duration) {
	access = token.DefaultAccessTTL
	refresh = token.DefaultRefreshTTL
	if s.config.Auth.Session == nil {
		return access, refresh
	}
	if v := s.config.Auth.Session.AccessTokenTTL; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			access = d
		}
	}
	if v := s.config.Auth.Session.RefreshTokenTTL; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			refresh = d
		}
	}
	return access, refresh
}
