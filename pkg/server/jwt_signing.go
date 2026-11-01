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
	"errors"
	"time"

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

	issuer, err := rest.BuildTokenIssuer(s.ctx, rest.TokenIssuerParams{
		Backend:      backend,
		BackendName:  s.defaultBackendName,
		SigningKeyCN: cn,
		IssuerName:   issuerName,
		Audience:     audience,
		AccessTTL:    accessTTL,
		RefreshTTL:   refreshTTL,
		QRDBClient:   s.qrdbClient,
		CallContext:  s.publicCallContext(),
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
