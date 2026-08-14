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
	stdcrypto "crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// defaultJWTSigningKeyCN is the reserved key that signs session tokens when
// the operator has not designated one via webauthn.jwt_key_id. It is
// auto-provisioned in the default backend, so it is hardware-backed whenever
// the default backend is.
const defaultJWTSigningKeyCN = "xkms-jwt-signing"

// initializeTokenIssuer provisions the session-token signing key and builds
// the token issuer behind every login flow (WebAuthn passkey login, PIV/mTLS
// cert login) and the /api/v1/auth session endpoints. Runs after the
// keystore is initialized; a missing xkms service (no backends) leaves the
// issuer nil and the login surfaces unmounted.
func (s *Server) initializeTokenIssuer() error {
	// Use the server's own freshly initialized backends, not the xkms
	// singleton: a stale singleton from a previous composition (tests,
	// reload) would hand back closed backends.
	backend, ok := s.backends[s.defaultBackendName]
	if !ok || backend == nil {
		s.logger.Info("Token issuer skipped: no default backend")
		return nil
	}

	cn := defaultJWTSigningKeyCN
	issuerName := ""
	var audience []string
	if s.config.WebAuthn != nil {
		if s.config.WebAuthn.JWTKeyID != "" {
			cn = s.config.WebAuthn.JWTKeyID
		}
		issuerName = s.config.WebAuthn.JWTIssuer
		audience = s.config.WebAuthn.JWTAudience
	}

	attrs := &types.KeyAttributes{
		CN:                 cn,
		StoreType:          types.ParseStoreType(s.defaultBackendName),
		KeyType:            types.KeyTypeSigning,
		KeyAlgorithm:       x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Hash:               stdcrypto.SHA256,
		ECCAttributes:      &types.ECCAttributes{Curve: elliptic.P256()},
	}

	// Reuse the key across restarts; generate it on first boot. A backend
	// that cannot persist the key (e.g. a storage mode without CAS support)
	// leaves the issuer nil: the login surfaces stay unmounted and the
	// daemon still serves — loudly, so the operator knows browser and
	// desktop logins cannot work on this deployment.
	if _, err := backend.GetKey(s.ctx, attrs); err != nil {
		if _, genErr := backend.GenerateECDSA(s.ctx, attrs); genErr != nil {
			s.logger.Error("Token issuer disabled: JWT signing key provisioning failed; "+
				"WebAuthn and PIV/mTLS logins will not work",
				"cn", cn, "backend", s.defaultBackendName, "error", genErr)
			return nil
		}
		s.logger.Info("JWT signing key provisioned",
			"cn", cn, "backend", s.defaultBackendName)
	}

	signer, err := backend.Signer(s.ctx, attrs)
	if err != nil {
		s.logger.Error("Token issuer disabled: JWT signing key signer unavailable",
			"cn", cn, "backend", s.defaultBackendName, "error", err)
		return nil
	}

	// Refresh-token records live on the qrdb identity plane when available,
	// falling back to process memory (sessions then end on restart, which is
	// the correct fail-closed behavior for non-qrdb storage modes).
	var refreshStore token.RefreshStore
	if s.qrdbClient != nil {
		qs, storeErr := token.NewQRDBRefreshStore(s.qrdbClient.KV())
		if storeErr != nil {
			return &ErrServiceInit{Service: "refresh token store", Err: storeErr}
		}
		refreshStore = qs
	} else {
		refreshStore = token.NewMemoryRefreshStore()
	}

	accessTTL, refreshTTL := s.sessionTTLs()

	issuer, err := token.NewIssuer(&token.Config{
		Signer:        signer,
		KeyAttributes: attrs,
		KeyID:         cn,
		Issuer:        issuerName,
		Audience:      audience,
		AccessTTL:     accessTTL,
		RefreshTTL:    refreshTTL,
		RefreshStore:  refreshStore,
	})
	if err != nil {
		return &ErrServiceInit{Service: "token issuer", Err: err}
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

// webAuthnTokenAdapter bridges the token issuer into the WebAuthn service:
// it implements webauthn.JWTGenerator and webauthn.TokenPairGenerator, so
// ceremony completion mints real, verifiable access/refresh pairs instead of
// the library's base64 user-ID fallback.
type webAuthnTokenAdapter struct {
	issuer *token.Issuer
}

// identityFor maps a WebAuthn user onto the auth identity carried in tokens.
// The subject is the base64url user ID — the same binding the qrdb-backed
// WebAuthn store keys users by.
func (a *webAuthnTokenAdapter) identityFor(user webauthn.User) *auth.Identity {
	id := &auth.Identity{
		Subject:  base64.RawURLEncoding.EncodeToString(user.WebAuthnID()),
		TenantID: webAuthnSystemTenant,
		Metadata: map[string]string{
			"username":     user.WebAuthnName(),
			"display_name": user.WebAuthnDisplayName(),
		},
	}
	if roleUser, ok := user.(interface{ GetRole() string }); ok {
		if role := roleUser.GetRole(); role != "" {
			id.Roles = []string{role}
		}
	}
	return id
}

// GenerateToken implements webauthn.JWTGenerator.
func (a *webAuthnTokenAdapter) GenerateToken(ctx context.Context, user webauthn.User) (string, error) {
	pair, err := a.issuer.Mint(ctx, a.identityFor(user))
	if err != nil {
		return "", err
	}
	return pair.AccessToken, nil
}

// GenerateTokenPair implements webauthn.TokenPairGenerator.
func (a *webAuthnTokenAdapter) GenerateTokenPair(ctx context.Context, user webauthn.User) (string, string, error) {
	pair, err := a.issuer.Mint(ctx, a.identityFor(user))
	if err != nil {
		return "", "", err
	}
	return pair.AccessToken, pair.RefreshToken, nil
}
