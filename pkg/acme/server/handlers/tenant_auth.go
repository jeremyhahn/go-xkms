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

package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
)

// authenticatedJWSContextKey is the context key under which
// TenantAuthMiddleware caches a parseKID result so a later call to parseKID
// for the same request returns it instead of re-verifying. It is unexported
// so nothing outside this file can inject a forged result into a request's
// context.
type authenticatedJWSContextKey struct{}

// authenticatedJWSResult is the outcome of a single parseKID verification:
// either a verified account and payload, or the error parseKID returned.
// Caching the error alongside the success path (not just the success path)
// preserves every existing parseKID call site's error mapping — bad nonce,
// URL mismatch, invalid signature, unknown or deactivated account — exactly
// as if parseKID had been called once, in place, by the handler itself.
type authenticatedJWSResult struct {
	account *entities.ACMEAccount
	payload []byte
	err     error
}

// withAuthenticatedJWS attaches a parseKID result to ctx.
func withAuthenticatedJWS(ctx context.Context, account *entities.ACMEAccount, payload []byte, err error) context.Context {
	return context.WithValue(ctx, authenticatedJWSContextKey{}, &authenticatedJWSResult{
		account: account,
		payload: payload,
		err:     err,
	})
}

// authenticatedJWSFromContext returns the parseKID result TenantAuthMiddleware
// cached for this request, if any.
func authenticatedJWSFromContext(ctx context.Context) (*authenticatedJWSResult, bool) {
	cached, ok := ctx.Value(authenticatedJWSContextKey{}).(*authenticatedJWSResult)
	return cached, ok
}

// peekJWSKeyID reports the "kid" field of a JWS protected header without
// verifying the signature or consuming the replay-nonce: it only parses the
// JWS envelope structure, to decide whether the request names an account at
// all. The kid it returns is unverified and is never used as an identity —
// parseKID verifies it before anything keys on it. A JWK-authenticated
// request (new-account, which has no account yet), a malformed body, or a
// JWS with no signatures reports ok=false — only a request that names an existing account by kid can ever
// resolve to a tenant.
func peekJWSKeyID(body []byte) (kid string, ok bool) {
	jws, err := parseSignedAny(strings.TrimSpace(string(body)), server.AllowedJOSEAlgorithms)
	if err != nil || len(jws.Signatures) == 0 {
		return "", false
	}
	header := jws.Signatures[0].Header
	if header.JSONWebKey != nil || header.KeyID == "" {
		return "", false
	}
	return header.KeyID, true
}

// TenantAuthMiddleware resolves the ACME tenant for admission control from
// the only source that cannot be spoofed: a fully verified JWS "kid". It
// never consults X-Tenant-ID, the request host, or the request path — see
// TenantMiddleware (middleware.go) for that client-asserted mechanism, which
// this middleware deliberately does not use for admission control, and which
// is not wired into the ACME router for that reason.
//
// For a POST request whose JWS protected header names an account (kid),
// this middleware performs the exact verification parseKID performs — nonce
// check, JWS "url" match, signature verification against the account's
// stored public key — by calling parseKID itself, exactly once. The result
// (success or failure) is cached on the request context so the handler's own
// parseKID call returns the identical result instead of re-verifying: the
// replay-nonce is single-use, so a second live verification would spuriously
// fail with badNonce. On success, the account's TenantID is published via
// server.WithTenantID so any TenantRateLimiter mounted after this middleware
// keys on it, and the verified account via server.WithVerifiedAccountID so
// server.ClientID keys per-account buckets on it rather than on the client IP.
//
// A request with no kid (new-account's JWK-authenticated JWS, new-nonce,
// directory, ca-bundle, or any GET) never publishes a tenant, and neither
// does one whose kid fails verification: those requests are bounded only by
// the per-client limiter (#885), never by a client-asserted tenant.
func (s *RestService) TenantAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// RequestBody returns the copy RequestBodyMiddleware already read;
		// a read failure is left for the handler, whose own parseKID call
		// reports the identical (buffered) error.
		body, err := server.RequestBody(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		if _, ok := peekJWSKeyID(body); !ok {
			next.ServeHTTP(w, r)
			return
		}

		account, payload, kidErr := s.parseKID(r.Context(), r)

		ctx := withAuthenticatedJWS(r.Context(), account, payload, kidErr)
		if kidErr == nil {
			// Only a verified kid may key a per-account rate-limit bucket
			// (server.ClientID); an unverified one is attacker-chosen.
			ctx = server.WithVerifiedAccountID(ctx, account.ID)
			if account.TenantID != "" {
				ctx = server.WithTenantID(ctx, account.TenantID)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
