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

// Package token issues and rotates the access/refresh token pairs behind the
// browser and desktop login flows (WebAuthn passkey login, PIV/mTLS cert
// login). Access tokens are short-lived JWTs whose claims match exactly what
// auth.JWTAuthenticator consumes; refresh tokens are long-lived rotating JWTs
// tracked in a RefreshStore so replaying a rotated token revokes the whole
// session family. Signing goes through crypto.Signer, so the issuing key can
// live in any xkms backend, hardware included.
package token

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	xkmsjwt "github.com/jeremyhahn/go-xkms/pkg/encoding/jwt"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Defaults for token lifetimes: a passkey or PIV re-auth prompts a physical
// user-presence ceremony, so the access token is kept short and renewal rides
// the rotating refresh token instead.
const (
	DefaultAccessTTL  = 15 * time.Minute
	DefaultRefreshTTL = 8 * time.Hour

	// refreshTokenType is the typ claim distinguishing refresh tokens from
	// access tokens, so one can never be presented as the other.
	refreshTokenType = auth.RefreshTokenType
)

// Pair is one issued access/refresh token pair.
type Pair struct {
	// AccessToken is the short-lived bearer JWT.
	AccessToken string `json:"access_token"`

	// RefreshToken is the rotating long-lived refresh JWT.
	RefreshToken string `json:"refresh_token"`

	// TokenType is always "Bearer".
	TokenType string `json:"token_type"`

	// ExpiresIn is the access token lifetime in seconds.
	ExpiresIn int64 `json:"expires_in"`
}

// Config configures an Issuer.
type Config struct {
	// Signer signs both token kinds. Required. May be hardware-backed.
	Signer crypto.Signer

	// KeyAttributes describe the signing key (algorithm and hash) for JWT
	// method selection. Required.
	KeyAttributes *types.KeyAttributes

	// KeyID is the kid header stamped on issued tokens (optional).
	KeyID string

	// Issuer is the iss claim. Defaults to "go-xkms".
	Issuer string

	// Audience is the aud claim. Defaults to ["go-xkms"].
	Audience []string

	// AccessTTL is the access token lifetime. Defaults to DefaultAccessTTL.
	AccessTTL time.Duration

	// RefreshTTL is the refresh token lifetime. Defaults to DefaultRefreshTTL.
	RefreshTTL time.Duration

	// RefreshStore tracks issued refresh tokens. Required.
	RefreshStore RefreshStore

	// UserResolver re-checks the refresh token's subject against the
	// CURRENT user record on every Refresh, so a disabled or deleted
	// account cannot keep refreshing and a role change takes effect
	// immediately rather than at the next full login (go-xkms#1297).
	// Optional: nil skips the re-check, trusting the identity snapshot
	// carried in the refresh token's own claims exactly as before -- the
	// correct behavior when there is no identity plane to check against.
	UserResolver UserResolver
}

// Issuer mints and rotates token pairs.
type Issuer struct {
	signer     crypto.Signer
	keyAttrs   *types.KeyAttributes
	keyID      string
	issuer     string
	audience   []string
	accessTTL  time.Duration
	refreshTTL time.Duration
	store      RefreshStore
	resolver   UserResolver
	jwtSigner  *xkmsjwt.Signer
}

// NewIssuer validates cfg and constructs an Issuer.
func NewIssuer(cfg *Config) (*Issuer, error) {
	if cfg == nil {
		return nil, &NilInputError{Field: "config"}
	}
	if cfg.Signer == nil {
		return nil, &NilInputError{Field: "signer"}
	}
	if cfg.KeyAttributes == nil {
		return nil, &NilInputError{Field: "key attributes"}
	}
	if cfg.RefreshStore == nil {
		return nil, &NilInputError{Field: "refresh store"}
	}

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "go-xkms"
	}
	audience := cfg.Audience
	if len(audience) == 0 {
		audience = []string{"go-xkms"}
	}
	accessTTL := cfg.AccessTTL
	if accessTTL <= 0 {
		accessTTL = DefaultAccessTTL
	}
	refreshTTL := cfg.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = DefaultRefreshTTL
	}
	// A refresh token that outlives its family's revocation tombstone could be
	// exchanged after the record of the revocation has been swept, which is the
	// one way a revoked lineage could come back to life.
	if refreshTTL > RevocationTombstoneTTL {
		return nil, &RefreshTTLTooLongError{TTL: refreshTTL, Max: RevocationTombstoneTTL}
	}

	return &Issuer{
		signer:     cfg.Signer,
		keyAttrs:   cfg.KeyAttributes,
		keyID:      cfg.KeyID,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		store:      cfg.RefreshStore,
		resolver:   cfg.UserResolver,
		jwtSigner:  xkmsjwt.NewSigner(),
	}, nil
}

// PublicKey returns the verification key for issued tokens.
func (i *Issuer) PublicKey() crypto.PublicKey {
	return i.signer.Public()
}

// Issuer returns the iss claim value.
func (i *Issuer) IssuerName() string { return i.issuer }

// Audience returns the aud claim values.
func (i *Issuer) Audience() []string { return i.audience }

// AccessTTL returns the access token lifetime.
func (i *Issuer) AccessTTL() time.Duration { return i.accessTTL }

// Mint issues a fresh token pair for the identity, opening a new refresh
// family.
func (i *Issuer) Mint(ctx context.Context, id *auth.Identity) (*Pair, error) {
	if id == nil || id.Subject == "" {
		return nil, &NilInputError{Field: "identity subject"}
	}

	family, err := randomID()
	if err != nil {
		return nil, &SigningError{Err: err}
	}

	return i.mintPair(ctx, id, family)
}

// Refresh exchanges a valid, unrotated refresh token for a new pair, rotating
// the refresh token. Presenting an already-rotated token revokes the entire
// family and fails: replay of a rotated refresh token means two parties hold
// the same lineage, which is the signature of theft.
//
// When a UserResolver is configured, the token's subject is re-checked
// against the CURRENT user record before any rotation is attempted: a
// disabled or deleted account, or one the resolver cannot currently vouch
// for, refuses the refresh with *UserRecheckFailedError -- mapped by every
// transport to the same generic response as *RefreshRevokedError, so a
// presented refresh token never reveals whether it failed because it was
// revoked or because the account behind it no longer may authenticate. The
// resolver's fresh identity -- current roles included -- is what the
// rotated pair is minted from, not the snapshot the old refresh token
// carried.
func (i *Issuer) Refresh(ctx context.Context, refreshToken string) (*Pair, error) {
	claims, err := i.verifyRefresh(refreshToken)
	if err != nil {
		return nil, err
	}

	jti, _ := claims["jti"].(string)
	family, _ := claims["fam"].(string)
	if jti == "" || family == "" {
		return nil, &InvalidTokenError{Reason: "missing jti or fam claim"}
	}

	identity := identityFromClaims(claims)
	if i.resolver != nil {
		fresh, resolveErr := i.resolver.ResolveUser(ctx, identity)
		if resolveErr != nil {
			return nil, &UserRecheckFailedError{Err: resolveErr}
		}
		identity = fresh
	}

	rec, err := i.store.Get(ctx, family, jti)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, &RefreshRevokedError{}
	}
	if rec.Rotated {
		// Reuse: revoke the lineage before failing.
		if revokeErr := i.store.RevokeFamily(ctx, family); revokeErr != nil {
			return nil, revokeErr
		}
		return nil, &RefreshReuseError{Family: family}
	}

	// MarkRotated is the arbitration point. The Rotated check above is an early
	// out for the replay that arrives after a rotation completed; it cannot
	// decide a race, because two refreshes can both read Rotated=false. Only
	// this atomic compare-and-swap can, and exactly one caller wins it. The
	// loser gets *RefreshRaceLostError and mints nothing.
	if err := i.store.MarkRotated(ctx, family, jti); err != nil {
		return nil, err
	}

	// The successor is committed by mintPair's Save, which refuses a family
	// that was revoked while this refresh was in flight.
	return i.mintPair(ctx, identity, family)
}

// RevokeBySubject revokes every refresh-token family belonging to subject
// in tenant, immediately ending every session it holds regardless of which
// login flow minted it, and no session of a same-named account in another
// tenant. It is the hook a user-lifecycle change (disable, delete) calls
// once the underlying account update has succeeded (go-xkms#1297); the
// refresh-time re-check a UserResolver performs is the backstop for a
// lifecycle change that reaches the identity plane through a path this
// method is never called from.
func (i *Issuer) RevokeBySubject(ctx context.Context, tenant, subject string) error {
	return i.store.RevokeBySubject(ctx, tenant, subject)
}

// Revoke invalidates the refresh token's whole family (logout). An invalid
// or unknown token is a no-op: logout must be idempotent.
func (i *Issuer) Revoke(ctx context.Context, refreshToken string) error {
	claims, err := i.verifyRefresh(refreshToken)
	if err != nil {
		return nil
	}
	family, _ := claims["fam"].(string)
	if family == "" {
		return nil
	}
	return i.store.RevokeFamily(ctx, family)
}

// mintPair signs an access/refresh pair inside the given family and records
// the refresh token.
func (i *Issuer) mintPair(ctx context.Context, id *auth.Identity, family string) (*Pair, error) {
	now := time.Now()

	accessClaims := jwt.MapClaims{
		"iss": i.issuer,
		"aud": i.audience,
		"sub": id.Subject,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(i.accessTTL).Unix(),
	}
	addIdentityClaims(accessClaims, id)

	accessToken, err := i.sign(accessClaims)
	if err != nil {
		return nil, &SigningError{Err: err}
	}

	jti, err := randomID()
	if err != nil {
		return nil, &SigningError{Err: err}
	}

	refreshExp := now.Add(i.refreshTTL)
	refreshClaims := jwt.MapClaims{
		"iss": i.issuer,
		"aud": i.audience,
		"sub": id.Subject,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": refreshExp.Unix(),
		"typ": refreshTokenType,
		"jti": jti,
		"fam": family,
	}
	addIdentityClaims(refreshClaims, id)

	refreshToken, err := i.sign(refreshClaims)
	if err != nil {
		return nil, &SigningError{Err: err}
	}

	if err := i.store.Save(ctx, &Record{
		JTI:       jti,
		Family:    family,
		Subject:   id.Subject,
		Tenant:    qrdbsdk.NormalizeTenantID(id.TenantID),
		ExpiresAt: refreshExp.Unix(),
	}); err != nil {
		return nil, err
	}

	return &Pair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(i.accessTTL.Seconds()),
	}, nil
}

// addIdentityClaims copies the identity snapshot onto a claim set. Both
// halves of a pair carry the same snapshot so a refresh reproduces the
// identity the original ceremony established. Empty values are omitted, so
// a principal without an email login key mints a token without an email
// claim rather than an empty one.
func addIdentityClaims(claims jwt.MapClaims, id *auth.Identity) {
	if id.TenantID != "" {
		claims["tenant_id"] = id.TenantID
	}
	if len(id.Roles) > 0 {
		claims["roles"] = id.Roles
	}
	if username := id.Metadata["username"]; username != "" {
		claims["username"] = username
	}
	if name := id.Metadata["display_name"]; name != "" {
		claims["name"] = name
	}
	if email := id.Metadata["email"]; email != "" {
		claims["email"] = email
	}
	if level := id.Metadata["attest_level"]; level != "" {
		claims["attest_level"] = level
	}
	if kind := id.Metadata[auth.SubjectKindMetadataKey]; kind != "" {
		claims[auth.SubjectKindMetadataKey] = kind
	}
}

// sign signs claims with the configured crypto.Signer.
func (i *Issuer) sign(claims jwt.MapClaims) (string, error) {
	if i.keyID != "" {
		return i.jwtSigner.SignWithSignerAndKID(i.signer, claims, i.keyAttrs, i.keyID)
	}
	return i.jwtSigner.SignWithSigner(i.signer, claims, i.keyAttrs)
}

// verifyRefresh validates a refresh token's signature, expiry, issuer, and
// typ claim, returning its claims.
func (i *Issuer) verifyRefresh(refreshToken string) (jwt.MapClaims, error) {
	if refreshToken == "" {
		return nil, &InvalidTokenError{Reason: "empty token"}
	}

	verifier := xkmsjwt.NewVerifier()
	parsed, err := verifier.VerifyWithOptions(refreshToken, i.PublicKey(), &xkmsjwt.VerifyOptions{
		ValidateIssuer: true,
		ExpectedIssuer: i.issuer,
		ValidateExpiry: true,
	})
	if err != nil {
		return nil, &InvalidTokenError{Reason: "verification failed", Err: err}
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &InvalidTokenError{Reason: "unexpected claims type"}
	}
	if typ, _ := claims["typ"].(string); typ != refreshTokenType {
		return nil, &InvalidTokenError{Reason: "not a refresh token"}
	}
	return claims, nil
}

// identityFromClaims rebuilds the identity carried in refresh-token claims.
// It is the starting point Refresh re-checks through a UserResolver, when
// one is configured, before minting the next pair; without one, this
// snapshot from the original login ceremony is what the rotated pair
// carries forward unchanged, and a role change then only takes effect at
// the next full login.
func identityFromClaims(claims jwt.MapClaims) *auth.Identity {
	id := &auth.Identity{Metadata: make(map[string]string)}
	id.Subject, _ = claims["sub"].(string)
	id.TenantID, _ = claims["tenant_id"].(string)
	if roles, ok := claims["roles"].([]interface{}); ok {
		for _, r := range roles {
			if s, ok := r.(string); ok && s != "" {
				id.Roles = append(id.Roles, s)
			}
		}
	}
	if username, ok := claims["username"].(string); ok && username != "" {
		id.Metadata["username"] = username
	}
	if name, ok := claims["name"].(string); ok && name != "" {
		id.Metadata["display_name"] = name
	}
	if email, ok := claims["email"].(string); ok && email != "" {
		id.Metadata["email"] = email
	}
	if level, ok := claims["attest_level"].(string); ok && level != "" {
		id.Metadata["attest_level"] = level
	}
	if kind, ok := claims[auth.SubjectKindMetadataKey].(string); ok && kind != "" {
		id.Metadata[auth.SubjectKindMetadataKey] = kind
	}
	return id
}

// randomID returns a 128-bit hex identifier for jti/family values.
func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
