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

package auth

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// SubjectKindMetadataKey is the Identity.Metadata key -- and, once minted,
// the refresh-token claim (pkg/auth/token addIdentityClaims / claims["sub_kind"]
// via identityFromClaims) -- naming which encoding an identity's Subject
// uses. Every login path that mints a token pair must set it explicitly.
//
// The encoding used to be inferred: QRDBUserResolver.lookup tried
// GetUserByUsername first and, on not-found, fell back to decoding Subject
// as a WebAuthn handle. That let a DELETED mTLS/PIV user whose username
// happened to also be a valid base64url-encoded 8-byte value resolve to
// WHICHEVER OTHER live account that value decodes to -- identity confusion
// and a privilege escalation, and exactly the failure mode this issue exists
// to close (go-xkms#1297 review). The kind is now declared by the login flow
// that minted the token, never guessed from the shape of the subject.
const SubjectKindMetadataKey = "sub_kind"

const (
	// SubjectKindUsername marks a Subject as a qrdb username: mTLS and PIV
	// logins (MTLSAuthenticator.userIdentity, pkg/api/rest handlePIVLogin,
	// which serves both).
	SubjectKindUsername = "username"

	// SubjectKindUserHandle marks a Subject as the base64url, unpadded,
	// big-endian 8-byte qrdb user id a WebAuthn passkey login stamps
	// (pkg/api/rest WebAuthnTokenAdapter.identityFor, encoding
	// pkg/webauthn.HandleFromUserID).
	SubjectKindUserHandle = "user_handle"
)

// QRDBUserResolver re-resolves the CURRENT state of the user behind a
// refresh token at refresh time, straight from the qrdb user client -- the
// same source MTLSAuthenticator.userIdentity reads for an mTLS login
// (go-xkms#1297). It satisfies pkg/auth/token's UserResolver interface
// structurally: that package already imports this one, so the reverse
// import would cycle, and the interface is implemented here rather than
// declared.
type QRDBUserResolver struct {
	users qrdbtransport.UserClient
	bind  func(ctx context.Context) (context.Context, error)
}

// QRDBUserResolverOption configures a QRDBUserResolver.
type QRDBUserResolverOption func(*QRDBUserResolver)

// WithResolverCallContext runs every user lookup on the context bind derives
// from the caller's. A refresh request carries no identity go-qrdb's
// authorization accepts, so an embedded node passes its service principal
// (node.ServiceContext). A bind failure fails the refresh closed with
// *RefreshUserLookupError.
func WithResolverCallContext(bind func(ctx context.Context) (context.Context, error)) QRDBUserResolverOption {
	return func(r *QRDBUserResolver) {
		r.bind = bind
	}
}

// NewQRDBUserResolver wires the qrdb user client into a QRDBUserResolver.
func NewQRDBUserResolver(users qrdbtransport.UserClient, opts ...QRDBUserResolverOption) *QRDBUserResolver {
	r := &QRDBUserResolver{users: users}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ResolveUser looks up the CURRENT qrdb record for id.Subject, resolved
// strictly under the encoding id.Metadata[SubjectKindMetadataKey] declares,
// and returns a fresh identity carrying the account's current roles and
// metadata. Refusal is *RefreshSubjectKindError when that metadata is
// missing or not one of SubjectKindUsername/SubjectKindUserHandle (pre-
// release: a token minted before this field existed simply fails refresh),
// ErrUserDisabled for an account whose Lifecycle is not
// qrdbsdk.LifecycleActive, ErrRefreshSubjectNotFound when the subject does
// not resolve under its declared kind, and *RefreshUserLookupError when the
// qrdb user client cannot currently answer -- fail closed, exactly as
// MTLSAuthenticator.userIdentity does when its own UserStore errs: an
// outage must never read as a resolved, current, still-active account.
func (r *QRDBUserResolver) ResolveUser(ctx context.Context, id *Identity) (*Identity, error) {
	if id == nil || id.Subject == "" {
		return nil, ErrRefreshSubjectNotFound
	}

	if r.bind != nil {
		bound, err := r.bind(ctx)
		if err != nil {
			return nil, &RefreshUserLookupError{Err: err}
		}
		ctx = bound
	}

	u, err := r.lookup(ctx, id)
	if err != nil {
		return nil, err
	}
	if u.Lifecycle != string(qrdbsdk.LifecycleActive) {
		return nil, ErrUserDisabled
	}

	fresh := &Identity{
		Subject:  id.Subject,
		TenantID: u.TenantID,
		Metadata: make(map[string]string, len(id.Metadata)+2),
	}
	for k, v := range id.Metadata {
		fresh.Metadata[k] = v
	}
	if len(u.RoleIDs) > 0 {
		fresh.Roles = append([]string(nil), u.RoleIDs...)
	}
	fresh.Metadata["username"] = u.Username
	fresh.Metadata["display_name"] = u.Name
	if u.Email != "" {
		fresh.Metadata["email"] = u.Email
	} else {
		delete(fresh.Metadata, "email")
	}
	return fresh, nil
}

// lookup resolves the qrdb user record behind id.Subject, strictly under
// its declared SubjectKindMetadataKey. It never tries the other encoding:
// a subject declared "username" is looked up ONLY by GetUserByUsername, and
// a not-found there is refused outright, never reinterpreted as a user
// handle that might happen to decode to a different, live account.
func (r *QRDBUserResolver) lookup(ctx context.Context, id *Identity) (*qrdbtransport.User, error) {
	var notFound *qrdbsdk.UserNotFoundError

	switch id.Metadata[SubjectKindMetadataKey] {
	case SubjectKindUsername:
		u, err := r.users.GetUserByUsername(ctx, id.TenantID, id.Subject)
		if err != nil {
			if errors.As(err, &notFound) {
				return nil, ErrRefreshSubjectNotFound
			}
			return nil, &RefreshUserLookupError{Err: err}
		}
		return u, nil

	case SubjectKindUserHandle:
		uid, ok := decodeWebAuthnHandle(id.Subject)
		if !ok {
			return nil, ErrRefreshSubjectNotFound
		}
		u, err := r.users.GetUser(ctx, uid)
		if err != nil {
			if errors.As(err, &notFound) {
				return nil, ErrRefreshSubjectNotFound
			}
			return nil, &RefreshUserLookupError{Err: err}
		}
		return u, nil

	default:
		return nil, &RefreshSubjectKindError{Kind: id.Metadata[SubjectKindMetadataKey]}
	}
}

// decodeWebAuthnHandle decodes a refresh-token subject as the base64url,
// unpadded, big-endian 8-byte qrdb user handle a WebAuthn login stamps
// (pkg/webauthn.HandleFromUserID), reporting ok=false for anything else.
func decodeWebAuthnHandle(subject string) (id uint64, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(subject)
	if err != nil || len(raw) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(raw), true
}
