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
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
)

// StaticTokenAuthenticator authenticates a single, per-launch bearer token
// presented over a loopback connection only. It backs the desktop
// standalone ("MS Access") mode: the shell boots the in-process engine on a
// loopback listener and hands the SPA this token, so the local owner is the
// only possible caller. It is deliberately HTTP-only and loopback-gated — it
// must never authenticate a remote request.
type StaticTokenAuthenticator struct {
	token    []byte
	identity Identity
}

// NewStaticTokenAuthenticator constructs an authenticator for the given
// per-launch token. The returned identity template is copied per request.
func NewStaticTokenAuthenticator(token string, identity Identity) *StaticTokenAuthenticator {
	if identity.Metadata == nil {
		identity.Metadata = map[string]string{}
	}
	identity.Metadata["auth_method"] = "loopback-token"
	return &StaticTokenAuthenticator{
		token:    []byte(token),
		identity: identity,
	}
}

// AuthenticateHTTP accepts the request only when it originates on the loopback
// interface and carries the exact bearer token. The token comparison is
// constant-time.
func (a *StaticTokenAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	if !isLoopbackRemote(r.RemoteAddr) {
		return nil, ErrAuthenticationFailed
	}

	const prefix = "Bearer "
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, prefix) {
		return nil, ErrAuthenticationFailed
	}
	presented := []byte(strings.TrimPrefix(authz, prefix))
	if subtle.ConstantTimeCompare(presented, a.token) != 1 {
		return nil, ErrAuthenticationFailed
	}

	return a.cloneIdentity(), nil
}

// AuthenticateGRPC always fails: the loopback token is an HTTP-only credential
// for the embedded desktop engine.
func (a *StaticTokenAuthenticator) AuthenticateGRPC(_ context.Context, _ metadata.MD) (*Identity, error) {
	return nil, ErrAuthenticationFailed
}

// Name returns the authenticator name.
func (a *StaticTokenAuthenticator) Name() string { return "statictoken" }

// cloneIdentity returns a fresh copy of the identity template so a handler
// mutating Metadata cannot corrupt the shared template.
func (a *StaticTokenAuthenticator) cloneIdentity() *Identity {
	md := make(map[string]string, len(a.identity.Metadata))
	for k, v := range a.identity.Metadata {
		md[k] = v
	}
	roles := make([]string, len(a.identity.Roles))
	copy(roles, a.identity.Roles)
	return &Identity{
		Subject:  a.identity.Subject,
		TenantID: a.identity.TenantID,
		Roles:    roles,
		Metadata: md,
	}
}

// isLoopbackRemote reports whether addr (as found on http.Request.RemoteAddr)
// is a loopback address. A malformed address is treated as non-loopback.
func isLoopbackRemote(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}
