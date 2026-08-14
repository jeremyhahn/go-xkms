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

package auth

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"

	"google.golang.org/grpc/metadata"
)

// ErrNoAuthenticator is returned by a LiveAuthenticator that holds no delegate.
//
// Every construction path installs one, so reaching this means a caller built
// the zero value directly. Authenticating is refused rather than allowed: an
// authenticator that cannot decide must not admit the request.
var ErrNoAuthenticator = errors.New("auth: no authenticator configured")

// LiveAuthenticator is an Authenticator whose implementation can be replaced
// while requests are in flight.
//
// It exists because a transport captures its Authenticator once, at
// construction, and a running listener therefore keeps serving with whatever
// authenticator existed when it started. Rebuilding the authenticator on
// SIGHUP had no effect on traffic until the process restarted, so tightening
// auth.* on a live server silently did nothing.
//
// Handing every transport this one value instead solves that without a
// per-transport setter: because it satisfies Authenticator itself, transports
// need no new method, no new field, and no knowledge that reloading exists.
// Store swaps the delegate and every listener picks it up on its next request.
//
// The delegate is published through an atomic.Pointer, so authentication stays
// lock-free on the hot path -- a load per request, with no mutex contention
// between concurrent requests and no writer starvation during a reload.
//
// A request that is already inside the previous delegate's Authenticate call
// finishes against that delegate. The swap is atomic per request, not per
// in-flight call: there is no torn state, and the next request uses the new
// delegate.
//
// The zero value is not usable; call NewLiveAuthenticator.
type LiveAuthenticator struct {
	delegate atomic.Pointer[Authenticator]
}

// Compile-time proof that the holder is itself an Authenticator. This is what
// lets it be substituted for a plain authenticator at every transport
// construction site without touching any of them.
var _ Authenticator = (*LiveAuthenticator)(nil)

// NewLiveAuthenticator returns a holder delegating to a. A nil a is permitted
// so a server can construct the holder before authentication is initialized;
// until Store is called, authentication fails closed with ErrNoAuthenticator.
func NewLiveAuthenticator(a Authenticator) *LiveAuthenticator {
	l := &LiveAuthenticator{}
	l.Store(a)
	return l
}

// Store replaces the delegate. Passing nil clears it, after which
// authentication fails closed rather than admitting callers.
func (l *LiveAuthenticator) Store(a Authenticator) {
	if l == nil {
		return
	}
	if a == nil {
		l.delegate.Store(nil)
		return
	}
	l.delegate.Store(&a)
}

// Load returns the current delegate, or nil when none is installed.
//
// A nil receiver reports no delegate rather than panicking. A holder reaches a
// transport as a non-nil auth.Authenticator interface even when the pointer
// inside it is nil, so a construction-order mistake would otherwise panic on a
// live request; this makes that case fail closed instead.
func (l *LiveAuthenticator) Load() Authenticator {
	if l == nil {
		return nil
	}
	if p := l.delegate.Load(); p != nil {
		return *p
	}
	return nil
}

// AuthenticateHTTP delegates to the current authenticator.
func (l *LiveAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	a := l.Load()
	if a == nil {
		return nil, ErrNoAuthenticator
	}
	return a.AuthenticateHTTP(r)
}

// AuthenticateGRPC delegates to the current authenticator.
func (l *LiveAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	a := l.Load()
	if a == nil {
		return nil, ErrNoAuthenticator
	}
	return a.AuthenticateGRPC(ctx, md)
}

// Name reports the current delegate's name, so logs and audit records name the
// authenticator actually deciding rather than the holder wrapping it.
func (l *LiveAuthenticator) Name() string {
	a := l.Load()
	if a == nil {
		return "none"
	}
	return a.Name()
}
