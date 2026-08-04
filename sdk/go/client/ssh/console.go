// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

import (
	"context"
	"net/http"

	gossh "golang.org/x/crypto/ssh"

	pkgconsole "github.com/jeremyhahn/go-xkms/pkg/ssh/console"
	pkgscope "github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// ConsoleSession is an interactive SSH PTY session: an io.ReadWriteCloser whose
// Read drains terminal output and Write feeds keystrokes, plus Resize. It backs
// an embedded terminal (xterm.js) in the browser, bridged over a WebSocket or a
// gRPC stream.
type ConsoleSession = pkgconsole.Console

// ConsoleConfig tunes the PTY (term, rows, cols, env).
type ConsoleConfig = pkgconsole.Config

// ConsoleTarget is a resolved console connection. SDK consumers build it with a
// STRING scope so they never import pkg/ssh/scope.
type ConsoleTarget struct {
	Host   string
	Port   int
	User   string
	Signer gossh.Signer

	// Signers are additional candidate signers offered alongside Signer
	// during public-key authentication, in order — the way the OpenSSH
	// client offers every agent/identity key until the server accepts
	// one. At least one of Signer/Signers must be set.
	Signers []gossh.Signer

	HostKeys HostKeyStore
	Scope    string // "tenant" | "user" | "service"; defaults to "user"
	Owner    string
	Config   ConsoleConfig

	// HostKeyPolicy selects how an unpinned host key is handled:
	// "" or "yes" = strict (fail, today's behavior), "ask" = pause the
	// handshake for an interactive hostkey/hostkey-response WebSocket
	// round trip, "accept-new" = auto-accept first contact and emit an
	// informational notify frame. A pin MISMATCH always fails
	// regardless of policy.
	HostKeyPolicy string

	// KnownHostsExtraFiles are additional OpenSSH known_hosts files
	// (e.g. ~/.ssh/known_hosts) consulted as a trust source and
	// mirrored to on accepted first contact.
	KnownHostsExtraFiles []string

	// KnownHostsSkipStore skips the pin store entirely ("system"-only
	// known-hosts policy): trust decisions rely on
	// KnownHostsExtraFiles alone.
	KnownHostsSkipStore bool
}

// ConsoleResolver authenticates/authorizes a console request and maps it to a
// ConsoleTarget. Implemented by the host app (xkey loopback, xkms REST,
// go-trusted-platform).
type ConsoleResolver interface {
	ResolveConsoleTarget(r *http.Request) (*ConsoleTarget, error)
}

// ConsoleResolverFunc adapts a function to ConsoleResolver.
type ConsoleResolverFunc func(r *http.Request) (*ConsoleTarget, error)

// ResolveConsoleTarget calls f.
func (f ConsoleResolverFunc) ResolveConsoleTarget(r *http.Request) (*ConsoleTarget, error) {
	return f(r)
}

// WithConsoleCheckOrigin sets the WebSocket Origin check on the handler.
var WithConsoleCheckOrigin = pkgconsole.WithCheckOrigin

// WithConsoleDialTimeout bounds the SSH dial for the bridge.
var WithConsoleDialTimeout = pkgconsole.WithDialTimeout

// WithConsoleHostKeyConfirmTimeout bounds how long the handler waits for the
// client's hostkey-response when HostKeyPolicy is "ask". Default 60s.
var WithConsoleHostKeyConfirmTimeout = pkgconsole.WithHostKeyConfirmTimeout

// NewConsoleWSHandler returns the reusable WebSocket↔SSH-console bridge handler.
// Mount it on any HTTP server (xkey's loopback server, the xkms REST router, a
// consuming web app). The resolver supplies host/port/user + a signer + the
// host-key store from the authenticated request, using string scopes.
func NewConsoleWSHandler(resolver ConsoleResolver, opts ...pkgconsole.HandlerOption) http.Handler {
	return pkgconsole.NewWSHandler(pkgconsole.ResolverFunc(func(r *http.Request) (*pkgconsole.Target, error) {
		t, err := resolver.ResolveConsoleTarget(r)
		if err != nil {
			return nil, err
		}
		sc := pkgscope.User
		if t.Scope != "" {
			parsed, perr := pkgscope.Parse(t.Scope)
			if perr != nil {
				return nil, &InvalidScopeError{Value: t.Scope}
			}
			sc = parsed
		}
		return &pkgconsole.Target{
			Host:                 t.Host,
			Port:                 t.Port,
			User:                 t.User,
			Signer:               t.Signer,
			Signers:              t.Signers,
			KnownHosts:           t.HostKeys,
			HostKeyScope:         sc,
			HostKeyOwner:         t.Owner,
			Config:               t.Config,
			HostKeyPolicy:        t.HostKeyPolicy,
			KnownHostsExtraFiles: t.KnownHostsExtraFiles,
			KnownHostsSkipStore:  t.KnownHostsSkipStore,
		}, nil
	}), opts...)
}

// ConsoleRequest identifies a console connection target for OpenConsole.
type ConsoleRequest struct {
	Host     string
	Port     int
	User     string
	HostKeys HostKeyStore
	Scope    string
	Owner    string
}

// OpenConsole opens an interactive console in-process (the embedded transport):
// it verifies the host against the pin store and returns a live ConsoleSession.
// signer is resolved by the caller via Client.Keys().Signer (so hardware keys
// never export material). Remote transports expose the same capability over
// their streaming channel.
func OpenConsole(ctx context.Context, signer gossh.Signer, req ConsoleRequest, cfg ConsoleConfig) (ConsoleSession, error) {
	if signer == nil {
		return nil, &NilInputError{Field: "signer"}
	}
	if req.HostKeys == nil {
		return nil, &NilInputError{Field: "HostKeys"}
	}
	sc := pkgscope.User
	if req.Scope != "" {
		parsed, err := pkgscope.Parse(req.Scope)
		if err != nil {
			return nil, &InvalidScopeError{Value: req.Scope}
		}
		sc = parsed
	}
	return pkgconsole.Dial(ctx, pkgconsole.DialRequest{
		Host:         req.Host,
		Port:         req.Port,
		User:         req.User,
		Signer:       signer,
		KnownHosts:   req.HostKeys,
		HostKeyScope: sc,
		HostKeyOwner: req.Owner,
	}, cfg)
}

// OpenConsoleWithSigners opens an interactive console offering an ordered
// list of candidate signers during public-key authentication — the way the
// OpenSSH client offers every agent/identity key until the server accepts
// one (see ResolveLocalSigners). Otherwise identical to OpenConsole.
func OpenConsoleWithSigners(ctx context.Context, signers []gossh.Signer, req ConsoleRequest, cfg ConsoleConfig) (ConsoleSession, error) {
	if len(signers) == 0 {
		return nil, &NilInputError{Field: "signers"}
	}
	if req.HostKeys == nil {
		return nil, &NilInputError{Field: "HostKeys"}
	}
	sc := pkgscope.User
	if req.Scope != "" {
		parsed, err := pkgscope.Parse(req.Scope)
		if err != nil {
			return nil, &InvalidScopeError{Value: req.Scope}
		}
		sc = parsed
	}
	return pkgconsole.Dial(ctx, pkgconsole.DialRequest{
		Host:         req.Host,
		Port:         req.Port,
		User:         req.User,
		Signers:      signers,
		KnownHosts:   req.HostKeys,
		HostKeyScope: sc,
		HostKeyOwner: req.Owner,
	}, cfg)
}
