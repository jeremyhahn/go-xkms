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

package netguard

import (
	"net"
	"net/http"
	"time"
)

// TransportConfig configures a GuardedTransport. A zero-value field uses
// the same default as the corresponding net.Dialer or http.Transport
// field; a caller that wants a bound (a timeout, an idle-connection limit)
// sets it explicitly.
type TransportConfig struct {
	// Allow reports whether a resolved address may be dialed. Nil refuses
	// every address ReservedAddr classifies as reserved (DenyReserved).
	Allow AllowFunc

	// Resolver resolves target host names. Nil uses net.DefaultResolver.
	// The resolved address is what the Control hook inspects, so a
	// resolver cannot be used to smuggle a refused address past it.
	Resolver *net.Resolver

	// DialTimeout bounds a single connection attempt.
	DialTimeout time.Duration

	// KeepAlive is the dialer's keep-alive probe interval.
	KeepAlive time.Duration

	// TLSHandshakeTimeout bounds the TLS handshake.
	TLSHandshakeTimeout time.Duration

	// ResponseHeaderTimeout bounds the wait for a response's headers.
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout bounds the wait for a "100 Continue" status
	// after a request carrying "Expect: 100-continue".
	ExpectContinueTimeout time.Duration

	// MaxResponseHeaderBytes caps a response's header block.
	MaxResponseHeaderBytes int64

	// MaxIdleConns caps idle connections kept open across requests.
	MaxIdleConns int

	// IdleConnTimeout bounds how long an idle connection is kept open.
	IdleConnTimeout time.Duration

	// ForceAttemptHTTP2 enables HTTP/2 over the guarded dialer.
	ForceAttemptHTTP2 bool
}

// GuardedTransport returns an *http.Transport that dials only addresses
// cfg.Allow accepts, checked in the dialer's Control hook after DNS
// resolution and on every connection -- including a redirect hop, when the
// caller reuses this transport for redirected requests -- so neither a
// hostname that resolves to a refused address nor a DNS-rebound one
// reaches it. It never uses a proxy: a proxy would dial on the caller's
// behalf and bypass the address check.
func GuardedTransport(cfg TransportConfig) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: cfg.KeepAlive,
		Resolver:  cfg.Resolver,
		Control:   DialControl(cfg.Allow),
	}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    cfg.TLSHandshakeTimeout,
		ResponseHeaderTimeout:  cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout:  cfg.ExpectContinueTimeout,
		MaxResponseHeaderBytes: cfg.MaxResponseHeaderBytes,
		MaxIdleConns:           cfg.MaxIdleConns,
		IdleConnTimeout:        cfg.IdleConnTimeout,
		ForceAttemptHTTP2:      cfg.ForceAttemptHTTP2,
	}
}
