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

package session

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// DialRequest is the complete set of inputs needed to establish an SSH
// session. The Session returned by Dial assumes ownership of Key — its
// enclave is destroyed when the Session is Closed. Callers must NOT
// Destroy the Key after a successful Dial; callers MUST Destroy it
// themselves on Dial failure (the error return path never takes
// ownership).
type DialRequest struct {
	// Host is the remote hostname or IP address (no port).
	Host string

	// Port is the SSH port. Defaults to 22 if zero.
	Port int

	// User is the remote username. Required.
	User string

	// Key is the authentication key. Required. The Session takes
	// ownership on success.
	Key *keys.Key

	// HostKeyScope and HostKeyOwner locate the pin in KnownHostsStore.
	// Typically the same (scope, owner) as Key, but they may differ
	// (e.g., a shared tenant-scoped host pin used by a user-scoped
	// key).
	HostKeyScope scope.Scope
	HostKeyOwner string

	// KnownHostsStore holds pinned host fingerprints. Required — there
	// is no trust-on-first-use path.
	KnownHostsStore known_hosts.Store

	// Timeout bounds the handshake (TCP dial + SSH handshake). When
	// zero, defaultTimeout is used. The context passed to Dial MAY
	// further shorten this bound.
	Timeout time.Duration
}

// validate returns a *NilInputError for the first missing field.
func (r DialRequest) validate() error {
	if r.Host == "" {
		return &NilInputError{Field: "Host"}
	}
	if r.User == "" {
		return &NilInputError{Field: "User"}
	}
	if r.Key == nil {
		return &NilInputError{Field: "Key"}
	}
	if r.Key.Material == nil {
		return &NilInputError{Field: "Key.Material"}
	}
	if r.KnownHostsStore == nil {
		return &NilInputError{Field: "KnownHostsStore"}
	}
	if !r.HostKeyScope.Valid() {
		return &NilInputError{Field: "HostKeyScope"}
	}
	if r.HostKeyOwner == "" {
		return &NilInputError{Field: "HostKeyOwner"}
	}
	return nil
}

// Dial performs TCP dial + SSH handshake + host-key verification and
// returns a live Session. On any failure path, the Key passed in
// remains the caller's responsibility to Destroy — Dial does not
// consume it until the returned Session's Close is eventually called.
//
// The context governs both the TCP dial and the SSH handshake. If the
// context fires after the handshake completes, Dial returns
// successfully and future Session operations honour the context passed
// to them.
func Dial(ctx context.Context, req DialRequest) (Session, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	port := req.Port
	if port == 0 {
		port = defaultPort
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	addr := net.JoinHostPort(req.Host, fmt.Sprintf("%d", port))

	// Signer is enclave-backed and only reaches plaintext inside a
	// single stack frame per Sign call. See pkg/ssh/keys.Signer.
	signer, err := req.Key.Signer()
	if err != nil {
		return nil, &HandshakeError{Host: req.Host, User: req.User, Err: err}
	}

	hostCallback := known_hosts.Callback(ctx, req.KnownHostsStore, req.HostKeyScope, req.HostKeyOwner)
	cfg := buildClientConfig(req, signer, hostCallback)

	// TCP dial with context. We bound the dial by min(ctx deadline,
	// timeout) so an unresponsive server does not hang beyond timeout.
	dialer := net.Dialer{Timeout: timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &TimeoutError{Host: req.Host, Duration: timeout, Err: ctx.Err()}
		}
		return nil, &DialError{Host: req.Host, Err: err}
	}

	// Set a handshake deadline derived from the smaller of ctx
	// deadline and timeout.
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if derr := netConn.SetDeadline(deadline); derr != nil {
		netConn.Close()
		return nil, &DialError{Host: req.Host, Err: derr}
	}

	sshConn, chans, reqs, hsErr := ssh.NewClientConn(netConn, addr, cfg)
	if hsErr != nil {
		netConn.Close()
		if ctx.Err() != nil {
			return nil, &TimeoutError{Host: req.Host, Duration: timeout, Err: ctx.Err()}
		}
		return nil, &HandshakeError{Host: req.Host, User: req.User, Err: hsErr}
	}

	// Handshake complete — clear the deadline so long-lived channels
	// are not affected by it.
	if derr := netConn.SetDeadline(time.Time{}); derr != nil {
		sshConn.Close()
		return nil, &DialError{Host: req.Host, Err: derr}
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	// Transfer Key ownership to the Session. We register Key.Destroy
	// as a closer so Session.Close destroys the enclave in LIFO order.
	key := req.Key
	s := &session{
		host:    req.Host,
		user:    req.User,
		client:  client,
		closers: []func(){key.Destroy},
	}
	return s, nil
}
