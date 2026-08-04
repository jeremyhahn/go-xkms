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

package known_hosts

import (
	"context"
	"errors"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// Callback returns an ssh.HostKeyCallback closure that verifies the
// server's host key against the pin in store for (sc, owner, host). The
// hostname argument x/crypto/ssh supplies includes the port (e.g.,
// "example.com:22"); Callback strips it before lookup so pins persist
// per-host, not per-(host, port).
//
// Use the returned closure as ssh.ClientConfig.HostKeyCallback. On any
// lookup or mismatch failure the closure returns a typed error (see
// Verify) which x/crypto/ssh surfaces as an auth-rejected handshake.
//
// The ctx argument is captured by the closure — callers should not
// pass a context that completes before the dial. For session-scoped
// verification wire the same context used by the dialer.
func Callback(ctx context.Context, store Store, sc scope.Scope, owner string) ssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		host := stripPort(hostname)
		return Verify(ctx, store, sc, owner, host, key)
	}
}

// Confirmer decides whether an unpinned host key should be trusted. It is
// invoked by CallbackWithConfirm only when no pin exists for the host — a
// conflicting pin (a *MismatchError from Verify) always hard-fails without
// ever reaching a Confirmer. Implementations typically prompt an operator
// (CLI/GUI) or apply an automated policy (e.g. accept-new).
//
// Returning (true, nil) trusts key for host — CallbackWithConfirm persists
// the pin before the handshake proceeds. Returning (false, nil) rejects the
// connection with *RejectedError. A non-nil err propagates unchanged as the
// handshake failure.
type Confirmer func(ctx context.Context, host string, key ssh.PublicKey) (accept bool, err error)

// CallbackWithConfirm returns an ssh.HostKeyCallback like Callback, but
// layers trust-on-first-use on top: when Verify reports *NotFoundError (no
// pin exists for the host), confirm is consulted instead of failing
// outright. A pin MISMATCH always hard-fails without consulting confirm —
// TOFU covers only the absence of a pin, never a conflicting one (a
// conflicting pin is exactly the MITM signal Verify exists to catch).
//
// confirm == nil reproduces Callback's strict behavior exactly (every
// unpinned host is rejected with *NotFoundError).
//
// On confirm accepting (true, nil), the offered key is persisted via
// store.Add (Source: SourceFirstContact) before the callback returns nil —
// so a concurrent second connection to the same host observes the new pin
// rather than re-prompting. On confirm declining (false, nil), the callback
// returns *RejectedError and no pin is written. Any error confirm returns
// propagates unchanged, and any error from the persisting store.Add also
// propagates (the handshake fails rather than silently leaving the pin
// unwritten).
func CallbackWithConfirm(ctx context.Context, store Store, sc scope.Scope, owner string, confirm Confirmer) ssh.HostKeyCallback {
	if confirm == nil {
		return Callback(ctx, store, sc, owner)
	}
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		host := stripPort(hostname)
		verr := Verify(ctx, store, sc, owner, host, key)
		if verr == nil {
			return nil
		}
		var notFound *NotFoundError
		if !errors.As(verr, &notFound) {
			return verr
		}
		accept, cerr := confirm(ctx, host, key)
		if cerr != nil {
			return cerr
		}
		if !accept {
			return &RejectedError{Host: host, Fingerprint: keys.Fingerprint(key)}
		}
		if aerr := store.Add(ctx, PinFromPublicKey(host, sc, owner, key, SourceFirstContact)); aerr != nil {
			return aerr
		}
		return nil
	}
}

// stripPort removes the ":port" suffix from hostname, returning the
// bare host. Leaves a bracketed IPv6 literal intact (still a bare host
// form). If hostname contains no ':' it is returned unchanged.
func stripPort(hostname string) string {
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		// SplitHostPort rejects inputs without a port; that's not an
		// error for our purposes.
		return hostname
	}
	return host
}
