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
	"net"

	"golang.org/x/crypto/ssh"

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
