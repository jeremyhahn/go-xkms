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
	"net/netip"
	"syscall"
)

// AllowFunc reports whether a resolved address may be dialed.
type AllowFunc func(netip.Addr) bool

// DenyReserved is an AllowFunc that refuses every address ReservedAddr
// classifies as reserved. It is the default a guarded dialer uses when no
// AllowFunc is given.
func DenyReserved(addr netip.Addr) bool {
	return !ReservedAddr(addr)
}

// AllowAll is an AllowFunc that permits every address. It exists for
// callers whose configuration opts a deployment into reserved targets (for
// example a test lane or a private-network lab), so the opt-in reads as a
// named choice at the call site rather than a nil Control hook.
func AllowAll(netip.Addr) bool {
	return true
}

// AddressNotPermittedError is returned by a guarded dialer, or by a
// redirect check built on CheckDialAddress, when the resolved address is
// not one Allow accepts.
type AddressNotPermittedError struct {
	Address string
}

// Error implements the error interface.
func (e *AddressNotPermittedError) Error() string {
	return "netguard: address not permitted: " + e.Address
}

// CheckDialAddress refuses a dial to address unless allow accepts it.
// address is the resolved "ip:port" a dialer is about to connect to.
func CheckDialAddress(address string, allow AllowFunc) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return &AddressNotPermittedError{Address: address}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return &AddressNotPermittedError{Address: address}
	}
	if !allow(addr.Unmap()) {
		return &AddressNotPermittedError{Address: address}
	}
	return nil
}

// DialControl returns a net.Dialer Control hook that refuses to dial an
// address allow rejects. It runs after DNS resolution, on every connection
// the dialer opens, so a hostname that resolves -- or re-resolves, DNS
// rebinding -- to a refused address is refused rather than reaching it. A
// nil allow defaults to DenyReserved.
func DialControl(allow AllowFunc) func(network, address string, c syscall.RawConn) error {
	if allow == nil {
		allow = DenyReserved
	}
	return func(_, address string, _ syscall.RawConn) error {
		return CheckDialAddress(address, allow)
	}
}
