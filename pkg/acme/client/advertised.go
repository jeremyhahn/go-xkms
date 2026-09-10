// Copyright (C) 2026 Jeremy Hahn
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package client

import (
	"errors"
	"net"
	"strconv"
)

// ErrAdvertisedURLMissingPort is the cause carried by an AdvertisedURLError
// when the listen address names no port.
var ErrAdvertisedURLMissingPort = errors.New("listen address has no port")

// AdvertisedURLError reports a listen address from which no URL can be
// advertised.
type AdvertisedURLError struct {
	// ListenAddr is the address that could not be turned into a URL.
	ListenAddr string
	// Err is the cause.
	Err error
}

// Error implements the error interface.
func (e *AdvertisedURLError) Error() string {
	return "acme: cannot derive an advertised URL from listen address " +
		strconv.Quote(e.ListenAddr) + ": " + e.Err.Error()
}

// Unwrap returns the cause.
func (e *AdvertisedURLError) Unwrap() error {
	return e.Err
}

// AdvertisedURL derives the origin a listener advertises when the operator has
// configured none. The listen address is split into host and port, so a bare
// port, an IPv6 literal, and a host:port pair all derive correctly. A wildcard
// host (empty, 0.0.0.0, or ::) advertises localhost, because a wildcard is not
// an address a client can reach; any other host is advertised as bound. The
// result carries no path.
func AdvertisedURL(scheme, listenAddr string) (string, error) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", &AdvertisedURLError{ListenAddr: listenAddr, Err: err}
	}
	if port == "" {
		return "", &AdvertisedURLError{ListenAddr: listenAddr, Err: ErrAdvertisedURLMissingPort}
	}
	if host == "" || isUnspecifiedIP(host) {
		host = "localhost"
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

// isUnspecifiedIP reports whether host is the IPv4 or IPv6 wildcard address.
func isUnspecifiedIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
