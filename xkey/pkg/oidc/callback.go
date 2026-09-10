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

package oidc

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

// RedirectURLError reports a redirect URL the callback listener cannot
// serve: it does not parse, or it names neither a port nor a scheme with a
// default port.
type RedirectURLError struct {
	// URL is the redirect URL.
	URL string
	// Reason says what is wrong with it.
	Reason string
}

// Error implements the error interface.
func (e *RedirectURLError) Error() string {
	return "oidc: redirect URL " + strconv.Quote(e.URL) + " " + e.Reason
}

// CallbackHostError reports a configured callback host that cannot serve
// the host the redirect URL sends the browser to.
type CallbackHostError struct {
	// Host is the configured callback host.
	Host string
	// RedirectHost is the host the browser is sent to.
	RedirectHost string
	// Accepted names the callback hosts that can serve RedirectHost.
	Accepted string
}

// Error implements the error interface.
func (e *CallbackHostError) Error() string {
	return "oidc: callback host " + strconv.Quote(e.Host) + " cannot serve the redirect host " + e.RedirectHost +
		": set oidc.callback_host to " + e.Accepted
}

// LoopbackName is the callback host meaning "both loopback families": the
// browser resolves localhost to whichever of 127.0.0.1 and ::1 its resolver
// prefers, so a redirect to localhost is served on both.
const LoopbackName = "localhost"

// AWSRedirectHost is the host AWS sign-in requires in the redirect URL.
const AWSRedirectHost = "127.0.0.1"

// DefaultRedirectPath is the path of the default OIDC redirect URL.
const DefaultRedirectPath = "/callback"

// AWSRedirectPath is the path AWS sign-in requires in the redirect URL.
const AWSRedirectPath = "/oauth/callback"

// Listener is what a callback listener binds and answers: the addresses on
// the redirect URL's port, and the redirect URL's path the handler serves,
// so the browser's return at the registered redirect URI reaches the
// handler whatever path the provider was given.
type Listener struct {
	Addrs []CallbackAddr
	Path  string
}

// CallbackAddr is one address the callback listener binds. An Optional
// address may be unavailable without failing the login: the IPv6 half of
// the loopback pair on a host without IPv6.
type CallbackAddr struct {
	Addr     string
	Optional bool
}

// Callback is the resolved local callback listener: the host it binds
// and the port of the default redirect URL.
type Callback struct {
	Host string
	Port int
}

// RedirectHost is the host the default OIDC redirect URL sends the browser
// to: localhost for the loopback pair and for the every-interface host (both
// serve it), and otherwise the callback host itself, so the browser is always
// sent to an address the listener serves.
func (c Callback) RedirectHost() string {
	if c.Host == "" || c.Host == LoopbackName {
		return LoopbackName
	}
	return c.Host
}

// RedirectURL is the default OIDC redirect URL: the browser is sent back to
// redirectHost on the callback port.
func (c Callback) RedirectURL() string {
	return "http://" + net.JoinHostPort(c.RedirectHost(), strconv.Itoa(c.Port)) + DefaultRedirectPath
}

// AWSRedirectURL is the default AWS redirect URL. AWS sign-in requires the
// literal 127.0.0.1 host and the /oauth/callback path; only the port is
// configuration.
func (c Callback) AWSRedirectURL() string {
	return "http://" + net.JoinHostPort(AWSRedirectHost, strconv.Itoa(c.Port)) + AWSRedirectPath
}

// redirectTarget returns the host, port and path a redirect URL sends the
// browser to (a URL with no path is served at "/"). The callback listener is
// a plain HTTP server, so only an http URL can be served: an https (or other)
// redirect would have the browser return over TLS to a listener that cannot
// answer, and is refused instead.
func redirectTarget(redirectURL string) (host, port, path string, err error) {
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return "", "", "", &RedirectURLError{URL: redirectURL, Reason: "does not parse: " + err.Error()}
	}
	if parsed.Scheme != "http" {
		return "", "", "", &RedirectURLError{URL: redirectURL, Reason: "must use http: the callback listener serves plain http"}
	}
	if parsed.Hostname() == "" {
		return "", "", "", &RedirectURLError{URL: redirectURL, Reason: "names no host"}
	}
	port = parsed.Port()
	if port == "" {
		port = "80"
	}
	path = parsed.Path
	if path == "" {
		path = "/"
	}
	return parsed.Hostname(), port, path, nil
}

// isLoopbackIP reports whether host is a loopback IP literal.
func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// LoopbackPair is the two loopback listeners that together serve the name
// localhost, whichever family the browser resolves it to.
func LoopbackPair(port string) []CallbackAddr {
	return []CallbackAddr{
		{Addr: net.JoinHostPort("127.0.0.1", port)},
		{Addr: net.JoinHostPort("::1", port), Optional: true},
	}
}

// ListenAddrs returns the addresses the OIDC callback listener binds for
// redirectURL, on the redirect URL's port, with the redirect URL's path the
// handler must answer on, and refuses a callback host that
// cannot serve the redirect URL's host, since the browser would then be sent
// where nothing listens and the login would wait out its timeout:
//
//   - an empty callback host binds every interface and serves any redirect;
//   - a redirect to localhost is served by the loopback pair, for a callback
//     host of localhost or a loopback address, and by nothing else;
//   - a redirect to an IP literal is served by that literal, which the
//     callback host must equal (localhost stands in for a loopback literal);
//   - a redirect to any other name is served by the configured address, and
//     a loopback callback host is refused, because loopback cannot answer for
//     a name the browser resolves elsewhere.
func (c Callback) ListenAddrs(redirectURL string) (Listener, error) {
	host, port, path, err := redirectTarget(redirectURL)
	if err != nil {
		return Listener{}, err
	}
	if c.Host == "" {
		return Listener{Addrs: []CallbackAddr{{Addr: net.JoinHostPort("", port)}}, Path: path}, nil
	}
	switch {
	case host == LoopbackName:
		if c.Host == LoopbackName || isLoopbackIP(c.Host) {
			return Listener{Addrs: LoopbackPair(port), Path: path}, nil
		}
		return Listener{}, &CallbackHostError{Host: c.Host, RedirectHost: host, Accepted: LoopbackName + ", a loopback address, or empty"}
	case net.ParseIP(host) != nil:
		if c.Host == host || (c.Host == LoopbackName && isLoopbackIP(host)) {
			return Listener{Addrs: []CallbackAddr{{Addr: net.JoinHostPort(host, port)}}, Path: path}, nil
		}
		return Listener{}, &CallbackHostError{Host: c.Host, RedirectHost: host, Accepted: host + " or empty"}
	default:
		if c.Host == LoopbackName || isLoopbackIP(c.Host) {
			return Listener{}, &CallbackHostError{Host: c.Host, RedirectHost: host, Accepted: "the address " + host + " resolves to, or empty"}
		}
		return Listener{Addrs: []CallbackAddr{{Addr: net.JoinHostPort(c.Host, port)}}, Path: path}, nil
	}
}

// AWSListenAddrs returns the addresses the AWS callback listener binds. AWS
// always sends the browser to 127.0.0.1, so the configured host must be able
// to serve it: localhost and 127.0.0.1 bind 127.0.0.1, and an empty host
// binds every interface. Any other host is refused before a browser opens,
// because the redirect would never arrive.
func (c Callback) AWSListenAddrs() (Listener, error) {
	port := strconv.Itoa(c.Port)
	switch c.Host {
	case LoopbackName, AWSRedirectHost:
		return Listener{Addrs: []CallbackAddr{{Addr: net.JoinHostPort(AWSRedirectHost, port)}}, Path: AWSRedirectPath}, nil
	case "":
		return Listener{Addrs: []CallbackAddr{{Addr: net.JoinHostPort("", port)}}, Path: AWSRedirectPath}, nil
	default:
		return Listener{}, &CallbackHostError{Host: c.Host, RedirectHost: AWSRedirectHost, Accepted: LoopbackName + ", " + AWSRedirectHost + ", or empty"}
	}
}

// BindCallback opens a listener on every address through lc (a zero
// ListenConfig when nil), so a caller can set socket options such as
// SO_REUSEADDR. A required address that
// cannot be bound fails the whole bind and closes what was opened; an
// optional one is skipped.
func BindCallback(ctx context.Context, lc *net.ListenConfig, addrs []CallbackAddr) ([]net.Listener, error) {
	if lc == nil {
		lc = &net.ListenConfig{}
	}
	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		listener, err := lc.Listen(ctx, "tcp", addr.Addr)
		if err != nil {
			if addr.Optional {
				// The IPv6 loopback is absent on this host; the IPv4
				// listener already serves localhost.
				continue
			}
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return nil, err
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

// ServeCallback serves handler on every listener with one server, reporting
// the first serve failure on errChan without blocking the others.
func ServeCallback(server *http.Server, listeners []net.Listener, errChan chan<- error) {
	for _, listener := range listeners {
		go func(listener net.Listener) {
			if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
				select {
				case errChan <- serveErr:
				default:
				}
			}
		}(listener)
	}
}

// ExactPathHandler serves handler only for requests whose path is exactly
// path and answers 404 to everything else. The redirect path comes from a
// saved or flag-supplied redirect URL, and an http.ServeMux pattern would
// read it as a pattern: "{name}" segments become wildcards, a trailing slash
// matches a whole subtree, and invalid wildcard syntax panics at
// registration. The callback handlers act on an "error" query parameter
// before verifying state, so a widened match would let an unrelated
// loopback request end an in-progress login.
func ExactPathHandler(path string, handler http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		handler(w, r)
	})
}
