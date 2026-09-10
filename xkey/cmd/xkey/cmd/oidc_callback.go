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

package cmd

import (
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// OIDCRedirectURLError reports a redirect URL the callback listener cannot
// serve: it does not parse, or it names neither a port nor a scheme with a
// default port.
type OIDCRedirectURLError struct {
	// URL is the redirect URL.
	URL string
	// Reason says what is wrong with it.
	Reason string
}

// Error implements the error interface.
func (e *OIDCRedirectURLError) Error() string {
	return "oidc: redirect URL " + strconv.Quote(e.URL) + " " + e.Reason
}

// OIDCCallbackHostError reports a configured callback host that cannot serve
// the host the redirect URL sends the browser to.
type OIDCCallbackHostError struct {
	// Host is the configured callback host.
	Host string
	// RedirectHost is the host the browser is sent to.
	RedirectHost string
	// Accepted names the callback hosts that can serve RedirectHost.
	Accepted string
}

// Error implements the error interface.
func (e *OIDCCallbackHostError) Error() string {
	return "oidc: callback host " + strconv.Quote(e.Host) + " cannot serve the redirect host " + e.RedirectHost +
		": set oidc.callback_host (or --callback-host) to " + e.Accepted
}

// OIDCCallbackPortError reports a --callback-port outside 1-65535.
type OIDCCallbackPortError struct {
	// Value is the flag value as given.
	Value string
}

// Error implements the error interface.
func (e *OIDCCallbackPortError) Error() string {
	return "oidc: --callback-port " + strconv.Quote(e.Value) + " must be between 1 and 65535"
}

// loopbackName is the callback host meaning "both loopback families": the
// browser resolves localhost to whichever of 127.0.0.1 and ::1 its resolver
// prefers, so a redirect to localhost is served on both.
const loopbackName = "localhost"

// awsRedirectHost is the host AWS sign-in requires in the redirect URL.
const awsRedirectHost = "127.0.0.1"

// callbackAddr is one address the callback listener binds. An Optional
// address may be unavailable without failing the login: the IPv6 half of
// the loopback pair on a host without IPv6.
type callbackAddr struct {
	Addr     string
	Optional bool
}

// oidcCallback is the resolved local callback listener: the host it binds
// and the port of the default redirect URL.
type oidcCallback struct {
	Host string
	Port int
}

// registerOIDCCallbackFlags defines --callback-host and --callback-port on
// fs. Their zero values mean "from configuration": resolveOIDCCallback only
// honours a flag the user set, so the loaded oidc section stays the default.
func registerOIDCCallbackFlags(fs *pflag.FlagSet) {
	defaults := xkeyconfig.DefaultConfig().OIDC
	fs.String("callback-host", "", "Host the local callback listener binds (default: oidc.callback_host, "+defaults.CallbackHost+")")
	fs.Int("callback-port", 0, "Port of the default redirect URL (default: oidc.callback_port, "+strconv.Itoa(defaults.CallbackPort)+")")
}

// resolveOIDCCallback returns the callback listener for cmd: the loaded
// configuration's oidc section (the built-in defaults when no configuration
// was loaded), overridden by --callback-host and --callback-port when set.
// A --callback-port outside 1-65535 is refused with OIDCCallbackPortError,
// the same bound oidc.callback_port has in the configuration.
func resolveOIDCCallback(cmd *cobra.Command) (oidcCallback, error) {
	section := xkeyconfig.DefaultConfig().OIDC
	if cfg := GetConfig(); cfg != nil {
		section = cfg.OIDC
	}
	callback := oidcCallback{Host: section.CallbackHost, Port: section.CallbackPort}
	if flag := cmd.Flags().Lookup("callback-host"); flag != nil && flag.Changed {
		callback.Host = flag.Value.String()
	}
	if flag := cmd.Flags().Lookup("callback-port"); flag != nil && flag.Changed {
		port, err := strconv.Atoi(flag.Value.String())
		if err != nil || port < 1 || port > 65535 {
			return oidcCallback{}, &OIDCCallbackPortError{Value: flag.Value.String()}
		}
		callback.Port = port
	}
	return callback, nil
}

// redirectHost is the host the default OIDC redirect URL sends the browser
// to: localhost for the loopback pair and for the every-interface host (both
// serve it), and otherwise the callback host itself, so the browser is always
// sent to an address the listener serves.
func (c oidcCallback) redirectHost() string {
	if c.Host == "" || c.Host == loopbackName {
		return loopbackName
	}
	return c.Host
}

// redirectURL is the default OIDC redirect URL: the browser is sent back to
// redirectHost on the callback port.
func (c oidcCallback) redirectURL() string {
	return "http://" + net.JoinHostPort(c.redirectHost(), strconv.Itoa(c.Port)) + "/callback"
}

// awsRedirectURL is the default AWS redirect URL. AWS sign-in requires the
// literal 127.0.0.1 host and the /oauth/callback path; only the port is
// configuration.
func (c oidcCallback) awsRedirectURL() string {
	return "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port)) + "/oauth/callback"
}

// redirectHostPort returns the host and port a redirect URL sends the browser
// to. The callback listener is a plain HTTP server, so only an http URL can
// be served: an https (or other) redirect would have the browser return over
// TLS to a listener that cannot answer, and is refused instead.
func redirectHostPort(redirectURL string) (string, string, error) {
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return "", "", &OIDCRedirectURLError{URL: redirectURL, Reason: "does not parse: " + err.Error()}
	}
	if parsed.Scheme != "http" {
		return "", "", &OIDCRedirectURLError{URL: redirectURL, Reason: "must use http: the callback listener serves plain http"}
	}
	if parsed.Hostname() == "" {
		return "", "", &OIDCRedirectURLError{URL: redirectURL, Reason: "names no host"}
	}
	port := parsed.Port()
	if port == "" {
		port = "80"
	}
	return parsed.Hostname(), port, nil
}

// isLoopbackIP reports whether host is a loopback IP literal.
func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackPair is the two loopback listeners that together serve the name
// localhost, whichever family the browser resolves it to.
func loopbackPair(port string) []callbackAddr {
	return []callbackAddr{
		{Addr: net.JoinHostPort("127.0.0.1", port)},
		{Addr: net.JoinHostPort("::1", port), Optional: true},
	}
}

// listenAddrs returns the addresses the OIDC callback listener binds for
// redirectURL, on the redirect URL's port, and refuses a callback host that
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
func (c oidcCallback) listenAddrs(redirectURL string) ([]callbackAddr, error) {
	host, port, err := redirectHostPort(redirectURL)
	if err != nil {
		return nil, err
	}
	if c.Host == "" {
		return []callbackAddr{{Addr: net.JoinHostPort("", port)}}, nil
	}
	switch {
	case host == loopbackName:
		if c.Host == loopbackName || isLoopbackIP(c.Host) {
			return loopbackPair(port), nil
		}
		return nil, &OIDCCallbackHostError{Host: c.Host, RedirectHost: host, Accepted: loopbackName + ", a loopback address, or empty"}
	case net.ParseIP(host) != nil:
		if c.Host == host || (c.Host == loopbackName && isLoopbackIP(host)) {
			return []callbackAddr{{Addr: net.JoinHostPort(host, port)}}, nil
		}
		return nil, &OIDCCallbackHostError{Host: c.Host, RedirectHost: host, Accepted: host + " or empty"}
	default:
		if c.Host == loopbackName || isLoopbackIP(c.Host) {
			return nil, &OIDCCallbackHostError{Host: c.Host, RedirectHost: host, Accepted: "the address " + host + " resolves to, or empty"}
		}
		return []callbackAddr{{Addr: net.JoinHostPort(c.Host, port)}}, nil
	}
}

// awsListenAddrs returns the addresses the AWS callback listener binds. AWS
// always sends the browser to 127.0.0.1, so the configured host must be able
// to serve it: localhost and 127.0.0.1 bind 127.0.0.1, and an empty host
// binds every interface. Any other host is refused before a browser opens,
// because the redirect would never arrive.
func (c oidcCallback) awsListenAddrs() ([]callbackAddr, error) {
	port := strconv.Itoa(c.Port)
	switch c.Host {
	case loopbackName, awsRedirectHost:
		return []callbackAddr{{Addr: net.JoinHostPort(awsRedirectHost, port)}}, nil
	case "":
		return []callbackAddr{{Addr: net.JoinHostPort("", port)}}, nil
	default:
		return nil, &OIDCCallbackHostError{Host: c.Host, RedirectHost: awsRedirectHost, Accepted: loopbackName + ", " + awsRedirectHost + ", or empty"}
	}
}

// bindCallback opens a listener on every address. A required address that
// cannot be bound fails the whole bind and closes what was opened; an
// optional one is skipped.
func bindCallback(addrs []callbackAddr) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr.Addr)
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

// serveCallback serves handler on every listener with one server, reporting
// the first serve failure on errChan without blocking the others.
func serveCallback(server *http.Server, listeners []net.Listener, errChan chan<- error) {
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
