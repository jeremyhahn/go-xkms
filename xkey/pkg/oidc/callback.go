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
	"bytes"
	"context"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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

// CallbackPageContentSecurityPolicy is the Content-Security-Policy of every
// page a callback listener shows the browser: the page loads nothing and
// runs nothing, and only its inline style is allowed.
const CallbackPageContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'"

// CallbackPage is the page a callback listener shows the browser once the
// provider has redirected back. Title and Message are plain text: the
// callback's error and error_description parameters are request input that
// anyone able to steer the browser to the loopback URL controls, so they
// are only ever rendered through callbackPageTemplate, which escapes them.
type CallbackPage struct {
	Title   string
	Message string
}

// callbackPageTemplate is contextually escaped by html/template, so no
// field of a CallbackPage can become markup or script.
var callbackPageTemplate = template.Must(template.New("callback").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{{.Title}}</title></head>
<body><h1>{{.Title}}</h1>{{if .Message}}<p>{{.Message}}</p>{{end}}</body></html>
`))

// CallbackPageError reports a callback page that could not be rendered or
// written to the browser.
type CallbackPageError struct {
	// Cause is the template or write failure.
	Cause error
}

// Error implements the error interface.
func (e *CallbackPageError) Error() string {
	return "oidc: callback page: " + e.Cause.Error()
}

// Unwrap returns the underlying failure.
func (e *CallbackPageError) Unwrap() error {
	return e.Cause
}

// WriteCallbackPage renders page, escaped, to w with the headers that keep
// the loopback origin inert: an explicit UTF-8 HTML content type with
// sniffing disabled, a Content-Security-Policy that forbids every script and
// resource, and no Referer, so the callback URL (which carries the
// authorization code) is never sent on. The page is rendered before any
// header is written, so a rendering failure leaves the response untouched.
func WriteCallbackPage(w http.ResponseWriter, page CallbackPage) error {
	var body bytes.Buffer
	if err := callbackPageTemplate.Execute(&body, page); err != nil {
		return &CallbackPageError{Cause: err}
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", CallbackPageContentSecurityPolicy)
	header.Set("Referrer-Policy", "no-referrer")
	if _, err := w.Write(body.Bytes()); err != nil {
		return &CallbackPageError{Cause: err}
	}
	return nil
}

// MaxProviderTextLen bounds, in bytes, the text SanitizeProviderText
// returns, truncation marker included.
const MaxProviderTextLen = 512

// ProviderTextTruncated is appended to provider text that
// SanitizeProviderText cut short to fit MaxProviderTextLen.
const ProviderTextTruncated = "...[truncated]"

// C1 controls that introduce a sequence rather than standing alone.
const (
	c1DCS = 0x90 // device control string
	c1SOS = 0x98 // start of string
	c1CSI = 0x9b // control sequence introducer
	c1ST  = 0x9c // string terminator
	c1OSC = 0x9d // operating system command
	c1PM  = 0x9e // privacy message
	c1APC = 0x9f // application program command
)

// SanitizeProviderText makes text an identity provider controls safe to
// print to a terminal or write to a log: the callback's error and
// error_description parameters, token-endpoint error codes and
// descriptions, and ID-token claims. A hostile or compromised provider can
// otherwise send escape sequences that rewrite the screen, spoof a prompt,
// or set the clipboard (OSC 52).
//
// Every ESC-introduced sequence (CSI, OSC, DCS, SOS, PM, APC and the short
// forms) and its 8-bit C1 equivalent is removed whole, parameters and
// payload included. Tab, line feed, vertical tab, form feed, carriage
// return, NEL and the Unicode line and paragraph separators become a
// space, so a provider cannot forge a new log line; every other C0 or C1
// control, DEL, and every Unicode bidirectional formatting character is
// dropped. A byte that is not valid UTF-8 becomes U+FFFD, except a lone
// byte in 0x80-0x9F, which a terminal in an 8-bit locale reads as a C1
// control and is treated as one. The result is at most MaxProviderTextLen
// bytes; longer text is cut on a rune boundary and ends with
// ProviderTextTruncated.
func SanitizeProviderText(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) && b.Len() <= MaxProviderTextLen {
		r, size := decodeProviderRune(s, i)
		i += size
		switch {
		case r == 0x1b:
			i = skipEscape(s, i)
		case r == c1CSI:
			i = skipControlSequence(s, i)
		case r == c1DCS || r == c1SOS || r == c1OSC || r == c1PM || r == c1APC:
			i = skipControlString(s, i)
		case isLineBreakOrTab(r):
			b.WriteByte(' ')
		case unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r):
			// Dropped: a lone control or a bidi override.
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) <= MaxProviderTextLen {
		return out
	}
	cut := MaxProviderTextLen - len(ProviderTextTruncated)
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return out[:cut] + ProviderTextTruncated
}

// decodeProviderRune decodes the rune at s[i]. A lone byte in 0x80-0x9F
// decodes to the C1 control of the same value, so the 8-bit form of a
// control sequence is recognised as one; any other invalid byte decodes to
// U+FFFD.
func decodeProviderRune(s string, i int) (rune, int) {
	r, size := utf8.DecodeRuneInString(s[i:])
	if r == utf8.RuneError && size == 1 && s[i] >= 0x80 && s[i] <= 0x9f {
		return rune(s[i]), 1
	}
	return r, size
}

// isLineBreakOrTab reports whether r moves the cursor to another column or
// line: SanitizeProviderText turns it into a space.
func isLineBreakOrTab(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// skipEscape returns the index just past the escape sequence whose ESC
// ended at s[i]: a CSI, a control string, an nF sequence (intermediates and
// a final byte), or a single Fp, Fe or Fs byte. An ESC followed by anything
// else is dropped alone.
func skipEscape(s string, i int) int {
	if i >= len(s) {
		return i
	}
	switch c := s[i]; {
	case c == '[':
		return skipControlSequence(s, i+1)
	case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_':
		return skipControlString(s, i+1)
	case c >= 0x20 && c <= 0x2f:
		for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
			i++
		}
		if i < len(s) && s[i] >= 0x30 && s[i] <= 0x7e {
			i++
		}
		return i
	case c >= 0x30 && c <= 0x7e:
		return i + 1
	}
	return i
}

// skipControlSequence returns the index just past the CSI sequence whose
// introducer ended at s[i]: its parameter and intermediate bytes and its
// final byte. A byte outside the sequence grammar ends it early and is
// sanitised on its own.
func skipControlSequence(s string, i int) int {
	for i < len(s) && s[i] >= 0x20 && s[i] <= 0x3f {
		i++
	}
	if i < len(s) && s[i] >= 0x40 && s[i] <= 0x7e {
		i++
	}
	return i
}

// skipControlString returns the index just past the OSC, DCS, SOS, PM or
// APC string whose introducer ended at s[i]. The string runs to BEL or ST;
// an ESC ends it without being consumed, so ESC \ (the 7-bit ST) and any
// sequence the ESC starts are removed by the caller. An unterminated string
// runs to the end of s.
func skipControlString(s string, i int) int {
	for i < len(s) {
		r, size := decodeProviderRune(s, i)
		switch r {
		case 0x07, c1ST:
			return i + size
		case 0x1b:
			return i
		}
		i += size
	}
	return i
}
