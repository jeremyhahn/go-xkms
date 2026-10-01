// Copyright (c) 2025-2026 Jeremy Hahn
// Copyright (c) 2025-2026 Automate The Things, LLC
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

// Package urlsafety validates URLs before they are handed to a system URL
// launcher (a browser, xdg-open, macOS open, or Windows
// rundll32/FileProtocolHandler) or treated as a remote OpenID Connect
// endpoint. It is the single place xkey enforces which URL schemes
// untrusted or semi-trusted input may reach a subprocess through, so a
// scheme such as javascript:, file:, or an OS-registered handler scheme
// (ms-msdt:, search-ms:) can never reach exec.Command by way of a
// discovered or attacker-influenced URL.
package urlsafety

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateLaunchURL parses raw and enforces the constraints required
// before handing it to a URL launcher: xdg-open, macOS "open", Windows
// rundll32/FileProtocolHandler, a browser binary, or
// github.com/pkg/browser. It rejects:
//
//   - an empty string;
//   - a leading '-', which a launcher invoked as `execCommand(url)` or with
//     url as a positional argument may parse as a command-line flag rather
//     than a URL;
//   - ASCII control characters;
//   - any scheme other than http or https -- this is what stops
//     javascript:, file:, data:, and OS-specific handler schemes such as
//     ms-msdt: or search-ms: from ever reaching a launcher;
//   - a URL with no host.
//
// Plain http (as opposed to https) is allowed here: at this layer the
// caller already decided to open *some* URL in the user's browser, the
// browser -- not xkey -- owns the decision of whether to warn about a lack
// of transport security, and disallowing http would break the common case
// of an operator deliberately opening an internal, unencrypted intranet
// URL. Callers that reach this validator with a remote, semi-trusted URL
// -- such as an OIDC authorization_endpoint returned by provider discovery
// -- apply a stricter https-only requirement of their own before the URL
// is ever considered for launch; see the oidc package's discovery
// validation, which uses IsLoopbackHost below.
//
// On success it returns the parsed URL. Callers should pass
// u.String() -- not the original raw string -- to the launcher, so that
// any parser normalization (e.g. a lower-cased scheme) is reflected in
// what actually gets executed.
func ValidateLaunchURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, ErrEmptyURL
	}
	if strings.HasPrefix(raw, "-") {
		return nil, ErrLeadingDash
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return nil, ErrControlCharacter
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidURL, Cause: err}
	}

	switch u.Scheme {
	case "http", "https":
	default:
		return nil, &DetailError{Err: ErrDisallowedScheme, Detail: fmt.Sprintf(": %q", u.Scheme)}
	}

	if u.Host == "" {
		return nil, ErrMissingHost
	}

	return u, nil
}

// IsLoopbackHost reports whether host -- a URL authority, optionally
// including a port and, for IPv6, brackets -- refers to the local loopback
// interface: the 127.0.0.0/8 range, ::1, or the literal hostname
// "localhost". It is used to allow plain http for development identity
// providers that are only ever reachable from the same machine.
func IsLoopbackHost(host string) bool {
	h := host
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		h = hostname
	}
	h = strings.Trim(h, "[]")

	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
