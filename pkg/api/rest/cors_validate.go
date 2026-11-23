// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package rest

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Validate checks every AllowedOrigins entry (#2331). An entry must be a
// bare origin: scheme http or https, a non-empty host without "*", an
// optional port in 1-65535, and no user info, path (not even "/"), query or
// fragment. The wildcard "*" is refused: the CORS policy covers routes that
// carry WebAuthn ceremonies and credentials. Nil options and an empty list
// are valid (CORS disabled). Errors wrap ErrInvalidCORSOrigin and name the
// entry.
func (o *CORSOptions) Validate() error {
	if o == nil {
		return nil
	}
	for _, origin := range o.AllowedOrigins {
		if err := validateCORSOrigin(origin); err != nil {
			return err
		}
	}
	return nil
}

func validateCORSOrigin(origin string) error {
	refuse := func(reason string) error {
		return fmt.Errorf("%w %q: %s", ErrInvalidCORSOrigin, origin, reason)
	}
	if origin == "*" {
		return refuse("no wildcard origin is allowed on routes that carry WebAuthn or credentials; list each origin")
	}
	if origin == "" {
		return refuse("empty origin")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return refuse("not a URL: " + err.Error())
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return refuse("scheme must be http or https")
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return refuse("host is required (scheme://host[:port])")
	}
	if strings.Contains(u.Host, "*") {
		return refuse("no wildcard is allowed in the host")
	}
	if u.User != nil {
		return refuse("user info is not allowed")
	}
	if u.Path != "" || u.RawPath != "" {
		return refuse("path is not allowed (not even \"/\")")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return refuse("query is not allowed")
	}
	if u.Fragment != "" || strings.Contains(origin, "#") {
		return refuse("fragment is not allowed")
	}
	if strings.HasPrefix(u.Host, "[") {
		// A bracketed host is an IPv6 literal: url.Parse does not check it.
		// Browsers send no zone and no IPv4 in brackets.
		ip := net.ParseIP(u.Hostname())
		if ip == nil || ip.To4() != nil || strings.Contains(u.Host, "%") {
			return refuse("bracketed host must be an IPv6 literal")
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return refuse("port must be 1-65535 (empty port after \":\")")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return refuse("port must be 1-65535")
		}
	}
	if origin != u.Scheme+"://"+strings.ToLower(u.Host) {
		return refuse("must be the exact lowercase scheme://host[:port] a browser sends")
	}
	return nil
}
