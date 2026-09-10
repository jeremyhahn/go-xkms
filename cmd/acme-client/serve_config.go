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

package main

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	acmeclient "github.com/jeremyhahn/go-xkms/pkg/acme/client"
)

// ErrServeConfig indicates a missing or invalid serve command configuration.
type ErrServeConfig struct {
	Detail string
}

// Error returns the error message.
func (e *ErrServeConfig) Error() string {
	return "serve: invalid configuration: " + e.Detail
}

// apiBasePath is the path the client REST API is mounted under. The browser
// UI appends it to the advertised base URL itself, so the base URL never
// carries it.
const apiBasePath = "/api/v1"

// registerServeFlags defines the serve command's flags on fs. It lives
// outside the gui build so the flag set and its precedence are testable
// without a webview toolchain.
func registerServeFlags(fs *pflag.FlagSet) {
	fs.String("addr", ":8443", "Listen address (host:port)")
	fs.String("tls-cert", "", "TLS certificate file path")
	fs.String("tls-key", "", "TLS private key file path")
	fs.Bool("no-tls", false, "Disable TLS (development/testing only)")
	fs.String("api-base-url", "", "Origin the browser UI reaches the API at, without /api/v1 (default: derived from the listen address)")
}

// bindServeFlags binds the serve flags on fs to their viper keys, so each key
// is settable by flag, ACME_CLIENT_SERVE_* environment variable, or config
// file, in that precedence.
func bindServeFlags(fs *pflag.FlagSet) {
	_ = viper.BindPFlag("serve.addr", fs.Lookup("addr"))
	_ = viper.BindPFlag("serve.tls_cert", fs.Lookup("tls-cert"))
	_ = viper.BindPFlag("serve.tls_key", fs.Lookup("tls-key"))
	_ = viper.BindPFlag("serve.no_tls", fs.Lookup("no-tls"))
	_ = viper.BindPFlag("serve.api_base_url", fs.Lookup("api-base-url"))
}

// advertisedAPIBaseURL returns the API base URL injected into the browser UI:
// the origin, or origin plus a mount prefix, that the UI appends apiBasePath
// and the endpoint path to. A configured value (serve.api_base_url) is
// advertised as given, once it parses as an absolute http or https URL, so an
// operator behind a reverse proxy or a public name states exactly what the
// browser should dial; a value that already ends in apiBasePath is refused,
// because the UI would double it. With nothing configured the URL is derived
// from the listen address: a wildcard bind advertises localhost, a named bind
// advertises that name. The bind address is never glued to a literal host.
func advertisedAPIBaseURL(configured string, noTLS bool, addr string) (string, error) {
	if configured != "" {
		parsed, err := url.Parse(configured)
		if err != nil {
			return "", &ErrServeConfig{Detail: "api base URL " + strconv.Quote(configured) + " is not a URL: " + err.Error()}
		}
		if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return "", &ErrServeConfig{Detail: "api base URL must be an absolute http or https URL, got " + strconv.Quote(configured)}
		}
		trimmed := strings.TrimRight(configured, "/")
		if strings.HasSuffix(trimmed, apiBasePath) {
			return "", &ErrServeConfig{Detail: "api base URL " + strconv.Quote(configured) + " must not end in " + apiBasePath + ": the UI appends it"}
		}
		return trimmed, nil
	}

	scheme := "https"
	if noTLS {
		scheme = "http"
	}
	origin, err := acmeclient.AdvertisedURL(scheme, addr)
	if err != nil {
		return "", &ErrServeConfig{Detail: err.Error()}
	}
	return origin, nil
}
