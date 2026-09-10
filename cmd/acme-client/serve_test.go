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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// TestAdvertisedAPIBaseURL_DerivedFromListenAddress proves that with nothing
// configured the advertised URL is the origin derived from the listen
// address: a wildcard bind advertises localhost, a named or literal bind
// advertises itself, the scheme follows --no-tls, and the API path is left to
// the UI, which appends it (#140, item 11).
func TestAdvertisedAPIBaseURL_DerivedFromListenAddress(t *testing.T) {
	cases := []struct {
		name  string
		addr  string
		noTLS bool
		want  string
	}{
		{"bare port", ":8443", false, "https://localhost:8443"},
		{"ipv4 wildcard from the command's own example", "0.0.0.0:9443", false, "https://localhost:9443"},
		{"ipv6 wildcard without tls", "[::]:8080", true, "http://localhost:8080"},
		{"loopback without tls", "127.0.0.1:8080", true, "http://127.0.0.1:8080"},
		{"hostname", "acme.example.com:8443", false, "https://acme.example.com:8443"},
		{"ipv6 literal", "[fd00::1]:8443", false, "https://[fd00::1]:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := advertisedAPIBaseURL("", tc.noTLS, tc.addr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("advertised %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAdvertisedAPIBaseURL_ConfiguredValueIsAdvertisedVerbatim proves that a
// configured URL wins over the listen address and is passed through as
// given (minus a trailing slash), so a reverse-proxied prefix survives.
func TestAdvertisedAPIBaseURL_ConfiguredValueIsAdvertisedVerbatim(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		want       string
	}{
		{"public name", "https://acme.example.com:9443", "https://acme.example.com:9443"},
		{"proxied prefix with trailing slash", "https://acme.example.com/acme-client/", "https://acme.example.com/acme-client"},
		{"plain http", "http://acme.internal:8080", "http://acme.internal:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := advertisedAPIBaseURL(tc.configured, false, "0.0.0.0:1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("advertised %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAdvertisedAPIBaseURL_RejectsBadInput proves that a configured value
// that is not an absolute http(s) URL, one that already ends in the API path
// the UI appends, and a listen address no client could dial, are refused
// with ErrServeConfig instead of being advertised.
func TestAdvertisedAPIBaseURL_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		addr       string
	}{
		{"configured without scheme", "acme.example.com", ":8443"},
		{"configured with a non-http scheme", "ftp://acme.example.com", ":8443"},
		{"configured without host", "https:///acme-client", ":8443"},
		{"configured unparsable", "https://acme.example.com:bad port", ":8443"},
		{"configured with the api path the UI appends", "https://acme.example.com:9443/api/v1", ":8443"},
		{"configured with the api path and a trailing slash", "https://acme.example.com/acme-client/api/v1/", ":8443"},
		{"derived from an address without a port", "", "8443"},
		{"derived from an empty address", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := advertisedAPIBaseURL(tc.configured, false, tc.addr)
			if err == nil {
				t.Fatalf("expected an error, advertised %q", got)
			}
			var cfgErr *ErrServeConfig
			if !errors.As(err, &cfgErr) {
				t.Fatalf("expected *ErrServeConfig, got %T: %v", err, err)
			}
			if got != "" {
				t.Fatalf("expected no URL on error, got %q", got)
			}
		})
	}
}

// initServeViper rebuilds the viper state the serve command sees: defaults,
// a fresh serve flag set bound to viper, the ACME_CLIENT_ environment prefix,
// and the config file. The returned flag set is the one a --flag lands on.
func initServeViper(t *testing.T, configPath string) *pflag.FlagSet {
	t.Helper()
	viper.Reset()
	setDefaults()
	fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	registerServeFlags(fs)
	bindServeFlags(fs)
	viper.SetEnvPrefix("ACME_CLIENT")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()
	if configPath != "" {
		viper.SetConfigFile(configPath)
		if err := viper.ReadInConfig(); err != nil {
			t.Fatalf("reading config: %v", err)
		}
	}
	return fs
}

// TestServeAPIBaseURL_Precedence proves that serve.api_base_url is settable
// by config file, environment variable and flag, in that precedence, and
// that with none of them set the value is empty so the URL is derived.
func TestServeAPIBaseURL_Precedence(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
		setDefaults()
	})
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("serve:\n  api_base_url: https://file.example.com\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	t.Run("default is empty so the url is derived", func(t *testing.T) {
		initServeViper(t, "")
		if got := viper.GetString("serve.api_base_url"); got != "" {
			t.Fatalf("expected no default, got %q", got)
		}
		got, err := advertisedAPIBaseURL(viper.GetString("serve.api_base_url"), false, viper.GetString("serve.addr"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "https://localhost:8443" {
			t.Fatalf("derived %q", got)
		}
	})

	t.Run("config file", func(t *testing.T) {
		initServeViper(t, configPath)
		if got := viper.GetString("serve.api_base_url"); got != "https://file.example.com" {
			t.Fatalf("file value not read, got %q", got)
		}
	})

	t.Run("environment over config file", func(t *testing.T) {
		t.Setenv("ACME_CLIENT_SERVE_API_BASE_URL", "https://env.example.com")
		initServeViper(t, configPath)
		if got := viper.GetString("serve.api_base_url"); got != "https://env.example.com" {
			t.Fatalf("environment did not win, got %q", got)
		}
	})

	t.Run("flag over environment", func(t *testing.T) {
		t.Setenv("ACME_CLIENT_SERVE_API_BASE_URL", "https://env.example.com")
		fs := initServeViper(t, configPath)
		if err := fs.Set("api-base-url", "https://flag.example.com"); err != nil {
			t.Fatalf("setting flag: %v", err)
		}
		if got := viper.GetString("serve.api_base_url"); got != "https://flag.example.com" {
			t.Fatalf("flag did not win, got %q", got)
		}
	})
}
