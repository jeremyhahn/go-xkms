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

package urlsafety

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateLaunchURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{name: "javascript scheme rejected", raw: "javascript:alert(1)", wantErr: ErrDisallowedScheme},
		{name: "file scheme rejected", raw: "file:///etc/passwd", wantErr: ErrDisallowedScheme},
		{name: "windows ms-msdt handler rejected", raw: "ms-msdt:/id PCWDiagnostic", wantErr: ErrDisallowedScheme},
		{name: "windows search-ms handler rejected", raw: "search-ms:query=x", wantErr: ErrDisallowedScheme},
		{name: "data scheme rejected", raw: "data:text/html,<script>alert(1)</script>", wantErr: ErrDisallowedScheme},
		{name: "leading dash rejected", raw: "-x", wantErr: ErrLeadingDash},
		{name: "leading dash before scheme rejected", raw: "--url=https://example.com", wantErr: ErrLeadingDash},
		{name: "no host rejected", raw: "https:///path", wantErr: ErrMissingHost},
		{name: "control character rejected", raw: "https://example.com/\x00path", wantErr: ErrControlCharacter},
		{name: "newline injection rejected", raw: "https://example.com/\r\nSet-Cookie: x", wantErr: ErrControlCharacter},
		{name: "empty string rejected", raw: "", wantErr: ErrEmptyURL},
		{
			name: "http on non-loopback host accepted at this layer",
			raw:  "http://evil.example.com",
			// The general launch validator allows plain http: it only
			// forecloses code/file-execution-capable schemes and argument
			// injection. Transport security for remote, semi-trusted URLs
			// (e.g. OIDC discovery) is enforced separately -- see the oidc
			// package, which is the caller that needs the stricter rule.
			wantErr: nil,
		},
		{name: "https accepted", raw: "https://example.com/callback?code=abc", wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateLaunchURL(tt.raw)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tt.raw, got.String())
		})
	}
}

func TestValidateLaunchURL_InvalidURL(t *testing.T) {
	// A control character in the middle of the string is caught by the
	// raw-string scan before url.Parse ever runs, so exercise the parse
	// failure path directly with a string url.Parse itself rejects.
	_, err := ValidateLaunchURL("https://[::1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidURL)
}

func TestValidateLaunchURL_NormalizesScheme(t *testing.T) {
	u, err := ValidateLaunchURL("HTTPS://Example.com/Path")
	require.NoError(t, err)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "https://Example.com/Path", u.String())
}

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "ipv4 loopback", host: "127.0.0.1", want: true},
		{name: "ipv4 loopback with port", host: "127.0.0.1:8080", want: true},
		{name: "ipv4 loopback range", host: "127.5.6.7", want: true},
		{name: "ipv6 loopback", host: "[::1]", want: true},
		{name: "ipv6 loopback with port", host: "[::1]:8080", want: true},
		{name: "localhost literal", host: "localhost", want: true},
		{name: "localhost literal with port", host: "localhost:8080", want: true},
		{name: "localhost mixed case", host: "LocalHost", want: true},
		{name: "remote hostname", host: "example.com", want: false},
		{name: "remote IP", host: "93.184.216.34", want: false},
		{name: "empty host", host: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsLoopbackHost(tt.host))
		})
	}
}
