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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestCORSOptionsValidate pins #2331: the allowed-origin list refuses the
// wildcard and every entry that is not a bare scheme://host[:port] origin.
func TestCORSOptionsValidate(t *testing.T) {
	var nilOpts *CORSOptions
	require.NoError(t, nilOpts.Validate())
	require.NoError(t, (&CORSOptions{}).Validate())
	require.NoError(t, (&CORSOptions{AllowedOrigins: []string{}}).Validate())

	for _, origin := range []string{
		"https://app.example",
		"http://localhost:8080",
		"https://[::1]:8443",
	} {
		t.Run("valid "+origin, func(t *testing.T) {
			require.NoError(t, (&CORSOptions{AllowedOrigins: []string{origin}}).Validate())
		})
	}

	for _, origin := range []string{
		"*",
		"https://*.example",
		"app.example",
		"ftp://app.example",
		"https://app.example/",
		"https://app.example/ui",
		"https://app.example?x=1",
		"https://app.example#f",
		"https://user@app.example",
		"https://",
		"https://app.example:0",
		"https://app.example:99999",
		"https://app.example:",
		"https://[::1]:",
		"https://[not-an-ip]",
		"https://[1.2.3.4]",
		"https://[fe80::1%25eth0]",
		"https://[]",
		"https://::1",
		"https://::1:8443",
		"http://fe80::1",
		"",
	} {
		t.Run("refused "+origin, func(t *testing.T) {
			err := (&CORSOptions{AllowedOrigins: []string{"https://ok.example", origin}}).Validate()
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidCORSOrigin)
			require.Contains(t, err.Error(), `"`+origin+`"`)
		})
	}
}

// TestNewServer_RefusesWildcardCORS pins #2331: NewServer refuses "*".
func TestNewServer_RefusesWildcardCORS(t *testing.T) {
	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends: map[string]xkms.Backend{
			"test": newMockKeyStore(),
		},
		Logger: testLogger(),
		CORS:   &CORSOptions{AllowedOrigins: []string{"*"}},
	}

	server, err := NewServer(cfg)
	require.Error(t, err)
	require.Nil(t, server)
	require.True(t, errors.Is(err, ErrInvalidCORSOrigin))
	require.True(t, strings.Contains(err.Error(), `"*"`))
}
