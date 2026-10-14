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

// credential_list_paths_test.go pins credential list's JSON rendering and
// the failures it reports before any response is read.
package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withCredentialServer points the global config at server and replaces the
// HTTP client factory for the duration of the test.
func withCredentialServer(t *testing.T, server, format string, factory func(*Config) (*http.Client, error)) {
	t.Helper()
	oldConfig, oldFactory := globalConfig, serverHTTPClientFactory
	t.Cleanup(func() { globalConfig, serverHTTPClientFactory = oldConfig, oldFactory })
	globalConfig = &Config{Server: server, OutputFormat: format}
	serverHTTPClientFactory = factory
}

func TestRunCredentialList_JSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"names":["aws-kms-key"]}`))
	}))
	t.Cleanup(server.Close)
	withCredentialServer(t, server.URL, "json", func(*Config) (*http.Client, error) { return server.Client(), nil })

	var runErr error
	out := captureStdout(t, func() { runErr = runCredentialList(credentialListCmd, nil) })
	require.NoError(t, runErr)
	assert.Equal(t, []any{"aws-kms-key"}, lastJSONObject(t, out)["names"])
}

func TestRunCredentialList_RefusesBeforeResponse(t *testing.T) {
	cases := []struct {
		name    string
		factory func(*Config) (*http.Client, error)
		want    error
	}{
		{"no mTLS certificate", nil, ErrCertFileRead},
		{"client factory failure", func(*Config) (*http.Client, error) { return nil, errUserExtBoom }, errUserExtBoom},
		// Port 1 on loopback refuses the connection without real network access.
		{"unreachable server", func(*Config) (*http.Client, error) { return &http.Client{}, nil }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCredentialServer(t, "http://127.0.0.1:1", "text", tc.factory)

			var runErr error
			out := captureStdout(t, func() { runErr = runCredentialList(credentialListCmd, nil) })
			require.Error(t, runErr)
			if tc.want != nil {
				assert.True(t, errors.Is(runErr, tc.want), "got %v", runErr)
			}
			assert.Empty(t, out)
		})
	}
}
