// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package wire

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestTrustRootClient_Routes proves every method sends its request to the
// route the server registers: the method, the path with the fingerprint
// escaped into it, the purpose query, and the import body.
func TestTrustRootClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := TrustRootClient{Do: rec.do}
	ctx := context.Background()
	root := &transport.TrustRootRequest{Fingerprint: "ab/cd"}

	tests := []struct {
		name   string
		call   func() error
		method string
		path   string
		body   map[string]any
	}{
		{"list", func() error {
			_, err := c.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: "user ca"})
			return err
		}, http.MethodGet, "/api/v1/trust-roots?purpose=user+ca", nil},
		{"list-all", func() error {
			_, err := c.TrustRootList(ctx, &transport.TrustRootListRequest{})
			return err
		}, http.MethodGet, "/api/v1/trust-roots", nil},
		{"get", func() error { _, err := c.TrustRootGet(ctx, root); return err },
			http.MethodGet, "/api/v1/trust-roots/ab%2Fcd", nil},
		{"import", func() error {
			_, err := c.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem", Purpose: "general", Source: "aia"})
			return err
		}, http.MethodPost, "/api/v1/trust-roots", map[string]any{"pem": "pem", "purpose": "general", "source": "aia"}},
		{"quarantine", func() error { _, err := c.TrustRootQuarantine(ctx, root); return err },
			http.MethodPost, "/api/v1/trust-roots/ab%2Fcd/quarantine", nil},
		{"remove", func() error { return c.TrustRootRemove(ctx, root) },
			http.MethodDelete, "/api/v1/trust-roots/ab%2Fcd", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.call())
			got := rec.last()
			assert.Equal(t, tt.method, got.method)
			assert.Equal(t, tt.path, got.path)
			assert.Equal(t, tt.body, got.body)
		})
	}
}

// TestTrustRootClient_DecodesResponses proves each method returns the
// server's response decoded into its transport type.
func TestTrustRootClient_DecodesResponses(t *testing.T) {
	ctx := context.Background()
	client := func(response string) TrustRootClient {
		return TrustRootClient{Do: (&recordingRequester{response: response}).do}
	}
	root := &transport.TrustRootRequest{Fingerprint: "ab"}

	list, err := client(`{"roots":[{"fingerprint":"ab","purpose":"general"}]}`).
		TrustRootList(ctx, &transport.TrustRootListRequest{})
	require.NoError(t, err)
	assert.Equal(t, []transport.TrustRoot{{Fingerprint: "ab", Purpose: "general"}}, list.Roots)

	got, err := client(`{"fingerprint":"ab","pem":"pem"}`).TrustRootGet(ctx, root)
	require.NoError(t, err)
	assert.Equal(t, &transport.TrustRoot{Fingerprint: "ab", PEM: "pem"}, got)

	quarantined, err := client(`{"fingerprint":"ab","purpose":"synced"}`).TrustRootQuarantine(ctx, root)
	require.NoError(t, err)
	assert.Equal(t, &transport.TrustRoot{Fingerprint: "ab", Purpose: "synced"}, quarantined)

	imported, err := client(`{"added":2,"skipped":1}`).
		TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem"})
	require.NoError(t, err)
	assert.Equal(t, &transport.TrustRootImportResponse{Added: 2, Skipped: 1}, imported)
}

// TestTrustRootClient_Errors proves a nil request is refused before any
// request, and a failed request and an undecodable response are returned
// with no result.
func TestTrustRootClient_Errors(t *testing.T) {
	ctx := context.Background()
	failingRec := &recordingRequester{err: errRequestFailed}
	failing := TrustRootClient{Do: failingRec.do}
	garbled := TrustRootClient{Do: (&recordingRequester{response: `{not json`}).do}
	root := &transport.TrustRootRequest{Fingerprint: "ab"}

	type calls struct {
		nilReq, withReq func(TrustRootClient) (any, error)
	}
	for name, call := range map[string]calls{
		"list": {
			func(c TrustRootClient) (any, error) { return c.TrustRootList(ctx, nil) },
			func(c TrustRootClient) (any, error) {
				return c.TrustRootList(ctx, &transport.TrustRootListRequest{})
			},
		},
		"get": {
			func(c TrustRootClient) (any, error) { return c.TrustRootGet(ctx, nil) },
			func(c TrustRootClient) (any, error) { return c.TrustRootGet(ctx, root) },
		},
		"import": {
			func(c TrustRootClient) (any, error) { return c.TrustRootImport(ctx, nil) },
			func(c TrustRootClient) (any, error) {
				return c.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem"})
			},
		},
		"quarantine": {
			func(c TrustRootClient) (any, error) { return c.TrustRootQuarantine(ctx, nil) },
			func(c TrustRootClient) (any, error) { return c.TrustRootQuarantine(ctx, root) },
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(failingRec.requests)
			got, err := call.nilReq(failing)
			assert.ErrorIs(t, err, ErrNilRequest)
			assert.Nil(t, got)
			assert.Len(t, failingRec.requests, before, "a nil request must not be sent")

			got, err = call.withReq(failing)
			assert.ErrorIs(t, err, errRequestFailed)
			assert.Nil(t, got)

			got, err = call.withReq(garbled)
			var decodeErr *DecodeError
			assert.ErrorAs(t, err, &decodeErr)
			assert.Nil(t, got)
		})
	}

	t.Run("remove", func(t *testing.T) {
		assert.ErrorIs(t, failing.TrustRootRemove(ctx, nil), ErrNilRequest)
		assert.ErrorIs(t, failing.TrustRootRemove(ctx, root), errRequestFailed)
	})
}
