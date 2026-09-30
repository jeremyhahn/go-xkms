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

// TestKeyVersionClient_Routes proves every method sends its request to the
// route the server registers: the method, the path with the key ID escaped
// into it, the backend query, and the rotate-all body.
func TestKeyVersionClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := KeyVersionClient{Do: rec.do}
	ctx := context.Background()
	version := &transport.KeyVersionRequest{Backend: "soft ware", KeyID: "a b", Version: 3}
	all := &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"}

	tests := []struct {
		name   string
		call   func() error
		method string
		path   string
		body   map[string]any
	}{
		{"list", func() error {
			_, err := c.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
			return err
		}, http.MethodGet, "/api/v1/keys/k/versions?backend=software", nil},
		{"enable", func() error { _, err := c.EnableKeyVersion(ctx, version); return err },
			http.MethodPost, "/api/v1/keys/a%20b/versions/3/enable?backend=soft+ware", nil},
		{"disable", func() error { _, err := c.DisableKeyVersion(ctx, version); return err },
			http.MethodPost, "/api/v1/keys/a%20b/versions/3/disable?backend=soft+ware", nil},
		{"retire", func() error { _, err := c.RetireKeyVersion(ctx, version); return err },
			http.MethodPost, "/api/v1/keys/a%20b/versions/3/retire?backend=soft+ware", nil},
		{"enable-all", func() error { _, err := c.EnableAllKeyVersions(ctx, all); return err },
			http.MethodPost, "/api/v1/keys/k/versions/enable-all?backend=software", nil},
		{"disable-all", func() error { _, err := c.DisableAllKeyVersions(ctx, all); return err },
			http.MethodPost, "/api/v1/keys/k/versions/disable-all?backend=software", nil},
		{"rotate-all", func() error {
			_, err := c.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{TenantID: "acme"})
			return err
		}, http.MethodPost, "/api/v1/keys/rotate-all", map[string]any{"tenant_id": "acme"}},
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

// TestKeyVersionClient_Errors proves a nil request is refused before any
// request, and a failed request and an undecodable response are returned.
func TestKeyVersionClient_Errors(t *testing.T) {
	ctx := context.Background()
	failing := KeyVersionClient{Do: (&recordingRequester{err: errRequestFailed}).do}
	garbled := KeyVersionClient{Do: (&recordingRequester{response: `{not json`}).do}
	version := &transport.KeyVersionRequest{KeyID: "k", Version: 1}
	all := &transport.AllKeyVersionsRequest{KeyID: "k"}

	type calls struct{ nilReq, withReq func(KeyVersionClient) error }
	for name, call := range map[string]calls{
		"list": {
			func(c KeyVersionClient) error { _, err := c.ListKeyVersions(ctx, nil); return err },
			func(c KeyVersionClient) error {
				_, err := c.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{KeyID: "k"})
				return err
			},
		},
		"enable": {
			func(c KeyVersionClient) error { _, err := c.EnableKeyVersion(ctx, nil); return err },
			func(c KeyVersionClient) error { _, err := c.EnableKeyVersion(ctx, version); return err },
		},
		"enable-all": {
			func(c KeyVersionClient) error { _, err := c.EnableAllKeyVersions(ctx, nil); return err },
			func(c KeyVersionClient) error { _, err := c.EnableAllKeyVersions(ctx, all); return err },
		},
		"rotate-all": {
			func(c KeyVersionClient) error { _, err := c.RotateScopeKeys(ctx, nil); return err },
			func(c KeyVersionClient) error {
				_, err := c.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{})
				return err
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call.nilReq(failing), ErrNilRequest)
			assert.ErrorIs(t, call.withReq(failing), errRequestFailed)
			var decodeErr *DecodeError
			assert.ErrorAs(t, call.withReq(garbled), &decodeErr)
		})
	}
}
