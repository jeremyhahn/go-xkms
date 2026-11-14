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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestSigningKeyClient_Routes proves every verb sends its request to the
// route the server registers: the method, the repository query escaped, and
// the binding body.
func TestSigningKeyClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := SigningKeyClient{Do: rec.do}
	ctx := context.Background()

	tests := []struct {
		name   string
		call   func() error
		method string
		path   string
		body   map[string]any
	}{
		{"set", func() error {
			_, err := c.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{Repository: "org/app", KeyID: "k", Backend: "pkcs11"})
			return err
		}, http.MethodPut, "/api/v1/attestation/signing-keys",
			map[string]any{"repository": "org/app", "key_id": "k", "backend": "pkcs11"}},
		{"get", func() error {
			_, err := c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: "org/app"})
			return err
		}, http.MethodGet, "/api/v1/attestation/signing-keys/binding?repository=org%2Fapp", nil},
		{"list", func() error { _, err := c.ListSigningKeyBindings(ctx); return err },
			http.MethodGet, "/api/v1/attestation/signing-keys", nil},
		{"delete", func() error {
			return c.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{Repository: "org/app"})
		}, http.MethodDelete, "/api/v1/attestation/signing-keys/binding?repository=org%2Fapp", nil},
		{"resolve", func() error {
			_, err := c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: "org/app"})
			return err
		}, http.MethodGet, "/api/v1/attestation/signing-keys/resolve?repository=org%2Fapp", nil},
		{"resolve-default", func() error {
			_, err := c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{})
			return err
		}, http.MethodGet, "/api/v1/attestation/signing-keys/resolve", nil},
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

// TestSigningKeyClient_DecodesResponses proves each verb returns the
// server's response decoded into its transport type.
func TestSigningKeyClient_DecodesResponses(t *testing.T) {
	ctx := context.Background()
	client := func(response string) SigningKeyClient {
		return SigningKeyClient{Do: (&recordingRequester{response: response}).do}
	}
	binding := `{"repository":"org/app","key_id":"k","backend":"pkcs11","updated_at":"2026-01-02T03:04:05Z"}`
	want := &transport.SigningKeyBinding{
		Repository: "org/app", KeyID: "k", Backend: "pkcs11",
		UpdatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	set, err := client(binding).SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{})
	require.NoError(t, err)
	assert.Equal(t, want, set)

	got, err := client(binding).GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{})
	require.NoError(t, err)
	assert.Equal(t, want, got)

	list, err := client(`{"bindings":[` + binding + `]}`).ListSigningKeyBindings(ctx)
	require.NoError(t, err)
	assert.Equal(t, []*transport.SigningKeyBinding{want}, list.Bindings)

	resolved, err := client(`{"repository":"org/app","key_id":"release","default":true}`).
		ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{})
	require.NoError(t, err)
	assert.Equal(t, &transport.SigningKeyResolution{Repository: "org/app", KeyID: "release", Default: true}, resolved)
}

// TestSigningKeyClient_Errors proves a nil request is refused before any
// request, and a failed request and an undecodable response are returned
// with no result.
func TestSigningKeyClient_Errors(t *testing.T) {
	ctx := context.Background()
	failingRec := &recordingRequester{err: errRequestFailed}
	failing := SigningKeyClient{Do: failingRec.do}
	garbled := SigningKeyClient{Do: (&recordingRequester{response: `{not json`}).do}

	type calls struct {
		nilReq, withReq func(SigningKeyClient) (any, error)
	}
	for name, call := range map[string]calls{
		"set": {
			func(c SigningKeyClient) (any, error) { return c.SetSigningKeyBinding(ctx, nil) },
			func(c SigningKeyClient) (any, error) {
				return c.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{})
			},
		},
		"get": {
			func(c SigningKeyClient) (any, error) { return c.GetSigningKeyBinding(ctx, nil) },
			func(c SigningKeyClient) (any, error) {
				return c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{})
			},
		},
		"resolve": {
			func(c SigningKeyClient) (any, error) { return c.ResolveSigningKey(ctx, nil) },
			func(c SigningKeyClient) (any, error) {
				return c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{})
			},
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

	t.Run("list", func(t *testing.T) {
		got, err := failing.ListSigningKeyBindings(ctx)
		assert.ErrorIs(t, err, errRequestFailed)
		assert.Nil(t, got)

		got, err = garbled.ListSigningKeyBindings(ctx)
		var decodeErr *DecodeError
		assert.ErrorAs(t, err, &decodeErr)
		assert.Nil(t, got)
	})

	t.Run("delete", func(t *testing.T) {
		assert.ErrorIs(t, failing.DeleteSigningKeyBinding(ctx, nil), ErrNilRequest)
		assert.ErrorIs(t, failing.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{}), errRequestFailed)
	})
}
