// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package wire

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestPasswordVaultClient_Routes proves every method sends its request to the
// route the server registers: the method, the path (with the factor ID
// escaped into it) and the body, whose byte fields are base64 in JSON.
func TestPasswordVaultClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := PasswordVaultClient{Do: rec.do}
	ctx := context.Background()
	cred := transport.PasswordVaultCredential{Factor: "passkey", CredentialID: []byte("id"), Secret: []byte("s"), Label: "key"}
	credBody := map[string]any{"factor": "passkey", "credential_id": "aWQ=", "secret": "cw==", "label": "key"}

	tests := []struct {
		name   string
		call   func() error
		method string
		path   string
		body   map[string]any
	}{
		{"status", func() error { _, err := c.PasswordVaultStatus(ctx); return err },
			http.MethodGet, "/api/v1/password-vault", nil},
		{"enroll", func() error {
			_, err := c.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: cred})
			return err
		}, http.MethodPost, "/api/v1/password-vault/factors", credBody},
		{"rotate", func() error {
			_, err := c.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{FactorID: "a/b", PasswordVaultCredential: cred})
			return err
		}, http.MethodPut, "/api/v1/password-vault/factors/a%2Fb", credBody},
		{"remove", func() error {
			return c.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: "f 1"})
		}, http.MethodDelete, "/api/v1/password-vault/factors/f%201", nil},
		{"recover", func() error {
			_, err := c.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{RecoveryCode: "CODE", PasswordVaultCredential: cred})
			return err
		}, http.MethodPost, "/api/v1/password-vault/recover", map[string]any{
			"recovery_code": "CODE", "factor": "passkey", "credential_id": "aWQ=", "secret": "cw==", "label": "key",
		}},
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

// TestPasswordVaultClient_DecodesResponses proves the responses decode,
// base64 byte fields included.
func TestPasswordVaultClient_DecodesResponses(t *testing.T) {
	ctx := context.Background()

	status := PasswordVaultClient{Do: (&recordingRequester{response: `{"initialized":true,"unlocked":false,` +
		`"factors":[{"id":"f1","factor":"passkey","created_at":"2026-01-02T03:04:05Z","credential_id":"aWQ=","prf_salt":"c2FsdA=="}]}`}).do}
	got, err := status.PasswordVaultStatus(ctx)
	require.NoError(t, err)
	assert.True(t, got.Initialized)
	require.Len(t, got.Factors, 1)
	assert.Equal(t, []byte("id"), got.Factors[0].CredentialID)
	assert.Equal(t, []byte("salt"), got.Factors[0].PRFSalt)

	enroll := PasswordVaultClient{Do: (&recordingRequester{response: `{"factor":{"id":"f1","factor":"passphrase"},"recovery_code":"CODE"}`}).do}
	enrolled, err := enroll.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{})
	require.NoError(t, err)
	assert.Equal(t, "CODE", enrolled.RecoveryCode)
	assert.Equal(t, "f1", enrolled.Factor.ID)
}

// TestPasswordVaultClient_Errors proves a nil request is refused before any
// request, and a failed request and an undecodable response are returned.
func TestPasswordVaultClient_Errors(t *testing.T) {
	ctx := context.Background()
	failing := PasswordVaultClient{Do: (&recordingRequester{err: errRequestFailed}).do}
	garbled := PasswordVaultClient{Do: (&recordingRequester{response: `{not json`}).do}

	type calls struct {
		nilReq, withReq func(PasswordVaultClient) error
	}
	for name, call := range map[string]calls{
		"enroll": {
			func(c PasswordVaultClient) error { _, err := c.PasswordVaultEnroll(ctx, nil); return err },
			func(c PasswordVaultClient) error {
				_, err := c.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{})
				return err
			},
		},
		"rotate": {
			func(c PasswordVaultClient) error { _, err := c.PasswordVaultRotate(ctx, nil); return err },
			func(c PasswordVaultClient) error {
				_, err := c.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{FactorID: "f"})
				return err
			},
		},
		"recover": {
			func(c PasswordVaultClient) error { _, err := c.PasswordVaultRecover(ctx, nil); return err },
			func(c PasswordVaultClient) error {
				_, err := c.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{})
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

	_, err := failing.PasswordVaultStatus(ctx)
	assert.ErrorIs(t, err, errRequestFailed)
	var decodeErr *DecodeError
	_, err = garbled.PasswordVaultStatus(ctx)
	assert.ErrorAs(t, err, &decodeErr)

	assert.ErrorIs(t, failing.PasswordVaultRemoveFactor(ctx, nil), ErrNilRequest)
	assert.ErrorIs(t, failing.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: "f"}), errRequestFailed)
}
