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

package quic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
)

// vaultRequest is one request the vault test server received.
type vaultRequest struct {
	method, path string
	body         map[string]any
}

// newVaultTransport returns a transport connected to a server that records
// every request and answers the vault routes: GET /vault with one passkey,
// the enrollment routes with an enrollment, DELETE with 204, and any other
// path with the server's 404 JSON error.
func newVaultTransport(t *testing.T) (*Transport, *[]vaultRequest) {
	t.Helper()
	var requests []vaultRequest
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := vaultRequest{method: r.Method, path: r.URL.EscapedPath()}
		raw, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		if len(raw) > 0 {
			assert.NoError(t, json.Unmarshal(raw, &rec.body))
		}
		requests = append(requests, rec)

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && rec.path == "/api/v1/password-vault":
			assert.NoError(t, json.NewEncoder(w).Encode(transport.PasswordVaultStatusResponse{
				Initialized: true,
				Factors:     []transport.PasswordVaultFactor{{ID: "f1", Factor: "passkey", CredentialID: []byte("id"), PRFSalt: []byte("salt")}},
			}))
		case r.Method == http.MethodDelete && rec.path == "/api/v1/password-vault/factors/f1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNotFound)
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "Vault factor not found"}))
		default:
			assert.NoError(t, json.NewEncoder(w).Encode(transport.PasswordVaultEnrollResponse{
				Factor: transport.PasswordVaultFactor{ID: "f2", Factor: "passkey"}, RecoveryCode: "CODE",
			}))
		}
	}))
	t.Cleanup(srv.Close)

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}
	return tr, &requests
}

// TestPasswordVault_ReachesTheServer proves every vault method sends its
// request to the REST route QUIC serves over HTTP/3, and the answers decode.
// The routes themselves are tested once, in pkg/api/rest/wire.
func TestPasswordVault_ReachesTheServer(t *testing.T) {
	tr, requests := newVaultTransport(t)
	ctx := context.Background()
	passkey := vaulttest.Passkey("key")

	status, err := tr.PasswordVaultStatus(ctx)
	require.NoError(t, err)
	assert.True(t, status.Initialized)
	require.Len(t, status.Factors, 1)
	assert.Equal(t, []byte("salt"), status.Factors[0].PRFSalt)

	enrolled, err := tr.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: passkey})
	require.NoError(t, err)
	assert.Equal(t, "CODE", enrolled.RecoveryCode)

	_, err = tr.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{FactorID: "f1", PasswordVaultCredential: passkey})
	require.NoError(t, err)

	require.NoError(t, tr.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: "f1"}))

	_, err = tr.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{RecoveryCode: "CODE", PasswordVaultCredential: passkey})
	require.NoError(t, err)

	got := *requests
	require.Len(t, got, 5)
	assert.Equal(t, vaultRequest{http.MethodGet, "/api/v1/password-vault", nil}, got[0])
	assert.Equal(t, http.MethodPost, got[1].method)
	assert.Equal(t, "/api/v1/password-vault/factors", got[1].path)
	assert.Equal(t, "passkey", got[1].body["factor"])
	assert.NotEmpty(t, got[1].body["secret"], "the PRF output crosses the wire")
	assert.Equal(t, http.MethodPut, got[2].method)
	assert.Equal(t, "/api/v1/password-vault/factors/f1", got[2].path)
	assert.Equal(t, vaultRequest{http.MethodDelete, "/api/v1/password-vault/factors/f1", nil}, got[3])
	assert.Equal(t, "/api/v1/password-vault/recover", got[4].path)
	assert.Equal(t, "CODE", got[4].body["recovery_code"])
}

func TestPasswordVault_ServerErrorReachesTheCaller(t *testing.T) {
	tr, _ := newVaultTransport(t)

	err := tr.PasswordVaultRemoveFactor(context.Background(), &transport.PasswordVaultRemoveFactorRequest{FactorID: "other"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Vault factor not found")
}

func TestPasswordVault_NotConnected(t *testing.T) {
	for name, call := range vaulttest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
