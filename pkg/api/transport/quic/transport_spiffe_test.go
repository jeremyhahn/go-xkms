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

package quic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// signCSRBodyServer answers sign-csr with status and records the JSON body.
func signCSRBodyServer(t *testing.T, code int, body *map[string]interface{}) *Transport {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/ca/sign-csr", r.URL.Path)
		assert.NoError(t, json.NewDecoder(r.Body).Decode(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{"certificate_pem": "Y2VydA=="}))
	}))
	t.Cleanup(srv.Close)
	return &Transport{config: transport.DefaultConfig(), httpClient: srv.Client(), baseURL: srv.URL, connected: true}
}

// TestSignCSR_SendsSPIFFEKind proves the client puts the request's tenant
// and SPIFFE kind in the sign-csr body (go-xkms#1659).
func TestSignCSR_SendsSPIFFEKind(t *testing.T) {
	var body map[string]interface{}
	tr := signCSRBodyServer(t, http.StatusOK, &body)

	_, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM: []byte("csr"), TenantID: "tenant-a", SPIFFEKind: "svc",
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", body["tenant_id"])
	assert.Equal(t, "svc", body["spiffe_kind"])
}

// TestSignCSR_OmitsEmptySPIFFEKind proves a request without a kind sends the
// same body as before the field existed.
func TestSignCSR_OmitsEmptySPIFFEKind(t *testing.T) {
	var body map[string]interface{}
	tr := signCSRBodyServer(t, http.StatusOK, &body)

	_, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{CSRPEM: []byte("csr"), TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.NotContains(t, body, "spiffe_kind")
}

// TestSignCSR_ForbiddenSPIFFEKindIsAnError proves a 403 refusal of a svc
// request reaches the caller as an error.
func TestSignCSR_ForbiddenSPIFFEKindIsAnError(t *testing.T) {
	var body map[string]interface{}
	tr := signCSRBodyServer(t, http.StatusForbidden, &body)

	resp, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM: []byte("csr"), TenantID: "tenant-a", SPIFFEKind: "svc",
	})
	require.Error(t, err)
	assert.Nil(t, resp)
}
