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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pkcs11StateCADServer answers the compare-and-delete route the way the server
// does: the guard is evaluated against the one value it holds, and the request
// it decoded is kept so the test can prove the transport put the DTO on the
// route the handler serves with the field names it decodes.
type pkcs11StateCADServer struct {
	holds   []byte
	gotPath string
	gotBody transport.PKCS11StateCADRequest
}

func (s *pkcs11StateCADServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.gotPath = r.URL.Path
	if err := json.NewDecoder(r.Body).Decode(&s.gotBody); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(transport.PKCS11StateCADResponse{Deleted: bytes.Equal(s.holds, s.gotBody.Expected)})
}

func newPKCS11StateCADTransport(t *testing.T, h http.Handler) *Transport {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}
}

func TestPKCS11StateCAD_ForwardsTheGuardOnTheServedRoute(t *testing.T) {
	server := &pkcs11StateCADServer{holds: []byte("holder-A")}
	tr := newPKCS11StateCADTransport(t, server)
	ctx := context.Background()

	resp, err := tr.PKCS11StateCAD(ctx, &transport.PKCS11StateCADRequest{
		TenantID: "tenant-x", Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-B"),
	})
	require.NoError(t, err)
	assert.False(t, resp.Deleted, "the server's refusal is reported as a refusal")
	assert.Equal(t, "/api/v1/pkcs11state/compare-and-delete", server.gotPath)
	assert.Equal(t, transport.PKCS11StateCADRequest{
		TenantID: "tenant-x", Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-B"),
	}, server.gotBody, "every namespace field and the guard reach the handler under its own field names")

	resp, err = tr.PKCS11StateCAD(ctx, &transport.PKCS11StateCADRequest{
		Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-A"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Deleted)
}

func TestPKCS11StateCAD_ErrorsAreNotRefusals(t *testing.T) {
	disconnected := &Transport{config: transport.DefaultConfig()}
	_, err := disconnected.PKCS11StateCAD(context.Background(), &transport.PKCS11StateCADRequest{Token: "tok0", Key: "k"})
	require.ErrorIs(t, err, ErrNotConnected)

	failing := newPKCS11StateCADTransport(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "store unavailable", http.StatusInternalServerError)
	}))
	resp, err := failing.PKCS11StateCAD(context.Background(), &transport.PKCS11StateCADRequest{Token: "tok0", Key: "k", Expected: []byte("holder-A")})
	require.Error(t, err, "a server failure must surface as an error, because the outcome is unknown")
	assert.Nil(t, resp)

	garbled := newPKCS11StateCADTransport(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	resp, err = garbled.PKCS11StateCAD(context.Background(), &transport.PKCS11StateCADRequest{Token: "tok0", Key: "k", Expected: []byte("holder-A")})
	require.Error(t, err)
	assert.Nil(t, resp)
}
