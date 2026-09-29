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

package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityFactorService_Do_TransportErrorIsWrapped covers do()'s
// client.Do failure branch: the server is closed before the request is
// sent, so the round trip fails at the transport layer.
func TestSecurityFactorService_Do_TransportErrorIsWrapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening once do() dials it

	svc := NewSecurityFactorService(nil, nil)
	req, err := http.NewRequest(http.MethodGet, url+"/x", nil)
	require.NoError(t, err)

	err = svc.do(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "security_factor: GET /x")
}

// TestSecurityFactorService_Do_ErrorBodyNotJSON covers the branch where a
// 4xx/5xx response body does not parse as JSON: do() must fall back to the
// generic "HTTP <code>" message instead of failing the whole call.
func TestSecurityFactorService_Do_ErrorBodyNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(nil, nil)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	require.NoError(t, err)

	err = svc.do(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

// TestSecurityFactorService_Do_ErrorBodyMessageField covers the branch
// where the JSON error body sets "message" but not "error".
func TestSecurityFactorService_Do_ErrorBodyMessageField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"bad request details"}`))
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(nil, nil)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	require.NoError(t, err)

	err = svc.do(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad request details")
}

// TestSecurityFactorService_Do_DecodeResponseError covers the branch where
// a 2xx response body does not parse into the caller's destination type.
func TestSecurityFactorService_Do_DecodeResponseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(nil, nil)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	require.NoError(t, err)

	var dst struct{ X string }
	err = svc.do(req, &dst)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "decode response"))
}
