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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubConnectionService builds a ConnectionService whose state points at
// the given httptest.Server. It does not start a real connection.
func stubConnectionService(srv *httptest.Server) *ConnectionService {
	cs := NewConnectionService()
	cs.state.Store(&ConnectionInfo{
		State:   "connected",
		Address: strings.TrimPrefix(srv.URL, "http://"),
		TLS:     false,
	})
	return cs
}

func TestSecurityFactorService_ListFactors(t *testing.T) {
	want := ListFactorsResponse{
		Factors: []AuthFactor{
			{
				ID:           "f1",
				UserID:       "u1",
				Type:         AuthFactorTypeFIDO2,
				Label:        "YubiKey 5",
				RegisteredAt: "2026-01-01T00:00:00Z",
			},
		},
		Total: 1,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/users/u1/factors", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	got, err := svc.ListFactors("u1")
	require.NoError(t, err)
	require.Len(t, got.Factors, 1)
	assert.Equal(t, "f1", got.Factors[0].ID)
	assert.Equal(t, AuthFactorTypeFIDO2, got.Factors[0].Type)
}

func TestSecurityFactorService_ListFactors_EmptyUserID(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.ListFactors("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID required")
}

func TestSecurityFactorService_AddFactor(t *testing.T) {
	var calledPath string
	var calledBody AddFactorRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&calledBody)
		resp := AddFactorResponse{
			Factor: AuthFactor{ID: "new-f", Type: AuthFactorTypeFIDO2, Label: "YubiKey"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	got, err := svc.AddFactor("u1", AddFactorRequest{
		Type:  AuthFactorTypeFIDO2,
		Label: "YubiKey",
	})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/u1/factors", calledPath)
	assert.Equal(t, AuthFactorTypeFIDO2, calledBody.Type)
	assert.Equal(t, "new-f", got.Factor.ID)
}

func TestSecurityFactorService_AddFactor_InvalidType(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.AddFactor("u1", AddFactorRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidFactorType)
}

func TestSecurityFactorService_RemoveFactor(t *testing.T) {
	var deletedPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deletedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	err := svc.RemoveFactor("u1", "f1")
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/u1/factors/f1", deletedPath)
}

func TestSecurityFactorService_RemoveFactor_MissingIDs(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	require.Error(t, svc.RemoveFactor("", "f1"))
	require.Error(t, svc.RemoveFactor("u1", ""))
}

func TestSecurityFactorService_RotateFactor(t *testing.T) {
	var calledPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		resp := AddFactorResponse{
			Factor: AuthFactor{ID: "rotated-f", Type: AuthFactorTypeMTLS},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	got, err := svc.RotateFactor("u1", RotateFactorRequest{
		FactorID: "old-f",
		CertPEM:  "-----BEGIN CERTIFICATE-----\n...",
	})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/u1/factors/old-f/rotate", calledPath)
	assert.Equal(t, "rotated-f", got.Factor.ID)
}

func TestSecurityFactorService_RelabelFactor(t *testing.T) {
	var gotLabel string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotLabel = body["label"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	err := svc.RelabelFactor("u1", "f1", "My YubiKey")
	require.NoError(t, err)
	assert.Equal(t, "My YubiKey", gotLabel)
}

func TestSecurityFactorService_SetMFAPolicy(t *testing.T) {
	var count int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/tenants/t1/security/mfa-policy", r.URL.Path)
		var body MFAPolicyRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, 2, body.RequireFactorCount)
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	err := svc.SetMFAPolicy(MFAPolicyRequest{TenantID: "t1", RequireFactorCount: 2})
	require.NoError(t, err)
	assert.EqualValues(t, 1, atomic.LoadInt32(&count))
}

func TestSecurityFactorService_SetMFAPolicy_EmptyTenant(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	require.Error(t, svc.SetMFAPolicy(MFAPolicyRequest{}))
}

func TestSecurityFactorService_NoServerConnection(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.ListFactors("u1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoServerConnection)
}

func TestSecurityFactorService_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthenticated"})
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.ListFactors("u1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthenticated")
}

func TestInferPIVVendor(t *testing.T) {
	cases := []struct {
		subject string
		want    string
	}{
		{"CN=YubiKey PIV, O=Yubico AB", "YubiKey PIV"},
		{"CN=NITROKEY3, O=Nitrokey", "Nitrokey PIV"},
		{"CN=GoldKey G4 v2", "GoldKey PIV"},
		{"CN=John Doe, O=ACME Corp", "PIV Card"},
		{"", "PIV Card"},
	}
	for _, c := range cases {
		t.Run(c.subject, func(t *testing.T) {
			assert.Equal(t, c.want, inferPIVVendor(c.subject))
		})
	}
}
