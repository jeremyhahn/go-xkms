// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryAudit_RoundTrip asserts that every AuditFilter field lands in the
// query string under its documented name, and that the JSON response body
// converts back into an AuditPage without losing Next or the chain's
// PrevHash link.
func TestQueryAudit_RoundTrip(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		assert.Equal(t, "/api/v1/audit", r.URL.Path)
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(transport.AuditPage{
			Events: []transport.AuditEvent{
				{
					Actor:    "alice",
					Resource: "key",
					Action:   "sign",
					Outcome:  "success",
					PrevHash: "deadbeef",
				},
			},
			Next:  "cursor-2",
			Total: 1,
		})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	resp, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{
		From:     from,
		To:       to,
		Actor:    "alice",
		Resource: "key",
		Action:   "sign",
		Outcome:  "success",
		TenantID: "tenant-1",
		Limit:    10,
		Cursor:   "cursor-1",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	q, err := url.ParseQuery(capturedQuery)
	require.NoError(t, err)
	assert.Equal(t, from.Format(time.RFC3339), q.Get("from"))
	assert.Equal(t, to.Format(time.RFC3339), q.Get("to"))
	assert.Equal(t, "alice", q.Get("actor"))
	assert.Equal(t, "key", q.Get("resource"))
	assert.Equal(t, "sign", q.Get("action"))
	assert.Equal(t, "success", q.Get("outcome"))
	assert.Equal(t, "tenant-1", q.Get("tenant_id"))
	assert.Equal(t, "10", q.Get("limit"))
	assert.Equal(t, "cursor-1", q.Get("cursor"))

	require.Len(t, resp.Events, 1)
	assert.Equal(t, "alice", resp.Events[0].Actor)
	assert.Equal(t, "deadbeef", resp.Events[0].PrevHash)
	assert.Equal(t, "cursor-2", resp.Next)
	assert.Equal(t, 1, resp.Total)
}

// TestQueryAudit_ZeroFieldsOmitted asserts that a zero From/To and empty
// filter fields are omitted from the query string entirely rather than sent
// as blanks: a stray "from=0001-01-01..." would silently turn an unbounded
// query into one with an epoch lower bound.
func TestQueryAudit_ZeroFieldsOmitted(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(transport.AuditPage{})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, capturedQuery)
}

// TestQueryAudit_NilFilterRejected asserts a nil filter is rejected before
// any request is sent, rather than panicking on a nil dereference while
// building the query string.
func TestQueryAudit_NilFilterRejected(t *testing.T) {
	tr, err := New(transport.WithAddress("http://127.0.0.1:0"))
	require.NoError(t, err)

	resp, err := tr.QueryAudit(context.Background(), nil)
	assert.ErrorIs(t, err, transport.ErrInvalidRequest)
	assert.Nil(t, resp)
}

// TestQueryAudit_TransportFailure asserts a server error surfaces as the
// transport's typed error rather than a bare string, and that a failed
// query never returns a non-nil page alongside the error.
func TestQueryAudit_TransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "audit chain unavailable"})
	}))
	defer srv.Close()

	tr, err := New(transport.WithAddress(srv.URL))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	resp, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{Actor: "alice"})
	require.Error(t, err)
	assert.Nil(t, resp)

	var msgErr *errs.Message
	assert.ErrorAs(t, err, &msgErr)
}

// TestQueryAudit_NotConnected asserts the transport-level typed error is
// returned when the client has not connected yet.
func TestQueryAudit_NotConnected(t *testing.T) {
	tr, err := New(transport.WithAddress("http://127.0.0.1:0"))
	require.NoError(t, err)

	resp, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{})
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.Nil(t, resp)
}
