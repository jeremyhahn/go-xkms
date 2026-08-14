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

// handlers_audit_test.go covers the read-only audit endpoint: how query
// parameters map onto the filter, the failure modes for malformed bounds, and
// the pass-through to the servicer.
package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// stubAuditService records the filter it was handed and returns a canned page.
type stubAuditService struct {
	gotFilter *transport.AuditFilter
	page      *transport.AuditPage
	err       error
}

func (s *stubAuditService) QueryAudit(_ context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error) {
	s.gotFilter = filter
	if s.err != nil {
		return nil, s.err
	}
	if s.page != nil {
		return s.page, nil
	}
	return &transport.AuditPage{Events: []transport.AuditEvent{}}, nil
}

func queryAudit(t *testing.T, svc auditServicer, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewAuditHandlers(svc, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	h.QueryHandler(rec, req)
	return rec
}

func TestAuditQuery_MapsEveryFilterField(t *testing.T) {
	svc := &stubAuditService{}

	rec := queryAudit(t, svc,
		"actor=alice&resource=keys&action=sign&outcome=allow&tenant_id=t1"+
			"&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z&limit=25&cursor=abc")

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, svc.gotFilter)
	assert.Equal(t, "alice", svc.gotFilter.Actor)
	assert.Equal(t, "keys", svc.gotFilter.Resource)
	assert.Equal(t, "sign", svc.gotFilter.Action)
	assert.Equal(t, "allow", svc.gotFilter.Outcome)
	assert.Equal(t, "t1", svc.gotFilter.TenantID)
	assert.Equal(t, 25, svc.gotFilter.Limit)
	assert.Equal(t, "abc", svc.gotFilter.Cursor)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), svc.gotFilter.From.UTC())
	assert.Equal(t, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), svc.gotFilter.To.UTC())
}

// An absent bound must stay the zero time. Defaulting it to the epoch would
// silently turn an unbounded query into a bounded one.
func TestAuditQuery_AbsentBoundsStayZero(t *testing.T) {
	svc := &stubAuditService{}

	rec := queryAudit(t, svc, "")

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, svc.gotFilter)
	assert.True(t, svc.gotFilter.From.IsZero(), "From must remain unset")
	assert.True(t, svc.gotFilter.To.IsZero(), "To must remain unset")
	assert.Zero(t, svc.gotFilter.Limit, "limit must be left for the servicer to default")
}

func TestAuditQuery_ReturnsThePageVerbatim(t *testing.T) {
	ts := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	svc := &stubAuditService{page: &transport.AuditPage{
		Events: []transport.AuditEvent{{
			Timestamp:  ts,
			Actor:      "alice",
			Resource:   "keys",
			Action:     "sign",
			Outcome:    "allow",
			Attributes: map[string]any{"key_id": "k1", "count": float64(3)},
			PrevHash:   "abc123",
		}},
		Next:  "cursor-2",
		Total: 1,
	}}

	rec := queryAudit(t, svc, "")

	require.Equal(t, http.StatusOK, rec.Code)
	var got transport.AuditPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got.Events, 1)
	assert.Equal(t, "alice", got.Events[0].Actor)
	// prev_hash is the tamper-evidence chain link; dropping it would make the
	// log unverifiable by the caller.
	assert.Equal(t, "abc123", got.Events[0].PrevHash)
	assert.Equal(t, "k1", got.Events[0].Attributes["key_id"])
	assert.Equal(t, "cursor-2", got.Next)
	assert.Equal(t, 1, got.Total)
}

func TestAuditQuery_RejectsMalformedTimestamps(t *testing.T) {
	for _, q := range []string{"from=yesterday", "to=2026-13-45", "from=1735689600"} {
		t.Run(q, func(t *testing.T) {
			svc := &stubAuditService{}

			rec := queryAudit(t, svc, q)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Nil(t, svc.gotFilter, "servicer must not be called on a bad bound")
		})
	}
}

func TestAuditQuery_RejectsMalformedLimit(t *testing.T) {
	for _, q := range []string{"limit=lots", "limit=-1"} {
		t.Run(q, func(t *testing.T) {
			svc := &stubAuditService{}

			rec := queryAudit(t, svc, q)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Nil(t, svc.gotFilter, "servicer must not be called on a bad limit")
		})
	}
}

func TestAuditQuery_NotConfiguredReportsUnavailable(t *testing.T) {
	svc := &stubAuditService{err: ErrAuditNotConfigured}

	rec := queryAudit(t, svc, "")

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// A backend failure must not leak the underlying error text to the caller.
func TestAuditQuery_BackendFailureIsOpaque(t *testing.T) {
	svc := &stubAuditService{err: errors.New("qrdb: chain segment 7 unreadable at /var/lib/qrdb")}

	rec := queryAudit(t, svc, "")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "/var/lib/qrdb")
	assert.NotContains(t, rec.Body.String(), "segment 7")
}

func TestNewAuditHandlers_DefaultsTheLogger(t *testing.T) {
	h := NewAuditHandlers(&stubAuditService{}, nil)

	require.NotNil(t, h)
	assert.NotNil(t, h.logger, "a nil logger must fall back to the default, not panic on first error")
}
