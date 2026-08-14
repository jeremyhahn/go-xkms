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

package xkms

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// stubAuditClient records the filter it received and returns a canned page.
type stubAuditClient struct {
	gotFilter qrdbtransport.AuditFilter
	page      *qrdbtransport.AuditPage
	err       error
}

func (s *stubAuditClient) EmitAudit(_ context.Context, _ qrdbtransport.AuditEvent) error {
	return nil
}

func (s *stubAuditClient) QueryAudit(_ context.Context, f qrdbtransport.AuditFilter) (*qrdbtransport.AuditPage, error) {
	s.gotFilter = f
	return s.page, s.err
}

func auditService(t *testing.T, client qrdbtransport.AuditClient) *XKMSService {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	svc.SetAuditClient(client)
	return svc
}

func TestQueryAudit_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.QueryAudit(context.Background(), &transport.AuditFilter{})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestQueryAudit_NilFilterRejected(t *testing.T) {
	svc := auditService(t, &stubAuditClient{})

	_, err := svc.QueryAudit(context.Background(), nil)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestQueryAudit_PassesEveryFilterFieldThrough(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	stub := &stubAuditClient{page: &qrdbtransport.AuditPage{}}
	svc := auditService(t, stub)

	_, err := svc.QueryAudit(context.Background(), &transport.AuditFilter{
		From:     from,
		To:       to,
		Actor:    "alice",
		Resource: "keys",
		Action:   "sign",
		Outcome:  "allow",
		TenantID: "t1",
		Limit:    25,
		Cursor:   "abc",
	})

	require.NoError(t, err)
	assert.Equal(t, from, stub.gotFilter.From)
	assert.Equal(t, to, stub.gotFilter.To)
	assert.Equal(t, "alice", stub.gotFilter.Actor)
	assert.Equal(t, "keys", stub.gotFilter.Resource)
	assert.Equal(t, "sign", stub.gotFilter.Action)
	assert.Equal(t, "allow", stub.gotFilter.Outcome)
	assert.Equal(t, "t1", stub.gotFilter.TenantID)
	assert.Equal(t, 25, stub.gotFilter.Limit)
	assert.Equal(t, "abc", stub.gotFilter.Cursor)
}

// An unbounded query would otherwise pull an entire long-lived chain into
// memory on both sides, so the limit is clamped rather than honoured.
func TestQueryAudit_ClampsPageSize(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "absent defaults", limit: 0, want: defaultAuditPageSize},
		{name: "negative defaults", limit: -5, want: defaultAuditPageSize},
		{name: "oversized clamps", limit: 100000, want: maxAuditPageSize},
		{name: "in range honoured", limit: 250, want: 250},
		{name: "exactly max honoured", limit: maxAuditPageSize, want: maxAuditPageSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &stubAuditClient{page: &qrdbtransport.AuditPage{}}
			svc := auditService(t, stub)

			_, err := svc.QueryAudit(context.Background(), &transport.AuditFilter{Limit: tt.limit})

			require.NoError(t, err)
			assert.Equal(t, tt.want, stub.gotFilter.Limit)
		})
	}
}

func TestQueryAudit_MapsEventsFaithfully(t *testing.T) {
	ts := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	stub := &stubAuditClient{page: &qrdbtransport.AuditPage{
		Events: []qrdbtransport.AuditEvent{{
			Timestamp:  ts,
			Actor:      "alice",
			TenantID:   "t1",
			Role:       "admin",
			Resource:   "keys",
			Action:     "sign",
			Outcome:    "allow",
			Attributes: map[string]any{"key_id": "k1"},
			ClientIP:   "10.0.0.9",
			RequestID:  "req-1",
			PrevHash:   "abc123",
		}},
		Next:  "cursor-2",
		Total: 1,
	}}
	svc := auditService(t, stub)

	page, err := svc.QueryAudit(context.Background(), &transport.AuditFilter{})

	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	got := page.Events[0]
	assert.Equal(t, ts, got.Timestamp)
	assert.Equal(t, "alice", got.Actor)
	assert.Equal(t, "t1", got.TenantID)
	assert.Equal(t, "admin", got.Role)
	assert.Equal(t, "keys", got.Resource)
	assert.Equal(t, "sign", got.Action)
	assert.Equal(t, "allow", got.Outcome)
	assert.Equal(t, "k1", got.Attributes["key_id"])
	assert.Equal(t, "10.0.0.9", got.ClientIP)
	assert.Equal(t, "req-1", got.RequestID)
	// PrevHash is the chain link that makes the log verifiable; dropping it in
	// translation would silently destroy the tamper evidence.
	assert.Equal(t, "abc123", got.PrevHash)
	assert.Equal(t, "cursor-2", page.Next)
	assert.Equal(t, 1, page.Total)
}

func TestQueryAudit_NilPageBecomesEmpty(t *testing.T) {
	svc := auditService(t, &stubAuditClient{page: nil})

	page, err := svc.QueryAudit(context.Background(), &transport.AuditFilter{})

	require.NoError(t, err)
	require.NotNil(t, page)
	assert.Empty(t, page.Events, "a nil page must not become a nil-events panic for callers")
}

func TestQueryAudit_WrapsBackendFailure(t *testing.T) {
	stub := &stubAuditClient{err: errors.New("chain segment unreadable")}
	svc := auditService(t, stub)

	_, err := svc.QueryAudit(context.Background(), &transport.AuditFilter{})

	require.Error(t, err)
	var opErr *ErrAuditOperation
	require.True(t, errors.As(err, &opErr), "must surface a typed audit error")
	assert.Equal(t, "query audit", opErr.Operation)
	assert.Contains(t, err.Error(), "chain segment unreadable")
}
