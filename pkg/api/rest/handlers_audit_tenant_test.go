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

package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// filterRecordingAuditClient records the filter that reaches the qrdb audit
// chain, which is the filter that decides whose events are returned.
type filterRecordingAuditClient struct {
	got qrdbtransport.AuditFilter
}

func (c *filterRecordingAuditClient) EmitAudit(context.Context, qrdbtransport.AuditEvent) error {
	return nil
}

func (c *filterRecordingAuditClient) QueryAudit(_ context.Context, f qrdbtransport.AuditFilter) (*qrdbtransport.AuditPage, error) {
	c.got = f
	return &qrdbtransport.AuditPage{}, nil
}

// TestAuditQuery_TenantCallerIsClampedToItsOwnTenant drives #1115 over REST
// against the real service: a tenant caller's empty or foreign tenant_id
// reaches the audit chain as its own tenant.
func TestAuditQuery_TenantCallerIsClampedToItsOwnTenant(t *testing.T) {
	client := &filterRecordingAuditClient{}
	svc := &xkms.XKMSService{}
	svc.SetAuditClient(client)
	h := NewAuditHandlers(svc, nil)

	for _, query := range []string{"", "tenant_id=tenant-b"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/?"+query, nil)
		req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{Subject: "alice", TenantID: "tenant-a"}))
		rec := httptest.NewRecorder()
		h.QueryHandler(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "tenant-a", client.got.TenantID, "query %q", query)
	}
}
