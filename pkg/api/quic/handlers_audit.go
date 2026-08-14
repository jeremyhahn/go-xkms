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
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// auditPathPrefix is the audit read endpoint. Audit state is owned by the
// embedded go-qrdb node; the handler delegates to the unified XKMSService
// servicer, exactly as the REST handler does.
const auditPathPrefix = "/api/v1/audit"

// setupAuditRoutes registers the audit read endpoint on mux.
func (s *Server) setupAuditRoutes(mux *http.ServeMux) {
	mux.HandleFunc(auditPathPrefix, s.handleQueryAudit)
}

// handleQueryAudit handles GET /api/v1/audit. The filter is carried entirely
// in the query string, mirroring the REST transport's client encoding:
// from, to (RFC3339), actor, resource, action, outcome, tenant_id, limit,
// cursor.
func (s *Server) handleQueryAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorize(w, r, auth.ResourceAudit, auth.ActionRead) {
		return
	}
	if s.xkmsService == nil {
		s.sendError(w, http.StatusServiceUnavailable, "audit service not configured")
		return
	}

	q := r.URL.Query()
	filter := &transport.AuditFilter{
		Actor:    q.Get("actor"),
		Resource: q.Get("resource"),
		Action:   q.Get("action"),
		Outcome:  q.Get("outcome"),
		TenantID: q.Get("tenant_id"),
		Cursor:   q.Get("cursor"),
	}
	if v := q.Get("from"); v != "" {
		from, err := time.Parse(time.RFC3339, v)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, "invalid from timestamp")
			return
		}
		filter.From = from
	}
	if v := q.Get("to"); v != "" {
		to, err := time.Parse(time.RFC3339, v)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, "invalid to timestamp")
			return
		}
		filter.To = to
	}
	if v := q.Get("limit"); v != "" {
		limit, err := strconv.Atoi(v)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		filter.Limit = limit
	}

	page, err := s.xkmsService.QueryAudit(r.Context(), filter)
	if err != nil {
		s.sendAuditError(w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, page)
}

// sendAuditError maps audit domain errors surfaced by the XKMS servicer to
// HTTP status codes.
func (s *Server) sendAuditError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		s.sendError(w, http.StatusServiceUnavailable, "audit service not configured")
	case errors.Is(err, xkms.ErrNilRequest):
		s.sendError(w, http.StatusBadRequest, "request is required")
	default:
		s.sendError(w, http.StatusInternalServerError, "audit query failed")
	}
}
