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
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Audit handler typed errors.
var (
	// ErrAuditNotConfigured reports that no audit client is wired, which is
	// the case when the server runs without an embedded qrdb node.
	ErrAuditNotConfigured = errors.New("rest: audit service not configured")

	// ErrInvalidAuditTime reports an unparseable from/to bound.
	ErrInvalidAuditTime = errors.New("rest: from and to must be RFC3339 timestamps")

	// ErrInvalidAuditLimit reports a non-numeric or negative limit.
	ErrInvalidAuditLimit = errors.New("rest: limit must be a positive integer")
)

// auditServicer is the subset of the XKMS service the audit handlers need.
// Keeping it an interface lets the handlers be driven directly in tests
// without standing up a qrdb node.
type auditServicer interface {
	QueryAudit(ctx context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error)
}

// AuditHandlers serves read access to the audit chain owned by the embedded
// go-qrdb node.
//
// There is no emit endpoint, and there should never be one: audit events are
// written server-side as a side effect of the operation being audited, so a
// caller cannot forge a record or backdate the chain.
type AuditHandlers struct {
	svc    auditServicer
	logger *slog.Logger
}

// NewAuditHandlers creates AuditHandlers over the given servicer.
func NewAuditHandlers(svc auditServicer, logger *slog.Logger) *AuditHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditHandlers{svc: svc, logger: logger}
}

// QueryHandler handles GET /api/v1/audit.
//
// Every filter field is a query parameter; all are optional. Paging is by
// opaque cursor (`cursor`), echoed back as `next` — not by offset, because an
// append-only chain shifts under an offset between pages.
func (h *AuditHandlers) QueryHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := &transport.AuditFilter{
		Actor:    q.Get("actor"),
		Resource: q.Get("resource"),
		Action:   q.Get("action"),
		Outcome:  q.Get("outcome"),
		TenantID: q.Get("tenant_id"),
		Cursor:   q.Get("cursor"),
	}

	if raw := q.Get("from"); raw != "" {
		from, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, ErrInvalidAuditTime, http.StatusBadRequest)
			return
		}
		filter.From = from
	}

	if raw := q.Get("to"); raw != "" {
		to, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, ErrInvalidAuditTime, http.StatusBadRequest)
			return
		}
		filter.To = to
	}

	if raw := q.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 0 {
			writeError(w, ErrInvalidAuditLimit, http.StatusBadRequest)
			return
		}
		filter.Limit = limit
	}

	page, err := h.svc.QueryAudit(r.Context(), filter)
	if err != nil {
		h.writeAuditError(w, err)
		return
	}

	writeJSON(w, page, http.StatusOK)
}

// writeAuditError maps audit-plane failures onto HTTP status codes. An
// unconfigured audit client is a deployment shape, not a caller mistake, so
// it reports 503 rather than 500.
func (h *AuditHandlers) writeAuditError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrAuditNotConfigured) {
		writeError(w, err, http.StatusServiceUnavailable)
		return
	}

	h.logger.Error("audit query failed", "error", err)
	writeErrorWithMessage(w, ErrInternalError, "audit query failed", http.StatusInternalServerError)
}
