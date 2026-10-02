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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// maxAuditPageSize caps a single audit page. An unbounded query against a
// long-lived chain would pull the whole log into memory on both sides, so an
// absent or oversized limit is clamped rather than honoured.
const maxAuditPageSize = 1000

// defaultAuditPageSize is used when the caller states no limit.
const defaultAuditPageSize = 100

// AuditServicer defines read access to the audit chain. Audit STORAGE belongs
// to the embedded go-qrdb node — this passes queries through to it. There is
// no emit method here on purpose: events are written through pkg/audit's
// Logger seam as a side effect of the operation being audited, so no API
// caller can inject a record.
type AuditServicer interface {
	QueryAudit(ctx context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error)
}

// QueryAudit returns one page of audit events from the embedded qrdb node's
// tamper-evident chain, confined to the caller's own tenant (see
// auditTenantFilter).
func (s *XKMSService) QueryAudit(ctx context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error) {
	if s.audit == nil {
		return nil, ErrNotConfigured
	}
	if filter == nil {
		return nil, ErrNilRequest
	}
	tenantID := auditTenantFilter(ctx)

	limit := filter.Limit
	if limit <= 0 {
		limit = defaultAuditPageSize
	}
	if limit > maxAuditPageSize {
		limit = maxAuditPageSize
	}

	page, err := s.audit.QueryAudit(ctx, qrdbtransport.AuditFilter{
		From:     filter.From,
		To:       filter.To,
		Actor:    filter.Actor,
		Resource: filter.Resource,
		Action:   filter.Action,
		Outcome:  filter.Outcome,
		TenantID: tenantID,
		Limit:    limit,
		Cursor:   filter.Cursor,
	})
	if err != nil {
		return nil, &ErrAuditOperation{Operation: "query audit", Err: err}
	}
	if page == nil {
		return &transport.AuditPage{Events: []transport.AuditEvent{}}, nil
	}

	events := make([]transport.AuditEvent, len(page.Events))
	for i, e := range page.Events {
		events[i] = transport.AuditEvent{
			Timestamp:  e.Timestamp,
			Actor:      e.Actor,
			TenantID:   e.TenantID,
			Role:       e.Role,
			Resource:   e.Resource,
			Action:     e.Action,
			Outcome:    e.Outcome,
			Attributes: e.Attributes,
			ClientIP:   e.ClientIP,
			RequestID:  e.RequestID,
			PrevHash:   e.PrevHash,
		}
	}

	return &transport.AuditPage{Events: events, Next: page.Next, Total: page.Total}, nil
}

// auditTenantFilter returns the tenant filter a caller's audit query runs
// under: the caller's own tenant, always, whatever the request named. This is
// go-qrdb's audit contract (tenant.ConfineAuditFilter): every caller reads
// only its own tenant's events, the system tenant included, and there is no
// cross-tenant read at all -- go-qrdb removed audit:read:cross.
//
// A foreign or empty requested tenant is narrowed to the caller's, never
// widened: "" is the audit chain's match-everything filter, so the caller's
// tenant is normalized through qrdbsdk.NormalizeTenantID and an absent
// identity, or one with an empty tenant, reads the system tenant. The embedded
// node then confines the same filter again against the identity on ctx, so a
// system-tenant caller also sees the untenanted platform events and nothing
// of any other tenant's.
func auditTenantFilter(ctx context.Context) string {
	identity := auth.GetIdentity(ctx)
	if identity == nil {
		return qrdbsdk.SystemTenantID
	}
	return qrdbsdk.NormalizeTenantID(identity.TenantID)
}
