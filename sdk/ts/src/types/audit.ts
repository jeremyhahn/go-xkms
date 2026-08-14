// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * Audit chain DTOs. Mirrors pkg/api/rest/handlers_audit.go and
 * pkg/api/transport/types.go (AuditEvent / AuditFilter / AuditPage). There is
 * deliberately no request/response pair for writing an event: audit records
 * are produced server-side as a side effect of the operation being audited.
 */

import type { RFC3339 } from './common.js';

/**
 * One record from the tamper-evident audit chain. `prev_hash` is the chain
 * link that makes the log verifiable — carry it through, never drop it.
 */
export interface AuditEvent {
  timestamp: RFC3339;
  actor: string;
  tenant_id?: string;
  role?: string;
  resource: string;
  action: string;
  outcome: string;
  attributes?: Record<string, unknown>;
  client_ip?: string;
  request_id?: string;
  prev_hash?: string;
}

/**
 * Query filter for GET /api/v1/audit/. Every field is optional; a zero/empty
 * field must be omitted from the request entirely rather than sent blank.
 */
export interface AuditFilter {
  /** RFC3339 lower bound (inclusive), unbounded when absent. */
  from?: RFC3339;
  /** RFC3339 upper bound (exclusive), unbounded when absent. */
  to?: RFC3339;
  actor?: string;
  resource?: string;
  action?: string;
  outcome?: string;
  tenant_id?: string;
  /** Server clamps: absent/0 -> 100, max 1000. */
  limit?: number;
  /** Opaque continuation token from a previous page's `next`. */
  cursor?: string;
}

/**
 * One page of audit events. `next` is empty/absent on the last page; it is a
 * cursor, not an offset, because an append-only chain shifts under an offset
 * between pages.
 */
export interface AuditPage {
  events: AuditEvent[];
  next?: string;
  total: number;
}
