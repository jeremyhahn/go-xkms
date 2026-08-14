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

import type { HttpCore } from '../http.js';
import type { AuditFilter, AuditPage } from '../types/audit.js';

const BASE = '/api/v1/audit';

/** Default bound on AuditClient.queryAll when the caller does not pass one. */
const DEFAULT_MAX_PAGES = 100;

/**
 * Read access to the tamper-evident audit chain owned by the embedded
 * go-qrdb node. There is no write method here, and there should never be
 * one: audit events are recorded server-side as a side effect of the
 * operation being audited, so a caller cannot forge a record or backdate the
 * chain.
 */
export class AuditClient {
  constructor(private readonly http: HttpCore) {}

  /**
   * GET /api/v1/audit/
   *
   * Every filter field is an optional query parameter; `buildURL` drops
   * undefined/null/empty-string values, so an absent field is simply not
   * sent rather than sent blank. Paging is by opaque cursor: pass a prior
   * page's `next` back as `cursor` to continue, and stop once `next` is
   * empty or absent.
   */
  query(filter: AuditFilter = {}): Promise<AuditPage> {
    return this.http.request('GET', `${BASE}/`, {
      query: {
        from: filter.from,
        to: filter.to,
        actor: filter.actor,
        resource: filter.resource,
        action: filter.action,
        outcome: filter.outcome,
        tenant_id: filter.tenant_id,
        limit: filter.limit,
        cursor: filter.cursor,
      },
    });
  }

  /**
   * queryAll follows the `next` cursor across pages, yielding each
   * AuditPage.query() returns, and stops as soon as a page's `next` is
   * empty/absent (the last page). `maxPages` bounds the number of requests
   * this can issue — an append-only chain that never stops handing back a
   * `next` cursor would otherwise loop forever — and defaults to
   * DEFAULT_MAX_PAGES (100).
   */
  async *queryAll(filter: AuditFilter = {}, maxPages = DEFAULT_MAX_PAGES): AsyncGenerator<AuditPage, void, void> {
    let cursor = filter.cursor;
    for (let i = 0; i < maxPages; i++) {
      const page = await this.query(cursor === undefined ? filter : { ...filter, cursor });
      yield page;
      if (!page.next) {
        return;
      }
      cursor = page.next;
    }
  }
}
