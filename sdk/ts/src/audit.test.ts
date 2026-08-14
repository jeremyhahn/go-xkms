/**
 * audit.test.ts — wire-contract tests for AuditClient.
 *
 * The audit surface is read-only cursor pagination: every filter field is an
 * optional query parameter that must be OMITTED entirely when unset (not
 * sent blank), and paging moves forward by echoing a page's `next` back as
 * `cursor` until the server returns no further cursor. Those are the
 * easiest things to get wrong, so the assertions here pin the exact URL for
 * each call and the termination of the cursor-following generator.
 */

import { describe, it, expect } from 'vitest';
import { createClient } from './client.js';
import { newFakeFetch } from './testutil.js';
import { XkmsApiError } from './errors.js';
import type { AuditPage } from './types/audit.js';

const BASE = 'https://xkms.example.com';

function make(fake: ReturnType<typeof newFakeFetch>) {
  return createClient({ baseURL: BASE, fetch: fake.fetch, token: () => 'tk' });
}

function event(over: Record<string, unknown> = {}) {
  return {
    timestamp: '2026-01-01T00:00:00Z',
    actor: 'alice',
    resource: 'key/abc',
    action: 'key.sign',
    outcome: 'allow',
    ...over,
  };
}

describe('AuditClient.query', () => {
  it('sends no query string at all when the filter is empty', async () => {
    const fake = newFakeFetch({ body: { events: [event()], total: 1 } satisfies AuditPage });
    const c = make(fake);

    const resp = await c.audit.query();

    expect(fake.calls[0]?.method).toBe('GET');
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/audit/`);
    expect(fake.calls[0]?.headers['Authorization']).toBe('Bearer tk');
    expect(resp.events[0]?.actor).toBe('alice');
    expect(resp.total).toBe(1);
  });

  it('puts every set filter field in the query string and an RFC3339 timestamp survives verbatim', async () => {
    const fake = newFakeFetch({ body: { events: [], total: 0 } satisfies AuditPage });
    const c = make(fake);

    await c.audit.query({
      from: '2026-01-01T00:00:00Z',
      to: '2026-02-01T00:00:00Z',
      actor: 'alice',
      resource: 'key/abc',
      action: 'key.sign',
      outcome: 'allow',
      tenant_id: 'tenant-1',
      limit: 50,
      cursor: 'cursor-1',
    });

    const url = new URL(fake.calls[0]?.url ?? '');
    expect(url.pathname).toBe('/api/v1/audit/');
    expect(url.searchParams.get('from')).toBe('2026-01-01T00:00:00Z');
    expect(url.searchParams.get('to')).toBe('2026-02-01T00:00:00Z');
    expect(url.searchParams.get('actor')).toBe('alice');
    expect(url.searchParams.get('resource')).toBe('key/abc');
    expect(url.searchParams.get('action')).toBe('key.sign');
    expect(url.searchParams.get('outcome')).toBe('allow');
    expect(url.searchParams.get('tenant_id')).toBe('tenant-1');
    expect(url.searchParams.get('limit')).toBe('50');
    expect(url.searchParams.get('cursor')).toBe('cursor-1');
  });

  it('decodes prev_hash and attributes intact', async () => {
    const fake = newFakeFetch({
      body: {
        events: [
          event({
            prev_hash: 'deadbeef',
            attributes: { requestSize: 128, nested: { ok: true } },
            client_ip: '10.0.0.1',
            request_id: 'req-1',
            tenant_id: 'tenant-1',
            role: 'admin',
          }),
        ],
        total: 1,
      } satisfies AuditPage,
    });
    const c = make(fake);

    const resp = await c.audit.query();

    expect(resp.events[0]?.prev_hash).toBe('deadbeef');
    expect(resp.events[0]?.attributes).toEqual({ requestSize: 128, nested: { ok: true } });
    expect(resp.events[0]?.client_ip).toBe('10.0.0.1');
    expect(resp.events[0]?.request_id).toBe('req-1');
    expect(resp.events[0]?.tenant_id).toBe('tenant-1');
    expect(resp.events[0]?.role).toBe('admin');
  });

  it('surfaces a non-2xx as XkmsApiError with the status intact', async () => {
    const fake = newFakeFetch({ status: 403, body: { error: 'rbac: audit:read denied' } });
    const c = make(fake);

    await expect(c.audit.query()).rejects.toBeInstanceOf(XkmsApiError);
    await expect(c.audit.query()).rejects.toMatchObject({ status: 403 });
  });
});

describe('AuditClient.queryAll', () => {
  it('follows next across two pages and stops when next is empty', async () => {
    const fake = newFakeFetch({
      body: {
        events: [event({ request_id: 'req-1' })],
        next: 'cursor-2',
        total: 2,
      } satisfies AuditPage,
    });
    const c = make(fake);
    fake.respond({
      body: { events: [event({ request_id: 'req-2' })], total: 2 } satisfies AuditPage,
    });

    const pages: AuditPage[] = [];
    for await (const page of c.audit.queryAll()) {
      pages.push(page);
    }

    expect(pages).toHaveLength(2);
    expect(pages[0]?.events[0]?.request_id).toBe('req-1');
    expect(pages[1]?.events[0]?.request_id).toBe('req-2');
    expect(fake.calls).toHaveLength(2);
    expect(fake.calls[0]?.url).toBe(`${BASE}/api/v1/audit/`);
    expect(fake.calls[1]?.url).toBe(`${BASE}/api/v1/audit/?cursor=cursor-2`);
  });

  it('never issues more requests than the maxPages bound, even if the server keeps handing back next', async () => {
    const fake = newFakeFetch({
      body: { events: [event()], next: 'always-more', total: 999 } satisfies AuditPage,
    });
    const c = make(fake);

    const pages: AuditPage[] = [];
    for await (const page of c.audit.queryAll({}, 3)) {
      pages.push(page);
    }

    expect(pages).toHaveLength(3);
    expect(fake.calls).toHaveLength(3);
  });
});
