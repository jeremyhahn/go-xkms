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

/**
 * The OIDC Credentials view in a real browser, against the mock API: the
 * status a dead login shows, a codex auth.json pasted and imported (the exact
 * request it sends), and a device login polled to completion.
 */

import { test, expect, type Page } from '@playwright/test';
import { installDefaultApiMocks } from './support/mockApi.ts';
import { defaultAuthMe, seedAuthenticated } from './support/mockAuth.ts';

const base = '/api/v1/oidc/credentials';

function credential(name: string, status: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    tenant_id: 'acme',
    scope: 'tenant',
    name,
    config: { template: 'openai', issuer: 'https://auth.openai.com', client_id: 'app_EMoamEEZ73f0CkXaXp7hrann' },
    status,
    refreshable: status === 'active',
    created_at: '2026-09-30T00:00:00Z',
    updated_at: '2026-09-30T00:00:00Z',
    ...extra,
  };
}

/** serveList answers the credential list with whatever list() returns at the time. */
async function serveList(page: Page, list: () => unknown[]): Promise<void> {
  await page.route(`**${base}?*`, async (route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ credentials: list() }) });
  });
  await page.route(`**${base}`, async (route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ credentials: list() }) });
  });
}

/** jwt returns an unsigned compact JWT carrying claims. */
function jwt(claims: Record<string, unknown>): string {
  const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  return `${enc({ alg: 'RS256' })}.${enc(claims)}.sig`;
}

test.describe('OIDC credentials', () => {
  test('flags a credential whose refresh token was rejected', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    await serveList(page, () => [
      credential('codex', 'relogin_required', { status_reason: 'refresh_token_reused' }),
      credential('claude', 'active', { config: { template: 'anthropic', issuer: 'https://claude.ai', no_refresh: true } }),
    ]);

    await page.goto('/#/oidc/credentials');
    await expect(page.getByText('re-login required')).toBeVisible();
    await expect(page.getByText('refresh_token_reused')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy access token of claude' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy access token of codex' })).toHaveCount(0);
  });

  test('creates a shared credential from a pasted codex auth.json', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    const created: unknown[] = [];
    let list: unknown[] = [];
    await serveList(page, () => list);
    await page.route(`**${base}`, async (route) => {
      if (route.request().method() !== 'POST') {
        await route.fallback();
        return;
      }
      created.push(route.request().postDataJSON());
      const body = credential('codex', 'active');
      list = [body];
      await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(body) });
    });

    const access = jwt({ exp: 4102444800 });
    const authJSON = JSON.stringify({
      OPENAI_API_KEY: null,
      tokens: { id_token: jwt({ sub: 'u' }), access_token: access, refresh_token: 'rt-pasted', account_id: 'acct' },
    });

    await page.goto('/#/oidc/credentials');
    await page.getByRole('button', { name: '+ Create' }).click();
    await page.getByLabel('Name').fill('codex');
    await page.getByLabel('Visibility').selectOption('tenant');
    await page.getByLabel('Provider').selectOption('openai');
    await page.getByRole('tab', { name: 'Import tokens' }).click();
    await page.locator('#oidc-auth-json').fill(authJSON);
    await page.getByRole('button', { name: 'Fill from auth.json' }).click();
    await page.getByRole('button', { name: 'Create', exact: true }).click();

    await expect.poll(() => created.length).toBe(1);
    const req = created[0] as { scope: string; name: string; config: { template: string }; tokens: Record<string, string> };
    expect(req.scope).toBe('tenant');
    expect(req.name).toBe('codex');
    expect(req.config.template).toBe('openai');
    expect(req.tokens.access_token).toBe(access);
    expect(req.tokens.refresh_token).toBe('rt-pasted');
    await expect(page.locator('#oidc-auth-json')).toHaveCount(0);
  });

  test('runs a device login until it is approved', async ({ page }) => {
    await installDefaultApiMocks(page);
    await seedAuthenticated(page, defaultAuthMe());
    let status = 'pending';
    await serveList(page, () => [credential('codex', status)]);
    const pendingLogin = {
      user_code: 'ABCD-EFGH',
      verification_uri: 'https://auth.openai.com/codex/device',
      interval_seconds: 1,
      expires_at: new Date(Date.now() + 600_000).toISOString(),
    };
    await page.route(/\/api\/v1\/oidc\/credentials\/tenant\/codex\/device(\?.*)?$/, async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(credential('codex', 'pending', { device_login: pendingLogin })) });
    });
    let polls = 0;
    await page.route(/\/api\/v1\/oidc\/credentials\/tenant\/codex\/device\/poll(\?.*)?$/, async (route) => {
      polls++;
      const done = polls >= 2;
      if (done) status = 'active';
      const body = done ? credential('codex', 'active') : credential('codex', 'pending', { device_login: pendingLogin });
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    });

    await page.goto('/#/oidc/credentials');
    await page.getByRole('button', { name: 'Device login for codex' }).click();
    await expect(page.getByLabel('User code')).toHaveText('ABCD-EFGH');
    await expect.poll(() => polls, { timeout: 10_000 }).toBeGreaterThanOrEqual(2);
    await expect(page.getByLabel('User code')).toHaveCount(0, { timeout: 10_000 });
  });
});
