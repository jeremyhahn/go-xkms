import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
} from '../helpers';
import { requireLiveEnv, assertLiveWailsMode, waitForBackendReady } from './helpers';

/**
 * Live-backend Playwright coverage for the Trust Store truststrap import
 * flow. Drives the real xkey Wails app against a real xkms-server. See
 * ./README.md for the setup required before running.
 *
 * Per the project convention we exercise the SPKI method because it
 * does not depend on the host's system trust store — the server pin is
 * supplied via env and pinned directly at TLS verify time. Direct mode
 * would require the test host to trust the generated CA in its system
 * store, and Noise / DANE have separate prerequisites covered in their
 * own files.
 */

test.describe('live: Trust Store → truststrap import (SPKI)', () => {
  test('fetches and imports a real CA bundle from the live xkms-server', async ({ page }) => {
    const env = requireLiveEnv();

    await page.goto('/');
    await waitForAppReady(page);
    await waitForBackendReady(page);
    await assertLiveWailsMode(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'trust-store');

    // Snapshot the cert count before import so we can assert the delta
    // rather than an absolute value (the backend may already hold
    // certs from prior test runs).
    const countBefore = await page.evaluate(async () =>
      await (window as any).go.services.TrustService.CertificateCount());

    await page.locator('[data-testid="truststore-import-btn"]').click();
    await page.waitForSelector('[data-testid="import-tabs"]', { timeout: 5_000 });
    await page.locator('[data-testid="import-tab-spki"]').click();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill(env.restURL);
    await page
      .locator('[data-testid="truststrap-spki-pin-input"]')
      .fill(env.spkiPin);

    // Intercept the success notification so we can surface the backend
    // error message on failure instead of guessing.
    const fetchBtn = page.locator('[data-testid="truststrap-fetch-btn"]');
    await expect(fetchBtn).toBeEnabled();
    await fetchBtn.click();

    // The modal closes on successful import (added > 0). If this exact CA
    // was already imported by a prior run against the same persistent dev
    // server/trust store, ImportFromTrustStrap legitimately returns 0 added
    // and TrustStore.svelte leaves the dialog open with a "no new
    // certificates" warning toast instead (see TrustStore.svelte
    // handleFetchImport). Either outcome proves the SPKI-pinned fetch
    // round-tripped successfully; an error toast is the only real failure
    // signal. Give the network roundtrip a generous window; the live
    // server typically responds in <1s.
    await Promise.race([
      page.locator('[data-testid="import-tabs"]').waitFor({ state: 'hidden', timeout: 15_000 }),
      page.locator('.toast-warning, .toast-success').first().waitFor({ state: 'visible', timeout: 15_000 }),
    ]);
    await expect(page.locator('.toast-error')).toHaveCount(0);

    const countAfter = await page.evaluate(async () =>
      await (window as any).go.services.TrustService.CertificateCount());

    expect(countAfter).toBeGreaterThanOrEqual(countBefore);
  });

  test('wrong SPKI pin is rejected without corrupting the trust store', async ({ page }) => {
    const env = requireLiveEnv();

    await page.goto('/');
    await waitForAppReady(page);
    await waitForBackendReady(page);
    await assertLiveWailsMode(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'trust-store');

    const countBefore = await page.evaluate(async () =>
      await (window as any).go.services.TrustService.CertificateCount());

    await page.locator('[data-testid="truststore-import-btn"]').click();
    await page.waitForSelector('[data-testid="import-tabs"]', { timeout: 5_000 });
    await page.locator('[data-testid="import-tab-spki"]').click();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill(env.restURL);
    // Syntactically valid but not the server's pin.
    await page
      .locator('[data-testid="truststrap-spki-pin-input"]')
      .fill('0'.repeat(64));

    await page.locator('[data-testid="truststrap-fetch-btn"]').click();

    // Modal must stay open so the user can correct.
    await expect(page.locator('[data-testid="import-tabs"]')).toBeVisible();

    const countAfter = await page.evaluate(async () =>
      await (window as any).go.services.TrustService.CertificateCount());

    expect(countAfter).toBe(countBefore);
  });
});

test.describe('live: Trust Store → truststrap import (Noise)', () => {
  test('fetches a CA bundle over Noise_NK', async ({ page }) => {
    const env = requireLiveEnv();

    await page.goto('/');
    await waitForAppReady(page);
    await waitForBackendReady(page);
    await assertLiveWailsMode(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'trust-store');

    const countBefore = await page.evaluate(async () =>
      await (window as any).go.services.TrustService.CertificateCount());

    await page.locator('[data-testid="truststore-import-btn"]').click();
    await page.waitForSelector('[data-testid="import-tabs"]', { timeout: 5_000 });
    await page.locator('[data-testid="import-tab-noise"]').click();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill(env.noiseAddr);
    await page
      .locator('[data-testid="truststrap-noise-key-input"]')
      .fill(env.noiseKey);

    await page.locator('[data-testid="truststrap-fetch-btn"]').click();

    // Noise bundle matches the SPKI bundle fetched by the earlier test in
    // this file (both pull from the same server), so this call legitimately
    // reports 0-added and TrustStore.svelte's handleFetchImport() leaves the
    // dialog open with a "no new certificates" warning toast rather than
    // closing it (it only closes on added > 0 — see TrustStore.svelte).
    // Either outcome proves the Noise_NK handshake + fetch round-tripped
    // successfully; an error toast is the only real failure signal.
    await Promise.race([
      page.locator('[data-testid="import-tabs"]').waitFor({ state: 'hidden', timeout: 15_000 }),
      page.locator('.toast-warning, .toast-success').first().waitFor({ state: 'visible', timeout: 15_000 }),
    ]);
    await expect(page.locator('.toast-error')).toHaveCount(0);

    const countAfter = await page.evaluate(async () =>
      await (window as any).go.services.TrustService.CertificateCount());

    expect(countAfter).toBeGreaterThanOrEqual(countBefore);
  });
});
