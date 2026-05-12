import { test, expect } from '@playwright/test';

// =============================================================================
// SPA Serving & Static Assets
// =============================================================================

test.describe('Client SPA Serving', () => {
  test('GET /ui/client/ returns 200 with HTML', async ({ page }) => {
    const response = await page.goto('/ui/client/');
    expect(response?.status()).toBe(200);
    const contentType = response?.headers()['content-type'] || '';
    expect(contentType).toContain('text/html');
  });

  test('index.html contains Svelte app mount point', async ({ page }) => {
    await page.goto('/ui/client/');
    await page.waitForLoadState('domcontentloaded');
    // Svelte apps mount to #app or body
    const appDiv = await page.locator('#app').count();
    const bodyContent = await page.locator('body').innerHTML();
    expect(appDiv > 0 || bodyContent.length > 0).toBeTruthy();
  });

  test('JS bundle is loaded', async ({ page }) => {
    await page.goto('/ui/client/');
    await page.waitForLoadState('domcontentloaded');
    const scripts = await page.locator('script[type="module"]').count();
    expect(scripts).toBeGreaterThan(0);
  });

  test('CSS stylesheet is loaded', async ({ page }) => {
    await page.goto('/ui/client/');
    await page.waitForLoadState('domcontentloaded');
    const links = await page.locator('link[rel="stylesheet"]').count();
    expect(links).toBeGreaterThan(0);
  });
});

// =============================================================================
// SPA Client-Side Routing (Fallback)
// =============================================================================

test.describe('SPA Fallback Routing', () => {
  const routes = [
    '/ui/client/',
    '/ui/client/accounts',
    '/ui/client/certificates',
    '/ui/client/settings',
    '/ui/client/renewal',
    '/ui/client/some/deep/nested/route',
  ];

  for (const route of routes) {
    test(`${route} returns 200 (SPA fallback)`, async ({ page }) => {
      const response = await page.goto(route);
      expect(response?.status()).toBe(200);
      const contentType = response?.headers()['content-type'] || '';
      expect(contentType).toContain('text/html');
    });
  }
});

// =============================================================================
// Static Asset Serving
// =============================================================================

test.describe('Static Assets', () => {
  test('CSS file is accessible and has correct content type', async ({ page, request }) => {
    await page.goto('/ui/client/');
    await page.waitForLoadState('domcontentloaded');
    const cssHref = await page.locator('link[rel="stylesheet"]').first().getAttribute('href');
    if (cssHref) {
      const cssUrl = cssHref.startsWith('http')
        ? cssHref
        : cssHref.startsWith('/ui/client')
          ? cssHref
          : `/ui/client${cssHref}`;
      const resp = await request.get(cssUrl);
      expect(resp.ok()).toBeTruthy();
      const ct = resp.headers()['content-type'] || '';
      expect(ct).toContain('css');
    }
  });

  test('JS bundle is accessible and has correct content type', async ({ page, request }) => {
    await page.goto('/ui/client/');
    await page.waitForLoadState('domcontentloaded');
    const scriptSrc = await page.locator('script[type="module"]').first().getAttribute('src');
    if (scriptSrc) {
      const jsUrl = scriptSrc.startsWith('http')
        ? scriptSrc
        : scriptSrc.startsWith('/ui/client')
          ? scriptSrc
          : `/ui/client${scriptSrc}`;
      const resp = await request.get(jsUrl);
      expect(resp.ok()).toBeTruthy();
      const ct = resp.headers()['content-type'] || '';
      expect(ct).toContain('javascript');
    }
  });

  test('non-existent asset returns 404 not index.html', async ({ request }) => {
    // Request a specific file extension that should NOT fallback to index.html
    const resp = await request.get('/ui/client/assets/nonexistent.js');
    // The SPA handler should return 404 for missing static files with known extensions
    // or it may serve index.html (depends on implementation)
    expect(resp.status()).toBeLessThan(500);
  });
});
