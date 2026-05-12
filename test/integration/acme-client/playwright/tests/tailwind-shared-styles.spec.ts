import { test, expect, type Page } from '@playwright/test';

// =============================================================================
// Tailwind shared-package class generation regression tests
//
// These tests guard against the bug where Tailwind v4 skips scanning
// packages/shared/src because workspace packages are treated as external
// dependencies. Without the @source directive in app.css, utility classes
// used only in shared components (Toast, Button, Sidebar) are absent from
// the generated CSS, causing broken rendering.
//
// Each test asserts a concrete visual property in computed style or bounding
// box so a missing CSS class produces a real failure, not just a DOM check.
// =============================================================================

async function loadSPA(page: Page): Promise<void> {
  await page.goto('/ui/client/', { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.locator('aside').first().waitFor({ state: 'visible', timeout: 10000 });
}

async function navigateTo(page: Page, navLabel: string): Promise<void> {
  await page.getByRole('navigation').getByText(navLabel, { exact: true }).click();
  await page.waitForTimeout(300);
}

// Inject a toast notification by calling the exported addNotification function
// through Svelte's module system, which is accessible on the window via Vite's
// dev/build output. If the direct store path is unavailable, we fall back to
// triggering the Register form error path, which always dispatches a toast.
async function triggerErrorToast(page: Page): Promise<void> {
  // Attempt to inject via the store export that the SPA exposes on window (dev server).
  const injected = await page.evaluate(async (): Promise<boolean> => {
    // Svelte stores are not automatically exposed, so we navigate the module
    // graph via the __sveltekit__ or vite module registry when available.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const w = window as any;
    if (w.__notifyError) {
      w.__notifyError('Regression test error toast');
      return true;
    }
    return false;
  });

  if (!injected) {
    // Reliable fallback: submit the Register form (email + TOS checked) against
    // a server that is not a real ACME CA. The client always dispatches an error
    // toast on a failed registration POST.
    await navigateTo(page, 'Register');
    await page.waitForTimeout(300);

    const main = page.locator('main');
    const emailInput = main
      .locator('input[type="email"], input[placeholder*="email" i], input[name*="email" i]')
      .first();
    await emailInput.fill('toast-regression@test.local');

    const tosCheckbox = main.locator('input[type="checkbox"]').first();
    if (!(await tosCheckbox.isChecked())) {
      await tosCheckbox.check();
    }
    await page.waitForTimeout(200);

    const registerBtn = main.getByRole('button', { name: /register/i }).first();
    await registerBtn.click();
  }
}

// =============================================================================
// Toast icon sizing (h-5 w-5 from shared Toast.svelte)
// =============================================================================

test.describe('Toast icon is sized correctly by Tailwind utility classes', () => {
  test('error toast SVG icon width is <= 32px (h-5 w-5 == 20px intent)', async ({ page }) => {
    await loadSPA(page);
    await triggerErrorToast(page);

    // Wait for the toast container to render an alert element.
    const alert = page.locator('[role="alert"]').first();
    await alert.waitFor({ state: 'visible', timeout: 8000 });

    // The first SVG inside the alert is the type icon rendered by Toast.svelte.
    const iconSvg = alert.locator('svg').first();
    await iconSvg.waitFor({ state: 'visible', timeout: 5000 });

    const box = await iconSvg.boundingBox();
    expect(box).not.toBeNull();

    // h-5 w-5 computes to 20px. Without the Tailwind class the SVG inherits
    // the default SVG viewport dimensions (~150px×150px or the viewBox value).
    // We allow up to 32px to absorb sub-pixel and zoom variation.
    expect(box!.width).toBeLessThan(32);
    expect(box!.height).toBeLessThan(32);
  });

  test('error toast SVG icon is not oversized (> 100px signals missing h-5 w-5)', async ({
    page,
  }) => {
    await loadSPA(page);
    await triggerErrorToast(page);

    const alert = page.locator('[role="alert"]').first();
    await alert.waitFor({ state: 'visible', timeout: 8000 });

    const iconSvg = alert.locator('svg').first();
    const box = await iconSvg.boundingBox();
    expect(box).not.toBeNull();
    // Guard: if the class was completely missing the browser would render it at
    // the SVG default (≥ 150px). Fail loudly at 100px to give headroom for
    // unusual but valid large-display environments.
    expect(box!.width).toBeLessThan(100);
  });
});

// =============================================================================
// Primary button background color (bg-blue-600 from shared Button.svelte)
// =============================================================================

test.describe('Primary Button has styled background color', () => {
  test('Register button has non-transparent computed background-color', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Register');
    await page.waitForTimeout(500);

    const main = page.locator('main');

    // Enable the button so it is not grayed-out by the disabled style.
    const emailInput = main
      .locator('input[type="email"], input[placeholder*="email" i], input[name*="email" i]')
      .first();
    await emailInput.fill('style-check@test.local');

    const tosCheckbox = main.locator('input[type="checkbox"]').first();
    if (!(await tosCheckbox.isChecked())) {
      await tosCheckbox.check();
    }
    await page.waitForTimeout(200);

    const registerBtn = main.getByRole('button', { name: /register/i }).first();

    // Read computed background-color from the browser. A missing bg-blue-600
    // class means the button falls back to the UA default which is transparent
    // or rgba(0,0,0,0). A styled button will have an opaque RGB value.
    const bgColor = await registerBtn.evaluate((el: Element) => {
      return window.getComputedStyle(el).backgroundColor;
    });

    // rgba(0,0,0,0) or "transparent" both indicate no background was applied.
    expect(bgColor).not.toBe('rgba(0, 0, 0, 0)');
    expect(bgColor).not.toBe('transparent');
    expect(bgColor.length).toBeGreaterThan(0);

    // The primary variant uses bg-blue-600 which produces an rgb with a dominant
    // blue channel. We verify it is not an achromatic grey (r==g==b) which would
    // indicate the class was applied but with the wrong value, or the default
    // button colour on some platforms.
    const match = bgColor.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
    if (match) {
      const [, r, g, b] = match.map(Number);
      // bg-blue-600 in oklch converts to approximately rgb(37, 99, 235).
      // Blue channel must dominate over red for any reasonable blue shade.
      expect(b).toBeGreaterThan(r);
    }
  });

  test('Enroll Device button has non-transparent background-color', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Enroll');
    await page.waitForTimeout(500);

    const main = page.locator('main');
    const submitBtn = main.getByRole('button', { name: /enroll device/i }).first();

    const bgColor = await submitBtn.evaluate((el: Element) => {
      return window.getComputedStyle(el).backgroundColor;
    });

    expect(bgColor).not.toBe('rgba(0, 0, 0, 0)');
    expect(bgColor).not.toBe('transparent');
  });
});

// =============================================================================
// Sidebar width (w-64 == 256px from shared Sidebar.svelte)
// =============================================================================

test.describe('Sidebar width respects Tailwind w-64 class', () => {
  test('sidebar <aside> element is >= 240px wide in expanded state', async ({ page }) => {
    await loadSPA(page);

    const sidebar = page.locator('aside').first();
    await sidebar.waitFor({ state: 'visible', timeout: 10000 });

    const box = await sidebar.boundingBox();
    expect(box).not.toBeNull();

    // w-64 == 256px. We allow ±16px for border, padding, or sub-pixel rendering.
    // If the class is missing the sidebar collapses to content width (often < 100px).
    expect(box!.width).toBeGreaterThanOrEqual(240);
  });

  test('sidebar <aside> is narrower than 320px (guards against runaway layout)', async ({
    page,
  }) => {
    await loadSPA(page);

    const sidebar = page.locator('aside').first();
    const box = await sidebar.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBeLessThan(320);
  });
});
