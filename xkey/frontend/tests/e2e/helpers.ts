import { type Page, type BrowserContext, expect } from '@playwright/test';

/**
 * View identifiers that correspond to the sidebar navigation items
 * defined in App.svelte navItems[].
 */
export type ViewId =
  | 'dashboard'
  | 'pairing'
  | 'keys'
  | 'fido2'
  | 'oath'
  | 'oidc'
  | 'piv'
  | 'tpm'
  | 'passwords'
  | 'seal'
  | 'audit-log'
  | 'api-explorer'
  | 'admin'
  | 'settings'
  | 'trust-store';

/**
 * Human-readable labels for each navigation item.
 * These must match the `label` property in App.svelte navItems[].
 */
export const VIEW_LABELS: Record<ViewId, string> = {
  dashboard: 'Dashboard',
  pairing: 'Pairing',
  keys: 'Keys',
  fido2: 'FIDO2',
  oath: 'OATH',
  oidc: 'OIDC',
  piv: 'PIV',
  tpm: 'TPM 2.0',
  passwords: 'Passwords',
  seal: 'Sealed Data',
  'audit-log': 'Audit Log',
  'api-explorer': 'API Explorer',
  admin: 'Admin',
  settings: 'Settings',
  'trust-store': 'Trust Store',
};

/**
 * The expected GradientHeader title for each view.
 * Used to verify the correct view has loaded after navigation.
 */
export const VIEW_TITLES: Record<ViewId, string> = {
  dashboard: 'xKey',
  pairing: 'Pairing',
  keys: 'Key Management',
  fido2: 'FIDO2',
  oath: 'OATH Accounts',
  oidc: 'OIDC',
  piv: 'PIV Smart Card',
  tpm: 'TPM 2.0',
  passwords: 'Passwords',
  seal: 'Sealed Data',
  'audit-log': 'Audit Log',
  'api-explorer': 'API Explorer',
  admin: 'Admin',
  settings: 'Settings',
  'trust-store': 'Trust Store',
};

/**
 * Navigate to a specific view by clicking the sidebar nav button.
 *
 * The sidebar uses <button class="nav-item"> with a <span class="nav-label">
 * that contains the view label text. Settings and Theme are in the sidebar footer.
 */
export async function navigateTo(page: Page, view: ViewId): Promise<void> {
  const label = VIEW_LABELS[view];
  const navButton = page.locator('nav.sidebar button.nav-item', {
    has: page.locator(`span.nav-label:text-is("${label}")`),
  });
  await navButton.click();
  // Wait for the view container content to settle.
  await page.waitForTimeout(300);
}

/**
 * Wait for the application shell to be ready.
 *
 * Checks that the sidebar navigation and main content area are present.
 * This does NOT require the Wails backend bridge to be available;
 * when running against the Vite dev server the UI renders in standalone
 * mode without backend calls.
 */
export async function waitForAppReady(page: Page): Promise<void> {
  await page.waitForSelector('nav.sidebar', { timeout: 15_000 });
  await page.waitForSelector('.main-content', { timeout: 5_000 });
}

/**
 * Verify that the sidebar is not in collapsed state so text labels are visible.
 * If collapsed, expand it by clicking the sidebar toggle button.
 */
export async function ensureSidebarExpanded(page: Page): Promise<void> {
  const shell = page.locator('.app-shell');
  const isCollapsed = await shell.evaluate(
    (el) => el.classList.contains('sidebar-collapsed'),
  );
  if (isCollapsed) {
    await page.locator('button.sidebar-toggle').click();
    await page.waitForTimeout(300);
  }
}

/**
 * Get the currently active navigation item label from the sidebar.
 */
export async function getActiveNavLabel(page: Page): Promise<string | null> {
  const activeItem = page.locator('nav.sidebar button.nav-active span.nav-label');
  const count = await activeItem.count();
  if (count === 0) return null;
  return activeItem.first().textContent();
}

/**
 * Get the main view container element.
 */
export function getViewContainer(page: Page) {
  return page.locator('.view-container');
}

/**
 * Wait for a GradientHeader with the specified title text.
 */
export async function waitForViewTitle(page: Page, title: string): Promise<void> {
  await expect(
    page.locator('.view-container').getByText(title, { exact: false }).first(),
  ).toBeVisible({ timeout: 10_000 });
}

/**
 * Check if the current page is running in Wails mode (window.go is defined).
 * Returns true if the Wails runtime bridge is available.
 */
export async function isWailsMode(page: Page): Promise<boolean> {
  return page.evaluate(() => typeof (window as any).go !== 'undefined');
}

/**
 * Wait for the Wails backend services to be defined on `window.go`.
 * Times out after 10 seconds if the backend is not available.
 * Call this only when you already know the page is in Wails mode.
 */
export async function waitForBackendReady(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as any;
      return w.go && w.go.main;
    },
    { timeout: 10_000 },
  );
}

/**
 * Open a 2FA QR code generator site in a new tab and generate a test QR code.
 * Returns the new Page handle. The caller is responsible for closing the page.
 *
 * This uses the public stefansundin 2fa-qr tool to create a visible QR code
 * on screen, which the OATHService.ScanQR backend method can detect.
 */
export async function openQRCodePage(context: BrowserContext): Promise<Page> {
  const qrPage = await context.newPage();
  await qrPage.goto('https://stefansundin.github.io/2fa-qr/', {
    waitUntil: 'domcontentloaded',
    timeout: 15_000,
  });
  // Fill in the URI to generate a QR code
  const uriInput = qrPage.locator('#uri');
  await uriInput.fill('otpauth://totp/TestIssuer:testuser@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestIssuer&digits=6&period=30');
  // Wait for the QR code canvas or img to render
  await qrPage.waitForTimeout(1000);
  return qrPage;
}

/**
 * Navigate to a settings category by clicking the settings nav sidebar button.
 */
export async function navigateToSettingsCategory(
  page: Page,
  category: string,
): Promise<void> {
  await page
    .locator('.settings-nav')
    .getByRole('button', { name: category })
    .click();
  await page.waitForTimeout(300);
}

/**
 * Navigate to a TPM category by clicking the TPM nav sidebar button.
 */
export async function navigateToTPMCategory(
  page: Page,
  categoryLabel: string,
): Promise<void> {
  const navItem = page.locator('.tpm-nav .tpm-nav-item', {
    hasText: categoryLabel,
  });
  await navItem.click();
  await page.waitForTimeout(300);
}

/**
 * Wait for async data loading to complete by waiting for any loading spinners
 * to disappear.
 */
export async function waitForLoadingComplete(page: Page): Promise<void> {
  // Wait for loading spinners to disappear (give them time to appear first)
  await page.waitForTimeout(300);
  const spinner = page.locator('.loading-spinner, .loading-container');
  const spinnerCount = await spinner.count();
  if (spinnerCount > 0) {
    await spinner.first().waitFor({ state: 'hidden', timeout: 10_000 }).catch(() => {
      // Spinner may have already gone
    });
  }
}

// ── FIDO2-specific helpers ──────────────────────────────────────────────

export type FIDO2Tab = 'credentials' | 'bridge' | 'relying-parties';

/**
 * Navigate to the FIDO2 view and wait for it to load.
 */
export async function navigateToFIDO2(page: Page): Promise<void> {
  await navigateTo(page, 'fido2');
  await expect(page.locator('[data-testid="fido2-view"]')).toBeVisible({ timeout: 5_000 });
}

/**
 * Switch to a FIDO2 tab by its data-testid.
 */
export async function switchFIDO2Tab(page: Page, tab: FIDO2Tab): Promise<void> {
  await page.locator(`[data-testid="tab-${tab}"]`).click();
  await page.waitForTimeout(200);
}

/**
 * Get the current authenticator status from the banner.
 */
export async function getAuthenticatorStatus(
  page: Page,
): Promise<'running' | 'disabled' | 'unknown'> {
  const banner = page.locator('[data-testid="fido2-status-banner"]');
  const count = await banner.count();
  if (count === 0) return 'unknown';
  const text = await banner.textContent();
  if (text?.includes('Authenticator Running')) return 'running';
  if (text?.includes('Authenticator Disabled')) return 'disabled';
  return 'unknown';
}

/**
 * Wait for a specific number of credential cards to appear.
 */
export async function waitForCredentialCount(
  page: Page,
  count: number,
): Promise<void> {
  if (count === 0) {
    await expect(page.getByText('No FIDO2 Credentials')).toBeVisible({ timeout: 5_000 });
  } else {
    await expect(
      page.locator('[data-testid="fido2-credential-list"] [data-testid^="fido2-credential-card-"]'),
    ).toHaveCount(count, { timeout: 5_000 });
  }
}
