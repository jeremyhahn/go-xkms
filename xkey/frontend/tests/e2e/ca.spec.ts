import { test, expect } from '@playwright/test';
import { waitForAppReady, ensureSidebarExpanded } from './helpers';

/**
 * Mock tier: the Certificate Authority view served by xKey's local CA with
 * no server connected. A window.go mock is installed before page load.
 */
test.describe('Certificate Authority view (mock)', () => {
  test.beforeEach(async ({ page }) => {
    // Install mock BEFORE goto so addInitScript fires on page load.
    await page.addInitScript(() => {
      (window as any).go = {
        services: {
          SetupWizardService: {
            GetStartupState: async () => ({
              setup_complete: true,
              enterprise_mode: false,
              enterprise_wizard_mode: '',
            }),
          },
          AppLockService: {
            GetStatus: async () => ({ is_locked: false }),
            RecordActivity: async () => {},
          },
          AuthService: {
            SetModeUser: async () => {},
          },
          AppService: {
            GetDeveloperTools: async () => false,
            GetConfig: async () => ({ theme: 'system', clipboard_timeout: 30 }),
          },
          CAService: {
            GetCAMode: async () => 'local',
            GetCAInfo: async () => ({
              subject: 'CN=xkey Local Root CA',
              issuer: 'CN=xkey Local Root CA',
              serial: '4242',
              algorithm: 'ECDSA',
              not_before: '2026-01-01T00:00:00Z',
              not_after: '2036-01-01T00:00:00Z',
              is_ca: true,
            }),
          },
        },
      };
    });
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  test('shows the local CA with no server connected', async ({ page }) => {
    const nav = page.locator('nav.sidebar button.nav-item', {
      has: page.locator('span.nav-label:text-is("Certificate Authority")'),
    });
    await nav.click();

    const view = page.locator('.view-container');
    await expect(view.getByText('Certificate Authority').first()).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId('ca-mode')).toHaveText('Local CA');
    await expect(view.getByText('CN=xkey Local Root CA').first()).toBeVisible();
  });
});
