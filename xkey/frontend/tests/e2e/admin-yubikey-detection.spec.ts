import { test, expect } from '@playwright/test';
import { navigateTo, waitForAppReady, ensureSidebarExpanded } from './helpers';

test.describe('Admin YubiKey detection', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'admin');
  });

  test('Admin view loads without page errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.waitForTimeout(500);
    expect(errors).toEqual([]);
  });

  test('YubiKey field name contract: Svelte reads lowercase JSON fields', async ({ page }) => {
    // This test verifies that the Svelte code uses lowercase field names
    // matching the Go struct JSON tags. We do this by checking the source
    // file content does NOT contain the wrong capitalized accessor pattern.
    const fs = await import('fs');
    const path = '/home/jhahn/sources/go-xkms/xkey/frontend/src/views/Admin.svelte';
    const content = fs.readFileSync(path, 'utf8');

    // The fix: should read result?.found, result?.library_path, result?.error
    // The bug: was reading result?.Found, result?.LibraryPath, result?.Error
    // We accept that result.LibraryPath as a Svelte VARIABLE name is OK,
    // but the OBJECT field accessor must use lowercase.

    // Find the DetectYubiKey block
    const detectMatch = content.match(/DetectYubiKey[\s\S]{0,500}/);
    expect(detectMatch).not.toBeNull();
    const block = detectMatch![0];

    // After the fix, these should NOT be present (they were the bug):
    expect(block).not.toMatch(/result\?\.Found\b/);
    expect(block).not.toMatch(/result\?\.LibraryPath\b/);
    expect(block).not.toMatch(/result\?\.Error\b/);

    // After the fix, these SHOULD be present (result?.found uses optional chaining;
    // result.library_path is accessed inside the if-guard, so no ?. is needed there):
    expect(block).toMatch(/result\?\.found\b/);
    expect(block).toMatch(/\.library_path\b/);
  });
});

test.describe('OIDC empty template state', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'oidc');
  });

  test('Add Provider dialog shows "Templates Unavailable" empty state in Vite mode', async ({ page }) => {
    // Click "Add Provider" button
    await page.getByRole('button', { name: 'Add Provider' }).first().click();

    // Dialog should open
    const dialog = page.locator('[role="dialog"]');
    await expect(dialog).toBeVisible();

    // The empty state should be visible
    await expect(page.locator('[data-testid="oidc-templates-unavailable"]')).toBeVisible();

    // Should NOT show any template cards
    const templateButtons = dialog.locator('.template-card');
    await expect(templateButtons).toHaveCount(0);
  });
});

test.describe('YubiKey FIDO2 capability suppression', () => {
  test('admin_service.go suppresses FIDO2 for YubiKey libykcs11 backends', async () => {
    const fs = await import('fs');
    const adminService = fs.readFileSync(
      '/home/jhahn/sources/go-xkms/xkey/pkg/gui/services/admin_service.go',
      'utf8'
    );
    // The fallback PKCS#11 builder must detect YubiKey by library path and
    // compute fido2Capable = !isYubiKey before populating BackendCapability.
    expect(adminService).toMatch(/libykcs11/);
    expect(adminService).toMatch(/fido2Capable/);
    expect(adminService).toMatch(/FIDO2:\s*fido2Capable/);
  });

  test('pkcs11mgr registerSlotBackends never sets CapFIDO2 for slot backends', async () => {
    const fs = await import('fs');
    const mgr = fs.readFileSync(
      '/home/jhahn/sources/go-xkms/xkey/pkg/pkcs11mgr/manager_impl.go',
      'utf8'
    );
    // Extract the registerSlotBackends function body and assert CapFIDO2 is
    // not present in its registered Capabilities map.
    const fnStart = mgr.indexOf('func (m *MemoryManager) registerSlotBackends');
    expect(fnStart).toBeGreaterThan(-1);
    const fnEnd = mgr.indexOf('\nfunc ', fnStart + 1);
    const body = mgr.slice(fnStart, fnEnd);
    expect(body).not.toMatch(/CapFIDO2:\s*true/);
  });
});
