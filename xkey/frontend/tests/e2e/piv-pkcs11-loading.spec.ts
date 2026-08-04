import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  waitForBackendReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';

/**
 * PKCS#11 PIV certificate loading tests.
 *
 * These tests verify that pre-existing certificates on a PKCS#11 token are
 * correctly displayed when the user selects the PKCS#11 backend in the PIV
 * page. This is a regression guard for the bug where pre-existing certs were
 * not shown after backend selection.
 *
 * Prerequisites:
 *   - SoftHSM2 token "e2e-piv-test" pre-populated via setup-softhsm-piv.sh
 *     (all four standard PIV slots loaded with test certificates). The
 *     PKCS#11 module is registered and connected by tests/e2e/global-setup.ts
 *     against the sandboxed SoftHSM2 config `make dev-browser-e2e` provisions
 *     (scripts/e2e-softhsm-setup.sh) — no Admin UI interaction is needed.
 *   - Wails backend running (tests skip in plain Vite mode)
 */
test.describe('PKCS#11 PIV Certificate Loading', () => {
  // Heal the SoftHSM2 fixture before this file's tests run, THROUGH the live
  // Wails backend's own PIVService binding — not by shelling out to
  // pkcs11-tool. SoftHSM2's default "file" objectstore backend caches a
  // process's view of a token's objects for the lifetime of that process's
  // PKCS#11 session; a separate CLI process writing new objects to the same
  // token file is a documented SoftHSM2 limitation (its docs recommend the
  // "db" backend for true concurrent multi-process access) and was verified
  // live here: pkcs11-tool saw newly-written objects immediately, but the
  // already-running Wails backend's PIVService.GetSlots() kept reporting
  // has_cert=false for the same slot indefinitely. Generating the
  // replacement certificate via PIVService.GenerateKey — the exact binding
  // the backend's own session uses — guarantees the write and every
  // subsequent read happen through the same process/session, so there is no
  // cross-process staleness. Other spec files sharing this backend (notably
  // piv-integration.spec.ts's "PKCS11 PIV Key Lifecycle" test) legitimately
  // consume slot 9A's fixture certificate as part of exercising key
  // generation on real PKCS#11 hardware; this hook restores whatever slots
  // are missing a certificate so the assertions below hold regardless of
  // what ran earlier in the suite.
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    try {
      await page.goto('/');
      await waitForAppReady(page);
      await waitForBackendReady(page);

      const wails = await isWailsMode(page).catch(() => false);
      if (!wails) return;

      type Pkcs11Module = { id: string; library_path: string };
      type PivSlot = { slot: string; has_cert: boolean };

      const moduleId = await page.evaluate(async () => {
        const svc = (window as { go?: { services?: { PKCS11Service?: { ListModules: () => Promise<Pkcs11Module[]> } } } })
          .go?.services?.PKCS11Service;
        const modules = (await svc?.ListModules?.()) ?? [];
        return modules.find((m) => m.library_path.includes('softhsm'))?.id ?? '';
      });
      if (!moduleId) return;

      await page.evaluate(
        async ({ id }) => {
          type PIVBinding = {
            SetBackend?: (backend: string) => Promise<void>;
            GetSlots?: () => Promise<PivSlot[]>;
            GenerateKey?: (slot: string, algorithm: string) => Promise<unknown>;
          };
          const piv = (window as { go?: { services?: { PIVService?: PIVBinding } } }).go?.services?.PIVService;
          if (!piv?.SetBackend || !piv.GetSlots || !piv.GenerateKey) return;
          await piv.SetBackend(id);
          const slots = await piv.GetSlots();
          for (const slotId of ['9A', '9C', '9D', '9E']) {
            const current = slots.find((s) => s.slot.toUpperCase() === slotId);
            if (current?.has_cert) continue;
            try {
              // RSA2048 avoids a separate, already-reported CKR_GENERAL_ERROR
              // on this SoftHSM build's CKM_EC_KEY_PAIR_GEN path; the tests
              // here only assert a certificate is present, not its algorithm.
              await piv.GenerateKey(slotId, 'RSA2048');
            } catch {
              // Best-effort — if generation fails the corresponding assertion
              // below will fail with clear evidence instead of silently
              // passing on stale data.
            }
          }
        },
        { id: moduleId },
      );
    } finally {
      await page.close();
    }
  });

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  // ---------------------------------------------------------------------------
  // Test 1: Pre-existing certificates are visible after backend selection
  // ---------------------------------------------------------------------------
  test('pre-existing PKCS#11 certificates are visible in PIV slots', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend for PKCS#11 PIV testing');

    await navigateTo(page, 'piv');
    await waitForLoadingComplete(page);

    // Select the PKCS#11 / SoftHSM backend chip. tests/e2e/global-setup.ts
    // registers and connects the sandboxed SoftHSM2 module for every
    // Wails-mode run, so the chip is already present — no Admin UI
    // registration flow is needed here.
    const backendChips = page.locator('.filter-chip, .backend-chip');
    const pkcs11Chip = backendChips.filter({ hasText: /PKCS|HSM|SoftHSM|softhsm/i });

    const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 5000 }).catch(() => false);
    test.skip(!hasPkcs11, 'PKCS#11 backend chip not available');

    await pkcs11Chip.first().click();
    await waitForLoadingComplete(page);

    // Slot 9A must be visible.
    const slot9a = page.locator('[data-testid="piv-slot-card-9A"], [data-testid="piv-slot-9a"]');
    await expect(slot9a).toBeVisible({ timeout: 10000 });

    // The slot must display certificate details — not the "No certificate" empty state.
    const certIndicator = slot9a.locator(
      '.slot-loaded, :has-text("PIV Authentication"), :has-text("RSA"), :has-text("ECDSA")',
    );
    await expect(certIndicator.first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Test 2: Switching away from PKCS#11 does not leave stale data or errors
  // ---------------------------------------------------------------------------
  test('switching away from PKCS#11 backend hides its certificates', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend');

    await navigateTo(page, 'piv');
    await waitForLoadingComplete(page);

    const backendChips = page.locator('.filter-chip, .backend-chip');
    const pkcs11Chip = backendChips.filter({ hasText: /PKCS|HSM|SoftHSM/i });
    const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 3000 }).catch(() => false);
    test.skip(!hasPkcs11, 'PKCS#11 backend not available');

    // Select PKCS#11 first.
    await pkcs11Chip.first().click();
    await waitForLoadingComplete(page);

    // Switch to the Software backend.
    const softwareChip = backendChips.filter({ hasText: /Software/i });
    if (await softwareChip.isVisible()) {
      await softwareChip.click();
      await waitForLoadingComplete(page);
    }

    // All five standard PIV slot cards must still be present (empty defaults).
    const slotCards = page.locator('[data-testid^="piv-slot-card-"]');
    const count = await slotCards.count();
    expect(count).toBe(5);

    // No error notifications must be visible.
    const errorNotif = page.locator('.notification.error, [data-testid="notification-error"]');
    await expect(errorNotif).not.toBeVisible();
  });

  // ---------------------------------------------------------------------------
  // Test 3: All four standard PIV slots show pre-loaded certificates
  // ---------------------------------------------------------------------------
  test('all four PIV slots show certificates from PKCS#11 token', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend for PKCS#11 PIV testing');

    // This test relies on setup-softhsm-piv.sh having populated slots
    // 9A, 9C, 9D, and 9E with test certificates using the YubiKey CKA_ID
    // convention (0x01–0x04).

    await navigateTo(page, 'piv');
    await waitForLoadingComplete(page);

    const backendChips = page.locator('.filter-chip, .backend-chip');
    const pkcs11Chip = backendChips.filter({ hasText: /PKCS|HSM|SoftHSM/i });
    const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 5000 }).catch(() => false);
    test.skip(!hasPkcs11, 'PKCS#11 backend not available');

    await pkcs11Chip.first().click();
    await waitForLoadingComplete(page);

    // Every standard PIV slot must have a loaded certificate indicator.
    for (const slotId of ['9A', '9C', '9D', '9E']) {
      const slot = page.locator(`[data-testid="piv-slot-card-${slotId}"]`);
      await expect(slot).toBeVisible({ timeout: 5000 });

      const loadedIndicator = slot.locator('.slot-loaded');
      await expect(loadedIndicator).toBeVisible({ timeout: 5000 });
    }
  });
});
