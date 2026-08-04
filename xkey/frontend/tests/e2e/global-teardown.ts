// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Playwright global teardown for the REAL-backend (Wails dev) run.
//
// Restores the app_auto_lock_minutes setting that global-setup.ts disabled
// (set to 0) before the suite began. The prior value is read from
// test-results/auto-lock-prior.txt, which global-setup.ts writes. If the file
// is absent (Vite UI-only mode or the setup did not run), this teardown is a
// no-op.
//
// The restore call mirrors exactly what Settings.svelte does:
//   AppLockService.SetAutoLockMinutes(priorMinutes)
import * as fs from 'fs';
import * as path from 'path';
import { chromium, type FullConfig } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || '';
const PRIOR_LOCK_FILE = path.join(process.cwd(), 'test-results', 'auto-lock-prior.txt');

export default async function globalTeardown(_config: FullConfig): Promise<void> {
  if (!BASE_URL) {
    return;
  }
  if (!fs.existsSync(PRIOR_LOCK_FILE)) {
    return;
  }

  /* eslint-disable no-console */
  const log = (m: string) => console.log(`[global-teardown] ${m}`);

  const raw = fs.readFileSync(PRIOR_LOCK_FILE, 'utf8').trim();
  const priorMinutes = parseInt(raw, 10);
  if (isNaN(priorMinutes)) {
    log(`WARN: could not parse prior auto-lock value "${raw}" — skipping restore.`);
    return;
  }

  log(`restoring app_auto_lock_minutes=${priorMinutes} on ${BASE_URL}`);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  try {
    await page.goto(BASE_URL, { waitUntil: 'domcontentloaded', timeout: 30_000 });

    // Wait for AppLockService to be available.
    await page.waitForFunction(
      () =>
        typeof (window as { go?: { services?: { AppLockService?: { SetAutoLockMinutes?: unknown } } } })
          .go?.services?.AppLockService?.SetAutoLockMinutes === 'function',
      undefined,
      { timeout: 15_000 },
    );

    await page.evaluate(
      async ({ minutes }) => {
        const svc = (window as { go: { services: { AppLockService: { SetAutoLockMinutes: (m: number) => Promise<void> } } } })
          .go.services.AppLockService;
        await svc.SetAutoLockMinutes(minutes);
      },
      { minutes: priorMinutes },
    );
    log(`AppLockService.SetAutoLockMinutes(${priorMinutes}) restored.`);

    // Clean up the stash file — it is only valid for one suite run.
    fs.unlinkSync(PRIOR_LOCK_FILE);
  } catch (e) {
    log(`WARN: teardown restore failed (non-fatal): ${(e as Error).message}`);
  } finally {
    await browser.close();
  }
  /* eslint-enable no-console */
}
