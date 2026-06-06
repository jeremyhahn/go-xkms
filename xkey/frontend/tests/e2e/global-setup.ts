// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Playwright global setup for the REAL-backend (Wails dev) run.
//
// The Wails-mode specs drive the real GUI against a freshly-initialized
// XKEY_HOME, where the app boots into the first-run setup wizard. Until the
// backend is initialized the specs cannot exercise real features.
//
// This hook initializes the shared Wails backend ONCE, deterministically, by
// calling the real `SetupWizardService.ApplySetup` API directly through the
// Wails binding — NOT by driving the wizard UI. Driving the UI was fragile, and
// because the app store defaults `setupComplete: true` (frontend/src/lib/
// stores/app.ts), the old hook reported success on an OPTIMISTIC sidebar
// without ever initializing the backend; fresh worker contexts then re-showed
// the wizard, making the suite order-dependent. Initializing through the real
// API and verifying `GetStartupState().setup_complete` makes every worker
// context see the unlocked main UI regardless of test ordering.
//
// In Vite UI-only mode (no BASE_URL) there is no backend, so the hook no-ops.
import { chromium, type FullConfig } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || '';
const SO_PIN = process.env.E2E_SO_PIN || '12345678';
const USER_PIN = process.env.E2E_USER_PIN || '123456';

export default async function globalSetup(_config: FullConfig): Promise<void> {
  if (!BASE_URL) {
    // Vite UI-only mode: no backend, no first-run state to resolve.
    return;
  }

  /* eslint-disable no-console */
  const log = (m: string) => console.log(`[global-setup] ${m}`);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  page.on('console', (m) => console.log(`[gs:page] ${m.type()}: ${m.text()}`.slice(0, 300)));
  try {
    log(`BASE_URL=${BASE_URL}`);
    await page.goto(BASE_URL, { waitUntil: 'domcontentloaded', timeout: 30_000 });

    // Wait for the real Wails runtime + the SetupWizardService binding.
    await page.waitForFunction(
      () =>
        typeof (window as { go?: { services?: { SetupWizardService?: { ApplySetup?: unknown } } } })
          .go?.services?.SetupWizardService?.ApplySetup === 'function',
      undefined,
      { timeout: 30_000 },
    );

    const setupComplete = async (): Promise<boolean> =>
      page.evaluate(async () => {
        const svc = (window as { go: { services: { SetupWizardService: { GetStartupState: () => Promise<{ setup_complete?: boolean }> } } } })
          .go.services.SetupWizardService;
        const s = await svc.GetStartupState();
        return !!s?.setup_complete;
      });

    if (await setupComplete()) {
      log('backend already initialized (setup_complete=true).');
      return;
    }

    // Deterministically initialize the backend via the real ApplySetup API.
    // The payload mirrors the wizard's defaultChoices (frontend/src/lib/stores/
    // wizard.ts) with a personal / software-passphrase profile and known PINs —
    // a software barrier avoids swtpm hierarchy-auth coupling and is stable.
    const result = await page.evaluate(
      async ({ soPin, userPin }) => {
        const choices = {
          mode: 'standalone',
          deployment_mode: 'personal',
          server_address: '',
          server_protocol: 'grpc',
          enable_storage: false,
          storage_size_gb: 2,
          storage_passphrase: '',
          enable_master_password: false,
          master_password: '',
          enable_platform_policy: true,
          tpm_seal_passwords: false,
          password_store_mode: 'aes_software',
          so_pin: soPin,
          user_pin: userPin,
          use_user_pin_as_master: true,
          save_pins_to_store: false,
          set_hierarchy_auth: false,
          storage_type: 'barrier',
          barrier_password: '',
          sealer_backend: 'passphrase',
          allow_extension: true,
          force_extension_auth: true,
          force_extension_pairing: true,
          force_extension_audit: true,
          allow_configure_extension: true,
          fido2_require_user_presence: true,
          fido2_user_intent_check: true,
          quick_setup: true,
        };
        const svc = (window as { go: { services: { SetupWizardService: { ApplySetup: (c: unknown) => Promise<{ success?: boolean; errors?: string[] }> } } } })
          .go.services.SetupWizardService;
        return svc.ApplySetup(choices);
      },
      { soPin: SO_PIN, userPin: USER_PIN },
    );
    log(`ApplySetup result: ${JSON.stringify(result).slice(0, 400)}`);

    // ApplySetup must genuinely succeed. The backend reports setup_complete=true
    // even on a PARTIAL init (e.g. SO PIN set but barrier init failed), so we
    // assert result.success here rather than trusting setup_complete — that is
    // exactly the false-positive that previously hid a broken first-boot.
    if (!(result as { success?: boolean })?.success) {
      throw new Error(`ApplySetup did not succeed: ${JSON.stringify(result).slice(0, 600)}`);
    }

    // Confirm a freshly-loaded page (the state every worker context will see)
    // reaches the unlocked main UI rather than the wizard or a lock overlay.
    await page.reload({ waitUntil: 'domcontentloaded' });
    const sidebar = await page
      .locator('nav.sidebar')
      .first()
      .isVisible({ timeout: 20_000 })
      .catch(() => false);
    if (!sidebar) {
      const body = (await page.locator('body').innerText().catch(() => '')).slice(0, 200).replace(/\s+/g, ' ');
      throw new Error(`setup_complete=true but sidebar not visible after reload. body="${body}"`);
    }
    log('SUCCESS: backend initialized via ApplySetup; main UI reachable on a fresh page.');
  } catch (e) {
    // Fail fast: a broken global-setup must abort the run loudly rather than
    // silently yield a flaky, order-dependent suite.
    log(`ERROR: ${(e as Error).message}`);
    await page.screenshot({ path: 'test-results/global-setup-final.png' }).catch(() => {});
    throw e;
  } finally {
    await browser.close();
  }
  /* eslint-enable no-console */
}
