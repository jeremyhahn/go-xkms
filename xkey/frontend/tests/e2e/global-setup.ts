// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Playwright global setup for the REAL-backend (Wails dev) run.
//
// The Wails-mode specs drive the real GUI against a freshly-initialized
// XKEY_HOME, where the app boots into the first-run setup wizard. Until the
// backend is initialized the specs cannot exercise real features.
// NOTE: a fresh XKEY_HOME alone is not sufficient — the GUI also reads
// bootstrap config from os.UserConfigDir() (~/.config/xkey/gui.json on
// Linux). Use `make dev-browser-e2e` which sets XDG_CONFIG_HOME as well,
// or a stale ~/.config/xkey/gui.json with setup_complete=true will send
// the app into an App-Locked screen that no PIN can unlock.
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
// UNLOCK GUARD (BASE_URL mode only):
// After setup is confirmed, this hook also checks the app-lock state and
// unlocks the backend if it auto-locked between runs. The app auto-locks after
// `app_auto_lock_minutes` of inactivity (default 15 min). After unlocking, the
// auto-lock timeout is set to 0 (disabled) for the duration of the suite so
// that long runs are not interrupted. The prior timeout value is written to
// test-results/auto-lock-prior.txt so that global-teardown.ts can restore it.
//
// NOTE: The e2e suite leaves auto-lock DISABLED on the shared dev backend for
// the duration of the run. This is intentional and acceptable for the e2e
// sandbox — a shared devserver is not a production device.
//
// In Vite UI-only mode (no BASE_URL) there is no backend, so the hook no-ops.
import * as fs from 'fs';
import * as path from 'path';
import { chromium, type FullConfig } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || '';
const SO_PIN = process.env.E2E_SO_PIN || '12345678';
const USER_PIN = process.env.E2E_USER_PIN || '123456';

// PKCS#11 sandbox fixture. `make dev-browser-e2e` provisions a sandboxed
// SoftHSM2 token store (via scripts/e2e-softhsm-setup.sh + SOFTHSM2_CONF) and
// runs test/e2e/setup-softhsm-piv.sh to create this exact token, pre-loaded
// with certificates in the four standard PIV slots (9A/9C/9D/9E). The PIN
// here matches setup-softhsm-piv.sh's USER_PIN constant.
const PKCS11_LIBRARY_PATH = process.env.E2E_PKCS11_LIBRARY || '/usr/lib/softhsm/libsofthsm2.so';
const PKCS11_TOKEN_LABEL = process.env.E2E_PKCS11_TOKEN_LABEL || 'e2e-piv-test';
const PKCS11_USER_PIN = process.env.E2E_PKCS11_PIN || '123456';

// Path where the prior auto-lock timeout is stashed for teardown restoration.
const PRIOR_LOCK_FILE = path.join(process.cwd(), 'test-results', 'auto-lock-prior.txt');

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
      // Fall through to the unlock guard below.
    } else {
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
            // Quick setup refuses to apply until the generated SO PIN is
            // acknowledged as recorded out of band (#290).
            so_pin_recorded: true,
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
    }

    // -------------------------------------------------------------------------
    // UNLOCK GUARD
    // The backend auto-locks after app_auto_lock_minutes of inactivity (default
    // 15 min). Any run against an auto-locked backend will fail with 602
    // blocked-by-overlay failures. We mirror exactly what AppLockOverlay.svelte
    // does: call AppLockService.GetStatus() to check, then AppLockService.Unlock(pin)
    // to clear the lock — which also unseals the barrier if it was sealed.
    // -------------------------------------------------------------------------

    // Wait for AppLockService to be available in the Wails binding.
    await page.waitForFunction(
      () =>
        typeof (window as { go?: { services?: { AppLockService?: { GetStatus?: unknown } } } })
          .go?.services?.AppLockService?.GetStatus === 'function',
      undefined,
      { timeout: 15_000 },
    );

    const lockStatus = await page.evaluate(async () => {
      const svc = (window as { go: { services: { AppLockService: { GetStatus: () => Promise<{ is_locked: boolean }> } } } })
        .go.services.AppLockService;
      return svc.GetStatus();
    });

    if (lockStatus?.is_locked) {
      log('backend is LOCKED — unlocking with E2E_USER_PIN...');
      const unlockResult = await page.evaluate(
        async ({ pin }) => {
          type VoidResult = { ok: boolean; error?: string };
          // AppLockService.Unlock mirrors callBackendVoidWithError — the Wails
          // binding returns null on success or throws/rejects on failure.
          try {
            const svc = (window as { go: { services: { AppLockService: { Unlock: (p: string) => Promise<null | { error?: string }> } } } })
              .go.services.AppLockService;
            await svc.Unlock(pin);
            return { ok: true } as VoidResult;
          } catch (e: unknown) {
            return { ok: false, error: (e as Error).message } as VoidResult;
          }
        },
        { pin: USER_PIN },
      );
      if (!unlockResult.ok) {
        throw new Error(`AppLockService.Unlock failed: ${unlockResult.error}`);
      }
      log('AppLockService.Unlock succeeded.');

      // Verify the lock was actually cleared.
      const postLockStatus = await page.evaluate(async () => {
        const svc = (window as { go: { services: { AppLockService: { GetStatus: () => Promise<{ is_locked: boolean }> } } } })
          .go.services.AppLockService;
        return svc.GetStatus();
      });
      if (postLockStatus?.is_locked) {
        throw new Error('Backend still reports is_locked=true after Unlock — wrong PIN or barrier failure?');
      }
      log('Lock cleared: is_locked=false confirmed.');
    } else {
      log('backend is not locked — no unlock needed.');
    }

    // -------------------------------------------------------------------------
    // DISABLE AUTO-LOCK for the duration of the suite
    // Record the prior timeout so global-teardown.ts can restore it.
    // SetAutoLockMinutes(0) disables the auto-lock timer.
    // This matches exactly what Settings.svelte does:
    //   await callBackendVoid('AppLockService', 'SetAutoLockMinutes', lockTimeout);
    // -------------------------------------------------------------------------

    // Wait for AppService.GetConfig to be available.
    await page.waitForFunction(
      () =>
        typeof (window as { go?: { services?: { AppService?: { GetConfig?: unknown } } } })
          .go?.services?.AppService?.GetConfig === 'function',
      undefined,
      { timeout: 10_000 },
    );

    const priorLockMinutes = await page.evaluate(async () => {
      const svc = (window as { go: { services: { AppService: { GetConfig: () => Promise<{ app_auto_lock_minutes?: number }> } } } })
        .go.services.AppService;
      const cfg = await svc.GetConfig();
      return cfg?.app_auto_lock_minutes ?? 15;
    });
    log(`prior app_auto_lock_minutes=${priorLockMinutes}; disabling auto-lock for suite run.`);

    // Persist the prior value for global-teardown.ts.
    fs.mkdirSync(path.dirname(PRIOR_LOCK_FILE), { recursive: true });
    fs.writeFileSync(PRIOR_LOCK_FILE, String(priorLockMinutes), 'utf8');

    // Disable auto-lock live (takes effect immediately in the running backend).
    await page.evaluate(async () => {
      const svc = (window as { go: { services: { AppLockService: { SetAutoLockMinutes: (m: number) => Promise<void> } } } })
        .go.services.AppLockService;
      await svc.SetAutoLockMinutes(0);
    });
    log('AppLockService.SetAutoLockMinutes(0) — auto-lock disabled.');

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

    // Confirm the lock overlay is absent on the freshly-loaded page.
    const lockOverlayVisible = await page
      .locator('[role="dialog"][aria-label="App locked"]')
      .isVisible({ timeout: 2_000 })
      .catch(() => false);
    if (lockOverlayVisible) {
      throw new Error('Lock overlay still visible after unlock + page reload — unlock did not take effect.');
    }

    // -------------------------------------------------------------------------
    // PKCS#11 SANDBOX PROVISIONING
    // `make dev-browser-e2e` provisions a sandboxed SoftHSM2 token (label
    // PKCS11_TOKEN_LABEL, pre-loaded with PIV certs) via scripts/
    // e2e-softhsm-setup.sh and points the Wails process at it with a
    // dedicated SOFTHSM2_CONF. This step drives the real PKCS11Service Wails
    // binding — exactly what the Admin "Add Backend" UI flow calls — to
    // register the module and log into the token, so every PKCS#11-gated
    // spec (FIDO2 backend selector, PIV slot loading) sees a live, connected
    // PKCS#11 backend instead of skipping. This is idempotent: reusing an
    // already-registered module / already-open connection is a no-op.
    // -------------------------------------------------------------------------
    await page.waitForFunction(
      () =>
        typeof (window as { go?: { services?: { PKCS11Service?: { IsAvailable?: unknown } } } })
          .go?.services?.PKCS11Service?.IsAvailable === 'function',
      undefined,
      { timeout: 15_000 },
    );

    const pkcs11Available = await page.evaluate(async () => {
      const svc = (window as { go: { services: { PKCS11Service: { IsAvailable: () => Promise<boolean> } } } })
        .go.services.PKCS11Service;
      return svc.IsAvailable();
    });

    if (!pkcs11Available) {
      throw new Error(
        'PKCS11Service.IsAvailable() returned false — the Wails binary was not built with the pkcs11 tag ' +
          '(check WITH_PKCS11 in the Makefile). PKCS#11 specs cannot run without it.',
      );
    }

    type Pkcs11Slot = { slot_id: number; label: string; token_present: boolean; initialized: boolean };
    type Pkcs11Module = { id: string; library_path: string; slots: Pkcs11Slot[] };
    type Pkcs11Connection = { module_id: string; slot_id: number; token_label: string };

    const findModuleAndSlot = async (): Promise<{ moduleId: string; slotId: number } | null> =>
      page.evaluate(
        async ({ libraryPath, tokenLabel }) => {
          const svc = (
            window as {
              go: { services: { PKCS11Service: { ListModules: () => Promise<Pkcs11Module[]> } } };
            }
          ).go.services.PKCS11Service;
          const modules = await svc.ListModules();
          for (const mod of modules) {
            if (mod.library_path !== libraryPath) continue;
            const slot = mod.slots.find((s) => s.label === tokenLabel && s.initialized);
            if (slot) return { moduleId: mod.id, slotId: slot.slot_id };
          }
          return null;
        },
        { libraryPath: PKCS11_LIBRARY_PATH, tokenLabel: PKCS11_TOKEN_LABEL },
      );

    let located = await findModuleAndSlot();
    if (!located) {
      log(`registering PKCS#11 module: ${PKCS11_LIBRARY_PATH}`);
      await page.evaluate(
        async ({ libraryPath }) => {
          const svc = (
            window as { go: { services: { PKCS11Service: { RegisterModule: (l: string, n: string) => Promise<string> } } } }
          ).go.services.PKCS11Service;
          await svc.RegisterModule(libraryPath, 'SoftHSM2 (e2e sandbox)');
        },
        { libraryPath: PKCS11_LIBRARY_PATH },
      );
      located = await findModuleAndSlot();
    }

    if (!located) {
      throw new Error(
        `PKCS#11 module registered but no initialized slot with token label "${PKCS11_TOKEN_LABEL}" was found. ` +
          'Was scripts/e2e-softhsm-setup.sh run before starting the backend (dev-browser-e2e runs it automatically)?',
      );
    }

    const { moduleId, slotId } = located;
    log(`PKCS#11 module located: module_id=${moduleId} slot_id=${slotId}`);

    const alreadyConnected = await page.evaluate(
      async ({ moduleId: mId, slotId: sId }) => {
        const svc = (
          window as { go: { services: { PKCS11Service: { ListConnections: () => Promise<Pkcs11Connection[]> } } } }
        ).go.services.PKCS11Service;
        const conns = await svc.ListConnections();
        return conns.some((c) => c.module_id === mId && c.slot_id === sId);
      },
      { moduleId, slotId },
    );

    if (alreadyConnected) {
      log('PKCS#11 token already connected — skipping Connect().');
    } else {
      log(`connecting to PKCS#11 token in slot ${slotId}...`);
      await page.evaluate(
        async ({ moduleId: mId, slotId: sId, pin }) => {
          const svc = (
            window as {
              go: { services: { PKCS11Service: { Connect: (m: string, s: number, pin: string, soPin: string) => Promise<void> } } };
            }
          ).go.services.PKCS11Service;
          await svc.Connect(mId, sId, pin, '');
        },
        { moduleId, slotId, pin: PKCS11_USER_PIN },
      );

      const connectedNow = await page.evaluate(
        async ({ moduleId: mId, slotId: sId }) => {
          const svc = (
            window as { go: { services: { PKCS11Service: { ListConnections: () => Promise<Pkcs11Connection[]> } } } }
          ).go.services.PKCS11Service;
          const conns = await svc.ListConnections();
          return conns.some((c) => c.module_id === mId && c.slot_id === sId);
        },
        { moduleId, slotId },
      );
      if (!connectedNow) {
        throw new Error('PKCS11Service.Connect() completed without throwing but ListConnections() shows no active session.');
      }
      log('PKCS#11 token connected.');
    }

    log('SUCCESS: backend initialized, unlocked, auto-lock disabled; main UI reachable on a fresh page.');
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
