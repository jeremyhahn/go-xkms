import { type Page, test as baseTest } from '@playwright/test';

/**
 * Environment variables the live-backend tests read. When any required
 * variable is missing the test suite skips cleanly instead of failing,
 * so running `npx playwright test` without a live stack is a no-op
 * rather than a noisy failure.
 */
export interface LiveEnv {
  restURL: string;
  spkiPin: string;
  noiseAddr: string;
  noiseKey: string;
  caPemPath: string;
}

/**
 * readLiveEnv reads the live-backend environment variables and returns
 * them, or null if any required variable is unset.
 */
export function readLiveEnv(): LiveEnv | null {
  const restURL = process.env.LIVE_XKMS_REST_URL;
  const spkiPin = process.env.LIVE_XKMS_SPKI_PIN;
  const noiseAddr = process.env.LIVE_XKMS_NOISE_ADDR;
  const noiseKey = process.env.LIVE_XKMS_NOISE_KEY;
  const caPemPath = process.env.LIVE_XKMS_CA_PEM;
  if (!restURL || !spkiPin || !noiseAddr || !noiseKey || !caPemPath) {
    return null;
  }
  return { restURL, spkiPin, noiseAddr, noiseKey, caPemPath };
}

/**
 * requireLiveEnv marks the current test as skipped when the live-backend
 * environment is not configured. Call inside beforeAll (or beforeEach)
 * of a describe block that exercises the real backend.
 */
export function requireLiveEnv(): LiveEnv {
  const env = readLiveEnv();
  if (!env) {
    baseTest.skip(true,
      'LIVE_XKMS_* env vars not set — start the dev server and export the ' +
      'variables emitted by `make dev-server-info`, then rerun.');
    // Unreachable, but keeps the type checker happy.
    throw new Error('skip');
  }
  return env;
}

/**
 * waitForBackendReady blocks until window.go.services is populated.
 * Fails fast if we are accidentally running against vite dev (no
 * window.go) so nobody mistakes a mocked run for a live one.
 */
export async function waitForBackendReady(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as any;
      return w.go && w.go.services && typeof w.go.services === 'object';
    },
    { timeout: 15_000 },
  );
}

/**
 * assertLiveWailsMode guards against a misconfigured run where the test
 * is accidentally targeting the vite dev server. If it passes we know
 * we're exercising the real Go backend.
 */
export async function assertLiveWailsMode(page: Page): Promise<void> {
  const mode = await page.evaluate(() => {
    const w = window as any;
    if (!w.go) return 'no-wails';
    if (!w.go.services) return 'partial-wails';
    if (!w.go.services.TrustService) return 'missing-trust-service';
    return 'live';
  });
  if (mode !== 'live') {
    throw new Error(
      `expected live Wails backend, got ${mode} — make sure \`wails dev\` ` +
      `is running and BASE_URL points at it (default http://localhost:34115)`,
    );
  }
}
