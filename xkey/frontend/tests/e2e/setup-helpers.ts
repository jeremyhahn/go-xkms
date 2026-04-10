import { type Page, expect } from '@playwright/test';

export { isWailsMode } from './helpers';

/**
 * Install a minimal mock of window.go so the Svelte app sees
 * isWailsAvailable() === true and receives a startup state with
 * setup_complete: false, which causes the SetupWizard to render
 * instead of the main application shell.
 *
 * Must be called BEFORE page.goto('/').
 */
export async function installWizardMock(page: Page): Promise<void> {
  await page.addInitScript(() => {
    (window as any).go = {
      services: {
        SetupWizardService: {
          GetStartupState: async () => ({
            setup_complete: false,
            enterprise_mode: false,
            enterprise_wizard_mode: '',
          }),
          ProbeEnvironment: async () => ({
            tpm_available: false,
            luks_available: false,
            platform: 'linux',
            server_address: '',
            barrier_strategies: [],
          }),
          GetPolicy: async () => null,
          SkipSetup: async () => {},
          ApplySetup: async () => ({
            success: true,
            errors: [],
            warnings: [],
          }),
        },
        AuthService: {
          SetModeUser: async () => {},
        },
        FIDO2DeviceService: {
          ApproveTouchRequest: async () => true,
        },
      },
    };
  });
}

/**
 * Wait for the setup wizard overlay and container to be visible.
 * Unlike waitForAppReady (which waits for nav.sidebar), this waits
 * for the wizard-specific DOM structure.
 */
export async function waitForSetupWizard(page: Page): Promise<void> {
  await page.waitForSelector('.wizard-overlay', { timeout: 15_000 });
  await page.waitForSelector('.wizard-container', { timeout: 5_000 });
  await page.waitForSelector('.step-content', { timeout: 5_000 });
}

/**
 * Get the current active step number from the progress step indicators.
 * The active step has the CSS class "active" on .progress-step.
 */
export async function getCurrentStep(page: Page): Promise<number> {
  const activeStep = page.locator('.progress-step.active .step-circle');
  await expect(activeStep).toBeVisible({ timeout: 5_000 });
  const text = await activeStep.textContent();
  return parseInt(text?.trim() ?? '0', 10);
}

/**
 * Click the "Next" navigation button in the wizard step actions.
 */
export async function clickNext(page: Page): Promise<void> {
  const nextBtn = page.locator('.step-actions .btn', { hasText: 'Next' });
  await nextBtn.click();
  await page.waitForTimeout(200);
}

/**
 * Click the "Back" navigation button in the wizard step actions.
 */
export async function clickBack(page: Page): Promise<void> {
  const backBtn = page.locator('.step-actions .btn', { hasText: 'Back' });
  await backBtn.click();
  await page.waitForTimeout(200);
}

/**
 * Select the Personal deployment mode by clicking its mode card.
 * This also advances to the next step (step 3) automatically.
 */
export async function selectPersonalMode(page: Page): Promise<void> {
  const personalCard = page.locator('.mode-card', { hasText: 'Personal' });
  await personalCard.click();
  await page.waitForTimeout(300);
}

/**
 * Select the Enterprise deployment mode by clicking its mode card.
 * This also advances to the next step (step 3) automatically.
 */
export async function selectEnterpriseMode(page: Page): Promise<void> {
  const enterpriseCard = page.locator('.mode-card', { hasText: 'Enterprise' });
  await enterpriseCard.click();
  await page.waitForTimeout(300);
}

/**
 * Fill the Security Officer PIN field in personal mode (step 4).
 */
export async function fillSOPin(page: Page, pin: string): Promise<void> {
  const input = page.locator('#wizard-so-pin');
  await input.fill(pin);
}

/**
 * Fill the Confirm SO PIN field in personal mode (step 4).
 */
export async function fillConfirmSOPin(page: Page, pin: string): Promise<void> {
  const input = page.locator('#wizard-so-pin-confirm');
  await input.fill(pin);
}

/**
 * Fill the User PIN field in personal mode (step 4).
 */
export async function fillUserPin(page: Page, pin: string): Promise<void> {
  const input = page.locator('#wizard-user-pin');
  await input.fill(pin);
}

/**
 * Fill the Confirm User PIN field in personal mode (step 4).
 */
export async function fillConfirmUserPin(page: Page, pin: string): Promise<void> {
  const input = page.locator('#wizard-user-pin-confirm');
  await input.fill(pin);
}

/**
 * Fill the Enterprise SO PIN field (step 3 enterprise flow).
 */
export async function fillEnterpriseSoPin(page: Page, pin: string): Promise<void> {
  const input = page.locator('#wizard-enterprise-so-pin');
  await input.fill(pin);
}

/**
 * Fill the Enterprise Confirm SO PIN field (step 3 enterprise flow).
 */
export async function fillEnterpriseConfirmSoPin(page: Page, pin: string): Promise<void> {
  const input = page.locator('#wizard-enterprise-so-pin-confirm');
  await input.fill(pin);
}

/**
 * Get the text content of the security error banner (.info-banner.warning),
 * or null if no error banner is visible.
 */
export async function getSecurityError(page: Page): Promise<string | null> {
  const banner = page.locator('.info-banner.warning');
  const count = await banner.count();
  if (count === 0) return null;
  const visible = await banner.first().isVisible().catch(() => false);
  if (!visible) return null;
  return banner.first().textContent();
}

/**
 * Get the text content of a field-level error (.field-error),
 * or null if no field error is visible.
 */
export async function getFieldError(page: Page): Promise<string | null> {
  const fieldError = page.locator('.field-error');
  const count = await fieldError.count();
  if (count === 0) return null;
  const visible = await fieldError.first().isVisible().catch(() => false);
  if (!visible) return null;
  return fieldError.first().textContent();
}
