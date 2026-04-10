import { test, expect } from '@playwright/test';
import {
  installWizardMock,
  waitForSetupWizard,
  getCurrentStep,
  clickNext,
  clickBack,
  selectPersonalMode,
  selectEnterpriseMode,
  fillSOPin,
  fillConfirmSOPin,
  fillUserPin,
  fillConfirmUserPin,
  fillEnterpriseSoPin,
  fillEnterpriseConfirmSoPin,
  getSecurityError,
  getFieldError,
  isWailsMode,
} from './setup-helpers';

test.describe('Setup Wizard - Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await installWizardMock(page);
    await page.goto('/');
    await waitForSetupWizard(page);
  });

  test('wizard shows step content when loaded', async ({ page }) => {
    const stepContent = page.locator('.step-content');
    await expect(stepContent).toBeVisible();

    // Welcome step should show the headline
    await expect(page.getByText('Welcome to xKey')).toBeVisible();
  });

  test('step indicators display correctly on first step', async ({ page }) => {
    const progressSteps = page.locator('.progress-step');
    // Before deployment mode is chosen, wizard shows 6 steps for personal
    // or the limited set. At minimum step 1 and 2 are visible.
    const count = await progressSteps.count();
    expect(count).toBeGreaterThanOrEqual(2);

    // Step 1 should be active
    const step = await getCurrentStep(page);
    expect(step).toBe(1);
  });

  test('Next button advances from Welcome to Deployment step', async ({ page }) => {
    const step1 = await getCurrentStep(page);
    expect(step1).toBe(1);

    await clickNext(page);

    // Should now be on step 2 - Deployment Mode
    await expect(page.getByText('Deployment Mode')).toBeVisible();
  });

  test('Back button returns to previous step', async ({ page }) => {
    // Go to step 2
    await clickNext(page);
    await expect(page.getByText('Deployment Mode')).toBeVisible();

    // Go back to step 1
    await clickBack(page);
    await expect(page.getByText('Welcome to xKey')).toBeVisible();
  });

  test('selecting Personal mode advances to step 3', async ({ page }) => {
    // Go to step 2
    await clickNext(page);
    await expect(page.getByText('Deployment Mode')).toBeVisible();

    // Select Personal
    await selectPersonalMode(page);

    // Should advance to step 3 - Operating Mode
    await expect(page.getByText('Operating Mode')).toBeVisible();
  });

  test('selecting Enterprise mode advances to step 3', async ({ page }) => {
    // Go to step 2
    await clickNext(page);
    await expect(page.getByText('Deployment Mode')).toBeVisible();

    // Select Enterprise
    await selectEnterpriseMode(page);

    // Should advance to step 3 - Security Policy
    await expect(page.getByRole('heading', { name: 'Security Policy' })).toBeVisible();
  });
});

test.describe('Setup Wizard - Personal Mode PIN Validation', () => {
  test.beforeEach(async ({ page }) => {
    await installWizardMock(page);
    await page.goto('/');
    await waitForSetupWizard(page);

    // Navigate: Welcome -> Deployment -> Personal -> Operating Mode -> Security
    await clickNext(page); // step 2
    await selectPersonalMode(page); // step 3
    await clickNext(page); // step 4 - Security
    await expect(page.getByText('PIN Management')).toBeVisible();
  });

  test('SO PIN field is visible and requires minimum 6 characters', async ({ page }) => {
    const soPin = page.locator('#wizard-so-pin');
    await expect(soPin).toBeVisible();

    // Fill short PIN then try Next - should show error
    await fillSOPin(page, '123');
    await fillConfirmSOPin(page, '123');
    await fillUserPin(page, '123456');
    await fillConfirmUserPin(page, '123456');

    // Click Next - should trigger validation error for short SO PIN
    const nextBtn = page.locator('.step-actions .btn', { hasText: 'Next' });
    await nextBtn.click();
    await page.waitForTimeout(200);

    const error = await getSecurityError(page);
    expect(error).toBeTruthy();
    expect(error).toContain('SO PIN');
  });

  test('User PIN field is visible and requires minimum 6 characters', async ({ page }) => {
    // Fill valid SO PIN but short User PIN
    await fillSOPin(page, '123456');
    await fillConfirmSOPin(page, '123456');
    await fillUserPin(page, '12');
    await fillConfirmUserPin(page, '12');

    const nextBtn = page.locator('.step-actions .btn', { hasText: 'Next' });
    await nextBtn.click();
    await page.waitForTimeout(200);

    const error = await getSecurityError(page);
    expect(error).toBeTruthy();
    expect(error).toContain('User PIN');
  });

  test('SO PIN confirm mismatch shows field error', async ({ page }) => {
    await fillSOPin(page, '123456');
    await fillConfirmSOPin(page, '654321');

    // The inline field error should appear
    const fieldErr = await getFieldError(page);
    expect(fieldErr).toBeTruthy();
    expect(fieldErr).toContain('PINs do not match');
  });

  test('User PIN confirm mismatch shows field error', async ({ page }) => {
    await fillUserPin(page, '123456');
    await fillConfirmUserPin(page, '654321');

    const fieldErr = await getFieldError(page);
    expect(fieldErr).toBeTruthy();
    expect(fieldErr).toContain('PINs do not match');
  });

  test('field error clears when user types in the confirm field', async ({ page }) => {
    // Create a mismatch
    await fillSOPin(page, '123456');
    await fillConfirmSOPin(page, '000000');

    // Error should appear
    let fieldErr = await getFieldError(page);
    expect(fieldErr).toContain('PINs do not match');

    // Type the correct confirm value
    await fillConfirmSOPin(page, '123456');

    // Error should disappear
    const fieldError = page.locator('.field-error');
    const visible = await fieldError.first().isVisible().catch(() => false);
    // If the first field error is gone or matches, the SO PIN error cleared
    if (visible) {
      const text = await fieldError.first().textContent();
      // It could be a user PIN mismatch if user PIN confirm was also filled,
      // but the SO PIN field error should be gone since they now match.
      // We just verify the SO PIN specific mismatch is resolved.
      expect(text).not.toContain('PINs do not match');
    }
  });

  test('cannot proceed with mismatched SO PIN confirmation', async ({ page }) => {
    await fillSOPin(page, '123456');
    await fillConfirmSOPin(page, '000000');
    await fillUserPin(page, '654321');
    await fillConfirmUserPin(page, '654321');

    // Click Next
    const nextBtn = page.locator('.step-actions .btn', { hasText: 'Next' });
    await nextBtn.click();
    await page.waitForTimeout(200);

    // Should show security error banner about confirming SO PIN
    const error = await getSecurityError(page);
    expect(error).toBeTruthy();
    expect(error).toContain('confirm');

    // Should still be on step 4
    await expect(page.getByText('PIN Management')).toBeVisible();
  });

  test('cannot proceed with mismatched User PIN confirmation', async ({ page }) => {
    await fillSOPin(page, '123456');
    await fillConfirmSOPin(page, '123456');
    await fillUserPin(page, '654321');
    await fillConfirmUserPin(page, '000000');

    // Click Next
    const nextBtn = page.locator('.step-actions .btn', { hasText: 'Next' });
    await nextBtn.click();
    await page.waitForTimeout(200);

    // Should show security error banner about confirming User PIN
    const error = await getSecurityError(page);
    expect(error).toBeTruthy();
    expect(error).toContain('confirm');

    // Should still be on step 4
    await expect(page.getByText('PIN Management')).toBeVisible();
  });

  test('valid PINs allow proceeding to next step', async ({ page }) => {
    await fillSOPin(page, '123456');
    await fillConfirmSOPin(page, '123456');
    await fillUserPin(page, '654321');
    await fillConfirmUserPin(page, '654321');

    // Click Next
    const nextBtn = page.locator('.step-actions .btn', { hasText: 'Next' });
    await nextBtn.click();
    await page.waitForTimeout(300);

    // Should advance to step 5 - Encrypted Storage
    await expect(page.getByText('Encrypted Storage')).toBeVisible();
  });
});

test.describe('Setup Wizard - Password Store Mode Default', () => {
  test.beforeEach(async ({ page }) => {
    await installWizardMock(page);
    await page.goto('/');
    await waitForSetupWizard(page);

    // Navigate to the Security step (step 4) in personal mode
    await clickNext(page); // step 2
    await selectPersonalMode(page); // step 3
    await clickNext(page); // step 4
    await expect(page.getByText('PIN Management')).toBeVisible();
  });

  test('default password store mode is aes_software when TPM unavailable', async ({ page }) => {
    // The Password Storage section should show "Software AES-256" as selected
    // Since our mock says tpm_available: false, TPM-Sealed option should not appear
    const aesSoftwareCard = page.locator('.mode-card', { hasText: 'Software AES-256' });
    await expect(aesSoftwareCard).toBeVisible();

    // The radio should be checked
    const radio = aesSoftwareCard.locator('input[type="radio"][value="aes_software"]');
    await expect(radio).toBeChecked();
  });

  test('none mode is available but not selected by default', async ({ page }) => {
    const noneCard = page.locator('.mode-card', { hasText: 'None' });
    await expect(noneCard).toBeVisible();

    const radio = noneCard.locator('input[type="radio"][value="none"]');
    await expect(radio).not.toBeChecked();
  });
});

test.describe('Setup Wizard - Enterprise Mode SO PIN Confirm', () => {
  test.beforeEach(async ({ page }) => {
    await installWizardMock(page);
    await page.goto('/');
    await waitForSetupWizard(page);

    // Navigate to Enterprise step 3 - Security Policy
    await clickNext(page); // step 2
    await selectEnterpriseMode(page); // step 3 (Security Policy)
    await expect(page.getByRole('heading', { name: 'Security Policy' })).toBeVisible();
  });

  test('enterprise SO PIN field requires confirmation', async ({ page }) => {
    const soPin = page.locator('#wizard-enterprise-so-pin');
    const confirmPin = page.locator('#wizard-enterprise-so-pin-confirm');
    await expect(soPin).toBeVisible();
    await expect(confirmPin).toBeVisible();
  });

  test('enterprise SO PIN mismatch shows field error', async ({ page }) => {
    await fillEnterpriseSoPin(page, '123456');
    await fillEnterpriseConfirmSoPin(page, '000000');

    const fieldErr = await getFieldError(page);
    expect(fieldErr).toBeTruthy();
    expect(fieldErr).toContain('PINs do not match');
  });

  test('cannot proceed without confirming enterprise SO PIN', async ({ page }) => {
    await fillEnterpriseSoPin(page, '123456');
    // Leave confirm empty

    // Click Next
    const nextBtn = page.locator('.step-actions .btn', { hasText: 'Next' });
    await nextBtn.click();
    await page.waitForTimeout(200);

    // Should show security error
    const error = await getSecurityError(page);
    expect(error).toBeTruthy();
    expect(error).toContain('confirm');

    // Should still be on the Security Policy step
    await expect(page.getByRole('heading', { name: 'Security Policy' })).toBeVisible();
  });

  test('valid enterprise SO PIN with matching confirm allows proceeding', async ({ page }) => {
    await fillEnterpriseSoPin(page, '123456');
    await fillEnterpriseConfirmSoPin(page, '123456');

    // Click Next
    const nextBtn = page.locator('.step-actions .btn', { hasText: 'Next' });
    await nextBtn.click();
    await page.waitForTimeout(300);

    // Should advance to step 4 - Encrypted Storage for enterprise
    await expect(page.getByText('Encrypted Storage')).toBeVisible();
  });
});

test.describe('Setup Wizard - User Onboarding Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Mock with enterprise_wizard_mode set to trigger onboarding flow
    await page.addInitScript(() => {
      (window as any).go = {
        services: {
          SetupWizardService: {
            GetStartupState: async () => ({
              setup_complete: false,
              enterprise_mode: true,
              enterprise_wizard_mode: 'user_onboarding',
            }),
            ProbeEnvironment: async () => ({
              tpm_available: false,
              luks_available: false,
              platform: 'linux',
              server_address: '',
              barrier_strategies: [],
            }),
            GetPolicy: async () => ({
              organization_name: 'Test Corp',
              require_encrypted_storage: true,
              require_tpm: false,
              min_pin_length: 6,
            }),
            SkipSetup: async () => {},
            ApplyUserOnboarding: async () => ({
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
    await page.goto('/');
    await waitForSetupWizard(page);
  });

  test('onboarding flow shows User Onboarding welcome', async ({ page }) => {
    await expect(page.getByText('User Onboarding')).toBeVisible();
  });

  test('onboarding User PIN confirm field is present on step 2', async ({ page }) => {
    // Click "Begin Onboarding" to advance to step 2
    const beginBtn = page.locator('.step-actions .btn', { hasText: 'Begin Onboarding' });
    await beginBtn.click();
    await page.waitForTimeout(300);

    await expect(page.getByText('Set User PIN')).toBeVisible();

    const userPin = page.locator('#wizard-onboarding-user-pin');
    const confirmPin = page.locator('#wizard-onboarding-user-pin-confirm');
    await expect(userPin).toBeVisible();
    await expect(confirmPin).toBeVisible();
  });

  test('onboarding PIN mismatch shows field error', async ({ page }) => {
    // Navigate to step 2
    const beginBtn = page.locator('.step-actions .btn', { hasText: 'Begin Onboarding' });
    await beginBtn.click();
    await page.waitForTimeout(300);

    // Fill User PIN and a different confirm
    const userPin = page.locator('#wizard-onboarding-user-pin');
    const confirmPin = page.locator('#wizard-onboarding-user-pin-confirm');

    await userPin.fill('123456');
    await confirmPin.fill('000000');

    const fieldErr = await getFieldError(page);
    expect(fieldErr).toBeTruthy();
    expect(fieldErr).toContain('PINs do not match');
  });

  test('onboarding step 3 shows Complete Onboarding with summary', async ({ page }) => {
    // Navigate to step 2
    const beginBtn = page.locator('.step-actions .btn', { hasText: 'Begin Onboarding' });
    await beginBtn.click();
    await page.waitForTimeout(300);

    // Fill valid onboarding fields
    const soPin = page.locator('#wizard-onboarding-so-pin');
    const userPin = page.locator('#wizard-onboarding-user-pin');
    const confirmPin = page.locator('#wizard-onboarding-user-pin-confirm');

    await soPin.fill('admin123');
    await userPin.fill('user1234');
    await confirmPin.fill('user1234');

    // Advance to step 3
    await clickNext(page);

    await expect(page.getByRole('heading', { name: 'Complete Onboarding' })).toBeVisible();
    await expect(page.getByText('Review and apply your configuration')).toBeVisible();
  });
});
