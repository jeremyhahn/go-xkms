import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForBackendReady,
} from './helpers';

test.describe('SSH View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'ssh');
  });

  test.describe('Header and Layout', () => {
    test('SSH view loads with correct header title', async ({ page }) => {
      await expect(page.getByRole('heading', { name: 'SSH', exact: true })).toBeVisible();
    });

    test('SSH view root element is visible', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-view"]')).toBeVisible();
    });

    test('Keys tab button is visible', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-tab-keys"]')).toBeVisible();
    });

    test('Profiles tab button is visible', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-tab-profiles"]')).toBeVisible();
    });

    test('Profiles tab is active by default', async ({ page }) => {
      // The SSH application is a connection manager, so it opens on Profiles.
      const profilesTab = page.locator('[data-testid="ssh-tab-profiles"]');
      await expect(profilesTab).toHaveAttribute('aria-selected', 'true');
    });
  });

  test.describe('Keys Tab', () => {
    test.beforeEach(async ({ page }) => {
      // Ensure we are on the Keys tab
      await page.locator('[data-testid="ssh-tab-keys"]').click();
      await page.waitForTimeout(100);
    });

    test('Generate Key button is visible in the toolbar', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-generate-button"]')).toBeVisible();
    });

    test('shows empty state or key table on Keys tab', async ({ page }) => {
      await page.waitForTimeout(500);

      const emptyState = page.locator('[data-testid="ssh-empty-state"]');
      const keyRow = page.locator('[data-testid="ssh-key-row"]');

      const hasEmpty = await emptyState.isVisible().catch(() => false);
      const hasRows = await keyRow.first().isVisible().catch(() => false);

      expect(hasEmpty || hasRows).toBeTruthy();
    });

    test('empty state in Vite standalone mode shows No SSH Keys', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(wails, 'Vite standalone only; real backend may have SSH keys');

      await expect(page.getByText('No SSH Keys')).toBeVisible();
      await expect(page.locator('[data-testid="ssh-empty-state"]')).toBeVisible();
    });

    test('empty state description is shown alongside No SSH Keys', async ({ page }) => {
      const emptyTitle = page.getByText('No SSH Keys');
      const isVisible = await emptyTitle.isVisible().catch(() => false);
      if (isVisible) {
        await expect(
          page.getByText('Generate your first SSH key to use with remote servers', { exact: false }),
        ).toBeVisible();
      }
    });

    test('empty state action button triggers Generate Key dialog', async ({ page }) => {
      const emptyTitle = page.getByText('No SSH Keys');
      const isVisible = await emptyTitle.isVisible().catch(() => false);
      if (isVisible) {
        const actionButton = page
          .locator('[data-testid="ssh-empty-state"]')
          .getByRole('button', { name: 'Generate Key' });
        await actionButton.click();
        await expect(page.getByRole('dialog')).toBeVisible();
        await expect(page.getByText('Generate SSH Key')).toBeVisible();
      }
    });
  });

  test.describe('Keys Tab — Source Toggle', () => {
    test.beforeEach(async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-keys"]').click();
      await page.waitForTimeout(100);
    });

    test('source toggle renders both xkey and Local options', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-key-source-toggle"]')).toBeVisible();
      await expect(page.locator('[data-testid="ssh-key-source-xkey"]')).toBeVisible();
      await expect(page.locator('[data-testid="ssh-key-source-local"]')).toBeVisible();
    });

    test('xkey source is selected by default with Generate button and backend selector visible', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-generate-button"]')).toBeVisible();
      await expect(page.locator('.backend-selector')).toBeVisible();
    });

    test('selecting Local hides the Generate button and backend selector', async ({ page }) => {
      await page.locator('[data-testid="ssh-key-source-local"]').click();
      await page.waitForTimeout(200);

      await expect(page.locator('[data-testid="ssh-generate-button"]')).not.toBeVisible();
      await expect(page.locator('.backend-selector')).not.toBeVisible();
    });

    test('Local source renders a table or empty state, with no delete/export actions', async ({ page }) => {
      await page.locator('[data-testid="ssh-key-source-local"]').click();
      await page.waitForTimeout(300);

      const emptyState = page.locator('[data-testid="ssh-empty-state"]');
      const localRow = page.locator('[data-testid="ssh-local-key-row"]');

      const hasEmpty = await emptyState.isVisible().catch(() => false);
      const hasRows = await localRow.first().isVisible().catch(() => false);
      expect(hasEmpty || hasRows).toBeTruthy();

      if (hasRows) {
        await expect(localRow.first().getByRole('button', { name: 'Delete' })).toHaveCount(0);
        await expect(localRow.first().getByRole('button', { name: 'Export' })).toHaveCount(0);
      }
    });

    test('Local empty state in Vite standalone mode shows No Local Keys', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(wails, 'Vite standalone only; real backend may report local keys');

      await page.locator('[data-testid="ssh-key-source-local"]').click();
      await page.waitForTimeout(200);

      await expect(page.getByText('No Local Keys')).toBeVisible();
      await expect(page.locator('[data-testid="ssh-empty-state"]')).toBeVisible();
    });

    test('switching back to xkey source restores the Generate button', async ({ page }) => {
      await page.locator('[data-testid="ssh-key-source-local"]').click();
      await page.waitForTimeout(100);
      await page.locator('[data-testid="ssh-key-source-xkey"]').click();
      await page.waitForTimeout(100);

      await expect(page.locator('[data-testid="ssh-generate-button"]')).toBeVisible();
    });
  });

  test.describe('Generate Key Dialog', () => {
    test.beforeEach(async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-keys"]').click();
      await page.waitForTimeout(100);
    });

    test('Generate Key button opens the dialog', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();
      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByText('Generate SSH Key')).toBeVisible();
    });

    test('generate dialog has a Key Name field', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();
      await expect(page.locator('#ssh-gen-name')).toBeVisible();
    });

    test('generate dialog has an Algorithm selector with expected options', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();

      const algorithmSelect = page.locator('#ssh-gen-algorithm');
      await expect(algorithmSelect).toBeVisible();

      const options = algorithmSelect.locator('option');
      const texts = await options.allTextContents();
      expect(texts).toContain('Ed25519');
      expect(texts).toContain('RSA');
      expect(texts).toContain('ECDSA P-256');
      expect(texts).toContain('ECDSA P-384');
      expect(texts).toContain('ECDSA P-521');
    });

    test('generate dialog shows RSA Bits selector when RSA is selected', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();

      const algorithmSelect = page.locator('#ssh-gen-algorithm');
      await algorithmSelect.selectOption('rsa');
      await page.waitForTimeout(100);

      await expect(page.locator('#ssh-gen-rsa-bits')).toBeVisible();
    });

    test('RSA Bits selector is hidden when Ed25519 is selected', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();

      const algorithmSelect = page.locator('#ssh-gen-algorithm');
      await algorithmSelect.selectOption('ed25519');
      await page.waitForTimeout(100);

      await expect(page.locator('#ssh-gen-rsa-bits')).not.toBeVisible();
    });

    test('generate dialog has an optional Comment field', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();
      await expect(page.locator('#ssh-gen-comment')).toBeVisible();
    });

    test('Cancel button closes the generate dialog', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();
      await expect(page.getByRole('dialog')).toBeVisible();

      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      await expect(page.getByRole('dialog')).not.toBeVisible();
    });

    test('Escape key closes the generate dialog', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();
      await expect(page.getByRole('dialog')).toBeVisible();

      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);

      await expect(page.getByRole('dialog')).not.toBeVisible();
    });

    test('dialog can be reopened after being dismissed', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();
      await expect(page.getByRole('dialog')).toBeVisible();

      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);

      await page.locator('[data-testid="ssh-generate-button"]').click();
      await expect(page.getByRole('dialog')).toBeVisible();
    });

    test('Key Name field is cleared when dialog is reopened', async ({ page }) => {
      await page.locator('[data-testid="ssh-generate-button"]').click();

      await page.locator('#ssh-gen-name').fill('test-key');
      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      await page.locator('[data-testid="ssh-generate-button"]').click();
      await page.waitForTimeout(100);

      const nameValue = await page.locator('#ssh-gen-name').inputValue();
      expect(nameValue).toBe('');
    });
  });

  test.describe('Connections Tab', () => {
    test.beforeEach(async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(200);
    });

    test('Profiles tab becomes active when clicked', async ({ page }) => {
      const profilesTab = page.locator('[data-testid="ssh-tab-profiles"]');
      await expect(profilesTab).toHaveAttribute('aria-selected', 'true');
    });

    test('profiles container is visible', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-profiles"]')).toBeVisible();
    });

    test('New Profile button is visible', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-new-profile"]')).toBeVisible();
    });

    test('New Connection button is visible', async ({ page }) => {
      await expect(page.locator('[data-testid="ssh-new-connection"]')).toBeVisible();
    });

    test('folder tree renders in the connections sidebar', async ({ page }) => {
      // The folder tree should have an aria role="tree" element
      await expect(page.locator('[role="tree"]')).toBeVisible();
    });

    test('New Profile button opens the profile dialog', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-profile"]').click();
      await page.waitForTimeout(200);
      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByText('New SSH Profile')).toBeVisible();
    });

    test('New Connection button opens the connect dialog', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);
      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByText('New SSH Connection')).toBeVisible();
    });

    test('Profile dialog has required fields', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-profile"]').click();
      await page.waitForTimeout(200);

      await expect(page.locator('#ssh-profile-name')).toBeVisible();
      await expect(page.locator('#ssh-profile-host')).toBeVisible();
      await expect(page.locator('#ssh-profile-port')).toBeVisible();
      await expect(page.locator('#ssh-profile-user')).toBeVisible();
    });

    test('Profile dialog port defaults to 22', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-profile"]').click();
      await page.waitForTimeout(200);

      const portValue = await page.locator('#ssh-profile-port').inputValue();
      expect(portValue).toBe('22');
    });

    test('Profile dialog cancel closes the dialog', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-profile"]').click();
      await page.waitForTimeout(200);
      await expect(page.getByRole('dialog')).toBeVisible();

      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      await expect(page.getByRole('dialog')).not.toBeVisible();
    });

    test('Connect dialog has host, port, and user fields', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);

      await expect(page.locator('#ssh-connect-host')).toBeVisible();
      await expect(page.locator('#ssh-connect-port')).toBeVisible();
      await expect(page.locator('#ssh-connect-user')).toBeVisible();
    });

    test('Connect dialog port defaults to 22', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);

      const portValue = await page.locator('#ssh-connect-port').inputValue();
      expect(portValue).toBe('22');
    });

    test('Connect dialog Save-as-profile checkbox shows extra fields', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);

      // Profile name should not be visible initially
      await expect(page.locator('#ssh-connect-profile-name')).not.toBeVisible();

      // Check the save-as-profile checkbox
      const checkbox = page.locator('input[type="checkbox"]').first();
      await checkbox.check();
      await page.waitForTimeout(100);

      // Profile name should now be visible
      await expect(page.locator('#ssh-connect-profile-name')).toBeVisible();
    });

    test('shows empty profile state or profile rows', async ({ page }) => {
      const emptyState = page.locator('text=No Profiles');
      const profileRow = page.locator('[data-testid="ssh-profile-row"]');

      // SSH.svelte renders the "No Profiles" empty state only once
      // profilesLoading is false, so a fixed wait races the live backend's
      // profile fetch and can observe neither branch. Wait for whichever
      // terminal state arrives first instead.
      await Promise.race([
        emptyState.waitFor({ state: 'visible', timeout: 10_000 }),
        profileRow.first().waitFor({ state: 'visible', timeout: 10_000 }),
      ]).catch(() => undefined);

      const hasEmpty = await emptyState.isVisible().catch(() => false);
      const hasRows = await profileRow.first().isVisible().catch(() => false);

      // At least one of these should be true
      expect(hasEmpty || hasRows).toBeTruthy();
    });

    test('profile rows have a Connect button when profiles exist', async ({ page }) => {
      await page.waitForTimeout(500);

      const profileRows = page.locator('[data-testid="ssh-profile-row"]');
      const count = await profileRows.count();
      if (count === 0) {
        // No profiles — skip connect-button check
        return;
      }
      // Each row should have a connect button
      const connectBtn = profileRows.first().locator('[data-testid="ssh-connect-button"]');
      await expect(connectBtn).toBeVisible();
    });
  });

  test.describe('Connect Dialog — Searchable Key Select', () => {
    test.beforeEach(async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(200);
      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);
    });

    const keyInput = (page: import('@playwright/test').Page) =>
      page.getByRole('dialog').locator('[data-testid="ssh-key-select-input"]');

    test('key select renders in the connect dialog', async ({ page }) => {
      await expect(keyInput(page)).toBeVisible();
    });

    test('defaults to No key (agent / password auth)', async ({ page }) => {
      await expect(keyInput(page)).toHaveValue('No key');
    });

    test('focusing opens the dropdown with the No key option', async ({ page }) => {
      await keyInput(page).focus();
      const list = page.locator('[data-testid="ssh-key-select-list"]');
      await expect(list).toBeVisible();
      await expect(list.locator('[data-testid="ssh-key-option-none"]')).toBeVisible();
    });

    test('type-to-search filters options and shows an empty state for no matches', async ({ page }) => {
      const input = keyInput(page);
      await input.focus();
      await input.fill('zzz-no-such-key-zzz');
      await expect(page.locator('[data-testid="ssh-key-select-empty"]')).toBeVisible();

      await input.fill('no key');
      await expect(page.locator('[data-testid="ssh-key-option-none"]')).toBeVisible();
    });

    test('selecting an option closes the dropdown and updates the input', async ({ page }) => {
      const input = keyInput(page);
      await input.focus();
      await page.locator('[data-testid="ssh-key-option-none"]').click();
      await expect(page.locator('[data-testid="ssh-key-select-list"]')).not.toBeVisible();
      await expect(input).toHaveValue('No key');
    });

    test('Escape closes the dropdown', async ({ page }) => {
      const input = keyInput(page);
      await input.focus();
      await expect(page.locator('[data-testid="ssh-key-select-list"]')).toBeVisible();
      await input.press('Escape');
      await expect(page.locator('[data-testid="ssh-key-select-list"]')).not.toBeVisible();
    });

    test('keyboard navigation selects with Enter', async ({ page }) => {
      const input = keyInput(page);
      await input.focus();
      await input.press('ArrowDown');
      await input.press('Enter');
      await expect(page.locator('[data-testid="ssh-key-select-list"]')).not.toBeVisible();
    });

    test('profile dialog also renders the key select', async ({ page }) => {
      // Close the connect dialog first
      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);
      await page.locator('[data-testid="ssh-new-profile"]').click();
      await page.waitForTimeout(200);
      await expect(keyInput(page)).toBeVisible();
    });
  });

  test.describe('Connections Tab — Config Hosts', () => {
    test.beforeEach(async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(300);
    });

    test('config-hosts section renders only when ~/.ssh/config hosts exist', async ({ page }) => {
      // Follows the same truthy/falsy guard pattern as the profile-row checks
      // above: the section is absent in Vite standalone mode (no backend to
      // report ssh_config hosts) and only asserted against when present.
      const section = page.locator('[data-testid="ssh-config-hosts-section"]');
      const hasSection = await section.isVisible().catch(() => false);
      if (!hasSection) {
        return;
      }

      const rows = page.locator('[data-testid="ssh-config-host-row"]');
      const count = await rows.count();
      expect(count).toBeGreaterThan(0);

      const firstRow = rows.first();
      await expect(firstRow.locator('[data-testid="ssh-config-host-connect"]')).toBeVisible();
      await expect(firstRow.getByRole('button', { name: 'Edit' })).toHaveCount(0);
      await expect(firstRow.getByRole('button', { name: 'Delete' })).toHaveCount(0);
    });

    test('config-hosts section is absent in Vite standalone mode', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(wails, 'Vite standalone only; real backend may report ssh_config hosts');

      await expect(page.locator('[data-testid="ssh-config-hosts-section"]')).not.toBeVisible();
    });
  });

  test.describe('Tab switching', () => {
    test('switching from Profiles to Keys shows key list', async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(100);

      await page.locator('[data-testid="ssh-tab-keys"]').click();
      await page.waitForTimeout(100);

      // Generate button should be visible again
      await expect(page.locator('[data-testid="ssh-generate-button"]')).toBeVisible();
    });

    test('Profiles tab content hides when Keys tab is active', async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-keys"]').click();
      await page.waitForTimeout(100);
      await expect(page.locator('[data-testid="ssh-profiles"]')).not.toBeVisible();
    });
  });

  test.describe('Console Mode — Settings', () => {
    test('SSH settings section has a Default console mode selector', async ({ page }) => {
      // Navigate to Settings → SSH category. Scope the category button to the
      // settings nav so it does not collide with the main app sidebar's SSH item.
      await navigateTo(page, 'settings');
      await page.waitForTimeout(200);

      await page.locator('.settings-nav-item', { hasText: 'SSH' }).first().click();
      await page.waitForTimeout(200);

      const modeSelect = page.locator('[data-testid="ssh-default-console-mode"]');
      await expect(modeSelect).toBeVisible();

      // Should have System terminal and Embedded console options
      const options = modeSelect.locator('option');
      const texts = await options.allTextContents();
      expect(texts.some(t => t.includes('System terminal'))).toBe(true);
      expect(texts.some(t => t.includes('Embedded console'))).toBe(true);
    });
  });

  test.describe('SSH Settings — Descriptions', () => {
    test.beforeEach(async ({ page }) => {
      await navigateTo(page, 'settings');
      await page.waitForTimeout(200);
      await page.locator('.settings-nav-item', { hasText: 'SSH' }).first().click();
      await page.waitForTimeout(200);
    });

    test('known-hosts description states it applies to both the embedded console and the system terminal', async ({ page }) => {
      await expect(
        page.getByText('Where to store and verify SSH host keys, for both the embedded', { exact: false }),
      ).toBeVisible();
    });

    test('host-key checking description states it applies to both consoles and mentions the inline embedded prompt', async ({ page }) => {
      await expect(
        page.getByText('Controls how SSH handles unknown or changed host keys, for both', { exact: false }),
      ).toBeVisible();
      await expect(
        page.getByText('prompts on new hosts', { exact: false }),
      ).toBeVisible();
    });
  });

  test.describe('Console Mode — Profile Dialog', () => {
    test.beforeEach(async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(200);
    });

    test('New Profile dialog exposes a console-mode selector', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-profile"]').click();
      await page.waitForTimeout(200);

      const modeSelect = page.locator('[data-testid="ssh-profile-console-mode"]');
      await expect(modeSelect).toBeVisible();

      const options = modeSelect.locator('option');
      const texts = await options.allTextContents();
      expect(texts.some(t => t.includes('Use default'))).toBe(true);
      expect(texts.some(t => t.includes('System terminal'))).toBe(true);
      expect(texts.some(t => t.includes('Embedded console'))).toBe(true);
    });
  });

  test.describe('Console Mode — New Connection Dialog', () => {
    test.beforeEach(async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(200);
    });

    test('New Connection dialog exposes a console-mode selector', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);

      const modeSelect = page.locator('[data-testid="ssh-connect-console-mode"]');
      await expect(modeSelect).toBeVisible();

      const options = modeSelect.locator('option');
      const texts = await options.allTextContents();
      expect(texts.some(t => t.includes('Use default'))).toBe(true);
      expect(texts.some(t => t.includes('System terminal'))).toBe(true);
      expect(texts.some(t => t.includes('Embedded console'))).toBe(true);
    });

    test('selecting Embedded mode in New Connection and connecting shows console panel (Vite mode)', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(wails, 'Vite standalone only — no real backend to prevent system terminal spawn');

      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);

      // Choose embedded console
      const modeSelect = page.locator('[data-testid="ssh-connect-console-mode"]');
      await modeSelect.selectOption('embedded');
      await page.waitForTimeout(100);

      // Fill minimum required fields
      await page.locator('#ssh-connect-host').fill('test-host.local');
      await page.locator('#ssh-connect-user').fill('admin');

      // Click Connect — in Vite mode, SSHConsoleService returns null and panel opens with empty url
      await page.getByRole('dialog').getByRole('button', { name: 'Connect' }).click();
      await page.waitForTimeout(400);

      // Dialog should close and console panel should appear
      const panel = page.locator('[data-testid="ssh-console-panel"]');
      const panelVisible = await panel.isVisible().catch(() => false);
      expect(panelVisible).toBe(true);

      // SSHConsole component renders a placeholder in no-backend mode
      const consolePlaceholder = page.locator('[data-testid="ssh-console"]');
      const consoleVisible = await consolePlaceholder.isVisible().catch(() => false);
      expect(consoleVisible).toBe(true);

      // Close button dismisses the panel
      const closeBtn = page.locator('[data-testid="ssh-console-close"]');
      await closeBtn.click();
      await page.waitForTimeout(200);

      const panelGone = await panel.isVisible().catch(() => false);
      expect(panelGone).toBe(false);
    });
  });

  test.describe('Console Mode — Global Default Resolution', () => {
    // Sets the global default console mode via Settings → SSH. The store is
    // localStorage-backed, so this drives the per-connection default in Vite mode
    // without a backend.
    async function setDefaultConsoleMode(page: import('@playwright/test').Page, mode: 'system' | 'embedded') {
      await navigateTo(page, 'settings');
      await page.waitForTimeout(200);
      await page.locator('.settings-nav-item', { hasText: 'SSH' }).first().click();
      await page.waitForTimeout(200);
      const modeSelect = page.locator('[data-testid="ssh-default-console-mode"]');
      await modeSelect.selectOption(mode);
      await page.waitForTimeout(100);
    }

    test('New Connection dialog inherits the global Embedded default', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(wails, 'Vite standalone only — drives the localStorage-backed default');

      await setDefaultConsoleMode(page, 'embedded');

      await navigateTo(page, 'ssh');
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(200);
      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);

      // The dialog initialises its console-mode from the global default.
      const modeSelect = page.locator('[data-testid="ssh-connect-console-mode"]');
      await expect(modeSelect).toHaveValue('embedded');

      // Connecting opens the embedded panel (effective mode = embedded).
      await page.locator('#ssh-connect-host').fill('global-default.local');
      await page.locator('#ssh-connect-user').fill('admin');
      await page.getByRole('dialog').getByRole('button', { name: 'Connect' }).click();
      await page.waitForTimeout(400);
      await expect(page.locator('[data-testid="ssh-console-panel"]')).toBeVisible();

      await page.locator('[data-testid="ssh-console-close"]').click();
      await page.waitForTimeout(200);
      await expect(page.locator('[data-testid="ssh-console-panel"]')).not.toBeVisible();
    });

    test('Use-default connection with a System global default does not open the embedded panel', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(wails, 'Vite standalone only');

      await setDefaultConsoleMode(page, 'system');

      await navigateTo(page, 'ssh');
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(200);
      await page.locator('[data-testid="ssh-new-connection"]').click();
      await page.waitForTimeout(200);

      // Explicitly pick "Use default" — effective mode resolves to the global (system).
      const modeSelect = page.locator('[data-testid="ssh-connect-console-mode"]');
      await modeSelect.selectOption('');
      await page.locator('#ssh-connect-host').fill('system-default.local');
      await page.locator('#ssh-connect-user').fill('admin');
      await page.getByRole('dialog').getByRole('button', { name: 'Connect' }).click();
      await page.waitForTimeout(400);

      // System mode has no embedded panel (it would launch an external terminal).
      await expect(page.locator('[data-testid="ssh-console-panel"]')).not.toBeVisible();
    });

    test('Global default persists across a reload', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(wails, 'Vite standalone only — localStorage-backed default');

      await setDefaultConsoleMode(page, 'embedded');

      await page.reload();
      await waitForAppReady(page);
      await ensureSidebarExpanded(page);

      await navigateTo(page, 'settings');
      await page.waitForTimeout(200);
      await page.locator('.settings-nav-item', { hasText: 'SSH' }).first().click();
      await page.waitForTimeout(200);
      await expect(page.locator('[data-testid="ssh-default-console-mode"]')).toHaveValue('embedded');
    });
  });

  test.describe('Console Mode — Profile Override', () => {
    test.beforeEach(async ({ page }) => {
      await page.locator('[data-testid="ssh-tab-profiles"]').click();
      await page.waitForTimeout(200);
    });

    test('New Profile console-mode defaults to "Use default" (inherit global)', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-profile"]').click();
      await page.waitForTimeout(200);

      // A fresh profile inherits the global default until explicitly overridden.
      const modeSelect = page.locator('[data-testid="ssh-profile-console-mode"]');
      await expect(modeSelect).toHaveValue('');
    });

    test('Profile dialog accepts an explicit Embedded override', async ({ page }) => {
      await page.locator('[data-testid="ssh-new-profile"]').click();
      await page.waitForTimeout(200);

      const modeSelect = page.locator('[data-testid="ssh-profile-console-mode"]');
      await modeSelect.selectOption('embedded');
      await expect(modeSelect).toHaveValue('embedded');
    });
  });

  test.describe('Wails Mode — Key Lifecycle', () => {
    test('generates an Ed25519 key and verifies it appears in the list', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await waitForBackendReady(page);

      // Ensure we are on Keys tab
      await page.locator('[data-testid="ssh-tab-keys"]').click();
      await page.waitForTimeout(100);

      const keyName = `test-e2e-ed25519-${Date.now()}`;

      // Open generate dialog and fill fields
      await page.locator('[data-testid="ssh-generate-button"]').click();
      await expect(page.getByRole('dialog')).toBeVisible();

      await page.locator('#ssh-gen-name').fill(keyName);
      await page.locator('#ssh-gen-algorithm').selectOption('ed25519');
      await page.locator('#ssh-gen-comment').fill('e2e-test');

      // Submit
      await page.locator('.modal-actions').getByRole('button', { name: 'Generate' }).click();
      await page.waitForTimeout(1500);

      // Key should appear in the table
      const keyRow = page.locator('[data-testid="ssh-key-row"]', { hasText: keyName });
      await expect(keyRow).toBeVisible({ timeout: 8_000 });

      // Clean up: delete the generated key
      const deleteBtn = keyRow.getByRole('button', { name: 'Delete' });
      await deleteBtn.click();
      await page.waitForTimeout(200);

      // Confirm deletion in the modal
      await page.locator('.modal-actions').getByRole('button', { name: 'Delete' }).click();
      await page.waitForTimeout(1000);

      // Key should no longer appear
      await expect(
        page.locator('[data-testid="ssh-key-row"]', { hasText: keyName }),
      ).not.toBeVisible({ timeout: 5_000 });
    });

    test('export public key dialog shows authorized_keys content', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with at least one SSH key');

      await waitForBackendReady(page);

      // Ensure we are on Keys tab
      await page.locator('[data-testid="ssh-tab-keys"]').click();
      await page.waitForTimeout(500);

      const keyRows = page.locator('[data-testid="ssh-key-row"]');
      const count = await keyRows.count();
      if (count === 0) {
        test.skip(true, 'No SSH keys present; skipping export test');
        return;
      }

      // Click Export on the first key row
      await keyRows.first().getByRole('button', { name: 'Export' }).click();
      await page.waitForTimeout(300);

      // Export dialog should open
      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByText('Export Public Key')).toBeVisible();

      // Close the dialog. The dialog renders both a "Close dialog" X icon
      // and a footer "Close" button — require the exact name so the locator
      // is unambiguous under strict mode.
      await page.getByRole('button', { name: 'Close', exact: true }).click();
      await page.waitForTimeout(200);
      await expect(page.getByRole('dialog')).not.toBeVisible();
    });
  });
});

// ── Regression: SSH Profiles auto-load must not loop ────────────────────────
// SSH.svelte's auto-load reactive statement was guarded on
// `profiles.length === 0 && !profilesLoading`. With a legitimately EMPTY
// profile list that guard re-fired every time loadProfiles() finished (it
// clears profilesLoading, which re-satisfies the condition), hammering
// ListProfiles/ListFolders/ListConfigHosts forever and preventing the
// "No Profiles" empty state from ever settling — the tab rendered blank.
// A profilesLoadAttempted latch now bounds it to one load per tab visit.
test.describe('SSH Profiles auto-load loop regression', () => {
  test('empty profile list loads once and settles on the empty state', async ({
    page,
  }) => {
    let listProfilesCalls = 0;

    await page.addInitScript(() => {
      (window as unknown as { __sshListProfilesCalls: number }).__sshListProfilesCalls = 0;
    });

    // Count backend ListProfiles invocations through the Wails binding.
    await page.exposeFunction('__countListProfiles', () => {
      listProfilesCalls += 1;
    });

    await page.addInitScript(() => {
      const install = (): boolean => {
        const svc = (window as unknown as {
          go?: { services?: { SSHProfileService?: Record<string, unknown> } };
        }).go?.services?.SSHProfileService;
        if (!svc || typeof svc.ListProfiles !== 'function') return false;
        const original = svc.ListProfiles as (...a: unknown[]) => Promise<unknown>;
        svc.ListProfiles = (...args: unknown[]) => {
          const counter = (window as unknown as {
            __countListProfiles?: () => void;
          }).__countListProfiles;
          if (counter) counter();
          return original.apply(svc, args);
        };
        return true;
      };
      if (!install()) {
        const timer = setInterval(() => {
          if (install()) clearInterval(timer);
        }, 25);
        setTimeout(() => clearInterval(timer), 10_000);
      }
    });

    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);

    const wails = await isWailsMode(page);
    test.skip(!wails, 'Requires the Wails backend to exercise the real binding');
    await waitForBackendReady(page);

    await navigateTo(page, 'ssh');
    await page.getByRole('tab', { name: 'Profiles' }).click();

    // Either the empty state or profile rows must settle within a bounded wait.
    const emptyState = page.locator('text=No Profiles');
    const profileRow = page.locator('[data-testid="ssh-profile-row"]');
    await Promise.race([
      emptyState.waitFor({ state: 'visible', timeout: 10_000 }),
      profileRow.first().waitFor({ state: 'visible', timeout: 10_000 }),
    ]);

    // Let any runaway reactive loop reveal itself.
    await page.waitForTimeout(3_000);

    // A loop produced dozens of calls per second; one settled load is a
    // handful at most (initial load plus any explicit refresh).
    expect(listProfilesCalls).toBeLessThanOrEqual(5);
  });
});

// ── Shared live-E2E SSH echo-server harness ─────────────────────────────────
// Used by both live describes below (single-session flows and session tabs).

const echoProcs: import('child_process').ChildProcess[] = [];

/**
 * A unique 127.0.0.0/8 loopback address per call. The live sandbox's pin
 * store persists across runs while each spawned server mints a fresh host
 * key — reusing one IP would trip the (correct) pin-mismatch hard failure
 * on the next run, so every server gets its own host identity.
 */
function uniqueLoopbackIP(): string {
  const r = () => 1 + Math.floor(Math.random() * 250);
  return `127.${r()}.${r()}.${r()}`;
}

async function startEchoServer(): Promise<{ host: string; port: number }> {
  const { spawn, execFileSync } = await import('child_process');
  const path = await import('path');
  const os = await import('os');
  // Playwright runs with cwd = frontend/; the xkey module root is one up.
  const cwd = process.cwd();
  const xkeyRoot = path.basename(cwd) === 'frontend' ? path.resolve(cwd, '..') : cwd;
  // Build then spawn the binary directly — killing a `go run` wrapper
  // orphans the compiled child, leaking echo servers across runs.
  const bin = path.join(os.tmpdir(), `xkey-sshechod-${process.pid}`);
  execFileSync('go', ['build', '-o', bin, './test/e2esupport/sshechod'], { cwd: xkeyRoot });
  const proc = spawn(bin, [uniqueLoopbackIP()], { cwd: xkeyRoot });
  echoProcs.push(proc);
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('sshechod did not start within 60s')), 60_000);
    let buf = '';
    proc.stdout!.on('data', (chunk: Buffer) => {
      buf += chunk.toString();
      const m = buf.match(/SSHECHO LISTEN (\S+) (\d+)/);
      if (m) {
        clearTimeout(timer);
        resolve({ host: m[1], port: parseInt(m[2], 10) });
      }
    });
    proc.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`sshechod exited early (code ${code})`));
    });
  });
}

function killEchoServers(): void {
  for (const proc of echoProcs) proc.kill();
  echoProcs.length = 0;
}

/**
 * Live end-to-end proof that the embedded console actually works: a real
 * Wails backend, a real SSH server (test/e2esupport/sshechod spawned via
 * `go run`), the searchable key picker, the first-contact TOFU prompt, and
 * a live xterm byte stream. Vite-mock mode skips (no backend to bridge).
 *
 * This spec exists because component/unit tiers cannot catch composition
 * failures like the strict-default host-key policy that dead-ended every
 * first-contact embedded connection on a fresh install.
 */
test.describe('SSH Embedded Console — live E2E', () => {
  test.afterAll(killEchoServers);

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'ssh');
  });

  test('first-contact embedded console: key picker → TOFU accept → live echo', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'live Wails backend only — the console bridges a real SSH connection');
    test.setTimeout(120_000);

    const { host: echoHost, port: echoPort } = await startEchoServer();
    const keyName = `e2e-console-${Date.now()}`;

    // 1. Generate a managed key for authentication (the echo server accepts
    //    any public key).
    await page.locator('[data-testid="ssh-tab-keys"]').click();
    await page.locator('[data-testid="ssh-generate-button"]').click();
    await page.locator('#ssh-gen-name').fill(keyName);
    await page.locator('#ssh-gen-algorithm').selectOption('ed25519');
    await page.getByRole('dialog').getByRole('button', { name: 'Generate' }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible({ timeout: 30_000 });

    // 2. Open a one-time embedded connection, picking the key through the
    //    searchable dropdown.
    await page.locator('[data-testid="ssh-tab-profiles"]').click();
    await page.locator('[data-testid="ssh-new-connection"]').click();
    await page.locator('#ssh-connect-host').fill(echoHost);
    await page.locator('#ssh-connect-port').fill(String(echoPort));
    await page.locator('#ssh-connect-user').fill('e2e');

    const keyInput = page.getByRole('dialog').locator('[data-testid="ssh-key-select-input"]');
    await keyInput.click();
    await keyInput.fill(keyName);
    await page.locator(`[data-testid="ssh-key-option-xkey:${keyName}"]`).click();

    await page.locator('[data-testid="ssh-connect-console-mode"]').selectOption('embedded');
    await page.getByRole('dialog').getByRole('button', { name: 'Connect' }).click();

    // 3. The console panel opens with a REAL WebSocket URL and the
    //    first-contact host-key prompt appears (default "ask" policy).
    await expect(page.locator('[data-testid="ssh-console-panel"]')).toBeVisible({ timeout: 15_000 });
    const prompt = page.locator('[data-testid="ssh-hostkey-prompt"]');
    await expect(prompt).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('[data-testid="ssh-hostkey-fingerprint"]')).toContainText('SHA256:');
    await page.locator('[data-testid="ssh-hostkey-accept"]').click();
    await expect(prompt).not.toBeVisible();

    // 4. The session is live: typed bytes round-trip through the real SSH
    //    server and render in the terminal (the echo server has no local
    //    echo, so visible text proves the full WS↔SSH bridge).
    const marker = `xkey-live-echo-${Date.now()}`;
    await page.locator('[data-testid="ssh-console"] .term-container').click();
    await page.keyboard.type(marker);
    await page.keyboard.press('Enter');
    await expect(page.locator('[data-testid="ssh-console"]')).toContainText(marker, { timeout: 15_000 });

    // 5. Reconnecting to the now-pinned host opens with no prompt.
    await page.locator('[data-testid="ssh-console-close"]').click();
    await page.locator('[data-testid="ssh-new-connection"]').click();
    await page.locator('#ssh-connect-host').fill(echoHost);
    await page.locator('#ssh-connect-port').fill(String(echoPort));
    await page.locator('#ssh-connect-user').fill('e2e');
    const keyInput2 = page.getByRole('dialog').locator('[data-testid="ssh-key-select-input"]');
    await keyInput2.click();
    await keyInput2.fill(keyName);
    await page.locator(`[data-testid="ssh-key-option-xkey:${keyName}"]`).click();
    await page.locator('[data-testid="ssh-connect-console-mode"]').selectOption('embedded');
    await page.getByRole('dialog').getByRole('button', { name: 'Connect' }).click();

    await expect(page.locator('[data-testid="ssh-console-panel"]')).toBeVisible({ timeout: 15_000 });
    const marker2 = `xkey-live-pinned-${Date.now()}`;
    await page.locator('[data-testid="ssh-console"] .term-container').click();
    await page.keyboard.type(marker2);
    await page.keyboard.press('Enter');
    await expect(page.locator('[data-testid="ssh-console"]')).toContainText(marker2, { timeout: 15_000 });
    // No host-key prompt this time — the pin recorded on accept verifies silently.
    await expect(page.locator('[data-testid="ssh-hostkey-prompt"]')).not.toBeVisible();

    // Terminate the session so the server-side channel closes cleanly.
    await page.keyboard.type('exit');
    await page.keyboard.press('Enter');
    await page.locator('[data-testid="ssh-console-close"]').click();
  });

  test('rejecting the first-contact fingerprint fails the session', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'live Wails backend only');
    test.setTimeout(120_000);

    const { host: echoHost, port: echoPort } = await startEchoServer();
    const keyName = `e2e-reject-${Date.now()}`;

    await page.locator('[data-testid="ssh-tab-keys"]').click();
    await page.locator('[data-testid="ssh-generate-button"]').click();
    await page.locator('#ssh-gen-name').fill(keyName);
    await page.locator('#ssh-gen-algorithm').selectOption('ed25519');
    await page.getByRole('dialog').getByRole('button', { name: 'Generate' }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible({ timeout: 30_000 });

    await page.locator('[data-testid="ssh-tab-profiles"]').click();
    await page.locator('[data-testid="ssh-new-connection"]').click();
    // This test's server has its own unique loopback IP, so the host entry
    // is un-pinned regardless of what other tests accepted.
    await page.locator('#ssh-connect-host').fill(echoHost);
    await page.locator('#ssh-connect-port').fill(String(echoPort));
    await page.locator('#ssh-connect-user').fill('e2e');
    const keyInput = page.getByRole('dialog').locator('[data-testid="ssh-key-select-input"]');
    await keyInput.click();
    await keyInput.fill(keyName);
    await page.locator(`[data-testid="ssh-key-option-xkey:${keyName}"]`).click();
    await page.locator('[data-testid="ssh-connect-console-mode"]').selectOption('embedded');
    await page.getByRole('dialog').getByRole('button', { name: 'Connect' }).click();

    const prompt = page.locator('[data-testid="ssh-hostkey-prompt"]');
    await expect(prompt).toBeVisible({ timeout: 15_000 });
    await page.locator('[data-testid="ssh-hostkey-reject"]').click();
    await expect(prompt).not.toBeVisible();

    // The session must fail — the status line reports the ended/failed
    // session rather than presenting a live shell.
    await expect(page.locator('[data-testid="ssh-console"] .ssh-console-status')).toBeVisible({ timeout: 15_000 });
    await page.locator('[data-testid="ssh-console-close"]').click();
  });
});

/**
 * Tab-strip mechanics for the multi-session embedded console, driven in
 * Vite standalone mode where embedded connects open placeholder tabs
 * unconditionally (no backend). The live-session behavior of the same tabs
 * is covered by "SSH Embedded Console — live E2E" below.
 */
test.describe('SSH Embedded Console — session tabs (Vite mode)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'ssh');
    await page.locator('[data-testid="ssh-tab-profiles"]').click();
    await page.waitForTimeout(200);
  });

  /** Opens an embedded placeholder connection to `host` via the dialog. */
  async function openEmbedded(page: import('@playwright/test').Page, host: string): Promise<void> {
    // The connect dialog is reachable from the toolbar or, once the panel
    // is open, from the tab strip's "+" button.
    const addTab = page.locator('[data-testid="ssh-console-tab-add"]');
    if (await addTab.isVisible().catch(() => false)) {
      await addTab.click();
    } else {
      await page.locator('[data-testid="ssh-new-connection"]').click();
    }
    await page.locator('#ssh-connect-host').fill(host);
    await page.locator('#ssh-connect-user').fill('e2e');
    await page.locator('[data-testid="ssh-connect-console-mode"]').selectOption('embedded');
    await page.getByRole('dialog').getByRole('button', { name: 'Connect' }).click();
    await page.waitForTimeout(300);
  }

  test('each embedded connection opens its own tab', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Vite standalone only — placeholder tabs need no backend');

    await openEmbedded(page, 'alpha.example.com');
    await expect(page.locator('[data-testid="ssh-console-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="ssh-console-tab"]')).toHaveCount(1);

    await openEmbedded(page, 'beta.example.com');
    await expect(page.locator('[data-testid="ssh-console-tab"]')).toHaveCount(2);

    // The newest tab is active and shows its target as the title.
    const tabs = page.locator('[data-testid="ssh-console-tab"]');
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(tabs.nth(1)).toContainText('e2e@beta.example.com');
    await expect(tabs.nth(0)).toHaveAttribute('aria-selected', 'false');
  });

  test('clicking a tab switches the active session pane', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Vite standalone only');

    await openEmbedded(page, 'alpha.example.com');
    await openEmbedded(page, 'beta.example.com');

    const tabs = page.locator('[data-testid="ssh-console-tab"]');
    await tabs.nth(0).click();
    await expect(tabs.nth(0)).toHaveAttribute('aria-selected', 'true');
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'false');

    // Both panes stay mounted (keep-alive); only one is visible.
    const panes = page.locator('.console-tab-pane');
    await expect(panes).toHaveCount(2);
    await expect(panes.nth(0)).toBeVisible();
    await expect(panes.nth(1)).not.toBeVisible();
  });

  test('closing one tab keeps the panel and activates a neighbor', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Vite standalone only');

    await openEmbedded(page, 'alpha.example.com');
    await openEmbedded(page, 'beta.example.com');

    const tabs = page.locator('[data-testid="ssh-console-tab"]');
    await tabs.nth(1).locator('[data-testid="ssh-console-tab-close"]').click();

    await expect(page.locator('[data-testid="ssh-console-tab"]')).toHaveCount(1);
    await expect(page.locator('[data-testid="ssh-console-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="ssh-console-tab"]').first()).toHaveAttribute('aria-selected', 'true');
  });

  test('closing the last tab hides the panel', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Vite standalone only');

    await openEmbedded(page, 'alpha.example.com');
    await page.locator('[data-testid="ssh-console-tab-close"]').click();
    await expect(page.locator('[data-testid="ssh-console-panel"]')).not.toBeVisible();
  });

  test('the panel close button closes every session tab', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Vite standalone only');

    await openEmbedded(page, 'alpha.example.com');
    await openEmbedded(page, 'beta.example.com');
    await page.locator('[data-testid="ssh-console-close"]').click();
    await expect(page.locator('[data-testid="ssh-console-panel"]')).not.toBeVisible();

    // Reopening starts a fresh tab set.
    await openEmbedded(page, 'gamma.example.com');
    await expect(page.locator('[data-testid="ssh-console-tab"]')).toHaveCount(1);
  });

  test('the + button in the tab strip opens the connect dialog', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Vite standalone only');

    await openEmbedded(page, 'alpha.example.com');
    await page.locator('[data-testid="ssh-console-tab-add"]').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByText('New SSH Connection')).toBeVisible();
  });
});

/**
 * Live multi-session proof for the console tabs: two REAL SSH sessions to
 * two servers at once, tab switching with both streams alive, independent
 * close, and in-place reconnect of an ended session.
 */
test.describe('SSH Embedded Console — live session tabs E2E', () => {
  test.afterAll(killEchoServers);

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'ssh');
  });

  /** Generates a managed key through the GUI (echo servers accept any key). */
  async function generateKey(page: import('@playwright/test').Page, keyName: string): Promise<void> {
    await page.locator('[data-testid="ssh-tab-keys"]').click();
    await page.locator('[data-testid="ssh-generate-button"]').click();
    await page.locator('#ssh-gen-name').fill(keyName);
    await page.locator('#ssh-gen-algorithm').selectOption('ed25519');
    await page.getByRole('dialog').getByRole('button', { name: 'Generate' }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible({ timeout: 30_000 });
    await page.locator('[data-testid="ssh-tab-profiles"]').click();
  }

  /** Opens an embedded connection (via toolbar or tab-strip "+") and accepts
   *  the first-contact fingerprint prompt. */
  async function openEmbedded(
    page: import('@playwright/test').Page,
    host: string,
    port: number,
    keyName: string,
    opts: { persist?: boolean; expectPrompt?: boolean } = {},
  ): Promise<void> {
    const addTab = page.locator('[data-testid="ssh-console-tab-add"]');
    if (await addTab.isVisible().catch(() => false)) {
      await addTab.click();
    } else {
      await page.locator('[data-testid="ssh-new-connection"]').click();
    }
    await page.locator('#ssh-connect-host').fill(host);
    await page.locator('#ssh-connect-port').fill(String(port));
    await page.locator('#ssh-connect-user').fill('e2e');
    const keyInput = page.getByRole('dialog').locator('[data-testid="ssh-key-select-input"]');
    await keyInput.click();
    await keyInput.fill(keyName);
    await page.locator(`[data-testid="ssh-key-option-xkey:${keyName}"]`).click();
    await page.locator('[data-testid="ssh-connect-console-mode"]').selectOption('embedded');
    if (opts.persist) {
      await page.locator('[data-testid="ssh-connect-persist-checkbox"]').check();
    }
    await page.getByRole('dialog').getByRole('button', { name: 'Connect' }).click();

    if (opts.expectPrompt !== false) {
      const prompt = page.locator('[data-testid="ssh-hostkey-prompt"]');
      await expect(prompt).toBeVisible({ timeout: 15_000 });
      await page.locator('[data-testid="ssh-hostkey-accept"]').click();
      await expect(prompt).not.toBeVisible();
    }
  }

  /** Persisted-session record count, straight from the backend binding. */
  async function persistedSessionCount(page: import('@playwright/test').Page): Promise<number> {
    return await page.evaluate(async () => {
      const records = await (window as any).go.services.SSHConsoleService.ListSessions();
      return (records ?? []).length;
    });
  }

  /** The console pane of the ACTIVE tab (inactive panes stay mounted but hidden). */
  const activePane = (page: import('@playwright/test').Page) =>
    page.locator('.console-tab-pane:not(.console-tab-pane--hidden)');

  /** Types marker into the active console and waits for the server echo. */
  async function typeAndExpectEcho(page: import('@playwright/test').Page, marker: string): Promise<void> {
    await activePane(page).locator('.term-container').click();
    await page.keyboard.type(marker);
    await page.keyboard.press('Enter');
    await expect(activePane(page)).toContainText(marker, { timeout: 15_000 });
  }

  test('two live sessions in tabs: both streams stay alive across switches', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'live Wails backend only');
    test.setTimeout(180_000);

    const srvA = await startEchoServer();
    const srvB = await startEchoServer();
    const keyName = `e2e-tabs-${Date.now()}`;
    await generateKey(page, keyName);

    // Session A, then session B from the tab strip's "+".
    await openEmbedded(page, srvA.host, srvA.port, keyName);
    const markerA = `tab-a-${Date.now()}`;
    await typeAndExpectEcho(page, markerA);

    await openEmbedded(page, srvB.host, srvB.port, keyName);
    await expect(page.locator('[data-testid="ssh-console-tab"]')).toHaveCount(2);
    const markerB = `tab-b-${Date.now()}`;
    await typeAndExpectEcho(page, markerB);

    // Switch back to A: its scrollback is intact and the stream is still
    // live (a fresh marker still echoes).
    await page.locator('[data-testid="ssh-console-tab"]').nth(0).click();
    await expect(activePane(page)).toContainText(markerA);
    const markerA2 = `tab-a-again-${Date.now()}`;
    await typeAndExpectEcho(page, markerA2);

    // Close tab B; A is untouched and still live.
    await page.locator('[data-testid="ssh-console-tab"]').nth(1).locator('[data-testid="ssh-console-tab-close"]').click();
    await expect(page.locator('[data-testid="ssh-console-tab"]')).toHaveCount(1);
    const markerA3 = `tab-a-after-b-closed-${Date.now()}`;
    await typeAndExpectEcho(page, markerA3);

    // Clean session end + panel close.
    await page.keyboard.type('exit');
    await page.keyboard.press('Enter');
    await page.locator('[data-testid="ssh-console-close"]').click();
  });

  test('an ended session tab reconnects in place', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'live Wails backend only');
    test.setTimeout(180_000);

    const srv = await startEchoServer();
    const keyName = `e2e-reconnect-${Date.now()}`;
    await generateKey(page, keyName);

    // Marker must not contain "exit" — the echo server ends the session on it.
    await openEmbedded(page, srv.host, srv.port, keyName);
    await typeAndExpectEcho(page, `pre-close-${Date.now()}`);

    // End the session server-side: the tab flips to "ended" and the
    // Reconnect action appears.
    await page.keyboard.type('exit');
    await page.keyboard.press('Enter');
    const tab = page.locator('[data-testid="ssh-console-tab"]').first();
    await expect(tab).toHaveClass(/console-tab--ended/, { timeout: 15_000 });
    const reconnect = page.locator('[data-testid="ssh-console-tab-reconnect"]');
    await expect(reconnect).toBeVisible();

    // Reconnect mints a fresh session in the same tab — the host is already
    // pinned from the first accept, so no prompt this time.
    await reconnect.click();
    await expect(tab).not.toHaveClass(/console-tab--ended/, { timeout: 15_000 });
    await expect(page.locator('[data-testid="ssh-hostkey-prompt"]')).not.toBeVisible();
    await typeAndExpectEcho(page, `post-reconnect-${Date.now()}`);

    await page.keyboard.type('exit');
    await page.keyboard.press('Enter');
    await page.locator('[data-testid="ssh-console-close"]').click();
  });

  test('a persistent session survives a page reload and reconnects', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'live Wails backend only');
    test.setTimeout(180_000);

    const srv = await startEchoServer();
    const keyName = `e2e-persist-${Date.now()}`;
    await generateKey(page, keyName);

    // Session explicitly started WITH persistence — a record is written.
    await openEmbedded(page, srv.host, srv.port, keyName, { persist: true });
    await typeAndExpectEcho(page, `persist-before-${Date.now()}`);
    await expect.poll(() => persistedSessionCount(page)).toBe(1);

    // Reload the app: the frontend loses all state; the persisted record
    // restores the tab, disconnected, with Reconnect ready.
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'ssh');

    const tab = page.locator('[data-testid="ssh-console-tab"]');
    await expect(tab).toHaveCount(1, { timeout: 15_000 });
    await expect(tab.first()).toHaveClass(/console-tab--ended/);
    await expect(tab.first()).toContainText(`e2e@${srv.host}`);
    await expect(page.getByText('Session not connected — press Reconnect')).toBeVisible();

    // Reconnect: the host is pinned, so the session opens prompt-free.
    await page.locator('[data-testid="ssh-console-tab-reconnect"]').click();
    await expect(tab.first()).not.toHaveClass(/console-tab--ended/, { timeout: 15_000 });
    await typeAndExpectEcho(page, `persist-after-${Date.now()}`);

    // Closing the tab ends the session for good — the record goes too.
    await page.keyboard.type('exit');
    await page.keyboard.press('Enter');
    await page.locator('[data-testid="ssh-console-tab-close"]').click();
    await expect(page.locator('[data-testid="ssh-console-panel"]')).not.toBeVisible();
    await expect.poll(() => persistedSessionCount(page)).toBe(0);
  });

  test('a default (memory-only) session leaves no record and is not restored', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'live Wails backend only');
    test.setTimeout(180_000);

    const srv = await startEchoServer();
    const keyName = `e2e-memory-${Date.now()}`;
    await generateKey(page, keyName);

    // Default connect — persistence NOT enabled.
    await openEmbedded(page, srv.host, srv.port, keyName);
    await typeAndExpectEcho(page, `memory-${Date.now()}`);
    await expect.poll(() => persistedSessionCount(page)).toBe(0);

    // After a reload nothing is restored.
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'ssh');
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="ssh-console-panel"]')).not.toBeVisible();
  });
});

/**
 * Persistent-session option surfaces (Vite mode): the opt-in is visible only
 * where it applies (embedded mode) and always defaults to OFF — sessions are
 * memory-only unless specifically started with persistence enabled.
 */
test.describe('SSH Console — persistent session option (Vite mode)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'ssh');
    await page.locator('[data-testid="ssh-tab-profiles"]').click();
    await page.waitForTimeout(200);
  });

  test('connect dialog shows the persist option only for embedded mode, default off', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Vite standalone only');

    await page.locator('[data-testid="ssh-new-connection"]').click();
    await page.waitForTimeout(200);

    // Default console mode is system — no persistence option.
    await expect(page.locator('[data-testid="ssh-connect-persist-toggle"]')).not.toBeVisible();

    await page.locator('[data-testid="ssh-connect-console-mode"]').selectOption('embedded');
    await expect(page.locator('[data-testid="ssh-connect-persist-toggle"]')).toBeVisible();
    await expect(page.locator('[data-testid="ssh-connect-persist-checkbox"]')).not.toBeChecked();

    // Switching back to system hides it again.
    await page.locator('[data-testid="ssh-connect-console-mode"]').selectOption('system');
    await expect(page.locator('[data-testid="ssh-connect-persist-toggle"]')).not.toBeVisible();
  });

  test('profile dialog has a persist option, default off', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Vite standalone only');

    await page.locator('[data-testid="ssh-new-profile"]').click();
    await page.waitForTimeout(200);
    await expect(page.locator('[data-testid="ssh-profile-persist-toggle"]')).toBeVisible();
    await expect(page.locator('[data-testid="ssh-profile-persist-checkbox"]')).not.toBeChecked();
  });
});
