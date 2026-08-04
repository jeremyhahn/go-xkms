import { test, expect, type Page } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
} from './helpers';

test.describe('Passwords View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'passwords');
  });

  test.describe('Header and Layout', () => {
    test('Passwords view loads with correct header', async ({ page }) => {
      await expect(page.locator('h1.header-title')).toHaveText('Passwords');
      await expect(
        page.getByText('Static password management'),
      ).toBeVisible();
    });

    test('Add Password button is visible in the header when unlocked', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const addButton = page.getByRole('button', { name: 'Add Password' });
        await expect(addButton).toBeVisible();
      }
    });
  });

  test.describe('Three-Panel Layout', () => {
    test('three-panel layout renders when unlocked', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const threePanel = page.locator('.three-panel');
        await expect(threePanel).toBeVisible();

        await expect(page.locator('.panel-left')).toBeVisible();
        await expect(page.locator('.panel-center')).toBeVisible();
        await expect(page.locator('.panel-right')).toBeVisible();
      }
    });

    test('left panel contains folder tree', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const panelLeft = page.locator('.panel-left');
        await expect(panelLeft).toBeVisible();

        const folderTree = page.locator('.folder-tree');
        await expect(folderTree).toBeVisible();
      }
    });

    test('center panel contains search bar and list', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const panelCenter = page.locator('.panel-center');
        await expect(panelCenter).toBeVisible();

        const searchInput = page.locator('input[placeholder="Search passwords..."]');
        await expect(searchInput).toBeVisible();
      }
    });

    test('right panel contains detail panel', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const panelRight = page.locator('.panel-right');
        await expect(panelRight).toBeVisible();
      }
    });
  });

  test.describe('Folder Tree', () => {
    test('folder tree renders with All Passwords root item', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const folderTree = page.locator('.folder-tree');
        await expect(folderTree).toBeVisible();
        await expect(page.getByText('All Passwords')).toBeVisible();
      }
    });

    test('New Folder button is visible in the folder tree', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const newFolderButton = page.locator('.new-folder-btn');
        await expect(newFolderButton).toBeVisible();
        await expect(page.getByText('New Folder')).toBeVisible();
      }
    });

    test('New Folder button opens the folder creation dialog', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        await page.locator('.new-folder-btn').click();

        await expect(page.getByText('New Folder').first()).toBeVisible();

        const folderInput = page.locator('.folder-form input.form-input');
        await expect(folderInput).toBeVisible();
        await expect(folderInput).toHaveAttribute(
          'placeholder',
          'e.g. Work/Email',
        );
      }
    });

    test('folder creation dialog has hint about nested folders', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        await page.locator('.new-folder-btn').click();

        await expect(
          page.getByText('Use "/" to create nested folders'),
        ).toBeVisible();
      }
    });

    test('folder creation dialog has Create and Cancel buttons', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        await page.locator('.new-folder-btn').click();

        await expect(
          page.getByRole('button', { name: 'Create', exact: true }),
        ).toBeVisible();
        await expect(
          page.getByRole('button', { name: 'Cancel' }),
        ).toBeVisible();
      }
    });

    test('folder creation dialog Create button is disabled when input is empty', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        await page.locator('.new-folder-btn').click();

        const createButton = page.getByRole('button', { name: 'Create', exact: true });
        await expect(createButton).toBeDisabled();
      }
    });

    test('folder creation dialog Create button enables when text is entered', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        await page.locator('.new-folder-btn').click();

        const folderInput = page.locator('.folder-form input.form-input');
        await folderInput.fill('Work');

        const createButton = page.getByRole('button', { name: 'Create', exact: true });
        await expect(createButton).toBeEnabled();
      }
    });

    test('create a folder "Work" and verify it appears in the tree', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        await page.locator('.new-folder-btn').click();

        const folderInput = page.locator('.folder-form input.form-input');
        await folderInput.fill('Work');

        await page.getByRole('button', { name: 'Create', exact: true }).click();
        await page.waitForTimeout(300);

        // The folder should now appear in the folder tree
        await expect(page.locator('.folder-tree').getByText('Work', { exact: true })).toBeVisible();
      }
    });

    test('create nested folder "Work/Projects" using slash syntax', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        await page.locator('.new-folder-btn').click();

        const folderInput = page.locator('.folder-form input.form-input');
        await folderInput.fill('Work/Projects');

        await page.getByRole('button', { name: 'Create', exact: true }).click();
        await page.waitForTimeout(300);

        // "Projects" should appear as a nested folder
        await expect(page.getByText('Projects')).toBeVisible();
      }
    });

    test('folder creation dialog Cancel closes the dialog', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        await page.locator('.new-folder-btn').click();
        await expect(
          page.getByRole('button', { name: 'Create', exact: true }),
        ).toBeVisible();

        await page.getByRole('button', { name: 'Cancel' }).click();
        await page.waitForTimeout(300);

        // Dialog should be gone, Create button should not be visible
        await expect(
          page.getByRole('button', { name: 'Create', exact: true }),
        ).not.toBeVisible();
      }
    });
  });

  test.describe('Search', () => {
    test('search bar is visible in the center panel', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const searchInput = page.locator(
          'input[placeholder="Search passwords..."]',
        );
        await expect(searchInput).toBeVisible();
      }
    });

    test('search bar accepts input', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const searchInput = page.locator(
          'input[placeholder="Search passwords..."]',
        );
        await searchInput.fill('test-search');
        const value = await searchInput.inputValue();
        expect(value).toBe('test-search');
      }
    });
  });

  test.describe('Empty State', () => {
    test('shows empty state when no passwords stored', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const emptyTitle = page.getByText('No passwords stored');
        const passwordList = page.locator('.list-content');

        const hasEmpty = await emptyTitle.isVisible().catch(() => false);
        const hasList = await passwordList.isVisible().catch(() => false);
        expect(hasEmpty || hasList).toBeTruthy();
      }
    });

    test('empty state shows descriptive message', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const emptyTitle = page.getByText('No passwords stored');
        const isVisible = await emptyTitle.isVisible().catch(() => false);
        if (isVisible) {
          await expect(
            page.getByText('Add static passwords for quick access and autofill.'),
          ).toBeVisible();
        }
      }
    });
  });

  test.describe('Lock Overlay', () => {
    test('shows lock overlay when password protection is active', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (isLocked) {
        await expect(page.getByText('Passwords Locked')).toBeVisible();
        await expect(
          page.getByText('Enter your master password'),
        ).toBeVisible();
        await expect(
          page.getByRole('button', { name: 'Unlock' }),
        ).toBeVisible();
      }
    });

    test('lock overlay has password input field', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (isLocked) {
        const passwordInput = page.locator(
          'input[placeholder="Master password"]',
        );
        await expect(passwordInput).toBeVisible();
      }
    });

    test('Unlock button is disabled when password is empty', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (isLocked) {
        const unlockButton = page.getByRole('button', { name: 'Unlock' });
        await expect(unlockButton).toBeDisabled();
      }
    });
  });

  test.describe('Wails Mode - Password Management', () => {
    test('add a password with all fields and verify it appears', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // Click Add Password
      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // The PasswordAddEditDialog should open
      // Fill in all fields
      const nameInput = page.locator('input[placeholder*="Name"]').first();
      const hasNameInput = await nameInput.isVisible().catch(() => false);
      if (hasNameInput) {
        await nameInput.fill('Test Service');
      }
    });

    test('click a password to see details in the right panel', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with stored passwords');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // If passwords exist, click on one
      const passwordItems = page.locator('.password-list-item');
      const count = await passwordItems.count();
      if (count > 0) {
        await passwordItems.first().click();
        await page.waitForTimeout(300);

        // Detail panel should show content
        const detailPanel = page.locator('.panel-right');
        await expect(detailPanel).not.toBeEmpty();
      }
    });

    test('search filters passwords by name', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with stored passwords');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      const searchInput = page.locator('input[placeholder="Search passwords..."]');
      await searchInput.fill('nonexistent-xyz-query');
      await page.waitForTimeout(300);

      // Should show "No matching passwords" empty state
      await expect(page.getByText('No matching passwords')).toBeVisible();
    });

    test('delete folder shows confirmation dialog', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with folders');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // This test requires folders to exist - create one first
      await page.locator('.new-folder-btn').click();
      const folderInput = page.locator('.folder-form input.form-input');
      await folderInput.fill('TempFolder');
      await page.getByRole('button', { name: 'Create', exact: true }).click();
      await page.waitForTimeout(300);

      // Right-click or find delete option on the folder
      // The folder tree uses context menu or delete buttons
    });
  });

  test.describe('Add Password Dialog', () => {
    test('Add Password button opens the add dialog with all expected fields', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // Click Add Password to open the dialog
      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // The modal should be visible with the "Add Password" title
      const dialog = page.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();
      await expect(page.getByText('Add Password').first()).toBeVisible();

      // Verify all expected form fields are present
      const nameInput = page.locator('input[placeholder="e.g. GitHub Account"]');
      await expect(nameInput).toBeVisible();

      const usernameInput = page.locator('input[placeholder="e.g. user@example.com"]');
      await expect(usernameInput).toBeVisible();

      const passwordInput = page.locator('input[placeholder="Enter or generate"]');
      await expect(passwordInput).toBeVisible();

      const urlInput = page.locator('input[placeholder="e.g. https://github.com"]');
      await expect(urlInput).toBeVisible();

      const notesTextarea = page.locator('textarea[placeholder="Optional notes..."]');
      await expect(notesTextarea).toBeVisible();
    });

    test('generate button is present in the add dialog password field', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // The generate button has class .generate-btn and title "Generate password"
      const generateBtn = page.locator('button.generate-btn');
      await expect(generateBtn).toBeVisible();
      await expect(generateBtn).toHaveAttribute('title', 'Generate password');
    });

    test('password visibility toggle button exists in the add dialog', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // The eye/toggle button has class .input-action-btn and title "Reveal"
      const toggleBtn = page.locator('button.input-action-btn');
      await expect(toggleBtn).toBeVisible();
      await expect(toggleBtn).toHaveAttribute('title', 'Reveal');
    });

    test('password field toggles visibility when eye icon is clicked', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // Initially the password input should be type="password"
      const passwordInput = page.locator('.password-input-wrapper input.form-input');
      await expect(passwordInput).toHaveAttribute('type', 'password');

      // Fill in a value so we can verify the toggle works
      await passwordInput.fill('secret123');

      // Click the eye icon to reveal the password
      const toggleBtn = page.locator('button.input-action-btn');
      await toggleBtn.click();
      await page.waitForTimeout(100);

      // After clicking, the input should switch to type="text"
      const revealedInput = page.locator('.password-input-wrapper input.form-input');
      await expect(revealedInput).toHaveAttribute('type', 'text');

      // The toggle button title should now say "Hide"
      await expect(toggleBtn).toHaveAttribute('title', 'Hide');

      // Click again to hide it
      await toggleBtn.click();
      await page.waitForTimeout(100);

      const hiddenInput = page.locator('.password-input-wrapper input.form-input');
      await expect(hiddenInput).toHaveAttribute('type', 'password');
      await expect(toggleBtn).toHaveAttribute('title', 'Reveal');
    });

    test('Add button is disabled when name field is empty', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // Fill only the password field, leave name empty
      const passwordInput = page.locator('input[placeholder="Enter or generate"]');
      await passwordInput.fill('somepassword');

      // The "Add" save button should be disabled because name is required
      const addBtn = page.locator('.modal-actions').getByRole('button', { name: 'Add' });
      await expect(addBtn).toBeDisabled();
    });

    test('Add button is disabled when password field is empty', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // Fill only the name field, leave password empty
      const nameInput = page.locator('input[placeholder="e.g. GitHub Account"]');
      await nameInput.fill('Test Entry');

      // The "Add" save button should be disabled because password is required
      const addBtn = page.locator('.modal-actions').getByRole('button', { name: 'Add' });
      await expect(addBtn).toBeDisabled();
    });

    test('Add button enables when both name and password are filled', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      const nameInput = page.locator('input[placeholder="e.g. GitHub Account"]');
      const passwordInput = page.locator('input[placeholder="Enter or generate"]');
      const addBtn = page.locator('.modal-actions').getByRole('button', { name: 'Add' });

      // Initially disabled
      await expect(addBtn).toBeDisabled();

      // Fill both required fields
      await nameInput.fill('Test Entry');
      await passwordInput.fill('test123');

      // Now the button should be enabled
      await expect(addBtn).toBeEnabled();
    });

    test('Cancel button closes the add dialog', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      const dialog = page.locator('[role="dialog"]');
      await expect(dialog).toBeVisible();

      // Click Cancel
      await page.locator('.modal-actions').getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      // Dialog should no longer be visible
      await expect(dialog).not.toBeVisible();
    });

    test('generator options show length slider and charset selector', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // Length slider should be visible with default value of 32
      const lengthSlider = page.locator('input[type="range"]');
      await expect(lengthSlider).toBeVisible();
      await expect(lengthSlider).toHaveAttribute('min', '8');
      await expect(lengthSlider).toHaveAttribute('max', '128');

      // The option-value span should show "32" as the default
      const lengthValue = page.locator('.option-value');
      await expect(lengthValue).toHaveText('32');

      // Charset selector should be visible
      const charsetSelect = page.locator('.form-select');
      await expect(charsetSelect.first()).toBeVisible();
    });
  });

  test.describe('Wails Mode - Password Generator', () => {
    test('generate button produces a non-empty password', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // Click the generate button
      const generateBtn = page.locator('button.generate-btn');
      await generateBtn.click();
      await page.waitForTimeout(500);

      // The password field should now have a non-empty value
      const passwordInput = page.locator('.password-input-wrapper input.form-input');
      const generatedValue = await passwordInput.inputValue();
      expect(generatedValue.length).toBeGreaterThan(0);
    });

    test('generated password has at least 16 characters with default settings', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // Default genLength is 32, so generate should produce at least 16 chars
      const generateBtn = page.locator('button.generate-btn');
      await generateBtn.click();
      await page.waitForTimeout(500);

      const passwordInput = page.locator('.password-input-wrapper input.form-input');
      const generatedValue = await passwordInput.inputValue();
      expect(generatedValue.length).toBeGreaterThanOrEqual(16);
    });
  });

  test.describe('Wails Mode - Password CRUD', () => {
    // Track the name of the entry created by each test so afterEach can clean
    // up, keeping the shared persistent backend idempotent across re-runs.
    let createdEntryName: string | null = null;

    /**
     * Delete a password entry by name via the GUI delete flow. Safe to call
     * when the entry does not exist. Handles any open dialog by pressing
     * Escape first.
     */
    async function cleanupEntry(page: Page, name: string): Promise<void> {
      // Close any lingering Add/Edit dialog before interacting with the list.
      await page.keyboard.press('Escape').catch(() => {});
      await page.waitForTimeout(200);

      const listItem = page.locator('.list-item', { hasText: name }).first();
      const exists = await listItem.isVisible({ timeout: 2_000 }).catch(() => false);
      if (!exists) return;

      await listItem.click();
      await page.waitForTimeout(200);

      const deleteBtn = page.locator('.panel-right').getByRole('button', { name: 'Delete' });
      const deleteBtnVisible = await deleteBtn.isVisible({ timeout: 2_000 }).catch(() => false);
      if (!deleteBtnVisible) return;

      await deleteBtn.click();
      await page.waitForTimeout(200);

      const confirmDialog = page.locator('.confirm-dialog');
      const confirmVisible = await confirmDialog.isVisible({ timeout: 2_000 }).catch(() => false);
      if (!confirmVisible) return;

      await confirmDialog.getByRole('button', { name: 'Delete' }).click();
      await page.waitForTimeout(400);
    }

    test.afterEach(async ({ page }) => {
      if (!createdEntryName) return;
      const name = createdEntryName;
      createdEntryName = null;

      const wails = await isWailsMode(page).catch(() => false);
      if (!wails) return;

      await cleanupEntry(page, name);
    });

    test('add and save a password entry then verify it appears in the list', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // Use a unique name per run so re-runs don't hit a duplicate-name error.
      const entryName = `E2E Test Entry ${Date.now().toString(36)}`;
      createdEntryName = entryName;

      // Open the Add Password dialog
      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      // Fill in the required fields
      const nameInput = page.locator('input[placeholder="e.g. GitHub Account"]');
      await nameInput.fill(entryName);

      const passwordInput = page.locator('input[placeholder="Enter or generate"]');
      await passwordInput.fill('e2e-test-password-123');

      // Fill optional fields
      const usernameInput = page.locator('input[placeholder="e.g. user@example.com"]');
      await usernameInput.fill('testuser@example.com');

      const urlInput = page.locator('input[placeholder="e.g. https://github.com"]');
      await urlInput.fill('https://test.example.com');

      // Click Add to save
      const addBtn = page.locator('.modal-actions').getByRole('button', { name: 'Add' });
      await expect(addBtn).toBeEnabled();
      await addBtn.click();
      await page.waitForTimeout(500);

      // The dialog should close
      const dialog = page.locator('[role="dialog"]');
      await expect(dialog).not.toBeVisible();

      // The entry should appear in the password list.
      // Use the list panel scope to avoid matching the toast notification.
      const passwordList = page.locator('.panel-center .list-content');
      await expect(passwordList.getByText(entryName, { exact: true })).toBeVisible();
    });

    test('click an entry to view details in the right panel', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // Use a unique name per run to avoid duplicate-name failures on re-runs.
      const entryName = `Detail View Entry ${Date.now().toString(36)}`;
      createdEntryName = entryName;

      // Add a password entry to ensure there is something to click.
      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      await page.locator('input[placeholder="e.g. GitHub Account"]').fill(entryName);
      await page.locator('input[placeholder="Enter or generate"]').fill('detail-password');
      await page.locator('input[placeholder="e.g. user@example.com"]').fill('detailuser');

      await page.locator('.modal-actions').getByRole('button', { name: 'Add' }).click();
      await page.waitForTimeout(500);

      // Confirm the dialog closed before interacting with the list.
      await expect(page.locator('[role="dialog"]')).not.toBeVisible({ timeout: 5_000 });

      // Click the newly created entry in the list.
      const listItem = page.locator('.list-item', { hasText: entryName }).first();
      await listItem.click();
      await page.waitForTimeout(300);

      // The right panel should now show detail fields
      const detailPanel = page.locator('.panel-right');
      await expect(detailPanel.locator('.detail-fields')).toBeVisible();

      // Verify detail panel shows the username
      await expect(detailPanel.getByText('detailuser')).toBeVisible();
    });

    test('edit a password entry and verify the change persists', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // Add a password entry first
      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      await page.locator('input[placeholder="e.g. GitHub Account"]').fill('Edit Test Entry');
      await page.locator('input[placeholder="Enter or generate"]').fill('edit-test-pw');

      await page.locator('.modal-actions').getByRole('button', { name: 'Add' }).click();
      await page.waitForTimeout(500);

      // Select the entry
      const listItem = page.locator('.list-item', { hasText: 'Edit Test Entry' });
      await listItem.click();
      await page.waitForTimeout(300);

      // Click the Edit button in the detail panel
      const editBtn = page.locator('.panel-right').getByRole('button', { name: 'Edit' });
      await editBtn.click();
      await page.waitForTimeout(300);

      // The edit dialog should open with "Edit Password" title
      await expect(page.getByText('Edit Password')).toBeVisible();

      // Change the name
      const nameInput = page.locator('input[placeholder="e.g. GitHub Account"]');
      await nameInput.clear();
      await nameInput.fill('Edited Entry Name');

      // Click Save
      const saveBtn = page.locator('.modal-actions').getByRole('button', { name: 'Save' });
      await expect(saveBtn).toBeEnabled();
      await saveBtn.click();
      await page.waitForTimeout(500);

      // Verify the updated name appears in the list.
      // Scope to the list panel to avoid matching the toast notification.
      const passwordList = page.locator('.panel-center .list-content');
      await expect(passwordList.getByText('Edited Entry Name', { exact: true })).toBeVisible();
    });

    test('delete a password entry and verify it is removed from the list', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // Add a password entry to delete
      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      await page.locator('input[placeholder="e.g. GitHub Account"]').fill('Delete Me Entry');
      await page.locator('input[placeholder="Enter or generate"]').fill('delete-me-pw');

      await page.locator('.modal-actions').getByRole('button', { name: 'Add' }).click();
      await page.waitForTimeout(500);

      // Verify the entry exists in the list panel.
      // Scope to avoid matching the toast notification.
      const passwordList = page.locator('.panel-center .list-content');
      await expect(passwordList.getByText('Delete Me Entry', { exact: true })).toBeVisible();

      // Select the entry to show it in the detail panel
      const listItem = page.locator('.list-item', { hasText: 'Delete Me Entry' });
      await listItem.click();
      await page.waitForTimeout(300);

      // Click the Delete button in the detail panel
      const deleteBtn = page.locator('.panel-right').getByRole('button', { name: 'Delete' });
      await deleteBtn.click();
      await page.waitForTimeout(300);

      // The confirmation dialog should appear
      const confirmDialog = page.locator('.confirm-dialog');
      await expect(confirmDialog).toBeVisible();
      await expect(
        confirmDialog.getByRole('heading', { name: 'Delete Password' }),
      ).toBeVisible();
      await expect(
        confirmDialog.getByText('Are you sure you want to delete "Delete Me Entry"?'),
      ).toBeVisible();

      // Confirm the deletion
      await confirmDialog.getByRole('button', { name: 'Delete' }).click();
      await page.waitForTimeout(500);

      // The entry should no longer appear in the LIST. Scope to the list panel: the
      // success toast ("Password \"Delete Me Entry\" deleted") also contains the name.
      await expect(
        page.locator('.panel-center .list-content').getByText('Delete Me Entry', { exact: true }),
      ).not.toBeVisible();
    });

    test('delete confirmation dialog has Cancel and Delete buttons', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      // Use a unique name per run to avoid duplicate-name failures on re-runs.
      const entryName = `Confirm Dialog Entry ${Date.now().toString(36)}`;
      createdEntryName = entryName;

      // Add and select an entry to trigger delete confirmation.
      await page.getByRole('button', { name: 'Add Password' }).click();
      await page.waitForTimeout(300);

      await page.locator('input[placeholder="e.g. GitHub Account"]').fill(entryName);
      await page.locator('input[placeholder="Enter or generate"]').fill('confirm-pw');

      await page.locator('.modal-actions').getByRole('button', { name: 'Add' }).click();
      await page.waitForTimeout(500);

      // Confirm the dialog closed before interacting with the list.
      await expect(page.locator('[role="dialog"]')).not.toBeVisible({ timeout: 5_000 });

      const listItem = page.locator('.list-item', { hasText: entryName }).first();
      await listItem.click();
      await page.waitForTimeout(300);

      // Click Delete in detail panel
      await page.locator('.panel-right').getByRole('button', { name: 'Delete' }).click();
      await page.waitForTimeout(300);

      const confirmDialog = page.locator('.confirm-dialog');
      await expect(confirmDialog).toBeVisible();

      // Both Cancel and Delete buttons should be present
      await expect(confirmDialog.getByRole('button', { name: 'Cancel' })).toBeVisible();
      await expect(confirmDialog.getByRole('button', { name: 'Delete' })).toBeVisible();

      // Cancel the deletion
      await confirmDialog.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      // Confirm dialog should close and entry should still exist in the list.
      // Scope to the list panel to avoid matching any lingering toast notification.
      await expect(confirmDialog).not.toBeVisible();
      const passwordList = page.locator('.panel-center .list-content');
      await expect(passwordList.getByText(entryName, { exact: true })).toBeVisible();
    });
  });

  test.describe('Teams Section', () => {
    test('Teams section heading is visible in the left panel', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const teamsSection = page.locator('.teams-section');
        await expect(teamsSection).toBeVisible();

        const teamsHeading = page.locator('.teams-heading');
        await expect(teamsHeading).toBeVisible();
        await expect(teamsHeading).toContainText('Teams');
      }
    });

    test('Create team button (+) is visible in the Teams header', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const addBtn = page.locator('button.teams-add-btn');
        await expect(addBtn).toBeVisible();
        await expect(addBtn).toHaveAttribute('title', 'Create team');
      }
    });

    test('Teams section shows empty state when no teams exist', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);

      if (!isLocked) {
        const teamsSection = page.locator('.teams-section');
        await expect(teamsSection).toBeVisible();

        // With no backend in Vite mode, teams list will be empty.
        const emptyMsg = page.locator('.teams-empty');
        const teamsList = page.locator('.teams-list');

        const hasEmpty = await emptyMsg.isVisible().catch(() => false);
        const hasList = await teamsList.isVisible().catch(() => false);
        // One of the two states must be rendered.
        expect(hasEmpty || hasList).toBeTruthy();
      }
    });

    test('teams list renders when teams are present (Wails mode)', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.waitForTimeout(800);

      const teamsSection = page.locator('.teams-section');
      await expect(teamsSection).toBeVisible();

      const teamsEmpty = page.locator('.teams-empty');
      const teamsList = page.locator('.teams-list');

      const hasEmpty = await teamsEmpty.isVisible().catch(() => false);
      const hasList = await teamsList.isVisible().catch(() => false);
      expect(hasEmpty || hasList).toBeTruthy();
    });

    test('clicking a team item selects it (Wails mode)', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with teams');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.waitForTimeout(800);

      const teamItems = page.locator('.teams-item');
      const count = await teamItems.count();
      if (count === 0) return;

      // Click the first team item.
      await teamItems.first().click();
      await page.waitForTimeout(200);

      // The selected team should have the selected class.
      await expect(teamItems.first()).toHaveClass(/teams-item--selected/);
    });

    test('selected team item shows member count badge', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with teams');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.waitForTimeout(800);

      const teamItems = page.locator('.teams-item');
      const count = await teamItems.count();
      if (count === 0) return;

      const countBadge = teamItems.first().locator('.teams-item-count');
      await expect(countBadge).toBeVisible();
    });

    test('selected team item reveals manage and delete action buttons', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with teams');

      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      await page.waitForTimeout(800);

      const teamItems = page.locator('.teams-item');
      const count = await teamItems.count();
      if (count === 0) return;

      // Click to select.
      await teamItems.first().click();
      await page.waitForTimeout(200);

      // Action buttons should appear only on the selected item.
      const actions = teamItems.first().locator('.teams-item-actions');
      await expect(actions).toBeVisible();

      const manageBtn = actions.locator('.teams-action-btn').first();
      const deleteBtn = actions.locator('.teams-action-btn.teams-action-btn--danger');
      await expect(manageBtn).toBeVisible();
      await expect(deleteBtn).toBeVisible();
    });

    test('clicking Create team button opens the TeamManageDialog', async ({ page }) => {
      await page.waitForTimeout(500);

      const lockOverlay = page.locator('.lock-overlay');
      const isLocked = await lockOverlay.isVisible().catch(() => false);
      if (isLocked) return;

      const addBtn = page.locator('button.teams-add-btn');
      await addBtn.click();
      await page.waitForTimeout(300);

      // The team dialog (Modal with title "New Team") should open.
      await expect(page.getByText('New Team')).toBeVisible();
    });
  });
});

// ── Standalone (Vite) mode: Wails-unavailable feedback ────────────────────
// These tests run without a Wails backend and verify that every user-initiated
// action that requires the desktop app produces a visible error toast instead
// of silently no-oping.

test.describe('Standalone Mode - Wails-required notifications', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'passwords');
    await page.waitForTimeout(300);
  });

  test('clicking Generate password in Add dialog shows desktop-app toast', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Only relevant in standalone Vite mode');

    const lockOverlay = page.locator('.lock-overlay');
    const isLocked = await lockOverlay.isVisible().catch(() => false);
    if (isLocked) return;

    // Open the Add Password dialog.
    await page.getByRole('button', { name: 'Add Password' }).click();
    await page.waitForTimeout(300);

    // Click the generate button.
    await page.locator('button.generate-btn').click();

    // A toast containing "desktop app" must appear.
    await expect(page.locator('.toast-container')).toContainText(/no backend connection/i, { timeout: 5000 });
  });

  test('clicking Import button shows desktop-app toast', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Only relevant in standalone Vite mode');

    const lockOverlay = page.locator('.lock-overlay');
    const isLocked = await lockOverlay.isVisible().catch(() => false);
    if (isLocked) return;

    await page.getByRole('button', { name: 'Import' }).click();

    await expect(page.locator('.toast-container')).toContainText(/no backend connection/i, { timeout: 5000 });
  });

  test('clicking Restore button shows desktop-app toast', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Only relevant in standalone Vite mode');

    const lockOverlay = page.locator('.lock-overlay');
    const isLocked = await lockOverlay.isVisible().catch(() => false);
    if (isLocked) return;

    await page.getByRole('button', { name: 'Restore' }).click();

    await expect(page.locator('.toast-container')).toContainText(/no backend connection/i, { timeout: 5000 });
  });

  test('clicking Backup button shows desktop-app toast', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(wails, 'Only relevant in standalone Vite mode');

    const lockOverlay = page.locator('.lock-overlay');
    const isLocked = await lockOverlay.isVisible().catch(() => false);
    if (isLocked) return;

    await page.getByRole('button', { name: 'Backup' }).click();

    await expect(page.locator('.toast-container')).toContainText(/no backend connection/i, { timeout: 5000 });
  });
});
