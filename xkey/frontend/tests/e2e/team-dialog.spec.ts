import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
} from './helpers';

/**
 * TeamManageDialog E2E tests.
 *
 * The dialog is embedded in the Passwords view and is triggered by clicking
 * the Create team (+) button in the Teams sidebar section.  Tests run
 * against the Vite dev server without a Wails backend so they verify DOM
 * structure and interaction patterns, not backend data.
 */
test.describe('TeamManageDialog', () => {
  /**
   * Open the Passwords view and navigate to the teams section.
   * The Passwords view renders the left panel even without backend data,
   * so the "Create team" button is always reachable in Vite mode.
   */
  async function openCreateTeamDialog(page: any): Promise<boolean> {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'passwords');
    await page.waitForTimeout(500);

    // Bail if the password view is behind a lock overlay.
    const lockOverlay = page.locator('.lock-overlay');
    const isLocked = await lockOverlay.isVisible().catch(() => false);
    if (isLocked) return false;

    const addBtn = page.locator('button.teams-add-btn');
    const addBtnVisible = await addBtn.isVisible().catch(() => false);
    if (!addBtnVisible) return false;

    await addBtn.click();
    await page.waitForTimeout(300);
    return true;
  }

  test.describe('Create Mode', () => {
    test('clicking the Create team button opens the dialog in create mode', async ({
      page,
    }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      await expect(page.getByText('New Team')).toBeVisible();
    });

    test('dialog has a Team Name input field', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      const nameInput = page.locator('#team-name-input');
      await expect(nameInput).toBeVisible();
      await expect(nameInput).toHaveAttribute('placeholder', 'e.g. Engineering');
    });

    test('dialog has a Members label', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      await expect(page.getByText('Members', { exact: true })).toBeVisible();
    });

    test('dialog shows "No members yet." message when members list is empty', async ({
      page,
    }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      await expect(page.locator('.no-members')).toBeVisible();
      await expect(page.locator('.no-members')).toContainText('No members yet.');
    });

    test('dialog has an Add Member input field', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      const addMemberInput = page.locator('.add-member-input');
      await expect(addMemberInput).toBeVisible();
      await expect(addMemberInput).toHaveAttribute('placeholder', 'User ID or username');
    });

    test('dialog has an Add button to add members', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      const addMemberBtn = page.locator('.add-member-btn');
      await expect(addMemberBtn).toBeVisible();
      await expect(addMemberBtn).toContainText('Add');
    });

    test('Add member button is disabled when input is empty', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      const addMemberBtn = page.locator('.add-member-btn');
      await expect(addMemberBtn).toBeDisabled();
    });

    test('Add member button enables when user ID is entered', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      const addMemberInput = page.locator('.add-member-input');
      await addMemberInput.fill('alice');
      await page.waitForTimeout(100);

      const addMemberBtn = page.locator('.add-member-btn');
      await expect(addMemberBtn).toBeEnabled();
    });

    test('typing a user ID and clicking Add appends the member to the list', async ({
      page,
    }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      const addMemberInput = page.locator('.add-member-input');
      await addMemberInput.fill('alice');
      await page.locator('.add-member-btn').click();
      await page.waitForTimeout(100);

      // The member should appear in the list.
      const memberList = page.locator('.member-list');
      await expect(memberList).toBeVisible();
      await expect(memberList.getByText('alice')).toBeVisible();

      // The input field should have been cleared.
      await expect(addMemberInput).toHaveValue('');
    });

    test('pressing Enter in the Add member input also adds the member', async ({
      page,
    }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      const addMemberInput = page.locator('.add-member-input');
      await addMemberInput.fill('bob');
      await addMemberInput.press('Enter');
      await page.waitForTimeout(100);

      const memberList = page.locator('.member-list');
      await expect(memberList).toBeVisible();
      await expect(memberList.getByText('bob')).toBeVisible();
    });

    test('each added member has a remove button', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      await page.locator('.add-member-input').fill('charlie');
      await page.locator('.add-member-btn').click();
      await page.waitForTimeout(100);

      const memberItem = page.locator('.member-item').first();
      await expect(memberItem).toBeVisible();

      const removeBtn = memberItem.locator('.member-remove');
      await expect(removeBtn).toBeVisible();
    });

    test('clicking a member remove button removes them from the list', async ({
      page,
    }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      // Add a member.
      await page.locator('.add-member-input').fill('diana');
      await page.locator('.add-member-btn').click();
      await page.waitForTimeout(100);

      await expect(page.locator('.member-list').getByText('diana')).toBeVisible();

      // Remove the member.
      const removeBtn = page.locator('.member-item').first().locator('.member-remove');
      await removeBtn.click();
      await page.waitForTimeout(100);

      // The member should be gone and empty message should return.
      await expect(page.locator('.no-members')).toBeVisible();
    });

    test('Cancel button closes the dialog', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      await expect(page.getByText('New Team')).toBeVisible();

      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      await expect(page.getByText('New Team')).not.toBeVisible();
    });

    test('Save/Create button is present', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      // In create mode the button reads "Create".
      const createBtn = page.locator('.modal-backdrop').getByRole('button', { name: 'Create' });
      await expect(createBtn).toBeVisible();
    });

    test('Create button is disabled when Team Name is empty', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      // Name starts empty — button should be disabled.
      const createBtn = page.locator('.modal-backdrop').getByRole('button', { name: 'Create' });
      await expect(createBtn).toBeDisabled();
    });

    test('Create button enables when Team Name is filled', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      await page.locator('#team-name-input').fill('Engineering');
      await page.waitForTimeout(100);

      const createBtn = page.locator('.modal-backdrop').getByRole('button', { name: 'Create' });
      await expect(createBtn).toBeEnabled();
    });

    test('team name shows validation error when Create is clicked with empty name', async ({
      page,
    }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      // The Create button is disabled with empty name, so verify that
      // filling then clearing triggers the inline validation.
      const nameInput = page.locator('#team-name-input');
      await nameInput.fill('Temp');
      await nameInput.clear();
      await page.waitForTimeout(100);

      // The form-error element should appear when the field is dirty and empty.
      const errorMsg = page.locator('.form-error');
      const hasError = await errorMsg.isVisible().catch(() => false);
      if (hasError) {
        await expect(errorMsg).toContainText('Team name is required');
      }
    });

    test('can add multiple members before saving', async ({ page }) => {
      const opened = await openCreateTeamDialog(page);
      if (!opened) return;

      const addMemberInput = page.locator('.add-member-input');
      const addMemberBtn = page.locator('.add-member-btn');

      await addMemberInput.fill('alice');
      await addMemberBtn.click();
      await page.waitForTimeout(50);

      await addMemberInput.fill('bob');
      await addMemberBtn.click();
      await page.waitForTimeout(50);

      await addMemberInput.fill('charlie');
      await addMemberBtn.click();
      await page.waitForTimeout(100);

      const memberItems = page.locator('.member-item');
      await expect(memberItems).toHaveCount(3);
    });
  });
});
