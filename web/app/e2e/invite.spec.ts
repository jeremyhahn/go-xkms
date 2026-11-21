// Invite link route (ruling 973 (3)): /#/invite/<tenant>/<token> opens the
// passkey enrolment view. Mock API tier: the live ceremony runs in
// test/integration/web/tests/invite.spec.ts.
import { test, expect } from '@playwright/test';
import { mockLoginCapabilities } from './support/mockAuth.ts';

const INVITE = '**/api/v1/invites/t1/tok';

test.describe('Invite link', () => {
  test('names webauthn.enabled and reads no invite when webauthn is off', async ({ page }) => {
    await mockLoginCapabilities(page, { webauthn_enabled: false, piv_login_enabled: false });
    let inviteCalls = 0;
    await page.route('**/api/v1/invites/**', async (route) => {
      inviteCalls++;
      await route.fulfill({ status: 500, body: '{}' });
    });

    await page.goto('/#/invite/t1/tok');

    await expect(page.getByText('webauthn.enabled')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Register passkey' })).toHaveCount(0);
    expect(inviteCalls).toBe(0);
  });

  test('shows the unusable-link state on a 404', async ({ page }) => {
    await mockLoginCapabilities(page);
    await page.route(INVITE, async (route) => {
      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'link is not valid', code: 'invite_unusable' }),
      });
    });

    await page.goto('/#/invite/t1/tok');

    await expect(page.getByText(/This invite link is not valid/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Register passkey' })).toHaveCount(0);
  });

  test('shows the tenant and invited address with the register action', async ({ page }) => {
    await mockLoginCapabilities(page);
    await page.route(INVITE, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          email: 'ada@example.com',
          expires_at: '2026-12-01T00:00:00Z',
          methods: ['webauthn'],
        }),
      });
    });

    await page.goto('/#/invite/t1/tok');

    await expect(page.getByTestId('invite-tenant')).toHaveText('t1');
    await expect(page.getByText('ada@example.com')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Register passkey' })).toBeVisible();
  });
});
