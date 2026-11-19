// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Invite link redemption against the live server (ruling 973 (3)): an
// operator creates a user, the user opens the /#/invite/<tenant>/<token>
// link the server minted, registers a passkey on a CDP virtual
// authenticator and lands signed in; the spent link then reads as unusable.
import { test, expect } from '@playwright/test';
import { installVirtualAuthenticator } from './support/virtualAuthenticator.ts';
import { registerOperator, uniqueOperator } from './support/operator.ts';

interface CreatedUser {
  invite?: { token: string; url: string; expires_at: string };
}

test.describe('Invite link redemption', () => {
  test('redeems an invite with a passkey, signs in, and spends the link', async ({ browser }) => {
    // Operator session: register, keep the bearer token from the finish call.
    const opContext = await browser.newContext();
    const opPage = await opContext.newPage();
    await installVirtualAuthenticator(opPage);
    const op = uniqueOperator('invite-admin');
    const finish = opPage.waitForResponse(
      (r) => r.url().includes('/registration/finish') && r.request().method() === 'POST',
    );
    await registerOperator(opPage, op);
    const { token: opToken } = (await (await finish).json()) as { token: string };
    expect(opToken).toBeTruthy();

    const invitee = uniqueOperator('invitee');
    const created = await opPage.request.post('/api/v1/users/', {
      headers: { Authorization: `Bearer ${opToken}` },
      data: { username: invitee.email, email: invitee.email, display_name: invitee.displayName },
    });
    expect(created.ok(), await created.text()).toBe(true);
    const body = (await created.json()) as CreatedUser;
    expect(body.invite?.url).toContain('/#/invite/');
    const hash = body.invite!.url.slice(body.invite!.url.indexOf('#'));
    await opContext.close();

    // Invitee: a fresh browser with its own authenticator opens the link.
    const context = await browser.newContext();
    const page = await context.newPage();
    await installVirtualAuthenticator(page);
    await page.goto(`/ui/${hash}`);

    await expect(page.getByText(invitee.email)).toBeVisible();
    await page.getByRole('button', { name: 'Register passkey' }).click();

    await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('aside')).toBeVisible();

    // The token is single-use: reopening the link shows the unusable state.
    const again = await context.newPage();
    await again.goto(`/ui/${hash}`);
    await expect(again.getByText(/This invite link is not valid/)).toBeVisible();
    await context.close();
  });
});
