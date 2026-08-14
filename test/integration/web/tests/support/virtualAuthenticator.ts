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

/**
 * Chrome CDP virtual WebAuthn authenticator setup, lifted verbatim (as
 * instructed) from
 * test/integration/webauthn-browser/tests/rp-ceremony.spec.ts, which already
 * proved this exact configuration against the real go-webauthn RP. Reused
 * here instead of reinventing it so the SPA's real navigator.credentials
 * calls (via @go-xkms/svelte-auth's BrowserCredentialProvider) resolve
 * against a real software authenticator.
 */

import type { CDPSession, Page } from '@playwright/test';

/**
 * addVirtualAuthenticator wires a CTAP2 software authenticator into the page
 * over the Chrome DevTools Protocol and returns its id. hasResidentKey +
 * automaticPresenceSimulation mean the SPA's registration ceremony can create
 * a discoverable credential with no manual "touch the key" step, and a later
 * login ceremony (same page/context) resolves it without a fake email prompt.
 */
export async function addVirtualAuthenticator(cdp: CDPSession): Promise<string> {
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const result = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return (result as { authenticatorId: string }).authenticatorId;
}

/**
 * installVirtualAuthenticator opens a CDP session on `page` and attaches a
 * virtual authenticator to it. Call this BEFORE the first
 * navigator.credentials.create()/get() the test drives through the SPA UI —
 * unlike the webauthn-browser precedent (which calls the RP over raw fetch),
 * this tier clicks real LoginPanel/RegisterPanel buttons, so the exact
 * moment only needs to precede the click, not the page navigation.
 */
export async function installVirtualAuthenticator(page: Page): Promise<CDPSession> {
  const cdp = await page.context().newCDPSession(page);
  await addVirtualAuthenticator(cdp);
  return cdp;
}
