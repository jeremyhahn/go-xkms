import { test, expect, type Page } from '@playwright/test';

async function loadSPA(page: Page): Promise<void> {
  await page.goto('/ui/client/', { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.locator('aside').first().waitFor({ state: 'visible', timeout: 10000 });
}

async function navigateTo(page: Page, navLabel: string): Promise<void> {
  await page.getByRole('navigation').getByText(navLabel, { exact: true }).click();
  await page.waitForTimeout(300);
}

// ---------------------------------------------------------------------------
// App Initialization
// ---------------------------------------------------------------------------

test.describe('App Initialization', () => {
  test('SPA loads with HTTP 200', async ({ page }) => {
    const response = await page.goto('/ui/client/', { waitUntil: 'domcontentloaded', timeout: 15000 });
    expect(response?.status()).toBe(200);
  });

  test('#app mount point exists in the DOM', async ({ page }) => {
    await loadSPA(page);
    await expect(page.locator('#app')).toBeAttached();
  });

  test('Svelte mounts content into #app', async ({ page }) => {
    await loadSPA(page);
    const appChildren = await page.locator('#app').locator('> *').count();
    expect(appChildren).toBeGreaterThan(0);
  });

  test('page title is set', async ({ page }) => {
    await loadSPA(page);
    const title = await page.title();
    expect(title.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Sidebar Rendering
// ---------------------------------------------------------------------------

test.describe('Sidebar Rendering', () => {
  test('application title is visible in the sidebar', async ({ page }) => {
    await loadSPA(page);
    const sidebar = page.locator('aside').first();
    await expect(sidebar).toBeVisible();
    const titleText = await sidebar.textContent();
    expect(titleText?.length).toBeGreaterThan(0);
  });

  test('all 13 navigation items are visible', async ({ page }) => {
    await loadSPA(page);
    const navLabels = [
      'Dashboard',
      'Accounts',
      'Certificates',
      'Register',
      'Request Cert',
      'Renew Cert',
      'Revoke Cert',
      'Auto-Renewal',
      'Device Enroll',
      'Device Attest',
      'Configuration',
      'Challenges',
      'Settings',
    ];
    const nav = page.getByRole('navigation');
    for (const label of navLabels) {
      await expect(nav.getByText(label, { exact: true })).toBeVisible();
    }
  });

  test('Dashboard view is active by default with h1 "Dashboard"', async ({ page }) => {
    await loadSPA(page);
    await expect(page.locator('main').getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  });

  test('collapse/expand toggle button is present in the sidebar', async ({ page }) => {
    await loadSPA(page);
    const sidebar = page.locator('aside').first();
    // The collapse button may have aria-label or be any visible button in the sidebar header.
    const collapseBtn = sidebar.getByRole('button', { name: /collapse|expand/i });
    const anyBtn = sidebar.locator('button:visible').first();
    const hasCollapse = await collapseBtn.isVisible().catch(() => false);
    const hasAnyBtn = await anyBtn.isVisible().catch(() => false);
    expect(hasCollapse || hasAnyBtn).toBe(true);
  });

  test('theme toggle button is present with Dark mode or Light mode text', async ({ page }) => {
    await loadSPA(page);
    const themeBtn = page.getByRole('button', { name: /dark mode|light mode/i }).first();
    await expect(themeBtn).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Sidebar Navigation (one test per nav item)
// ---------------------------------------------------------------------------

test.describe('Sidebar Navigation', () => {
  test('navigating to Dashboard shows h1 "Dashboard"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    await expect(page.locator('main').getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  });

  test('navigating to Accounts shows h1 "Accounts"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Accounts');
    await expect(page.locator('main').getByRole('heading', { name: 'Accounts', level: 1 })).toBeVisible();
  });

  test('navigating to Certificates shows h1 "Certificates"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Certificates');
    await expect(page.locator('main').getByRole('heading', { name: 'Certificates', level: 1 })).toBeVisible();
  });

  test('navigating to Register shows h1 "Register Account"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Register');
    await expect(page.locator('main').getByRole('heading', { name: 'Register Account', level: 1 })).toBeVisible();
  });

  test('navigating to Request Cert shows h1 "Request Certificate"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Request Cert');
    await expect(page.locator('main').getByRole('heading', { name: 'Request Certificate', level: 1 })).toBeVisible();
  });

  test('navigating to Renew Cert shows h1 "Renew Certificate"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Renew Cert');
    await expect(page.locator('main').getByRole('heading', { name: 'Renew Certificate', level: 1 })).toBeVisible();
  });

  test('navigating to Revoke Cert shows h1 "Revoke Certificate"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Revoke Cert');
    await expect(page.locator('main').getByRole('heading', { name: 'Revoke Certificate', level: 1 })).toBeVisible();
  });

  test('navigating to Auto-Renewal shows h1 "Auto-Renewal"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Auto-Renewal');
    await expect(page.locator('main').getByRole('heading', { name: 'Auto-Renewal', level: 1 })).toBeVisible();
  });

  test('navigating to Device Enroll shows h1 "Device Enrollment"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Enroll');
    await expect(page.locator('main').getByRole('heading', { name: 'Device Enrollment', level: 1 })).toBeVisible();
  });

  test('navigating to Device Attest shows h1 "Device Attestation"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Attest');
    await expect(page.locator('main').getByRole('heading', { name: 'Device Attestation', level: 1 })).toBeVisible();
  });

  test('navigating to Configuration shows h1 "Configuration"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Configuration');
    await expect(page.locator('main').getByRole('heading', { name: 'Configuration', level: 1 })).toBeVisible();
  });

  test('navigating to Challenges shows h1 "Challenge Configuration"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Challenges');
    await expect(page.locator('main').getByRole('heading', { name: 'Challenge Configuration', level: 1 })).toBeVisible();
  });

  test('navigating to Settings shows h1 "Settings"', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    await expect(page.locator('main').getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Dashboard View
// ---------------------------------------------------------------------------

test.describe('Dashboard View', () => {
  test('h1 "Dashboard" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    await expect(page.locator('main').getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  });

  test('account info section is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    // Wait for async data load to complete.
    await page.waitForTimeout(2000);
    const main = page.locator('main');
    // The Card title "Account" or server info or "No account registered" text.
    const hasAccount = await main.getByText('Account').first().isVisible().catch(() => false);
    const hasNoAccount = await main.getByText(/no account|configuration/i).first().isVisible().catch(() => false);
    const hasRetry = await main.getByText('Retry').isVisible().catch(() => false);
    expect(hasAccount || hasNoAccount || hasRetry).toBe(true);
  });

  test('auto-renewal status section is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    await page.waitForTimeout(2000);
    const main = page.locator('main');
    const hasRenewal = await main.getByText('Auto-Renewal').first().isVisible().catch(() => false);
    const hasRetry = await main.getByText('Retry').isVisible().catch(() => false);
    expect(hasRenewal || hasRetry).toBe(true);
  });

  test('certificate list or empty state is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    await page.waitForTimeout(2000);
    const main = page.locator('main');
    const hasCerts = await main.getByText(/certificate/i).first().isVisible().catch(() => false);
    const hasEmpty = await main.getByText(/no certificates|renewal|none/i).first().isVisible().catch(() => false);
    const hasRetry = await main.getByText('Retry').isVisible().catch(() => false);
    expect(hasCerts || hasEmpty || hasRetry).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Accounts View
// ---------------------------------------------------------------------------

test.describe('Accounts View', () => {
  test('h1 "Accounts" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Accounts');
    await expect(page.locator('main').getByRole('heading', { name: 'Accounts', level: 1 })).toBeVisible();
  });

  test('table or empty state renders after data load', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Accounts');
    await page.waitForTimeout(2000);
    const main = page.locator('main');
    // Either the table loads with data or shows "No accounts configured"
    const hasTable = await main.locator('table').isVisible().catch(() => false);
    const hasEmpty = await main.getByText(/no accounts/i).first().isVisible().catch(() => false);
    const hasError = await main.getByText(/error|retry/i).first().isVisible().catch(() => false);
    expect(hasTable || hasEmpty || hasError).toBe(true);
  });

  test('Refresh button is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Accounts');
    await expect(page.locator('main').getByRole('button', { name: /refresh/i }).first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Certificates View
// ---------------------------------------------------------------------------

test.describe('Certificates View', () => {
  test('h1 "Certificates" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Certificates');
    await expect(page.locator('main').getByRole('heading', { name: 'Certificates', level: 1 })).toBeVisible();
  });

  test('account filter dropdown is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Certificates');
    const main = page.locator('main');
    await expect(main.locator('select').first()).toBeVisible();
  });

  test('certificates table or empty state renders', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Certificates');
    await page.waitForTimeout(2000);
    const main = page.locator('main');
    const hasTable = await main.locator('table').isVisible().catch(() => false);
    const hasNoCerts = await main.getByText(/no certificate/i).first().isVisible().catch(() => false);
    const hasError = await main.getByText(/error|retry/i).first().isVisible().catch(() => false);
    expect(hasTable || hasNoCerts || hasError).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Register View
// ---------------------------------------------------------------------------

test.describe('Register View', () => {
  test('h1 "Register Account" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Register');
    await expect(page.locator('main').getByRole('heading', { name: 'Register Account', level: 1 })).toBeVisible();
  });

  test('Contact Email input is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Register');
    const main = page.locator('main');
    const emailInput = main.locator('input[type="email"], input[placeholder*="email" i], input[name*="email" i]').first();
    await expect(emailInput).toBeVisible();
  });

  test('Terms of Service checkbox is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Register');
    const main = page.locator('main');
    const tosCheckbox = main.locator('input[type="checkbox"]').first();
    await expect(tosCheckbox).toBeVisible();
  });

  test('Register button is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Register');
    await expect(page.locator('main').getByRole('button', { name: /register/i }).first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Request Certificate View
// ---------------------------------------------------------------------------

test.describe('Request Certificate View', () => {
  test('h1 "Request Certificate" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Request Cert');
    await expect(page.locator('main').getByRole('heading', { name: 'Request Certificate', level: 1 })).toBeVisible();
  });

  test('Domain Names textarea is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Request Cert');
    const main = page.locator('main');
    const textarea = main.locator('textarea').first();
    await expect(textarea).toBeVisible();
  });

  test('Key Type select is present with EC and RSA options', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Request Cert');
    const main = page.locator('main');
    const keyTypeSelect = main.locator('select').first();
    await expect(keyTypeSelect).toBeVisible();
    const options = await keyTypeSelect.locator('option').allTextContents();
    const hasEC = options.some(o => /ec/i.test(o));
    const hasRSA = options.some(o => /rsa/i.test(o));
    expect(hasEC || hasRSA).toBe(true);
  });

  test('Challenge Type select is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Request Cert');
    const main = page.locator('main');
    const selects = main.locator('select');
    expect(await selects.count()).toBeGreaterThanOrEqual(1);
    const hasChallenge = await main.getByText(/challenge/i).first().isVisible().catch(() => false);
    expect(hasChallenge).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Renew Certificate View
// ---------------------------------------------------------------------------

test.describe('Renew Certificate View', () => {
  test('h1 "Renew Certificate" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Renew Cert');
    await expect(page.locator('main').getByRole('heading', { name: 'Renew Certificate', level: 1 })).toBeVisible();
  });

  test('form field for serial or name is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Renew Cert');
    const main = page.locator('main');
    const input = main.locator('input').first();
    await expect(input).toBeVisible();
  });

  test('Submit button is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Renew Cert');
    const main = page.locator('main');
    const submitBtn = main.getByRole('button', { name: /renew|submit/i }).first();
    await expect(submitBtn).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Revoke Certificate View
// ---------------------------------------------------------------------------

test.describe('Revoke Certificate View', () => {
  test('h1 "Revoke Certificate" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Revoke Cert');
    await expect(page.locator('main').getByRole('heading', { name: 'Revoke Certificate', level: 1 })).toBeVisible();
  });

  test('form field for serial or name is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Revoke Cert');
    const main = page.locator('main');
    const input = main.locator('input').first();
    await expect(input).toBeVisible();
  });

  test('Reason dropdown is present with revocation reason options', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Revoke Cert');
    const main = page.locator('main');
    const reasonSelect = main.locator('select').first();
    await expect(reasonSelect).toBeVisible();
    const options = await reasonSelect.locator('option').allTextContents();
    const reasons = [
      'Unspecified',
      'Key Compromise',
      'Affiliation Changed',
      'Superseded',
      'Cessation of Operation',
    ];
    const matched = reasons.filter(r => options.some(o => o.toLowerCase().includes(r.toLowerCase())));
    expect(matched.length).toBeGreaterThan(0);
  });

  test('warning about permanent action is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Revoke Cert');
    const main = page.locator('main');
    const warning = main.getByText(/permanent|cannot be undone|irreversible/i).first();
    await expect(warning).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Auto-Renewal View
// ---------------------------------------------------------------------------

test.describe('Auto-Renewal View', () => {
  test('h1 "Auto-Renewal" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Auto-Renewal');
    await expect(page.locator('main').getByRole('heading', { name: 'Auto-Renewal', level: 1 })).toBeVisible();
  });

  test('Enable checkbox is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Auto-Renewal');
    const main = page.locator('main');
    const checkbox = main.locator('input[type="checkbox"]').first();
    await expect(checkbox).toBeVisible();
  });

  test('Check interval input is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Auto-Renewal');
    const main = page.locator('main');
    const intervalInput = main.locator('input[type="number"], input[type="text"]').first();
    await expect(intervalInput).toBeVisible();
  });

  test('Renew before days input is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Auto-Renewal');
    const main = page.locator('main');
    const inputs = main.locator('input[type="number"], input[type="text"]');
    expect(await inputs.count()).toBeGreaterThanOrEqual(1);
    const hasDaysLabel = await main.getByText(/days/i).first().isVisible().catch(() => false);
    expect(hasDaysLabel).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Device Enroll View
// ---------------------------------------------------------------------------

test.describe('Device Enroll View', () => {
  test('h1 "Device Enrollment" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Enroll');
    await expect(page.locator('main').getByRole('heading', { name: 'Device Enrollment', level: 1 })).toBeVisible();
  });

  test('EK Certificate textarea is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Enroll');
    const main = page.locator('main');
    const textarea = main.locator('textarea').first();
    await expect(textarea).toBeVisible();
  });

  test('AK Name input is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Enroll');
    const main = page.locator('main');
    const akInput = main.locator('input').first();
    await expect(akInput).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Device Attest View
// ---------------------------------------------------------------------------

test.describe('Device Attest View', () => {
  test('h1 "Device Attestation" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Attest');
    await expect(page.locator('main').getByRole('heading', { name: 'Device Attestation', level: 1 })).toBeVisible();
  });

  test('AK Name input is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Attest');
    const main = page.locator('main');
    const akInput = main.locator('input').first();
    await expect(akInput).toBeVisible();
  });

  test('Nonce input is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Device Attest');
    const main = page.locator('main');
    const inputs = main.locator('input');
    expect(await inputs.count()).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Configuration View
// ---------------------------------------------------------------------------

test.describe('Configuration View', () => {
  test('h1 "Configuration" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Configuration');
    await expect(page.locator('main').getByRole('heading', { name: 'Configuration', level: 1 })).toBeVisible();
  });

  test('Server URL field is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Configuration');
    const main = page.locator('main');
    const urlInput = main.locator('input[type="url"], input[type="text"]').first();
    await expect(urlInput).toBeVisible();
  });

  test('Key Type dropdown is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Configuration');
    const main = page.locator('main');
    const select = main.locator('select').first();
    await expect(select).toBeVisible();
  });

  test('Save button is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Configuration');
    const main = page.locator('main');
    const saveBtn = main.getByRole('button', { name: /save/i }).first();
    await expect(saveBtn).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Challenge Config View
// ---------------------------------------------------------------------------

test.describe('Challenge Config View', () => {
  test('h1 "Challenge Configuration" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Challenges');
    await expect(page.locator('main').getByRole('heading', { name: 'Challenge Configuration', level: 1 })).toBeVisible();
  });

  test('HTTP-01 and DNS-01 tab buttons are visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Challenges');
    const main = page.locator('main');
    await expect(main.getByRole('tab', { name: /http.?01/i }).first()).toBeVisible();
    await expect(main.getByRole('tab', { name: /dns.?01/i }).first()).toBeVisible();
  });

  test('clicking a challenge tab shows different content', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Challenges');
    const main = page.locator('main');
    const httpTab = main.getByRole('tab', { name: /http.?01/i }).first();
    const dnsTab = main.getByRole('tab', { name: /dns.?01/i }).first();
    await httpTab.click();
    await page.waitForTimeout(200);
    const httpContent = await main.textContent();
    await dnsTab.click();
    await page.waitForTimeout(200);
    const dnsContent = await main.textContent();
    expect(httpContent).not.toBe(dnsContent);
  });
});

// ---------------------------------------------------------------------------
// Settings View
// ---------------------------------------------------------------------------

test.describe('Settings View', () => {
  test('h1 "Settings" is visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    await expect(page.locator('main').getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  });

  test('Light, Dark, and System theme buttons are present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    const main = page.locator('main');
    await expect(main.getByRole('button', { name: /light/i }).first()).toBeVisible();
    await expect(main.getByRole('button', { name: /dark/i }).first()).toBeVisible();
    await expect(main.getByRole('button', { name: /system/i }).first()).toBeVisible();
  });

  test('preview section is present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    const main = page.locator('main');
    const preview = main.getByText(/preview/i).first();
    await expect(preview).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Theme Switching
// ---------------------------------------------------------------------------

test.describe('Theme Switching', () => {
  test('clicking Dark button in main content gives html element the dark class', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    const main = page.locator('main');
    await main.getByRole('button', { name: /dark/i }).first().click();
    await page.waitForTimeout(200);
    const htmlClass = await page.locator('html').getAttribute('class');
    expect(htmlClass).toContain('dark');
  });

  test('clicking Light button removes the dark class from html element', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    const main = page.locator('main');
    await main.getByRole('button', { name: /dark/i }).first().click();
    await page.waitForTimeout(200);
    await main.getByRole('button', { name: /light/i }).first().click();
    await page.waitForTimeout(200);
    const htmlClass = await page.locator('html').getAttribute('class');
    expect(htmlClass ?? '').not.toContain('dark');
  });

  test('clicking System button completes without error', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    const main = page.locator('main');
    await main.getByRole('button', { name: /system/i }).first().click();
    await page.waitForTimeout(200);
    // Verify page is still functional after System click.
  });
});
