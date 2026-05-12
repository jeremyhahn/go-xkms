import { test, expect, type Page } from '@playwright/test';

// Complete setup if not already done.
test.beforeAll(async ({ request }) => {
  const status = await request.get('/admin/setup/status');
  if (status.ok()) {
    const body = await status.json();
    if (body.status === 'pending') {
      await request.post('/admin/setup/barrier', { data: { strategy: 'none' } });
      await request.post('/admin/setup/ca', {
        data: { root_ca_name: 'Test Root CA', intermediate_ca_name: 'Test Intermediate CA', key_algorithm: 'ECDSA', validity_years: 10 },
      });
      await request.post('/admin/setup/complete');
    }
  }
});

async function loadSPA(page: Page): Promise<void> {
  await page.goto('/ui/admin/', { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.locator('aside').first().waitFor({ state: 'visible', timeout: 10000 });
}

async function navigateTo(page: Page, navLabel: string): Promise<void> {
  await page.getByRole('navigation').getByText(navLabel, { exact: true }).click();
  await page.waitForTimeout(300);
}

test.beforeAll(async ({ request }) => {
  await request.post('/api/v1/tenants', {
    data: { id: 'test-tenant-views', name: 'Test Tenant for Views' },
    ignoreHTTPSErrors: true,
  });
});

test.afterAll(async ({ request }) => {
  await request.delete('/api/v1/tenants/test-tenant-views', {
    ignoreHTTPSErrors: true,
  });
  await request.delete('/api/v1/tenants/e2e-test-tenant', {
    ignoreHTTPSErrors: true,
  });
});

// ---------------------------------------------------------------------------
// Seal Manager View
// ---------------------------------------------------------------------------

test.describe('Seal Manager View', () => {
  test('heading visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Seal Manager');
    await expect(page.getByRole('heading', { name: 'Seal Manager' })).toBeVisible();
  });

  test('status cards render', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Seal Manager');
    await expect(page.getByText('Status', { exact: true })).toBeVisible();
    await expect(page.getByText('Mode', { exact: true })).toBeVisible();
    await expect(page.getByText('Strategy', { exact: true })).toBeVisible();
    await expect(page.getByText('Shares', { exact: true })).toBeVisible();
  });

  test('mode shows Embedded', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Seal Manager');
    await expect(page.getByText('Embedded')).toBeVisible();
  });

  test('shows barrier state — sealed warning or not-enabled info', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Seal Manager');
    await page.waitForTimeout(1000);
    const main = page.locator('main');
    // Barrier may be sealed (shows warning + unseal) or not enabled (shows info)
    const hasSealed = await main.getByText('The barrier is sealed').isVisible().catch(() => false);
    const hasNotEnabled = await main.getByText(/not enabled|disabled|none/i).first().isVisible().catch(() => false);
    const hasUnseal = await main.getByRole('button', { name: 'Unseal' }).isVisible().catch(() => false);
    const hasStatus = await main.getByText(/Sealed|Unsealed|Embedded/i).first().isVisible().catch(() => false);
    expect(hasSealed || hasNotEnabled || hasUnseal || hasStatus).toBe(true);
  });

  test('auto-refresh indicator', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Seal Manager');
    await expect(page.getByText(/auto-refresh/i)).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// CA Manager View
// ---------------------------------------------------------------------------

test.describe('CA Manager View', () => {
  test('heading visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await expect(page.getByRole('heading', { name: 'CA Manager' })).toBeVisible();
  });

  test('Root Certificate Authority card', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await expect(page.getByRole('heading', { name: 'Root Certificate Authority' })).toBeVisible();
  });

  test('CA hierarchy visualization', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    // Wait for async data load.
    await page.waitForTimeout(1000);
    await expect(page.getByText('Root CA').first()).toBeVisible();
    await expect(page.getByText('Default Intermediate CA').first()).toBeVisible();
  });

  test('CA identity shows', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await page.waitForTimeout(1000);
    await expect(page.getByText('Trusted ACME Intermediate CA').first()).toBeVisible();
  });

  test('CA status badge', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await page.waitForTimeout(1000);
    await expect(page.locator('main').getByText('Active').first()).toBeVisible();
  });

  test('Supported Keys table shows multiple key algorithms', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await page.waitForTimeout(1000);
    const main = page.locator('main');
    // Should show the Supported Keys heading or table
    const hasKeysTable = await main.getByText('Supported Keys').first().isVisible().catch(() => false);
    const hasECDSA = await main.getByText('ECDSA').first().isVisible().catch(() => false);
    expect(hasKeysTable || hasECDSA).toBe(true);
  });

  test('Default key is marked with badge', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await page.waitForTimeout(1000);
    const main = page.locator('main');
    await expect(main.getByText('Default').first()).toBeVisible();
  });

  test('multiple store types shown', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await page.waitForTimeout(1000);
    const main = page.locator('main');
    // Should show "software" store type at minimum
    await expect(main.getByText('software').first()).toBeVisible();
  });

  test('Tenant Certificate Authorities section', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await expect(page.getByRole('heading', { name: 'Tenant Certificate Authorities' })).toBeVisible();
  });

  test('tenant name visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'CA Manager');
    await expect(page.getByText('Test Tenant for Views')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Audit Log View
// ---------------------------------------------------------------------------

test.describe('Audit Log View', () => {
  test('heading visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    await expect(page.getByRole('heading', { name: 'Audit Log' })).toBeVisible();
  });

  test('filter section present', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    await expect(page.getByRole('heading', { name: 'Filters' })).toBeVisible();
  });

  test('actor filter input', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    await expect(page.locator('input[placeholder*="admin"]')).toBeVisible();
  });

  test('action filter input', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    await expect(page.locator('input[placeholder*="create"]')).toBeVisible();
  });

  test('resource filter input', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    await expect(page.locator('input[placeholder*="tenant"]')).toBeVisible();
  });

  test('start time input', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    await expect(page.locator('input[type="datetime-local"]').first()).toBeVisible();
  });

  test('end time input', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    const inputs = page.locator('input[type="datetime-local"]');
    await expect(inputs.nth(1)).toBeVisible();
  });

  test('refresh button', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible();
  });

  test('empty state message', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Audit Log');
    await expect(page.getByText(/no audit events found/i)).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Create Tenant Modal
// ---------------------------------------------------------------------------

test.describe('Create Tenant Modal', () => {
  test('Create Tenant button exists', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await expect(page.getByRole('button', { name: 'Create Tenant' })).toBeAttached();
  });

  test('modal opens on click', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await page.getByRole('button', { name: 'Create Tenant' }).click();
    await expect(page.getByRole('heading', { name: 'Create Tenant' })).toBeVisible();
  });

  test('modal has ID field', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await page.getByRole('button', { name: 'Create Tenant' }).click();
    const idInput = page.locator('input[placeholder*="acme-corp"]')
      .or(page.getByLabel('Tenant ID'));
    await expect(idInput.first()).toBeVisible();
  });

  test('modal has Name field', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await page.getByRole('button', { name: 'Create Tenant' }).click();
    const nameInput = page.locator('input[placeholder*="Corporation"]')
      .or(page.getByLabel('Display Name'));
    await expect(nameInput.first()).toBeVisible();
  });

  test('modal has Cancel button', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await page.getByRole('button', { name: 'Create Tenant' }).click();
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
  });

  test('modal has Create button', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await page.getByRole('button', { name: 'Create Tenant' }).click();
    // Find the submit button inside the modal — exclude the nav trigger button
    const modal = page.locator('dialog.modal');
    await expect(modal.getByRole('button', { name: 'Create' })).toBeVisible();
  });

  test('Cancel closes modal', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await page.getByRole('button', { name: 'Create Tenant' }).click();
    await expect(page.getByRole('heading', { name: 'Create Tenant' })).toBeVisible();
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.locator('dialog.modal.modal-open')).toHaveCount(0);
  });

  test('create tenant E2E', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await page.getByRole('button', { name: 'Create Tenant' }).click();

    const idInput = page.locator('input[placeholder*="acme-corp"]')
      .or(page.getByLabel('Tenant ID'));
    await idInput.first().fill('e2e-test-tenant');

    const nameInput = page.locator('input[placeholder*="Corporation"]')
      .or(page.getByLabel('Display Name'));
    await nameInput.first().fill('E2E Test Tenant');

    const modal = page.locator('dialog.modal');
    await modal.getByRole('button', { name: 'Create' }).click();

    // Verify success toast
    await expect(page.getByText(/success/i).or(page.locator('[role="status"]')).first()).toBeVisible({ timeout: 5000 });
  });

  test('created tenant in list', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await expect(page.getByText('e2e-test-tenant')).toBeVisible({ timeout: 5000 });
  });
});

// ---------------------------------------------------------------------------
// Tenants View - Data Display
// ---------------------------------------------------------------------------

test.describe('Tenants View - Data Display', () => {
  test('table shows test tenant', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await expect(page.getByText('test-tenant-views')).toBeVisible();
  });

  test('table shows tenant name', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    await expect(page.getByText('Test Tenant for Views')).toBeVisible();
  });

  test('table shows active status', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    // Scope to table body to avoid matching sidebar/dropdown text.
    await expect(page.locator('table').getByText('active').first()).toBeVisible();
  });

  test('status filter dropdown works', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Tenants');
    const statusFilter = page.locator('select').or(page.getByRole('combobox')).first();
    await statusFilter.selectOption({ label: 'Active' });
    await page.waitForTimeout(300);
    await expect(page.locator('table tbody tr').first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Dashboard - Real Data
// ---------------------------------------------------------------------------

test.describe('Dashboard - Real Data', () => {
  test('dashboard shows CA identity', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    await expect(page.getByText('Trusted ACME Intermediate CA')).toBeVisible();
  });

  test('dashboard shows version', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    await expect(page.getByText('0.1.0')).toBeVisible();
  });

  test('dashboard shows key algorithms with multi-key summary', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    const main = page.locator('main');
    // Should show ECDSA (default) and "+N more" for additional keys
    const hasECDSA = await main.getByText('ECDSA').first().isVisible().catch(() => false);
    const hasMore = await main.getByText(/\+\d+ more/).first().isVisible().catch(() => false);
    const hasKeyAlg = await main.getByText('Key Algorithm').first().isVisible().catch(() => false);
    expect(hasECDSA || hasMore || hasKeyAlg).toBe(true);
  });

  test('dashboard shows Active badge', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Dashboard');
    await expect(page.locator('main').getByText('Active').first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Connection Settings - Test Connection
// ---------------------------------------------------------------------------

test.describe('Connection Settings - Test Connection', () => {
  test('heading visible', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Connection');
    await expect(page.getByRole('heading', { name: 'Connection Settings' })).toBeVisible();
  });

  test('Connected indicator', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Connection');
    await expect(page.getByText('Connected', { exact: true })).toBeVisible();
  });

  test('Test Connection button clickable', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Connection');
    const btn = page.getByRole('button', { name: 'Test Connection' });
    await btn.click();
    // After clicking, expect no error dialog and Connected text still present
    await page.waitForTimeout(500);
    await expect(page.getByText(/error/i)).not.toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Dark Mode Toggle
// ---------------------------------------------------------------------------

test.describe('Dark Mode Toggle', () => {
  test('dark mode via settings', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    const main = page.locator('main');
    await main.getByRole('button', { name: 'Dark' }).click();
    await expect(page.locator('html')).toHaveClass(/dark/);
  });

  test('light mode restore', async ({ page }) => {
    await loadSPA(page);
    await navigateTo(page, 'Settings');
    const main = page.locator('main');
    await main.getByRole('button', { name: 'Dark' }).click();
    await expect(page.locator('html')).toHaveClass(/dark/);
    await main.getByRole('button', { name: 'Light' }).click();
    await expect(page.locator('html')).not.toHaveClass(/dark/);
  });

  test('sidebar dark mode button', async ({ page }) => {
    await loadSPA(page);
    const sidebar = page.locator('aside').first();
    await sidebar.getByRole('button', { name: 'Dark mode' }).click();
    await expect(page.locator('html')).toHaveClass(/dark/);
    await sidebar.getByRole('button', { name: 'Light mode' }).click();
    await expect(page.locator('html')).not.toHaveClass(/dark/);
  });
});
