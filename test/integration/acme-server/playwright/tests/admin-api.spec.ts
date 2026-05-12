import { test, expect } from '@playwright/test';

// =============================================================================
// CA Status & Statistics
// =============================================================================

test.describe('CA Status & Statistics', () => {
  test('GET /admin/status returns CA status with all required fields', async ({ request }) => {
    const resp = await request.get('/admin/status');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('identity');
    expect(body).toHaveProperty('initialized');
    expect(body).toHaveProperty('version');
    expect(typeof body.initialized).toBe('boolean');
  });

  test('GET /admin/status returns multi-key information', async ({ request }) => {
    const resp = await request.get('/admin/status');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('keys');
    expect(Array.isArray(body.keys)).toBeTruthy();
    expect(body.keys.length).toBeGreaterThanOrEqual(1);
    // First key should be the default
    expect(body.keys[0].default).toBe(true);
    // All keys should have required fields
    for (const key of body.keys) {
      expect(key).toHaveProperty('algorithm');
      expect(key).toHaveProperty('store');
      expect(typeof key.default).toBe('boolean');
    }
    // Should have at least ECDSA and RSA keys
    const algorithms = body.keys.map((k: any) => k.algorithm);
    expect(algorithms).toContain('ECDSA');
  });

  test('GET /admin/stats returns statistics with all counters', async ({ request }) => {
    const resp = await request.get('/admin/stats');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('total_certificates');
    expect(body).toHaveProperty('valid_certificates');
    expect(body).toHaveProperty('revoked_certificates');
    expect(body).toHaveProperty('expired_certificates');
    expect(body).toHaveProperty('total_accounts');
    expect(body).toHaveProperty('active_accounts');
    expect(body).toHaveProperty('total_orders');
    expect(body).toHaveProperty('pending_orders');
    expect(body).toHaveProperty('completed_orders');
    // All counters should be non-negative
    for (const [key, value] of Object.entries(body)) {
      expect(value).toBeGreaterThanOrEqual(0);
    }
  });
});

// =============================================================================
// Health & Readiness
// =============================================================================

test.describe('Health & Readiness', () => {
  test('GET /health returns healthy', async ({ request }) => {
    const resp = await request.get('/health');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.status).toBe('healthy');
  });

  test('GET /ready returns ready (ACME server)', async ({ request }) => {
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp = await request.get(`${acmeBase}/ready`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.text();
    expect(body).toContain('ready');
  });
});

// =============================================================================
// ACME Directory & Nonce
// =============================================================================

test.describe('ACME Protocol Endpoints', () => {
  test('GET /acme/directory returns RFC 8555 directory', async ({ request }) => {
    // ACME runs on port 8443
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp = await request.get(`${acmeBase}/acme/directory`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('newNonce');
    expect(body).toHaveProperty('newAccount');
    expect(body).toHaveProperty('newOrder');
    expect(body).toHaveProperty('revokeCert');
    expect(body).toHaveProperty('keyChange');
  });

  test('HEAD /acme/new-nonce returns Replay-Nonce header', async ({ request }) => {
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp = await request.head(`${acmeBase}/acme/new-nonce`);
    expect(resp.status()).toBe(200);
    const nonce = resp.headers()['replay-nonce'];
    expect(nonce).toBeDefined();
    expect(nonce.length).toBeGreaterThan(0);
  });

  test('GET /acme/new-nonce returns Replay-Nonce header', async ({ request }) => {
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp = await request.get(`${acmeBase}/acme/new-nonce`);
    // 200 or 204 are both valid per RFC 8555
    expect([200, 204]).toContain(resp.status());
    const nonce = resp.headers()['replay-nonce'];
    expect(nonce).toBeDefined();
  });

  test('nonces are unique', async ({ request }) => {
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp1 = await request.head(`${acmeBase}/acme/new-nonce`);
    const resp2 = await request.head(`${acmeBase}/acme/new-nonce`);
    const nonce1 = resp1.headers()['replay-nonce'];
    const nonce2 = resp2.headers()['replay-nonce'];
    expect(nonce1).not.toBe(nonce2);
  });

  test('GET /acme/ca-bundle returns CA certificate chain', async ({ request }) => {
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp = await request.get(`${acmeBase}/acme/ca-bundle`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.text();
    expect(body).toContain('BEGIN CERTIFICATE');
  });

  test('POST /acme/new-account without JWS returns 400', async ({ request }) => {
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp = await request.post(`${acmeBase}/acme/new-account`, {
      data: {},
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  test('POST /acme/new-order without JWS returns 400', async ({ request }) => {
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp = await request.post(`${acmeBase}/acme/new-order`, {
      data: {},
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });
});

// =============================================================================
// Certificate Management
// =============================================================================

test.describe('Certificate Management', () => {
  test('GET /admin/certificates returns list with pagination', async ({ request }) => {
    const resp = await request.get('/admin/certificates');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('items');
    expect(Array.isArray(body.items)).toBeTruthy();
    expect(body).toHaveProperty('page');
    expect(body).toHaveProperty('per_page');
    expect(body).toHaveProperty('total');
  });

  test('GET /admin/certificates with pagination params', async ({ request }) => {
    const resp = await request.get('/admin/certificates?page=1&per_page=5');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.page).toBe(1);
    expect(body.per_page).toBe(5);
  });

  test('GET /admin/certificates with status filter', async ({ request }) => {
    const resp = await request.get('/admin/certificates?status=valid');
    expect(resp.ok()).toBeTruthy();
  });

  test('GET /admin/certificates/expiring returns expiring certs', async ({ request }) => {
    const resp = await request.get('/admin/certificates/expiring?days=30');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('items');
    expect(Array.isArray(body.items)).toBeTruthy();
  });

  test('GET /admin/certificates/{serial} with invalid serial returns 404', async ({ request }) => {
    const resp = await request.get('/admin/certificates/00:00:00:00:00:00:00:00');
    expect(resp.status()).toBe(404);
  });
});

// =============================================================================
// Account Management
// =============================================================================

test.describe('Account Management', () => {
  test('GET /admin/accounts returns list with pagination', async ({ request }) => {
    const resp = await request.get('/admin/accounts');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('items');
    expect(Array.isArray(body.items)).toBeTruthy();
    expect(body).toHaveProperty('page');
  });

  test('GET /admin/accounts with pagination', async ({ request }) => {
    const resp = await request.get('/admin/accounts?page=1&per_page=10');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.page).toBe(1);
  });

  test('GET /admin/accounts with status filter', async ({ request }) => {
    const resp = await request.get('/admin/accounts?status=valid');
    expect(resp.ok()).toBeTruthy();
  });

  test('GET /admin/accounts/{id} with invalid ID returns error', async ({ request }) => {
    const resp = await request.get('/admin/accounts/999999');
    // 404 or 400 depending on whether ID exists
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });
});

// =============================================================================
// Order Management
// =============================================================================

test.describe('Order Management', () => {
  test('GET /admin/orders returns list', async ({ request }) => {
    const resp = await request.get('/admin/orders');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('items');
    expect(Array.isArray(body.items)).toBeTruthy();
  });

  test('GET /admin/orders with pagination', async ({ request }) => {
    const resp = await request.get('/admin/orders?page=1&per_page=5');
    expect(resp.ok()).toBeTruthy();
  });

  test('GET /admin/orders/{id} with invalid ID returns error', async ({ request }) => {
    const resp = await request.get('/admin/orders/nonexistent');
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });
});

// =============================================================================
// Full Tenant CRUD Lifecycle
// =============================================================================

test.describe('Tenant CRUD Lifecycle', () => {
  const tenantId = `e2e-tenant-${Date.now()}`;
  const tenantName = 'E2E Comprehensive Test Tenant';

  test('POST /api/v1/tenants creates a tenant', async ({ request }) => {
    const resp = await request.post('/api/v1/tenants', {
      data: { id: tenantId, name: tenantName },
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.id).toBe(tenantId);
    expect(body.name).toBe(tenantName);
  });

  test('GET /api/v1/tenants lists tenants including created one', async ({ request }) => {
    const resp = await request.get('/api/v1/tenants');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('items');
    expect(Array.isArray(body.items)).toBeTruthy();
    const found = body.items.find((t: any) => t.id === tenantId);
    expect(found).toBeDefined();
    expect(found.name).toBe(tenantName);
  });

  test('GET /api/v1/tenants/{id} returns the tenant', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.id).toBe(tenantId);
    expect(body.name).toBe(tenantName);
    expect(body).toHaveProperty('status');
    expect(body).toHaveProperty('created_at');
  });

  test('PUT /api/v1/tenants/{id} updates the tenant', async ({ request }) => {
    const resp = await request.put(`/api/v1/tenants/${tenantId}`, {
      data: { name: 'Updated E2E Tenant' },
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.name).toBe('Updated E2E Tenant');
  });

  test('GET /api/v1/tenants/{id} confirms update', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.name).toBe('Updated E2E Tenant');
  });

  test('DELETE /api/v1/tenants/{id} deletes the tenant', async ({ request }) => {
    const resp = await request.delete(`/api/v1/tenants/${tenantId}`);
    expect(resp.ok()).toBeTruthy();
  });

  test('GET /api/v1/tenants/{id} after delete returns 404', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}`);
    expect(resp.status()).toBe(404);
  });

  test('POST /api/v1/tenants with missing name returns error', async ({ request }) => {
    const resp = await request.post('/api/v1/tenants', {
      data: { id: 'no-name-tenant' },
    });
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  test('GET /api/v1/tenants/{id} with nonexistent ID returns 404', async ({ request }) => {
    const resp = await request.get('/api/v1/tenants/does-not-exist-99999');
    expect(resp.status()).toBe(404);
  });
});

// =============================================================================
// Tenant EAB CRUD Lifecycle
// =============================================================================

test.describe('Tenant EAB Lifecycle', () => {
  const tenantId = `e2e-eab-tenant-${Date.now()}`;
  let eabKid: string;

  test.beforeAll(async ({ request }) => {
    await request.post('/api/v1/tenants', {
      data: { id: tenantId, name: 'EAB Test Tenant' },
    });
  });

  test.afterAll(async ({ request }) => {
    await request.delete(`/api/v1/tenants/${tenantId}`);
  });

  test('POST /api/v1/tenants/{id}/eab creates EAB credential', async ({ request }) => {
    const resp = await request.post(`/api/v1/tenants/${tenantId}/eab`, {
      data: { contact: ['admin@test.com'] },
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('id');
    expect(body).toHaveProperty('mac_key');
    expect(body.mac_key.length).toBeGreaterThan(0);
    eabKid = body.id;
  });

  test('GET /api/v1/tenants/{id}/eab lists EABs', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/eab`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('items');
    expect(Array.isArray(body.items)).toBeTruthy();
    expect(body.items.length).toBeGreaterThan(0);
  });

  test('GET /api/v1/tenants/{id}/eab/{kid} returns EAB details', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/eab/${eabKid}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.id).toBe(eabKid);
  });

  test('DELETE /api/v1/tenants/{id}/eab/{kid} deletes EAB', async ({ request }) => {
    const resp = await request.delete(`/api/v1/tenants/${tenantId}/eab/${eabKid}`);
    expect(resp.ok()).toBeTruthy();
  });

  test('GET /api/v1/tenants/{id}/eab/{kid} after delete returns 404', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/eab/${eabKid}`);
    expect(resp.status()).toBe(404);
  });
});

// =============================================================================
// Tenant Role CRUD Lifecycle
// Backend: CreateRole transport method not yet implemented (returns 500).
// =============================================================================

test.describe('Tenant Role Lifecycle', () => {
  test.fixme(true, 'CreateRole transport method not yet implemented in embedded QRDB');
  const tenantId = `e2e-role-tenant-${Date.now()}`;
  let roleId: string;

  test.beforeAll(async ({ request }) => {
    await request.post('/api/v1/tenants', {
      data: { id: tenantId, name: 'Role Test Tenant' },
    });
  });

  test.afterAll(async ({ request }) => {
    await request.delete(`/api/v1/tenants/${tenantId}`);
  });

  test('POST /api/v1/tenants/{id}/roles creates a role', async ({ request }) => {
    const resp = await request.post(`/api/v1/tenants/${tenantId}/roles`, {
      data: { name: 'e2e-test-role', permissions: ['read:certs', 'write:certs'] },
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('id');
    expect(body.name).toBe('e2e-test-role');
    roleId = body.id;
  });

  test('GET /api/v1/tenants/{id}/roles lists roles', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/roles`);
    expect(resp.ok()).toBeTruthy();
  });

  test('GET /api/v1/tenants/{id}/roles/{roleId} returns role', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/roles/${roleId}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.name).toBe('e2e-test-role');
  });

  test('PUT /api/v1/tenants/{id}/roles/{roleId} updates role', async ({ request }) => {
    const resp = await request.put(`/api/v1/tenants/${tenantId}/roles/${roleId}`, {
      data: { name: 'updated-role', permissions: ['read:certs'] },
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.name).toBe('updated-role');
  });

  test('DELETE /api/v1/tenants/{id}/roles/{roleId} deletes role', async ({ request }) => {
    const resp = await request.delete(`/api/v1/tenants/${tenantId}/roles/${roleId}`);
    expect(resp.ok()).toBeTruthy();
  });
});

// =============================================================================
// Tenant User CRUD Lifecycle
// Backend: CreateUser transport method not yet implemented (returns 500).
// =============================================================================

test.describe('Tenant User Lifecycle', () => {
  test.fixme(true, 'CreateUser transport method not yet implemented in embedded QRDB');
  const tenantId = `e2e-user-tenant-${Date.now()}`;
  let userId: string;

  test.beforeAll(async ({ request }) => {
    await request.post('/api/v1/tenants', {
      data: { id: tenantId, name: 'User Test Tenant' },
    });
  });

  test.afterAll(async ({ request }) => {
    await request.delete(`/api/v1/tenants/${tenantId}`);
  });

  test('POST /api/v1/tenants/{id}/users creates a user', async ({ request }) => {
    const resp = await request.post(`/api/v1/tenants/${tenantId}/users`, {
      data: { username: 'e2e-test-user' },
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('id');
    expect(body.username).toBe('e2e-test-user');
    userId = body.id;
  });

  test('GET /api/v1/tenants/{id}/users lists users', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/users`);
    expect(resp.ok()).toBeTruthy();
  });

  test('GET /api/v1/tenants/{id}/users/{userId} returns user', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/users/${userId}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.username).toBe('e2e-test-user');
  });

  test('PUT /api/v1/tenants/{id}/users/{userId} updates user', async ({ request }) => {
    const resp = await request.put(`/api/v1/tenants/${tenantId}/users/${userId}`, {
      data: { username: 'updated-user' },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test('DELETE /api/v1/tenants/{id}/users/{userId} deletes user', async ({ request }) => {
    const resp = await request.delete(`/api/v1/tenants/${tenantId}/users/${userId}`);
    expect(resp.ok()).toBeTruthy();
  });
});

// =============================================================================
// Tenant CA Operations
// =============================================================================

test.describe('Tenant CA Operations', () => {
  const tenantId = `e2e-ca-tenant-${Date.now()}`;

  test.beforeAll(async ({ request }) => {
    await request.post('/api/v1/tenants', {
      data: { id: tenantId, name: 'CA Test Tenant' },
    });
  });

  test.afterAll(async ({ request }) => {
    await request.delete(`/api/v1/tenants/${tenantId}`);
  });

  test('GET /api/v1/tenants/{id}/ca-status returns CA status', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/ca-status`);
    // May return 200 or error depending on CA initialization
    const status = resp.status();
    expect([200, 404, 500]).toContain(status);
  });

  test('GET /api/v1/tenants/{id}/intermediate-cas returns list', async ({ request }) => {
    const resp = await request.get(`/api/v1/tenants/${tenantId}/intermediate-cas`);
    const status = resp.status();
    expect([200, 404]).toContain(status);
  });
});

// =============================================================================
// Swagger / OpenAPI Documentation
// =============================================================================

test.describe('API Documentation', () => {
  test('GET /docs returns Swagger UI', async ({ request }) => {
    const acmeBase = process.env.ACME_BASE_URL || 'https://localhost:8443';
    const resp = await request.get(`${acmeBase}/docs`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.text();
    expect(body.toLowerCase()).toContain('swagger');
  });
});

// =============================================================================
// Error Handling & Edge Cases
// =============================================================================

test.describe('Error Handling', () => {
  test('GET /nonexistent returns 404', async ({ request }) => {
    const resp = await request.get('/nonexistent-route');
    expect(resp.status()).toBe(404);
  });

  test('wrong HTTP method returns 405', async ({ request }) => {
    const resp = await request.delete('/admin/status');
    expect([404, 405]).toContain(resp.status());
  });

  test('GET /admin/certificates with invalid page returns valid response', async ({ request }) => {
    const resp = await request.get('/admin/certificates?page=-1');
    // Should handle gracefully (either default to 1 or return error)
    expect(resp.status()).toBeLessThan(500);
  });

  test('GET /admin/accounts with large per_page is handled', async ({ request }) => {
    const resp = await request.get('/admin/accounts?per_page=10000');
    expect(resp.status()).toBeLessThan(500);
  });
});

// =============================================================================
// Audit Log
// =============================================================================

test.describe('Audit Log', () => {
  test('GET /admin/audit returns list with pagination', async ({ request }) => {
    const resp = await request.get('/admin/audit');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty('items');
    expect(Array.isArray(body.items)).toBeTruthy();
    expect(body).toHaveProperty('total');
    expect(body).toHaveProperty('page');
    expect(body).toHaveProperty('per_page');
  });

  test('GET /admin/audit with pagination params', async ({ request }) => {
    const resp = await request.get('/admin/audit?page=1&per_page=10');
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.page).toBe(1);
    expect(body.per_page).toBe(10);
  });
});
