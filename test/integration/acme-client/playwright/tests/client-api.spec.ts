import { test, expect } from '@playwright/test';

const API = '/api/v1';

// =============================================================================
// Account Endpoints
// =============================================================================

test.describe('Account Endpoints', () => {
  test('GET /accounts returns pre-populated accounts', async ({ request }) => {
    const res = await request.get(`${API}/accounts`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.data).toBeDefined();
    // Should have test-ca and staging-ca
    const accounts = body.data.accounts || body.data;
    expect(accounts['test-ca']).toBeDefined();
    expect(accounts['staging-ca']).toBeDefined();
  });

  test('GET /accounts/{name} returns specific account', async ({ request }) => {
    const res = await request.get(`${API}/accounts/test-ca`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.data).toBeDefined();
    const acct = body.data.account || body.data;
    expect(acct.email).toBe('admin@test.local');
  });

  test('GET /accounts/nonexistent returns 404', async ({ request }) => {
    const res = await request.get(`${API}/accounts/nonexistent`);
    expect(res.status()).toBe(404);
  });

  test('POST /accounts creates a new account', async ({ request }) => {
    const res = await request.post(`${API}/accounts`, {
      data: {
        name: 'test-add',
        directory: 'https://example.com/acme/directory',
        email: 'test@example.com',
        key: { algorithm: 'ECDSA', store: 'file' },
      },
    });
    // Could be 200 or 201
    expect(res.status()).toBeLessThan(300);
  });

  test('DELETE /accounts/{name} removes account', async ({ request }) => {
    // First create one to delete
    await request.post(`${API}/accounts`, {
      data: {
        name: 'to-delete',
        directory: 'https://example.com/acme',
        email: 'del@test.com',
        key: { algorithm: 'ECDSA', store: 'file' },
      },
    });
    const res = await request.delete(`${API}/accounts/to-delete`);
    expect(res.status()).toBeLessThan(300);
    // Verify it's gone
    const check = await request.get(`${API}/accounts/to-delete`);
    expect(check.status()).toBe(404);
  });

  test('POST /account/register without workflow returns error', async ({ request }) => {
    const res = await request.post(`${API}/account/register`, {
      data: { email: 'test@test.com' },
    });
    // No workflow configured, should return 400+
    expect(res.status()).toBeGreaterThanOrEqual(400);
  });
});

// =============================================================================
// Certificate Endpoints
// =============================================================================

test.describe('Certificate Endpoints', () => {
  test('GET /certificates returns pre-populated specs', async ({ request }) => {
    const res = await request.get(`${API}/certificates`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.data).toBeDefined();
    const certs = body.data.certificates || body.data;
    expect(certs['web-server']).toBeDefined();
    expect(certs['api-server']).toBeDefined();
  });

  test('GET /certificates?account=test-ca returns filtered specs', async ({ request }) => {
    const res = await request.get(`${API}/certificates?account=test-ca`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    const certs = body.data.certificates || body.data;
    // web-server uses test-ca, api-server uses staging-ca
    expect(certs['web-server']).toBeDefined();
    // api-server should be filtered out
    expect(certs['api-server']).toBeUndefined();
  });

  test('GET /certificates/{name} returns spec info', async ({ request }) => {
    const res = await request.get(`${API}/certificates/web-server`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.data).toBeDefined();
  });

  test('GET /certificates/nonexistent returns 404', async ({ request }) => {
    const res = await request.get(`${API}/certificates/nonexistent`);
    expect(res.status()).toBe(404);
  });

  test('POST /certificate/request with missing name returns 400', async ({ request }) => {
    const res = await request.post(`${API}/certificate/request`, { data: {} });
    expect(res.status()).toBeGreaterThanOrEqual(400);
  });

  test('POST /certificate/renew with missing name returns 400', async ({ request }) => {
    const res = await request.post(`${API}/certificate/renew`, { data: {} });
    expect(res.status()).toBeGreaterThanOrEqual(400);
  });

  test('POST /certificate/revoke with missing name returns 400', async ({ request }) => {
    const res = await request.post(`${API}/certificate/revoke`, { data: {} });
    expect(res.status()).toBeGreaterThanOrEqual(400);
  });
});

// =============================================================================
// Device Endpoints (Not Implemented)
// =============================================================================

test.describe('Device Endpoints (Not Implemented)', () => {
  test('POST /device/enroll returns 501', async ({ request }) => {
    const res = await request.post(`${API}/device/enroll`, {
      data: { device_id: 'test', ek_cert: 'dummy' },
    });
    expect(res.status()).toBe(501);
  });

  test('POST /device/attest returns 501', async ({ request }) => {
    const res = await request.post(`${API}/device/attest`, {
      data: { ak_name: 'test', nonce: 'dummy' },
    });
    expect(res.status()).toBe(501);
  });
});

// =============================================================================
// Config Endpoints
// =============================================================================

test.describe('Config Endpoints', () => {
  test('GET /config returns configuration', async ({ request }) => {
    const res = await request.get(`${API}/config`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.data).toBeDefined();
  });

  test('PUT /config updates configuration', async ({ request }) => {
    const res = await request.put(`${API}/config`, {
      data: { log_level: 'debug' },
    });
    expect(res.status()).toBeLessThan(300);
  });
});

// =============================================================================
// Renewal Endpoints
// =============================================================================

test.describe('Renewal Endpoints', () => {
  test('GET /renewal/status returns status', async ({ request }) => {
    const res = await request.get(`${API}/renewal/status`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.data).toBeDefined();
  });

  test('GET /renewal/config returns config', async ({ request }) => {
    const res = await request.get(`${API}/renewal/config`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.data).toBeDefined();
  });

  test('PUT /renewal/config updates config', async ({ request }) => {
    const res = await request.put(`${API}/renewal/config`, {
      data: { enabled: true },
    });
    expect(res.status()).toBeLessThan(300);
  });
});

// =============================================================================
// Response Format
// =============================================================================

test.describe('Response Format', () => {
  test('successful response has data field', async ({ request }) => {
    const res = await request.get(`${API}/config`);
    const body = await res.json();
    expect(body).toHaveProperty('data');
  });

  test('error response has error field', async ({ request }) => {
    const res = await request.post(`${API}/certificate/request`, { data: {} });
    const body = await res.json();
    expect(body).toHaveProperty('error');
  });

  // The client REST API is served either in-process behind the Wails asset
  // handler (every origin accepted, wildcard echoed) or on a TCP listener via
  // "trusted-acme-client serve" (only a same-origin caller served). Playwright
  // always drives the networked `serve` binary (see start-server.sh), so
  // these specs exercise the network-mode contract implemented by
  // pkg/acme/gui/guard.
  test('same-origin request echoes Access-Control-Allow-Origin', async ({ request, baseURL }) => {
    const res = await request.get(`${API}/config`, {
      headers: { Origin: baseURL! },
    });
    expect(res.status()).toBe(200);
    const headers = res.headers();
    expect(headers['access-control-allow-origin']).toBe(baseURL);
    expect(headers['vary']).toContain('Origin');
  });

  test('cross-origin request is rejected', async ({ request }) => {
    const res = await request.get(`${API}/config`, {
      headers: { Origin: 'http://evil.example.com' },
    });
    expect(res.status()).toBe(403);
    const headers = res.headers();
    expect(headers['access-control-allow-origin']).toBeUndefined();
  });

  test('request with no Origin header gets no CORS header', async ({ request }) => {
    const res = await request.get(`${API}/config`);
    expect(res.status()).toBe(200);
    const headers = res.headers();
    expect(headers['access-control-allow-origin']).toBeUndefined();
  });
});
