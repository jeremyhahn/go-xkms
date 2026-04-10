// IPC-level integration tests for the xKey autofill pipeline.
//
// These tests exercise the FULL autofill pipeline end-to-end by speaking the
// IPC protocol directly over Unix sockets:
//
//   Test Client → Unix Socket → IPC Server → headlessHandler → AutoFillService
//                                                          → StaticPasswordStore
//                                                          → OATHStore
//
// No browser or Chrome extension is required. This ensures all business logic
// is tested reliably in Docker/CI environments.
import { test, expect } from '@playwright/test';
import * as net from 'net';

const SOCKET_PATH = process.env.IPC_SOCKET || '/tmp/xkey-test/xkey.sock';

// sendIPC connects to the Unix socket, sends a JSON message, reads the
// response, and returns the parsed JSON. Each call opens a new connection
// (matching the IPC protocol's one-message-per-connection design).
function sendIPC(socketPath: string, message: object): Promise<any> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath, () => {
      client.write(JSON.stringify(message) + '\n');
    });
    let data = '';
    client.on('data', (chunk: Buffer) => {
      data += chunk.toString();
    });
    client.on('end', () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error(`Invalid JSON response: ${data}`));
      }
    });
    client.on('error', (err: Error) => reject(err));
    client.setTimeout(5000, () => {
      client.destroy();
      reject(new Error('IPC timeout'));
    });
  });
}

test.describe('IPC Server Connectivity', () => {
  test('server is running and accepts connections', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'status',
    });
    expect(resp.status).toBe('ok');
    expect(resp.action).toBe('daemon_ready');
  });

  test('touch returns approved_up in headless mode', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'touch',
    });
    expect(resp.status).toBe('ok');
    expect(resp.action).toBe('approved_up');
  });

  test('rejects invalid message type', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'invalid_type',
    });
    expect(resp.status).toBe('error');
    expect(resp.error).toContain('unknown message type');
  });

  test('rejects empty message', async () => {
    const resp = await sendIPC(SOCKET_PATH, {});
    expect(resp.status).toBe('error');
    expect(resp.error).toContain('type is required');
  });
});

test.describe('Autofill Credential Search', () => {
  test('finds credentials matching test-site domain', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'search', domain: 'test-site' },
    });
    expect(resp.status).toBe('ok');
    expect(resp.autofill).toBeDefined();
    expect(resp.autofill.credentials).toBeDefined();
    expect(resp.autofill.credentials.length).toBeGreaterThanOrEqual(1);

    // Verify credential structure.
    const cred = resp.autofill.credentials[0];
    expect(cred.id).toBeTruthy();
    expect(cred.username).toBeTruthy();
    expect(cred.url).toBeTruthy();
  });

  test('finds multiple credentials for multi-account domain', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'search', domain: 'test-site' },
    });
    expect(resp.status).toBe('ok');
    // We seeded 3 credentials for test-site:8080.
    expect(resp.autofill.credentials.length).toBeGreaterThanOrEqual(2);

    const usernames = resp.autofill.credentials.map(
      (c: any) => c.username
    );
    expect(usernames).toContain('testuser@example.com');
    expect(usernames).toContain('user1@example.com');
    expect(usernames).toContain('user2@example.com');
  });

  test('returns empty for non-matching domain', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'search', domain: 'nonexistent-domain.example' },
    });
    expect(resp.status).toBe('ok');
    expect(resp.autofill).toBeDefined();
    // Should be empty array or null.
    const creds = resp.autofill.credentials ?? [];
    expect(creds.length).toBe(0);
  });

  test('rejects search without domain', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'search' },
    });
    expect(resp.status).toBe('error');
    expect(resp.error).toContain('domain is required');
  });
});

test.describe('Autofill Credential Get', () => {
  test('retrieves credential with username and password', async () => {
    // First search to get a credential ID.
    const searchResp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'search', domain: 'test-site' },
    });
    expect(searchResp.status).toBe('ok');
    expect(searchResp.autofill.credentials.length).toBeGreaterThan(0);

    const credId = searchResp.autofill.credentials[0].id;

    // Get the full credential including password.
    const getResp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'get', id: credId },
    });
    expect(getResp.status).toBe('ok');
    expect(getResp.autofill).toBeDefined();
    expect(getResp.autofill.fill).toBeDefined();
    expect(getResp.autofill.fill.username).toBeTruthy();
    expect(getResp.autofill.fill.password).toBeTruthy();
  });

  test('rejects get without id', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'get' },
    });
    expect(resp.status).toBe('error');
    expect(resp.error).toContain('id is required');
  });
});

test.describe('Autofill TOTP', () => {
  test('generates TOTP code for matching domain', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'totp', domain: 'test-site' },
    });
    expect(resp.status).toBe('ok');
    expect(resp.autofill).toBeDefined();
    expect(resp.autofill.totp).toBeDefined();
    expect(resp.autofill.totp.code).toMatch(/^\d{6}$/);
    expect(resp.autofill.totp.time_left).toBeGreaterThan(0);
    expect(resp.autofill.totp.period).toBe(30);
  });

  test('rejects TOTP without domain', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'totp' },
    });
    expect(resp.status).toBe('error');
    expect(resp.error).toContain('domain is required');
  });
});

test.describe('Autofill Status and Policy', () => {
  test('returns autofill status', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'status' },
    });
    expect(resp.status).toBe('ok');
    expect(resp.autofill).toBeDefined();
    expect(resp.autofill.status).toBeDefined();
    expect(typeof resp.autofill.status.available).toBe('boolean');
    expect(typeof resp.autofill.status.extension_enabled).toBe('boolean');
  });

  test('returns autofill policy', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'policy' },
    });
    expect(resp.status).toBe('ok');
    expect(resp.autofill).toBeDefined();
    expect(resp.autofill.policy).toBeDefined();
    expect(typeof resp.autofill.policy.session_timeout_sec).toBe('number');
    expect(typeof resp.autofill.policy.fill_mode).toBe('string');
  });

  test('rejects unknown autofill action', async () => {
    const resp = await sendIPC(SOCKET_PATH, {
      type: 'autofill',
      autofill: { action: 'bogus_action' },
    });
    expect(resp.status).toBe('error');
    expect(resp.error).toContain('unknown autofill action');
  });
});
