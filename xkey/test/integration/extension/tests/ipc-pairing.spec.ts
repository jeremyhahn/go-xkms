// IPC-level integration tests for the xKey extension pairing ceremony.
//
// These tests exercise the FULL native messaging pairing protocol end-to-end
// by spawning `xkey extension host` as a child process and speaking the native
// messaging wire protocol (4-byte LE length prefix + JSON) over stdin/stdout:
//
//   Test Client → stdin → xkey extension host → IPC Server → headlessHandler
//   Test Client ← stdout ← xkey extension host
//
// The pairing ceremony flow:
//   1. Extension sends handshake with X25519 pubkey + Ed25519 identity key
//   2. Host responds with handshake_pair (pairing required)
//   3. Extension sends pairing_confirm with 6-digit code
//   4. Host responds with pairing_ok + handshake_ok
//
// No browser or Chrome extension is required.
import { test, expect } from '@playwright/test';
import { ChildProcess, spawn } from 'child_process';
import * as crypto from 'crypto';
import * as net from 'net';
import * as path from 'path';
import * as fs from 'fs';

const XKEY_BIN = process.env.XKEY_BIN || '/usr/local/bin/xkey';
const IPC_SOCKET = process.env.IPC_SOCKET || '/tmp/xkey-test/xkey.sock';
const XKEY_HOME = process.env.XKEY_HOME || '/tmp/xkey-test';

// --- Native messaging wire protocol helpers ---

/** Write a native messaging length-prefixed JSON message to a stream. */
function writeNativeMessage(stream: NodeJS.WritableStream, msg: object): void {
  const json = JSON.stringify(msg);
  const payload = Buffer.from(json, 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(payload.length, 0);
  stream.write(header);
  stream.write(payload);
}

/** Read a single native messaging length-prefixed JSON message from a buffer. */
function parseNativeMessage(buf: Buffer): { msg: any; consumed: number } | null {
  if (buf.length < 4) return null;
  const length = buf.readUInt32LE(0);
  if (length === 0 || length > 1024 * 1024) return null;
  if (buf.length < 4 + length) return null;
  const payload = buf.subarray(4, 4 + length);
  return { msg: JSON.parse(payload.toString('utf-8')), consumed: 4 + length };
}

/**
 * NativeMessageReader buffers ALL stdout data from a child process from the
 * moment it is constructed. Messages are consumed via readNext(), which
 * resolves as soon as a complete length-prefixed JSON message is available.
 *
 * This avoids the race condition where the Go host writes to stdout before
 * the test attaches an `on('data')` handler — data that arrives before any
 * listener is attached is buffered internally by Node.js, but `data` events
 * are only emitted to listeners that are present at emit time.
 */
class NativeMessageReader {
  private buf = Buffer.alloc(0);
  private stderrBuf = '';
  private waiters: Array<{
    resolve: (msg: any) => void;
    reject: (err: Error) => void;
  }> = [];
  private closed = false;
  private closeError: Error | null = null;

  constructor(private proc: ChildProcess) {
    proc.stdout?.on('data', (chunk: Buffer) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.drain();
    });
    proc.stdout?.on('close', () => {
      this.closed = true;
      this.closeError = new Error('Process stdout closed before message received');
      this.rejectAll();
    });
    proc.stderr?.on('data', (chunk: Buffer) => {
      this.stderrBuf += chunk.toString();
    });
  }

  /** Read the next complete native message, with a timeout. */
  readNext(timeoutMs = 10000): Promise<any> {
    // Check if a message is already buffered.
    const existing = this.tryParse();
    if (existing !== null) return Promise.resolve(existing);

    if (this.closed) {
      return Promise.reject(this.closeError ?? new Error('stdout closed'));
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.waiters.findIndex(w => w.resolve === resolve);
        if (idx !== -1) this.waiters.splice(idx, 1);
        reject(new Error(
          `Timeout waiting for native message (${timeoutMs}ms)\n` +
          `Host stderr: ${this.stderrBuf || '(empty)'}`,
        ));
      }, timeoutMs);

      this.waiters.push({
        resolve: (msg) => { clearTimeout(timer); resolve(msg); },
        reject: (err) => { clearTimeout(timer); reject(err); },
      });
    });
  }

  /** Get captured stderr for diagnostics. */
  get stderr(): string { return this.stderrBuf; }

  private tryParse(): any | null {
    const result = parseNativeMessage(this.buf);
    if (result) {
      this.buf = this.buf.subarray(result.consumed);
      return result.msg;
    }
    return null;
  }

  private drain(): void {
    while (this.waiters.length > 0) {
      const msg = this.tryParse();
      if (msg === null) break;
      const waiter = this.waiters.shift()!;
      waiter.resolve(msg);
    }
  }

  private rejectAll(): void {
    for (const waiter of this.waiters) {
      waiter.reject(this.closeError ?? new Error('stdout closed'));
    }
    this.waiters = [];
  }
}

/** Send an IPC message directly to the IPC server (for direct IPC tests). */
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

/** Generate an X25519 keypair and return raw 32-byte buffers. */
function generateX25519Keypair(): { publicKey: Buffer; privateKey: Buffer } {
  const kp = crypto.generateKeyPairSync('x25519');
  const pubDer = kp.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const privDer = kp.privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  return {
    publicKey: pubDer.subarray(pubDer.length - 32),
    privateKey: privDer.subarray(privDer.length - 32),
  };
}

/** Generate an Ed25519 keypair and return raw 32-byte buffers. */
function generateEd25519Keypair(): { publicKey: Buffer; privateKey: Buffer } {
  const kp = crypto.generateKeyPairSync('ed25519');
  const pubDer = kp.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const privDer = kp.privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  return {
    publicKey: pubDer.subarray(pubDer.length - 32),
    privateKey: privDer.subarray(privDer.length - 32),
  };
}

/** Sign data with an Ed25519 raw private key. */
function ed25519Sign(privateKey: Buffer, data: Buffer): Buffer {
  const key = crypto.createPrivateKey({
    key: Buffer.concat([
      // Ed25519 PKCS8 DER prefix (16 bytes) + key octet-string header (2 bytes).
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      privateKey,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  return crypto.sign(null, data, key) as Buffer;
}

/** Compute identity sign data: SHA-256(ephemeralPubKey || origin || "xkey-ext-v1"). */
function computeSignData(ephemeralPubKey: Buffer, origin: string): Buffer {
  const hash = crypto.createHash('sha256');
  hash.update(ephemeralPubKey);
  hash.update(origin);
  hash.update('xkey-ext-v1');
  return hash.digest();
}

/**
 * Create a mock IPC server that captures pairing codes and responds immediately.
 *
 * IMPORTANT: The Go IPC client writes a JSON line then reads the response on
 * the SAME connection without closing its write side. We must respond as soon
 * as a complete JSON line arrives (on 'data'), NOT on 'end' (which deadlocks).
 */
function createMockIPCServer(
  socketPath: string,
  codeRef: { code: string },
): Promise<net.Server> {
  return new Promise<net.Server>((resolve) => {
    const server = net.createServer((conn) => {
      let buf = '';
      conn.on('data', (chunk) => {
        buf += chunk.toString();
        // Attempt JSON parse on each data event — Go sends a single JSON
        // object terminated by '\n' via json.Encoder.
        try {
          const msg = JSON.parse(buf.trim());
          buf = '';
          if (msg.type === 'pairing' && msg.pairing?.action === 'notify_code') {
            codeRef.code = msg.pairing.code;
            conn.end(JSON.stringify({
              status: 'ok',
              pairing: { acknowledged: true },
            }) + '\n');
          } else {
            conn.end(JSON.stringify({
              status: 'ok',
              action: 'daemon_ready',
            }) + '\n');
          }
        } catch {
          // Incomplete JSON — wait for more data.
        }
      });
    });
    server.listen(socketPath, () => resolve(server));
  });
}

/** Wait for a captured code to appear (polling). */
async function waitForCode(codeRef: { code: string }, maxWaitMs = 3000): Promise<string> {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    if (codeRef.code) return codeRef.code;
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error(`Pairing code not captured within ${maxWaitMs}ms`);
}

/**
 * Spawn a host process and return a NativeMessageReader that is already
 * listening for stdout data. This guarantees no messages are lost due to
 * late listener attachment.
 */
function spawnHost(
  args: string[],
  env: Record<string, string | undefined>,
): { host: ChildProcess; reader: NativeMessageReader } {
  const host = spawn(XKEY_BIN, args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    env,
  });
  const reader = new NativeMessageReader(host);
  return { host, reader };
}

/** Kill a host process and wait for it to exit. */
async function killHost(host: ChildProcess): Promise<void> {
  host.stdin?.end();
  host.kill('SIGTERM');
  await new Promise<void>(r => host.on('close', () => r()));
}

// Increase test timeout — pairing involves multi-step protocol exchange.
test.setTimeout(30_000);

// ─── Direct IPC Tests ────────────────────────────────────────────────────────
// These test the IPC pairing message handler directly (no native messaging host).

test.describe('Extension Pairing — IPC Handler', () => {

  test('IPC server accepts pairing notify_code messages', async () => {
    const resp = await sendIPC(IPC_SOCKET, {
      type: 'pairing',
      pairing: {
        action: 'notify_code',
        code: '123456',
        identity_key: Buffer.alloc(32).toString('base64'),
        origin: 'chrome-extension://test/',
      },
    });
    expect(resp.status).toBe('ok');
    expect(resp.pairing).toBeDefined();
    expect(resp.pairing.acknowledged).toBe(true);
  });

  test('IPC server rejects pairing with missing action', async () => {
    const resp = await sendIPC(IPC_SOCKET, {
      type: 'pairing',
      pairing: {},
    });
    expect(resp.status).toBe('error');
    expect(resp.error).toContain('action');
  });

  test('IPC server rejects pairing with unknown action', async () => {
    const resp = await sendIPC(IPC_SOCKET, {
      type: 'pairing',
      pairing: { action: 'bogus' },
    });
    expect(resp.status).toBe('error');
    expect(resp.error).toContain('unknown pairing action');
  });
});

// ─── Full E2E Pairing Tests ─────────────────────────────────────────────────
// Each test spawns its own mini IPC server + native host process for isolation.

test.describe('Extension Pairing — Full Ceremony', () => {

  test('complete pairing ceremony', async () => {
    const tmpDir = fs.mkdtempSync('/tmp/xkey-pairing-test-');
    const testSocket = path.join(tmpDir, 'test.sock');
    const codeRef = { code: '' };
    const ipcServer = await createMockIPCServer(testSocket, codeRef);

    try {
      const x25519 = generateX25519Keypair();
      const ed25519kp = generateEd25519Keypair();
      const origin = 'chrome-extension://test-pairing-e2e/';

      const { host, reader } = spawnHost(
        ['extension', 'host', '--socket', testSocket],
        { ...process.env, HOME: tmpDir },
      );

      try {
        // 1. Handshake with identity key.
        writeNativeMessage(host.stdin!, {
          type: 'handshake',
          pubkey: x25519.publicKey.toString('base64'),
          identity_key: ed25519kp.publicKey.toString('base64'),
          origin: origin,
        });

        // 2. Expect handshake_pair.
        const pairResp = await reader.readNext();
        expect(pairResp.type).toBe('handshake_pair');
        expect(pairResp.pairing_required).toBe(true);
        expect(pairResp.pubkey).toBeTruthy();

        // 3. Wait for code via mock IPC server.
        const code = await waitForCode(codeRef);
        expect(code).toMatch(/^\d{6}$/);

        // 4. Submit code.
        writeNativeMessage(host.stdin!, {
          type: 'pairing_confirm',
          code: code,
          identity_key: ed25519kp.publicKey.toString('base64'),
        });

        // 5. Read pairing_ok (host sends pairing_ok only, NOT handshake_ok —
        //    the extension already received our pubkey in handshake_pair).
        const pairingOK = await reader.readNext();
        expect(pairingOK.type).toBe('pairing_ok');

        // 6. Verify pairing state persisted to disk.
        // The host stores state at $HOME/.xkey/data/extension/pairing.json
        // using a multi-origin map format keyed by extension origin.
        const stateFile = path.join(tmpDir, '.xkey', 'data', 'extension', 'pairing.json');
        expect(fs.existsSync(stateFile)).toBe(true);
        const state = JSON.parse(fs.readFileSync(stateFile, 'utf-8'));
        expect(state[origin]).toBeDefined();
        expect(state[origin].identity_key).toBeTruthy();
        expect(state[origin].paired_at).toBeTruthy();
      } finally {
        await killHost(host);
      }
    } finally {
      ipcServer.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('pairing ceremony rejects wrong code', async () => {
    const tmpDir = fs.mkdtempSync('/tmp/xkey-pairing-test-');
    const testSocket = path.join(tmpDir, 'test.sock');
    const codeRef = { code: '' };
    const ipcServer = await createMockIPCServer(testSocket, codeRef);

    try {
      const x25519 = generateX25519Keypair();
      const ed25519kp = generateEd25519Keypair();
      const origin = 'chrome-extension://test-wrong-code/';

      const { host, reader } = spawnHost(
        ['extension', 'host', '--socket', testSocket],
        { ...process.env, HOME: tmpDir },
      );

      try {
        writeNativeMessage(host.stdin!, {
          type: 'handshake',
          pubkey: x25519.publicKey.toString('base64'),
          identity_key: ed25519kp.publicKey.toString('base64'),
          origin: origin,
        });

        const pairResp = await reader.readNext();
        expect(pairResp.type).toBe('handshake_pair');

        const code = await waitForCode(codeRef);
        const wrongCode = code === '000000' ? '111111' : '000000';

        writeNativeMessage(host.stdin!, {
          type: 'pairing_confirm',
          code: wrongCode,
          identity_key: ed25519kp.publicKey.toString('base64'),
        });

        // Expect pairing_failed.
        const failedResp = await reader.readNext();
        expect(failedResp.type).toBe('pairing_failed');
        expect(failedResp.error).toBeTruthy();

        // State should NOT be persisted.
        const stateFile = path.join(tmpDir, '.xkey', 'pairing.json');
        expect(fs.existsSync(stateFile)).toBe(false);
      } finally {
        await killHost(host);
      }
    } finally {
      ipcServer.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('paired host accepts reconnection with valid Ed25519 signature', async () => {
    const tmpDir = fs.mkdtempSync('/tmp/xkey-pairing-test-');
    const testSocket = path.join(tmpDir, 'test.sock');
    const codeRef = { code: '' };
    const ipcServer = await createMockIPCServer(testSocket, codeRef);

    try {
      const ed25519kp = generateEd25519Keypair();
      const origin = 'chrome-extension://test-reconnect/';

      // Phase 1: Initial pairing.
      {
        codeRef.code = '';
        const x25519 = generateX25519Keypair();

        const { host, reader } = spawnHost(
          ['extension', 'host', '--socket', testSocket],
          { ...process.env, HOME: tmpDir },
        );

        writeNativeMessage(host.stdin!, {
          type: 'handshake',
          pubkey: x25519.publicKey.toString('base64'),
          identity_key: ed25519kp.publicKey.toString('base64'),
          origin: origin,
        });

        expect((await reader.readNext()).type).toBe('handshake_pair');

        const code = await waitForCode(codeRef);
        writeNativeMessage(host.stdin!, {
          type: 'pairing_confirm',
          code: code,
          identity_key: ed25519kp.publicKey.toString('base64'),
        });

        expect((await reader.readNext()).type).toBe('pairing_ok');

        await killHost(host);
      }

      // Phase 2: Reconnect with Ed25519 identity signature.
      {
        const x25519 = generateX25519Keypair();

        const { host, reader } = spawnHost(
          ['extension', 'host', '--socket', testSocket],
          { ...process.env, HOME: tmpDir },
        );

        const signData = computeSignData(x25519.publicKey, origin);
        const signature = ed25519Sign(ed25519kp.privateKey, signData);

        writeNativeMessage(host.stdin!, {
          type: 'handshake',
          pubkey: x25519.publicKey.toString('base64'),
          identity_key: ed25519kp.publicKey.toString('base64'),
          identity_sig: signature.toString('base64'),
          origin: origin,
        });

        // Should get handshake_ok directly — no pairing needed.
        const resp = await reader.readNext();
        expect(resp.type).toBe('handshake_ok');
        expect(resp.pubkey).toBeTruthy();

        await killHost(host);
      }
    } finally {
      ipcServer.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('paired host rejects reconnection with wrong Ed25519 key', async () => {
    const tmpDir = fs.mkdtempSync('/tmp/xkey-pairing-test-');
    const testSocket = path.join(tmpDir, 'test.sock');
    const codeRef = { code: '' };
    const ipcServer = await createMockIPCServer(testSocket, codeRef);

    try {
      const ed25519Original = generateEd25519Keypair();
      const origin = 'chrome-extension://test-rogue/';

      // Phase 1: Initial pairing with original key.
      {
        codeRef.code = '';
        const x25519 = generateX25519Keypair();

        const { host, reader } = spawnHost(
          ['extension', 'host', '--socket', testSocket],
          { ...process.env, HOME: tmpDir },
        );

        writeNativeMessage(host.stdin!, {
          type: 'handshake',
          pubkey: x25519.publicKey.toString('base64'),
          identity_key: ed25519Original.publicKey.toString('base64'),
          origin: origin,
        });

        expect((await reader.readNext()).type).toBe('handshake_pair');

        const code = await waitForCode(codeRef);
        writeNativeMessage(host.stdin!, {
          type: 'pairing_confirm',
          code: code,
          identity_key: ed25519Original.publicKey.toString('base64'),
        });

        expect((await reader.readNext()).type).toBe('pairing_ok');

        await killHost(host);
      }

      // Phase 2: Reconnect with a DIFFERENT (rogue) Ed25519 key.
      {
        const ed25519Rogue = generateEd25519Keypair();
        const x25519 = generateX25519Keypair();

        const { host, reader } = spawnHost(
          ['extension', 'host', '--socket', testSocket],
          { ...process.env, HOME: tmpDir },
        );

        const signData = computeSignData(x25519.publicKey, origin);
        const signature = ed25519Sign(ed25519Rogue.privateKey, signData);

        writeNativeMessage(host.stdin!, {
          type: 'handshake',
          pubkey: x25519.publicKey.toString('base64'),
          identity_key: ed25519Rogue.publicKey.toString('base64'),
          identity_sig: signature.toString('base64'),
          origin: origin,
        });

        // Identity mismatch triggers re-pairing (the extension may have been
        // reinstalled with a new key). The host sends handshake_pair so the
        // user can confirm the new extension via the 6-digit code ceremony.
        const resp = await reader.readNext();
        expect(resp.type).toBe('handshake_pair');
        expect(resp.pairing_required).toBe(true);
        expect(resp.pubkey).toBeTruthy();

        await killHost(host);
      }
    } finally {
      ipcServer.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('host without pairing skips identity verification', async () => {
    const x25519 = generateX25519Keypair();

    const { host, reader } = spawnHost(
      ['extension', 'host', '--socket', IPC_SOCKET, '--no-pairing'],
      { ...process.env, HOME: XKEY_HOME },
    );

    try {
      writeNativeMessage(host.stdin!, {
        type: 'handshake',
        pubkey: x25519.publicKey.toString('base64'),
      });

      const resp = await reader.readNext();
      expect(resp.type).toBe('handshake_ok');
      expect(resp.pubkey).toBeTruthy();
    } finally {
      await killHost(host);
    }
  });
});
