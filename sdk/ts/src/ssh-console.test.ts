// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * ssh-console.test.ts — SSHConsoleClient (src/ssh-console.ts): the terminal
 * <-> WebSocket bridge itself, not the control-frame wire format (see
 * protocol.test.ts for that).
 *
 * Coverage note: the previous version of this file imported only
 * './protocol.js' and never touched './ssh-console.js', which is why
 * ssh-console.ts showed 0% coverage despite a same-named test file with 15
 * passing tests. That content now lives in protocol.test.ts; this file
 * exercises the real SSHConsoleClient.
 *
 * @xterm/xterm's default renderer needs a real <canvas> 2D context, which
 * jsdom does not provide without the optional native `canvas` package (not
 * installed here). Rather than pull in a heavy/fragile canvas polyfill for a
 * one-file terminal wrapper, this test mocks '@xterm/xterm' and
 * '@xterm/addon-fit' with lightweight in-memory fakes that expose the same
 * surface SSHConsoleClient actually calls (constructor options, loadAddon,
 * open, onData, onResize, write, dispose; fit). That keeps the test focused
 * on SSHConsoleClient's own logic — message routing, resize/keystroke
 * forwarding, host-key confirm/notify handling, dispose idempotency — which
 * is exactly what this module is responsible for; xterm's own rendering is
 * xterm's problem, not this SDK's.
 *
 * WebSocket is likewise not implemented by jsdom, so a minimal FakeWebSocket
 * is installed on globalThis before each test.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { encodeResize, encodeHostKeyResponse } from './protocol.js';

// ---------------------------------------------------------------------------
// @xterm/xterm / @xterm/addon-fit fakes
//
// vi.mock factories are hoisted above the rest of the module, so the fake
// classes must be *declared inside* the factory (a `class` reference from
// module scope would still be in its temporal-dead-zone when the hoisted
// factory runs). Each factory attaches its class to `globalThis` so the test
// body below — and SSHConsoleClient.open(), via the mocked import — share
// the exact same constructor and its `instances` registry.
// ---------------------------------------------------------------------------

interface FakeTerminalCtor {
  new (options: Record<string, unknown>): FakeTerminal;
  instances: FakeTerminal[];
}
interface FakeTerminal {
  options: Record<string, unknown>;
  rows: number;
  cols: number;
  written: Uint8Array[];
  disposed: boolean;
  openedOn: unknown;
  onDataCb: ((data: string) => void) | undefined;
  onResizeCb: ((size: { rows: number; cols: number }) => void) | undefined;
  loadAddon(addon: unknown): void;
  open(el: unknown): void;
  write(data: Uint8Array): void;
  onData(cb: (data: string) => void): void;
  onResize(cb: (size: { rows: number; cols: number }) => void): void;
  dispose(): void;
}

interface FakeFitAddonCtor {
  new (): FakeFitAddon;
  instances: FakeFitAddon[];
  throwOnFit: boolean;
}
interface FakeFitAddon {
  fitCalls: number;
  fit(): void;
}

vi.mock('@xterm/xterm', () => {
  class Terminal implements FakeTerminal {
    static instances: FakeTerminal[] = [];
    rows = 24;
    cols = 80;
    written: Uint8Array[] = [];
    disposed = false;
    openedOn: unknown;
    onDataCb: ((data: string) => void) | undefined;
    onResizeCb: ((size: { rows: number; cols: number }) => void) | undefined;

    constructor(public options: Record<string, unknown>) {
      Terminal.instances.push(this);
    }

    loadAddon(_addon: unknown): void {}
    open(el: unknown): void {
      this.openedOn = el;
    }
    write(data: Uint8Array): void {
      this.written.push(data);
    }
    onData(cb: (data: string) => void): void {
      this.onDataCb = cb;
    }
    onResize(cb: (size: { rows: number; cols: number }) => void): void {
      this.onResizeCb = cb;
    }
    dispose(): void {
      this.disposed = true;
    }
  }
  return { Terminal };
});

vi.mock('@xterm/addon-fit', () => {
  class FitAddon implements FakeFitAddon {
    static instances: FakeFitAddon[] = [];
    static throwOnFit = false;
    fitCalls = 0;

    constructor() {
      FitAddon.instances.push(this);
    }

    fit(): void {
      this.fitCalls++;
      if (FitAddon.throwOnFit) {
        throw new Error('container not laid out');
      }
    }
  }
  return { FitAddon };
});

import { SSHConsoleClient, type HostKeyPrompt } from './ssh-console.js';
import { Terminal as FakeTerminalImport } from '@xterm/xterm';
import { FitAddon as FakeFitAddonImport } from '@xterm/addon-fit';

const FakeTerminal = FakeTerminalImport as unknown as FakeTerminalCtor;
const FakeFitAddon = FakeFitAddonImport as unknown as FakeFitAddonCtor;

// ---------------------------------------------------------------------------
// WebSocket fake
// ---------------------------------------------------------------------------

class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  readyState = FakeWebSocket.OPEN;
  binaryType = '';
  closed = false;
  sent: unknown[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(
    public url: string,
    public protocols?: string[],
  ) {
    FakeWebSocket.instances.push(this);
  }

  send(data: unknown): void {
    this.sent.push(data);
  }

  close(): void {
    this.closed = true;
    this.readyState = FakeWebSocket.CLOSED;
  }
}

function lastSentControl(ws: FakeWebSocket): unknown {
  const raw = ws.sent[ws.sent.length - 1];
  return typeof raw === 'string' ? JSON.parse(raw) : raw;
}

beforeEach(() => {
  FakeTerminal.instances = [];
  FakeFitAddon.instances = [];
  FakeFitAddon.throwOnFit = false;
  FakeWebSocket.instances = [];
  (globalThis as unknown as { WebSocket: unknown }).WebSocket = FakeWebSocket;
});

function open(client: SSHConsoleClient, protocols?: string[]): { term: FakeTerminal; ws: FakeWebSocket } {
  const el = {} as HTMLElement;
  client.open(el, protocols !== undefined ? { url: 'ws://x/console', protocols } : { url: 'ws://x/console' });
  const term = FakeTerminal.instances[FakeTerminal.instances.length - 1]!;
  const ws = FakeWebSocket.instances[FakeWebSocket.instances.length - 1]!;
  return { term, ws };
}

// ---------------------------------------------------------------------------
// open()
// ---------------------------------------------------------------------------

describe('SSHConsoleClient.open', () => {
  it('renders a Terminal into the element and connects a WebSocket without protocols', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    expect(term.openedOn).toBeDefined();
    expect(ws.url).toBe('ws://x/console');
    expect(ws.protocols).toBeUndefined();
    expect(ws.binaryType).toBe('arraybuffer');
    // safeFit() runs during open().
    expect(FakeFitAddon.instances[0]?.fitCalls).toBe(1);
  });

  it('passes WebSocket subprotocols through when supplied', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client, ['bridge.v1']);
    expect(ws.protocols).toEqual(['bridge.v1']);
  });

  it('applies fontSize/fontFamily/theme options, defaulting fontSize and fontFamily', () => {
    const withDefaults = new SSHConsoleClient();
    open(withDefaults);
    expect(FakeTerminal.instances[0]?.options['fontSize']).toBe(13);
    expect(FakeTerminal.instances[0]?.options['fontFamily']).toBe('monospace');
    expect(FakeTerminal.instances[0]?.options['theme']).toBeUndefined();

    const theme = { background: '#000' };
    const withOverrides = new SSHConsoleClient({ fontSize: 18, fontFamily: 'Menlo', theme });
    open(withOverrides);
    expect(FakeTerminal.instances[1]?.options['fontSize']).toBe(18);
    expect(FakeTerminal.instances[1]?.options['fontFamily']).toBe('Menlo');
    expect(FakeTerminal.instances[1]?.options['theme']).toBe(theme);
  });

  it('swallows a fit() error during open (container not yet laid out)', () => {
    FakeFitAddon.throwOnFit = true;
    const client = new SSHConsoleClient();
    expect(() => open(client)).not.toThrow();
  });

  it('sends a resize control frame matching term dimensions when the socket opens', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    term.rows = 40;
    term.cols = 100;
    ws.onopen?.();
    expect(lastSentControl(ws)).toEqual(JSON.parse(encodeResize(40, 100)));
  });

  it('forwards keystrokes from term.onData as binary frames when the socket is open', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    term.onDataCb?.('ls\n');
    expect(ws.sent).toHaveLength(1);
    const frame = ws.sent[0] as Uint8Array;
    expect(new TextDecoder().decode(frame)).toBe('ls\n');
  });

  it('does not forward keystrokes when the socket is not open', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    ws.readyState = FakeWebSocket.CONNECTING;
    term.onDataCb?.('ls\n');
    expect(ws.sent).toHaveLength(0);
  });

  it('sends a resize control frame from term.onResize when the socket is open', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    term.onResizeCb?.({ rows: 30, cols: 90 });
    expect(lastSentControl(ws)).toEqual({ type: 'resize', rows: 30, cols: 90 });
  });

  it('does not send a resize frame from term.onResize when the socket is not open', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    ws.readyState = FakeWebSocket.CLOSED;
    term.onResizeCb?.({ rows: 30, cols: 90 });
    expect(ws.sent).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// fit()
// ---------------------------------------------------------------------------

describe('SSHConsoleClient.fit', () => {
  it('re-fits the addon and sends an updated resize frame', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    const fitCallsAfterOpen = FakeFitAddon.instances[0]!.fitCalls;
    term.rows = 50;
    term.cols = 200;
    client.fit();
    expect(FakeFitAddon.instances[0]?.fitCalls).toBe(fitCallsAfterOpen + 1);
    expect(lastSentControl(ws)).toEqual({ type: 'resize', rows: 50, cols: 200 });
  });

  it('swallows a fit() error without throwing or sending a stale resize', () => {
    const client = new SSHConsoleClient();
    open(client);
    FakeFitAddon.throwOnFit = true;
    expect(() => client.fit()).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// dispose()
// ---------------------------------------------------------------------------

describe('SSHConsoleClient.dispose', () => {
  it('closes the socket and disposes the terminal', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    client.dispose();
    expect(ws.closed).toBe(true);
    expect(term.disposed).toBe(true);
  });

  it('is idempotent (safe to call twice, and before open())', () => {
    const client = new SSHConsoleClient();
    expect(() => client.dispose()).not.toThrow();
    open(client);
    client.dispose();
    expect(() => client.dispose()).not.toThrow();
  });

  it('swallows errors from ws.close() and term.dispose()', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    ws.close = () => {
      throw new Error('socket already gone');
    };
    term.dispose = () => {
      throw new Error('already disposed');
    };
    expect(() => client.dispose()).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Incoming message routing (ws.onmessage)
// ---------------------------------------------------------------------------

describe('SSHConsoleClient incoming messages', () => {
  it('writes binary frames to the terminal', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    const payload = new TextEncoder().encode('output').buffer;
    ws.onmessage?.({ data: payload });
    expect(term.written).toHaveLength(1);
    expect(Array.from(term.written[0]!)).toEqual(Array.from(new Uint8Array(payload)));
  });

  it('does not write binary frames once the terminal has been disposed', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    client.dispose();
    const payload = new TextEncoder().encode('late').buffer;
    expect(() => ws.onmessage?.({ data: payload })).not.toThrow();
  });

  it('routes an error control frame to onError', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    const messages: string[] = [];
    client.onError = (m) => messages.push(m);
    ws.onmessage?.({ data: '{"type":"error","message":"boom"}' });
    expect(messages).toEqual(['boom']);
  });

  it('falls back to a generic message for an error frame with no message field', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    const messages: string[] = [];
    client.onError = (m) => messages.push(m);
    ws.onmessage?.({ data: '{"type":"error"}' });
    expect(messages).toEqual(['console error']);
  });

  it('routes an exit control frame to dispose() + onClose', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    let closed = false;
    client.onClose = () => {
      closed = true;
    };
    ws.onmessage?.({ data: '{"type":"exit"}' });
    expect(closed).toBe(true);
    expect(term.disposed).toBe(true);
  });

  it('ignores text frames that are not a recognized control frame', () => {
    const client = new SSHConsoleClient();
    const { term, ws } = open(client);
    const onError = vi.fn();
    const onClose = vi.fn();
    client.onError = onError;
    client.onClose = onClose;
    ws.onmessage?.({ data: '{"type":"whatever"}' });
    ws.onmessage?.({ data: 'not json' });
    expect(onError).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    expect(term.written).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// ws.onerror / ws.onclose
// ---------------------------------------------------------------------------

describe('SSHConsoleClient socket lifecycle callbacks', () => {
  it('reports a socket error via onError', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    const onError = vi.fn();
    client.onError = onError;
    ws.onerror?.();
    expect(onError).toHaveBeenCalledWith('console connection error');
  });

  it('tolerates a socket error with no onError handler registered', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    expect(() => ws.onerror?.()).not.toThrow();
  });

  it('reports socket close via onClose', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    const onClose = vi.fn();
    client.onClose = onClose;
    ws.onclose?.();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('tolerates socket close with no onClose handler registered', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    expect(() => ws.onclose?.()).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Host-key confirm / notify handling
// ---------------------------------------------------------------------------

describe('SSHConsoleClient host-key prompts', () => {
  const confirmFrame = JSON.stringify({
    type: 'hostkey',
    host: 'db1.example.com:22',
    key_type: 'ssh-ed25519',
    fingerprint: 'SHA256:abc',
    known: false,
    mode: 'confirm',
  });
  const notifyFrame = JSON.stringify({
    type: 'hostkey',
    host: 'db1.example.com:22',
    key_type: 'ssh-ed25519',
    fingerprint: 'SHA256:abc',
    known: true,
    mode: 'notify',
  });

  it('fail-closed: auto-rejects a "confirm" prompt when no onHostKey handler is set', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    ws.onmessage?.({ data: confirmFrame });
    expect(lastSentControl(ws)).toEqual(JSON.parse(encodeHostKeyResponse(false)));
  });

  it('invokes onHostKey for a "confirm" prompt and sends accept/reject exactly once', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    let captured: HostKeyPrompt | undefined;
    let respondFn: ((accept: boolean) => void) | undefined;
    client.onHostKey = (prompt, respond) => {
      captured = prompt;
      respondFn = respond;
    };
    ws.onmessage?.({ data: confirmFrame });
    expect(captured?.mode).toBe('confirm');
    expect(captured?.host).toBe('db1.example.com:22');
    expect(ws.sent).toHaveLength(0); // awaiting the caller's decision

    respondFn?.(true);
    expect(lastSentControl(ws)).toEqual({ type: 'hostkey-response', accept: true });

    // A second respond() call must not send a duplicate frame.
    respondFn?.(false);
    expect(ws.sent).toHaveLength(1);
  });

  it('invokes onHostKey for a "notify" prompt and treats respond() as a no-op', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    let captured: HostKeyPrompt | undefined;
    let respondFn: ((accept: boolean) => void) | undefined;
    client.onHostKey = (prompt, respond) => {
      captured = prompt;
      respondFn = respond;
    };
    ws.onmessage?.({ data: notifyFrame });
    expect(captured?.mode).toBe('notify');
    expect(ws.sent).toHaveLength(0);

    // notify's respond() is a no-op: calling it sends nothing.
    respondFn?.(true);
    expect(ws.sent).toHaveLength(0);
  });

  it('does not send a hostkey-response frame when the socket is not open', () => {
    const client = new SSHConsoleClient();
    const { ws } = open(client);
    ws.readyState = FakeWebSocket.CLOSED;
    ws.onmessage?.({ data: confirmFrame });
    expect(ws.sent).toHaveLength(0);
  });
});
