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

import { Terminal, type ITheme } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { parseControl, encodeResize, encodeHostKeyResponse } from './protocol.js';

/** Connection details for SSHConsoleClient.open. */
export interface ConsoleConnection {
  /** Full WebSocket URL including any one-time token query, e.g.
   * `ws://127.0.0.1:54321/console?token=abc` or `wss://host/xkms/v1/ssh/console?...`. */
  url: string;
}

/** Construction options. */
export interface SSHConsoleOptions {
  fontSize?: number;
  fontFamily?: string;
  theme?: ITheme;
}

/** A server-reported host key awaiting client confirmation or notification. */
export interface HostKeyPrompt {
  host: string;
  key_type: string;
  fingerprint: string;
  known: boolean;
  mode: 'confirm' | 'notify';
}

/**
 * SSHConsoleClient is a framework-agnostic embedded SSH terminal: it renders an
 * xterm.js terminal into a DOM element and bridges it to a go-xkms SSH console
 * over a WebSocket. xkey (Svelte) and other web UIs (React, etc.) wrap it.
 */
export class SSHConsoleClient {
  private term: Terminal | undefined;
  private fitAddon: FitAddon | undefined;
  private ws: WebSocket | undefined;
  private readonly encoder = new TextEncoder();
  private pendingHostKeyResponded = false;

  /** Called when the server reports an error control frame or the socket errors. */
  onError: ((message: string) => void) | undefined;
  /** Called when the session ends (exit control frame or socket close). */
  onClose: (() => void) | undefined;
  /**
   * Called when the server reports a host key control frame. For mode
   * "confirm" the server is paused awaiting a response (subject to a
   * server-side timeout); call respond(accept) exactly once to continue or
   * abort the handshake. For mode "notify" the server already decided under
   * its own accept-new policy and respond() is a no-op — this is informational
   * only. If onHostKey is left unset, a "confirm" prompt is auto-rejected
   * (fail-closed): the client never silently trusts an unverified host key.
   */
  onHostKey: ((prompt: HostKeyPrompt, respond: (accept: boolean) => void) => void) | undefined;

  constructor(private readonly opts: SSHConsoleOptions = {}) {}

  /** open renders the terminal into element and connects to conn.url. */
  open(element: HTMLElement, conn: ConsoleConnection): void {
    const termOptions: ConstructorParameters<typeof Terminal>[0] = {
      fontSize: this.opts.fontSize ?? 13,
      fontFamily: this.opts.fontFamily ?? 'monospace',
      cursorBlink: true,
      convertEol: false,
      scrollback: 5000,
    };
    if (this.opts.theme) {
      termOptions.theme = this.opts.theme;
    }
    const term = new Terminal(termOptions);
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(element);
    this.term = term;
    this.fitAddon = fitAddon;
    this.safeFit();

    const ws = new WebSocket(conn.url);
    ws.binaryType = 'arraybuffer';
    this.ws = ws;

    ws.onopen = () => this.sendResize();
    ws.onmessage = (ev: MessageEvent) => this.onMessage(ev);
    ws.onerror = () => this.onError?.('console connection error');
    ws.onclose = () => this.onClose?.();

    // Keystrokes → binary frames.
    term.onData((data: string) => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(this.encoder.encode(data));
      }
    });
    // Local resize → control frame.
    term.onResize(({ rows, cols }: { rows: number; cols: number }) => this.sendResizeRC(rows, cols));
  }

  /** fit resizes the terminal to its container and notifies the server. */
  fit(): void {
    this.safeFit();
    this.sendResize();
  }

  /** dispose closes the socket and tears down the terminal. Idempotent. */
  dispose(): void {
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // ignore
      }
      this.ws = undefined;
    }
    if (this.term) {
      try {
        this.term.dispose();
      } catch {
        // ignore
      }
      this.term = undefined;
    }
    this.fitAddon = undefined;
  }

  private onMessage(ev: MessageEvent): void {
    const data = ev.data as unknown;
    if (typeof data === 'string') {
      const control = parseControl(data);
      if (control?.type === 'error') {
        this.onError?.(control.message ?? 'console error');
      } else if (control?.type === 'exit') {
        this.dispose();
        this.onClose?.();
      } else if (control?.type === 'hostkey') {
        this.onHostKeyFrame(control);
      }
      return;
    }
    if (data instanceof ArrayBuffer && this.term) {
      this.term.write(new Uint8Array(data));
    }
  }

  private onHostKeyFrame(prompt: HostKeyPrompt): void {
    if (prompt.mode === 'notify') {
      // Informational only: the server already decided; no response expected.
      this.onHostKey?.(prompt, () => {
        // no-op: a "notify" frame is not awaiting a response.
      });
      return;
    }
    // mode === 'confirm': the server is paused awaiting exactly one response.
    this.pendingHostKeyResponded = false;
    if (!this.onHostKey) {
      // Fail-closed: no handler means we never silently trust an unverified
      // host key. Reject so the server aborts the handshake.
      this.sendHostKeyResponse(false);
      return;
    }
    this.onHostKey(prompt, (accept: boolean) => this.sendHostKeyResponse(accept));
  }

  private sendHostKeyResponse(accept: boolean): void {
    if (this.pendingHostKeyResponded) {
      return;
    }
    this.pendingHostKeyResponded = true;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(encodeHostKeyResponse(accept));
    }
  }

  private sendResize(): void {
    if (this.term) {
      this.sendResizeRC(this.term.rows, this.term.cols);
    }
  }

  private sendResizeRC(rows: number, cols: number): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(encodeResize(rows, cols));
    }
  }

  private safeFit(): void {
    try {
      this.fitAddon?.fit();
    } catch {
      // container may not be laid out yet
    }
  }
}
