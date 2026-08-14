import {
  __publicField,
  encodeHostKeyResponse,
  encodeResize,
  parseControl
} from "./chunk-JUMKVBAM.js";

// src/ssh-console.ts
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
var SSHConsoleClient = class {
  constructor(opts = {}) {
    __publicField(this, "opts", opts);
    __publicField(this, "term");
    __publicField(this, "fitAddon");
    __publicField(this, "ws");
    __publicField(this, "encoder", new TextEncoder());
    __publicField(this, "pendingHostKeyResponded", false);
    /** Called when the server reports an error control frame or the socket errors. */
    __publicField(this, "onError");
    /** Called when the session ends (exit control frame or socket close). */
    __publicField(this, "onClose");
    /**
     * Called when the server reports a host key control frame. For mode
     * "confirm" the server is paused awaiting a response (subject to a
     * server-side timeout); call respond(accept) exactly once to continue or
     * abort the handshake. For mode "notify" the server already decided under
     * its own accept-new policy and respond() is a no-op — this is informational
     * only. If onHostKey is left unset, a "confirm" prompt is auto-rejected
     * (fail-closed): the client never silently trusts an unverified host key.
     */
    __publicField(this, "onHostKey");
  }
  /** open renders the terminal into element and connects to conn.url. */
  open(element, conn) {
    const termOptions = {
      fontSize: this.opts.fontSize ?? 13,
      fontFamily: this.opts.fontFamily ?? "monospace",
      cursorBlink: true,
      convertEol: false,
      scrollback: 5e3
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
    const ws = conn.protocols !== void 0 && conn.protocols.length > 0 ? new WebSocket(conn.url, conn.protocols) : new WebSocket(conn.url);
    ws.binaryType = "arraybuffer";
    this.ws = ws;
    ws.onopen = () => this.sendResize();
    ws.onmessage = (ev) => this.onMessage(ev);
    ws.onerror = () => this.onError?.("console connection error");
    ws.onclose = () => this.onClose?.();
    term.onData((data) => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(this.encoder.encode(data));
      }
    });
    term.onResize(({ rows, cols }) => this.sendResizeRC(rows, cols));
  }
  /** fit resizes the terminal to its container and notifies the server. */
  fit() {
    this.safeFit();
    this.sendResize();
  }
  /** dispose closes the socket and tears down the terminal. Idempotent. */
  dispose() {
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
      }
      this.ws = void 0;
    }
    if (this.term) {
      try {
        this.term.dispose();
      } catch {
      }
      this.term = void 0;
    }
    this.fitAddon = void 0;
  }
  onMessage(ev) {
    const data = ev.data;
    if (typeof data === "string") {
      const control = parseControl(data);
      if (control?.type === "error") {
        this.onError?.(control.message ?? "console error");
      } else if (control?.type === "exit") {
        this.dispose();
        this.onClose?.();
      } else if (control?.type === "hostkey") {
        this.onHostKeyFrame(control);
      }
      return;
    }
    if (data instanceof ArrayBuffer && this.term) {
      this.term.write(new Uint8Array(data));
    }
  }
  onHostKeyFrame(prompt) {
    if (prompt.mode === "notify") {
      this.onHostKey?.(prompt, () => {
      });
      return;
    }
    this.pendingHostKeyResponded = false;
    if (!this.onHostKey) {
      this.sendHostKeyResponse(false);
      return;
    }
    this.onHostKey(prompt, (accept) => this.sendHostKeyResponse(accept));
  }
  sendHostKeyResponse(accept) {
    if (this.pendingHostKeyResponded) {
      return;
    }
    this.pendingHostKeyResponded = true;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(encodeHostKeyResponse(accept));
    }
  }
  sendResize() {
    if (this.term) {
      this.sendResizeRC(this.term.rows, this.term.cols);
    }
  }
  sendResizeRC(rows, cols) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(encodeResize(rows, cols));
    }
  }
  safeFit() {
    try {
      this.fitAddon?.fit();
    } catch {
    }
  }
};
export {
  SSHConsoleClient
};
//# sourceMappingURL=ssh-console.js.map