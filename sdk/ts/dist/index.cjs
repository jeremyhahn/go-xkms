"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  SSHConsoleClient: () => SSHConsoleClient,
  encodeHostKeyResponse: () => encodeHostKeyResponse,
  encodeResize: () => encodeResize,
  parseControl: () => parseControl
});
module.exports = __toCommonJS(index_exports);

// src/ssh-console.ts
var import_xterm = require("@xterm/xterm");
var import_addon_fit = require("@xterm/addon-fit");

// src/protocol.ts
function parseControl(data) {
  let m;
  try {
    m = JSON.parse(data);
  } catch {
    return null;
  }
  if (!m || typeof m.type !== "string") {
    return null;
  }
  if (m.type === "error") {
    return { type: "error", message: typeof m.message === "string" ? m.message : void 0 };
  }
  if (m.type === "exit") {
    return { type: "exit" };
  }
  if (m.type === "hostkey") {
    if (typeof m.host !== "string" || typeof m.key_type !== "string" || typeof m.fingerprint !== "string" || typeof m.known !== "boolean") {
      return null;
    }
    const mode = m.mode === "confirm" || m.mode === "notify" ? m.mode : "confirm";
    return {
      type: "hostkey",
      host: m.host,
      key_type: m.key_type,
      fingerprint: m.fingerprint,
      known: m.known,
      mode
    };
  }
  return null;
}
function encodeResize(rows, cols) {
  return JSON.stringify({ type: "resize", rows, cols });
}
function encodeHostKeyResponse(accept) {
  return JSON.stringify({ type: "hostkey-response", accept });
}

// src/ssh-console.ts
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
    const term = new import_xterm.Terminal(termOptions);
    const fitAddon = new import_addon_fit.FitAddon();
    term.loadAddon(fitAddon);
    term.open(element);
    this.term = term;
    this.fitAddon = fitAddon;
    this.safeFit();
    const ws = new WebSocket(conn.url);
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  SSHConsoleClient,
  encodeHostKeyResponse,
  encodeResize,
  parseControl
});
//# sourceMappingURL=index.cjs.map