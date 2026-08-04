import { ITheme } from '@xterm/xterm';

/** Connection details for SSHConsoleClient.open. */
interface ConsoleConnection {
    /** Full WebSocket URL including any one-time token query, e.g.
     * `ws://127.0.0.1:54321/console?token=abc` or `wss://host/xkms/v1/ssh/console?...`. */
    url: string;
}
/** Construction options. */
interface SSHConsoleOptions {
    fontSize?: number;
    fontFamily?: string;
    theme?: ITheme;
}
/** A server-reported host key awaiting client confirmation or notification. */
interface HostKeyPrompt {
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
declare class SSHConsoleClient {
    private readonly opts;
    private term;
    private fitAddon;
    private ws;
    private readonly encoder;
    private pendingHostKeyResponded;
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
    constructor(opts?: SSHConsoleOptions);
    /** open renders the terminal into element and connects to conn.url. */
    open(element: HTMLElement, conn: ConsoleConnection): void;
    /** fit resizes the terminal to its container and notifies the server. */
    fit(): void;
    /** dispose closes the socket and tears down the terminal. Idempotent. */
    dispose(): void;
    private onMessage;
    private onHostKeyFrame;
    private sendHostKeyResponse;
    private sendResize;
    private sendResizeRC;
    private safeFit;
}

/**
 * The WebSocket console protocol (implemented by the go-xkms console bridge,
 * pkg/ssh/console):
 *   - BINARY message  = raw terminal bytes (server→client: output; client→server: keystrokes)
 *   - TEXT message    = JSON control frame
 *       client→server: { "type": "resize", "rows": R, "cols": C }
 *       client→server: { "type": "hostkey-response", "accept": true|false }
 *       server→client: { "type": "error", "message": "..." } | { "type": "exit" }
 *       server→client: { "type": "hostkey", "host": "...", "key_type": "...",
 *                         "fingerprint": "SHA256:...", "known": false,
 *                         "mode": "confirm"|"notify" }
 *
 * The "hostkey" frame's mode determines the semantics: "confirm" means the
 * server has paused the SSH handshake awaiting a "hostkey-response" frame
 * (subject to a server-side timeout); "notify" means the server already
 * decided under its own accept-new policy and is only informing the client
 * — no response is expected (sending one anyway is harmless; the server
 * ignores unknown or late frames).
 *
 * These helpers are framework- and DOM-free so the protocol can be tested and
 * reused independently of xterm.js.
 */
/** hostkey confirmation mode: "confirm" pauses the handshake for a response; "notify" is informational only. */
type HostKeyMode = 'confirm' | 'notify';
/** A server→client control frame. */
type ServerControl = {
    type: 'error';
    message?: string | undefined;
} | {
    type: 'exit';
} | {
    type: 'hostkey';
    host: string;
    key_type: string;
    fingerprint: string;
    known: boolean;
    mode: HostKeyMode;
};
/** parseControl parses a TEXT control frame; returns null if not a known control. */
declare function parseControl(data: string): ServerControl | null;
/** encodeResize renders a client→server resize control frame. */
declare function encodeResize(rows: number, cols: number): string;
/** encodeHostKeyResponse renders a client→server hostkey-response control frame. */
declare function encodeHostKeyResponse(accept: boolean): string;

export { type ConsoleConnection, type HostKeyMode, type HostKeyPrompt, SSHConsoleClient, type SSHConsoleOptions, type ServerControl, encodeHostKeyResponse, encodeResize, parseControl };
